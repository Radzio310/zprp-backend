"""Kopia dodatkowego raportu na Discordzie, wysyłana wyłącznie przez backend.

Jak webhook backupu/raportu Beach: embed, własny User-Agent, timeout i błąd
odizolowany od głównej operacji. PDF jest załącznikiem, nie publicznym linkiem.
Nie ponawiamy POST automatycznie: po timeout Discord mógł już zapisać wiadomość.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import urllib.error
import urllib.request
import uuid
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

logger = logging.getLogger(__name__)
MAX_PDF_BYTES = 10 * 1024 * 1024
WEBHOOK_PATH = re.compile(r"/api(?:/v\d+)?/webhooks/([0-9]+)/([A-Za-z0-9_-]+)/?\Z")
HOSTS = {"discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com"}


def normalize_webhook_url(value: str | None) -> str:
    """Puste = wyłączone. Pozostałe adresy muszą być webhookami Discord HTTPS.

    Adres zawiera sekret. Wyjątki, odpowiedzi publiczne i logi go nie ujawniają.
    Opcjonalny thread_id pozwala wskazać istniejący wątek forum.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    error = ValueError("Podaj adres HTTPS webhooka Discord (opcjonalnie z thread_id).")
    try:
        url = urlsplit(raw)
        match = WEBHOOK_PATH.fullmatch(url.path)
        if (
            len(raw) > 512 or any(c.isspace() for c in raw)
            or url.scheme != "https" or url.hostname not in HOSTS
            or url.port not in (None, 443) or url.username or url.password
            or url.fragment or not match
        ):
            raise error
        query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
        if set(query) - {"wait", "thread_id"}:
            raise error
        thread = query.get("thread_id")
        if thread and (len(thread) != 1 or not re.fullmatch(r"[0-9]+", thread[0])):
            raise error
        host = "discord.com" if url.hostname == "discordapp.com" else url.hostname
        return urlunsplit((
            "https", host, f"/api/webhooks/{match[1]}/{match[2]}",
            urlencode({"thread_id": thread[0]}) if thread else "", "",
        ))
    except (ValueError, TypeError):
        raise error from None


def unique_targets(targets: list[dict[str, str]]) -> list[dict[str, str]]:
    """Ten sam webhook przypisany grupie i okręgowi dostaje tylko jedną kopię."""
    by_url: dict[str, dict[str, str]] = {}
    for target in targets:
        url = normalize_webhook_url(target.get("url"))
        if not url:
            continue
        if url not in by_url:
            by_url[url] = {"url": url, "name": target["name"]}
        elif target["name"] not in by_url[url]["name"].split(" / "):
            by_url[url]["name"] += " / " + target["name"]
    return list(by_url.values())


def report_payload(*, kind: str, match_number: str, names: list[str],
                   teams: list[str], generated_at: str, filename: str) -> dict[str, Any]:
    label = "Raport sędziów" if kind == "referees" else "Raport delegata"
    return {
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": f"📄 Dodatkowy raport — {label.lower()}",
            "color": 0xC38E70 if kind == "referees" else 0x60CDFF,
            "fields": [
                {"name": "Mecz", "value": (match_number or "Bez numeru")[:1024]},
                {"name": "Drużyny", "value": (" — ".join(teams) or "—")[:1024]},
                {"name": "Autorzy raportu", "value": (", ".join(names) or "—")[:1024]},
            ],
            "timestamp": generated_at,
            "footer": {"text": "BAZA • dodatkowy raport PDF"},
        }],
        "attachments": [{"id": 0, "filename": filename}],
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Załącznik może zawierać dane osobowe: nigdy nie idzie na przekierowanie.
        return None


def _send_pdf_sync(url: str, payload: dict[str, Any], pdf: bytes, filename: str) -> str:
    url = normalize_webhook_url(url)
    url += ("&" if "?" in url else "?") + "wait=true"
    boundary = "baza-report-" + uuid.uuid4().hex
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="payload_json"\r\n'
        'Content-Type: application/json\r\n\r\n'
    ).encode() + json.dumps(payload, ensure_ascii=False).encode("utf-8") + (
        f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="files[0]"; '
        f'filename="{safe_name}"\r\nContent-Type: application/pdf\r\n\r\n'
    ).encode() + pdf + f"\r\n--{boundary}--\r\n".encode()
    request = urllib.request.Request(url, data=body, headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "BAZA-ExtraReport/1.0 (zprp-backend)",
    })
    with urllib.request.build_opener(_NoRedirect()).open(request, timeout=10) as response:
        message = json.loads(response.read())
    message_id = str(message.get("id") or "")
    if not message_id:
        raise ValueError("Brak potwierdzenia Discord")
    return message_id


async def send_report_copies(*, targets: list[dict[str, str]], pdf: bytes,
                            filename: str, payload: dict[str, Any]) -> dict[str, Any]:
    targets = unique_targets(targets)
    if not targets:
        return {"status": "disabled", "deliveries": []}
    semaphore = asyncio.Semaphore(4)

    async def send(target: dict[str, str]) -> dict[str, Any]:
        error = ""
        if len(pdf) > MAX_PDF_BYTES:
            error = "PDF przekracza limit wysyłki 10 MiB."
        else:
            try:
                async with semaphore:
                    message_id = await asyncio.to_thread(
                        _send_pdf_sync, target["url"], payload, pdf, filename,
                    )
                logger.info("Extra report Discord copy sent (%s)", message_id)
                return {"name": target["name"], "status": "sent", "messageId": message_id}
            except urllib.error.HTTPError as exc:
                error = (
                    "Discord ograniczył liczbę wysyłek (429)."
                    if exc.code == 429 else f"Discord odrzucił wysyłkę (HTTP {exc.code})."
                )
            except Exception:
                error = "Nie potwierdzono dostarczenia kopii do Discorda."
        # Bez str(exc), URL i response body: mogą zawierać token webhooka.
        logger.warning("Extra report Discord copy: %s", error)
        return {"name": target["name"], "status": "failed", "error": error}

    deliveries = await asyncio.gather(*(send(t) for t in targets))
    sent = sum(d["status"] == "sent" for d in deliveries)
    return {
        "status": "sent" if sent == len(deliveries) else "partial" if sent else "failed",
        "deliveries": deliveries,
    }
