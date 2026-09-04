"""Kopia PDF na Discord: bez prawdziwych webhooków, sieci i produkcyjnej bazy."""
import json
import urllib.error
from email import policy
from email.parser import BytesParser
from unittest.mock import AsyncMock

import pytest

from app import extra_report_discord as discord
from app.extra_reports import RecipientGroup, ProvinceRecipients, _webhook_for_save

URL = "https://discord.com/api/webhooks/123456/test_token"


@pytest.mark.parametrize("url", [
    "http://discord.com/api/webhooks/123456/token",
    "https://discord.com.evil.example/api/webhooks/123456/token",
    "https://discord.com@127.0.0.1/api/webhooks/123456/token",
    "https://discord.com:8443/api/webhooks/123456/token",
    "https://127.0.0.1/api/webhooks/123456/token",
    URL + "/messages/123", URL + "#fragment", URL + "?thread_id=bad",
    URL + "?thread_id=1&thread_id=2", URL + "?redirect=https://evil.example",
    URL + "\r\nX-Token: secret",
])
def test_only_discord_webhook_urls(url):
    with pytest.raises(ValueError) as error:
        discord.normalize_webhook_url(url)
    assert "test_token" not in str(error.value)


def test_normalization_deduplicates_alias_version_wait_and_keeps_thread():
    assert discord.normalize_webhook_url("  ") == ""
    alias = URL.replace("discord.com/api/", "discordapp.com/api/v10/") + "/?wait=false"
    assert discord.normalize_webhook_url(alias) == URL
    assert discord.normalize_webhook_url(URL + "?with_components=true&wait=false") == URL
    assert discord.unique_targets([
        {"url": URL, "name": "II liga"},
        {"url": alias, "name": "SLASKIE"},
        {"url": URL + "?thread_id=42", "name": "Wątek"},
    ]) == [
        {"url": URL, "name": "II liga / SLASKIE"},
        {"url": URL + "?thread_id=42", "name": "Wątek"},
    ]


def test_older_clients_preserve_webhooks_and_empty_string_disables():
    assert _webhook_for_save(RecipientGroup(name="Liga").discordWebhookUrl, URL) == URL
    assert _webhook_for_save(ProvinceRecipients(province="SLASKIE").discordWebhookUrl, URL) == URL
    assert _webhook_for_save("", URL) == ""


def test_real_multipart_contains_exact_pdf_and_wait_confirmation(monkeypatch):
    pdf = b"%PDF-1.7\n\x00\xff\r\nbinary report"
    payload = discord.report_payload(
        kind="referees", match_number="IIM4/1", names=["ŻÓŁĆ Jan @everyone"],
        teams=["Gospodarz", "Gość"], generated_at="2026-09-05T12:00:00+00:00",
        filename="raport.pdf",
    )
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b'{"id":"987654"}'

    class Opener:
        def open(self, request, timeout):
            captured.update(request=request, timeout=timeout)
            return Response()

    def build_opener(handler):
        assert isinstance(handler, discord._NoRedirect)
        return Opener()

    monkeypatch.setattr(discord.urllib.request, "build_opener", build_opener)
    assert discord._send_pdf_sync(URL + "?thread_id=42", payload, pdf, "raport.pdf") == "987654"
    request = captured["request"]
    assert request.full_url == URL + "?thread_id=42&wait=true"
    assert captured["timeout"] == 10
    assert "BAZA-ExtraReport" in request.get_header("User-agent")
    msg = BytesParser(policy=policy.default).parsebytes(
        f'Content-Type: {request.get_header("Content-type")}\r\nMIME-Version: 1.0\r\n\r\n'.encode() + request.data,
    )
    params, attachment = list(msg.iter_parts())
    parsed = json.loads(params.get_payload(decode=True))
    assert parsed["allowed_mentions"] == {"parse": []}
    assert parsed["attachments"] == [{"id": 0, "filename": "raport.pdf"}]
    assert "ŻÓŁĆ" in parsed["embeds"][0]["fields"][2]["value"]
    assert attachment.get_param("name", header="Content-Disposition") == "files[0]"
    assert attachment.get_filename() == "raport.pdf"
    assert attachment.get_content_type() == "application/pdf"
    assert attachment.get_payload(decode=True) == pdf


async def test_partial_delivery_deduplication_and_secret_free_errors(monkeypatch, caplog):
    calls = []

    def send(url, payload, pdf, filename):
        calls.append(url)
        if url.endswith("broken_token"):
            raise urllib.error.HTTPError(url, 429, "secret error", {}, None)
        return "987654"

    monkeypatch.setattr(discord, "_send_pdf_sync", send)
    result = await discord.send_report_copies(
        targets=[{"name": "Liga", "url": URL}, {"name": "Okręg", "url": URL},
                 {"name": "Drugi", "url": URL.replace("test_token", "broken_token")}],
        pdf=b"%PDF", filename="r.pdf", payload={},
    )
    assert len(calls) == 2
    assert result["status"] == "partial"
    assert [d["status"] for d in result["deliveries"]] == ["sent", "failed"]
    assert result["deliveries"][0]["name"] == "Liga / Okręg"
    assert "429" in result["deliveries"][1]["error"]
    assert "token" not in json.dumps(result) + caplog.text


async def test_disabled_and_oversize_make_no_network_calls(monkeypatch):
    transport = AsyncMock()
    monkeypatch.setattr(discord.asyncio, "to_thread", transport)
    assert (await discord.send_report_copies(targets=[], pdf=b"pdf", filename="r.pdf", payload={}))["status"] == "disabled"
    monkeypatch.setattr(discord, "MAX_PDF_BYTES", 3)
    result = await discord.send_report_copies(
        targets=[{"name": "Liga", "url": URL}], pdf=b"long pdf", filename="r.pdf", payload={},
    )
    assert result["status"] == "failed"
    transport.assert_not_called()


async def test_timeout_is_not_retried_or_reported_as_success(monkeypatch, caplog):
    def fail(*args):
        raise TimeoutError(URL)

    monkeypatch.setattr(discord, "_send_pdf_sync", fail)
    result = await discord.send_report_copies(
        targets=[{"name": "Liga", "url": URL}], pdf=b"pdf", filename="r.pdf", payload={},
    )
    assert result["status"] == "failed"
    assert "Nie potwierdzono" in result["deliveries"][0]["error"]
    assert "test_token" not in caplog.text
