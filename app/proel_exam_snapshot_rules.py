"""Czyste reguły współdzielonej migawki badań ProEla."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
VALID_MARKS = {"none", "manual", "wzpr", "zprp"}
MAX_PLAYERS_PER_TEAM = 64


def polish_day(now: datetime) -> str:
    """Dzień kalendarzowy w Polsce, także dla czasu UTC z bazy."""
    aware = now if now.tzinfo is not None else now.replace(tzinfo=WARSAW)
    return aware.astimezone(WARSAW).date().isoformat()


def valid_date_key(value: Any) -> str:
    key = str(value or "").strip()
    if not DATE_RE.fullmatch(key):
        raise ValueError("Nieprawidłowy dzień meczu")
    # `fromisoformat` odrzuca np. 2026-02-31.
    datetime.fromisoformat(key)
    return key


def snapshot_is_frozen(date_key: str, now: datetime) -> bool:
    """Po polskiej północy migawki z zakończonego dnia są niezmienne."""
    return valid_date_key(date_key) < polish_day(now)


def _clean_player(raw: Any) -> Dict[str, Any]:
    value = raw if isinstance(raw, dict) else {}
    name = str(value.get("fullName") or "").strip()[:180]
    surname = str(value.get("surname") or "").strip()[:120]
    photo = str(value.get("photoUrl") or "").strip()[:1000]
    mark = str(value.get("exam") or "none").strip().lower()
    if mark not in VALID_MARKS:
        mark = "none"

    out: Dict[str, Any] = {"fullName": name, "exam": mark}
    try:
        number = int(value.get("number"))
        if 0 <= number <= 999:
            out["number"] = number
    except (TypeError, ValueError):
        pass
    if surname:
        out["surname"] = surname
    if photo.startswith(("https://", "http://")):
        out["photoUrl"] = photo
    # Kto postawił ręczny ptaszek - inicjał „długopisem" w kratce badań.
    exam_by = str(value.get("examBy") or "").strip()[:80]
    if exam_by and mark == "manual":
        out["examBy"] = exam_by
    return out


def clean_players(values: Iterable[Any]) -> List[Dict[str, Any]]:
    return [_clean_player(item) for item in list(values or [])[:MAX_PLAYERS_PER_TEAM]]


def clean_snapshot(host: Iterable[Any], guest: Iterable[Any]) -> Dict[str, Any]:
    return {
        "hostPlayers": clean_players(host),
        "guestPlayers": clean_players(guest),
    }


def snapshot_hash(date_key: str, snapshot: Dict[str, Any]) -> str:
    body = json.dumps(
        {"dateKey": valid_date_key(date_key), **snapshot},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


# ─────────── potwierdzenia z zapisu ProEla meczu ───────────
#
# Migawka bywa starsza niż potwierdzenia. Ręczny ptaszek postawiony w meczu
# ProEl (ekran konfiguracji, arkusz w meczu) żyje w overlayu (`fields_json`)
# albo - w zapisach sprzed wchłaniania - wyłącznie w kartach bloba. Telefon
# wysyła migawkę tylko ze szczegółów meczu, więc potwierdzenie zrobione gdzie
# indziej nie trafiało do niej nigdy, a po północy migawka zamarza. Odczyt
# scala je więc w locie: stare mecze działają bez migracji, nowe tak samo.

EXAM_SRC_BLOB = "blob"
EXAM_SRC_ZPRP = "zprp"
_CONFIRMING_MARKS = ("manual", "wzpr", "zprp")


def _entry_day(at: Any) -> str:
    raw = str(at or "").strip()
    if not raw:
        return ""
    try:
        moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw[:10]
    return polish_day(moment)


def exam_confirmations(
    overlay: Any,
    blob_config: Any,
    date_key: Any = None,
) -> List[Dict[str, Any]]:
    """Potwierdzenia badań meczu: `{team, number, name, mark, by, at, src}`.

    * Overlay wygrywa z kartą bloba pod tą samą ścieżką (także wpis „none",
      czyli cofnięcie - wtedy karta nie wskrzesza ptaszka).
    * Wpis z `/proel/patch` liczy się tylko z dnia meczu lub wcześniej -
      migawka mówi, co było prawdą TEGO dnia. Wchłonięty z bloba (`src=blob`)
      i awans z bazy związku (`src=zprp`) liczą się zawsze: pierwszy to sam
      protokół meczu (bywa wysłany po północy), drugi dzieje się tylko przed
      pierwszym gwizdkiem.
    """
    # Import w funkcji: reguły migawki zostają lekkie dla testów i tras.
    from app.proel_fields import blob_exam_cards, live_exam_entries

    day = ""
    try:
        day = valid_date_key(date_key) if date_key else ""
    except ValueError:
        day = ""
    out: List[Dict[str, Any]] = []
    live = live_exam_entries(overlay if isinstance(overlay, dict) else {})
    for path, item in live.items():
        entry = item.get("entry") or {}
        src = str(entry.get("src") or "")
        if item["mark"] not in _CONFIRMING_MARKS:
            continue
        if day and src not in (EXAM_SRC_BLOB, EXAM_SRC_ZPRP):
            entry_day = _entry_day(entry.get("at"))
            if entry_day and entry_day > day:
                continue
        out.append(
            {
                "team": item["team"],
                "number": item["number"],
                "name": item["name"],
                "mark": item["mark"],
                "by": str(((entry.get("by") or {}).get("name")) or "").strip()[:80],
                "at": str(entry.get("at") or ""),
                "src": src or "patch",
            }
        )
    blob = {"matchConfig": blob_config} if isinstance(blob_config, dict) else None
    for card in blob_exam_cards(blob):
        if card["mark"] != "manual" or card["path"] in live:
            continue
        out.append(
            {
                "team": card["team"],
                "number": card["number"],
                "name": card["name"],
                "mark": "manual",
                "by": "",
                "at": "",
                "src": EXAM_SRC_BLOB,
            }
        )
    return out


def merge_exam_confirmations(
    players: Iterable[Any],
    team: str,
    confirmations: Iterable[Dict[str, Any]],
    requirement: str = "any",
) -> List[Dict[str, Any]]:
    """Nałóż potwierdzenia na karty migawki. Tylko w górę, nigdy w dół.

    Reguła ta sama co `applyExamOverlay`: status karty zostaje, dopóki
    WYSTARCZA w tej rozgrywce; inaczej wchodzi potwierdzenie, jeśli ono
    wystarcza. Dopasowanie po numerze (gdy nazwisko się zgadza albo go
    brak), potem po nazwisku - jak w `promotions_for`.
    """
    from app.proel_fields import _same_person, exam_mark_meets, normalize_name

    mine = [c for c in confirmations or [] if str(c.get("team") or "") == team]
    out: List[Dict[str, Any]] = []
    for raw in players or []:
        player = dict(raw) if isinstance(raw, dict) else {}
        current = str(player.get("exam") or "none")
        if exam_mark_meets(current, requirement) or not mine:
            out.append(player)
            continue
        want = player.get("fullName") or ""
        number = player.get("number")
        hit = None
        if number is not None:
            hit = next(
                (
                    c
                    for c in mine
                    if c.get("number") == number
                    and (
                        not normalize_name(want)
                        or not normalize_name(c.get("name"))
                        or _same_person(want, c.get("name"))
                    )
                ),
                None,
            )
        if hit is None and normalize_name(want):
            hit = next((c for c in mine if _same_person(want, c.get("name"))), None)
        if hit is not None and exam_mark_meets(hit.get("mark"), requirement):
            player["exam"] = str(hit["mark"])
            if hit["mark"] == "manual" and hit.get("by"):
                player["examBy"] = str(hit["by"])
        out.append(player)
    return out
