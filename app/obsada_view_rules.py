"""
Obsada na zywo (12.11.2026) - lisc regul bez bazy i sieci.

Podglad obsady okregowej tylko do odczytu. Zrodlo to migawka `province_matches`
(to, co jest w ZPRP), nigdy szkice. Tu siedza: tryby dostepu, losowy token linku,
klucz sedziego niezalezny od kolejnosci czlonow, rewizja do ETag, roznica
obsady/terminu do dziennika zmian i plik .ics sedziego. Dane osobowe: same
nazwiska, zadnych telefonow ani numerow licencji.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional

from app.person_names import person_name_key

MODES = ("off", "app", "link")
DEFAULT_MODE = "off"

#: Bez O/0/I/1/l - nie do pomylenia przy przepisywaniu linku.
TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
TOKEN_LENGTH = 16

#: Gniazda w wersji dla klienta -> gniazda ZPRP.
SLOT_MAP = {
    "first": "pierwszy",
    "second": "drugi",
    "secretary": "sekretarz",
    "time": "czas",
    "delegate": "delegat",
    "delegate2": "delegat2",
}

KINDS = ("new_crew", "crew_change", "moved", "cancelled")
MATCH_DURATION = timedelta(hours=2)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def normalize_mode(value: Any) -> Optional[str]:
    mode = _s(value).lower()
    return mode if mode in MODES else None


def new_token() -> str:
    return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LENGTH))


def valid_token(value: Any) -> bool:
    text = _s(value)
    return len(text) == TOKEN_LENGTH and all(ch in TOKEN_ALPHABET for ch in text)


# --- sedzia -----------------------------------------------------------------

def judge_key(name: Any) -> str:
    """
    Klucz sedziego do adresu: bez kolejnosci czlonow, ogonkow i wielkosci liter.

    "KOWALCZYK Bartlomiej O" i "Bartlomiej O. Kowalczyk" daja ten sam klucz
    (inicjal zostaje - rozdziela imiennikow, patrz `person_names`).
    """
    return person_name_key(name).replace(" ", "-")


class Roster:
    """Sedziowie okregu: po numerze (judge_id) i po kluczu nazwiska. Namesaki = brak zdjecia."""

    def __init__(self, rows: Iterable[Mapping[str, Any]] = ()):
        self.by_id: dict[str, str] = {}
        self.by_key: dict[str, Optional[str]] = {}
        for raw in rows:
            # Rekord z `databases` nie ma .get() - zawsze przez zwykly slownik.
            row = dict(raw)
            photo = _s(row.get("photo_url"))
            photo = photo if photo.lower().startswith("https://") else ""
            jid = _s(row.get("judge_id"))
            if jid:
                self.by_id[jid] = photo
            key = judge_key(row.get("full_name"))
            if not key:
                continue
            # Ten sam klucz u dwoch osob: zdjecie niczyje (nigdy cudza twarz).
            self.by_key[key] = None if key in self.by_key else (photo or None)

    def knows(self, person: Optional[Mapping[str, Any]]) -> bool:
        """Czy osoba z obsady jest sedzia tego okregu (numer albo klucz nazwiska)."""
        if not isinstance(person, Mapping):
            return False
        number = _s(person.get("number"))
        if number and number in self.by_id:
            return True
        return judge_key(person.get("name")) in self.by_key

    def photo(self, person: Optional[Mapping[str, Any]]) -> Optional[str]:
        if not isinstance(person, Mapping):
            return None
        number = _s(person.get("number"))
        if number:
            if number in self.by_id:
                return self.by_id[number] or None
            return None
        return self.by_key.get(judge_key(person.get("name"))) or None


def keep_match(organizer_kind: Any, crew: Mapping[str, Any], roster: Roster) -> bool:
    """Mecz organizowany przez okreg (albo DRK) albo cudzy z naszym sedzia w obsadzie."""
    if _s(organizer_kind) in ("own", "drk"):
        return True
    return any(roster.knows(person) for person in crew.values())


def crew_view(crew: Mapping[str, Any], roster: Optional[Roster] = None) -> dict:
    """Obsada dla klienta: nazwisko, klucz i zdjecie (tylko sedziowie okregu). Bez numerow."""
    out: dict = {}
    for slot_out, slot_zprp in SLOT_MAP.items():
        person = crew.get(slot_zprp)
        name = _s(person.get("name")) if isinstance(person, Mapping) else ""
        out[slot_out] = ({"name": name, "key": judge_key(name),
                          "photo": roster.photo(person) if roster else None} if name else None)
    return out


def needs_view(crew: Mapping[str, Any], needs: Mapping[str, Any]) -> dict:
    """Ktore gniazda sa do obsadzenia: puste i wymagane (delegaci nigdy)."""
    field = int(needs.get("field") or 0)
    table = int(needs.get("table") or 0)
    wanted = {"first": field >= 1, "second": field >= 2,
              "secretary": table >= 1, "time": table >= 2}
    return {slot: bool(wanted.get(slot) and not crew.get(SLOT_MAP[slot]))
            for slot in ("first", "second", "secretary", "time", "delegate", "delegate2")}


def status_live(state: Mapping[str, Any]) -> Optional[str]:
    """Znacznik odwolania/przelozenia, jesli migawka go niesie."""
    for key in ("match_status", "status_meczu", "Status", "status"):
        text = _s(state.get(key)).lower()
        if any(mark in text for mark in ("odwo", "przeloz", "przełoż", "walkower")):
            return _s(state.get(key))
    return None


# --- rewizja ---------------------------------------------------------------

def compute_rev(matches: Iterable[Mapping[str, Any]], updated_at: Any = None) -> str:
    """Krotki odcisk tresci - ten sam stan daje ten sam `rev` (ETag)."""
    payload = json.dumps([list(matches), _s(updated_at)], sort_keys=True,
                         ensure_ascii=False, default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


def etag_matches(header: Any, rev: str) -> bool:
    """Czy `If-None-Match` wskazuje ten `rev` (z cudzyslowem, W/ albo bez)."""
    for part in _s(header).split(","):
        if part.strip().removeprefix("W/").strip('"') == rev:
            return True
    return False


# --- dziennik zmian ---------------------------------------------------------

def _names(state: Mapping[str, Any]) -> dict:
    out = {}
    for slot_out, slot in SLOT_MAP.items():
        name = _s(state.get(f"NrSedzia_{slot}_nazwisko"))
        out[slot_out] = None if (not name or name.strip("- ") == "") else name
    return out


def _iso(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    return value.isoformat() if hasattr(value, "isoformat") else _s(value)


def diff_changes(before: Mapping[str, Any], after: Mapping[str, Any],
                 before_at: Any, after_at: Any) -> list[dict]:
    """
    Zmiany jednego meczu miedzy dwiema migawkami: [{kind, before, after}].

    new_crew - mecz nie mial obsady, teraz ma; crew_change - zmiana osob w
    obsadzie, ktora juz byla; moved - inny termin; cancelled - nowy znacznik
    odwolania. Obsada liczy sie po kluczu osoby, nie po zapisie nazwiska.
    """
    out: list[dict] = []
    b, a = _names(before), _names(after)
    keys_b = {k: judge_key(v) for k, v in b.items() if v}
    keys_a = {k: judge_key(v) for k, v in a.items() if v}
    if keys_b != keys_a:
        out.append({"kind": "new_crew" if not keys_b else "crew_change",
                    "before": b, "after": a})
    if _iso(before_at) != _iso(after_at) and (before_at or after_at):
        out.append({"kind": "moved",
                    "before": {"match_at": _iso(before_at)},
                    "after": {"match_at": _iso(after_at)}})
    if status_live(after) and not status_live(before):
        out.append({"kind": "cancelled", "before": None,
                    "after": {"status": status_live(after)}})
    return out


# --- .ics ------------------------------------------------------------------

def _ics_escape(text: Any) -> str:
    return (_s(text).replace("\\", "\\\\").replace(";", "\\;")
            .replace(",", "\\,").replace("\r", "").replace("\n", "\\n"))


def _fold(line: str) -> str:
    if len(line.encode("utf-8")) <= 74:
        return line
    parts, current, size = [], "", 0
    for ch in line:
        width = len(ch.encode("utf-8"))
        if size + width > (74 if not parts else 73):
            parts.append(current)
            current, size = "", 0
        current += ch
        size += width
    parts.append(current)
    return "\r\n ".join(parts)


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_ics(matches: Iterable[Mapping[str, Any]], key: str, *,
              calendar_name: str = "Obsada", now: Optional[datetime] = None) -> str:
    """
    Kalendarz .ics sedziego o kluczu `key` z payloadu widoku (pola `crew`,
    `match_at`, `host`, `guest`, `hall`, `city`, `code`). Mecze bez terminu
    pomijamy. Rola (np. "1. sedzia") idzie w tytule i opisie.
    """
    now = now or datetime.now(timezone.utc)
    labels = {"first": "1. sędzia", "second": "2. sędzia", "secretary": "sekretarz",
              "time": "czas", "delegate": "delegat", "delegate2": "delegat 2"}
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//BAZA//Obsada na zywo//PL",
             "CALSCALE:GREGORIAN", "METHOD:PUBLISH",
             f"X-WR-CALNAME:{_ics_escape(calendar_name)}",
             "REFRESH-INTERVAL;VALUE=DURATION:PT6H"]
    for match in matches:
        role = next((slot for slot, p in (match.get("crew") or {}).items()
                     if p and p.get("key") == key), None)
        at = match.get("match_at")
        if role is None or not at:
            continue
        start = datetime.fromisoformat(_s(at).replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        title = f"{_s(match.get('host'))} - {_s(match.get('guest'))}"
        place = ", ".join(x for x in (_s(match.get("hall")), _s(match.get("address")),
                                      _s(match.get("city"))) if x)
        desc = f"{labels[role]} | {_s(match.get('competition_label') or match.get('code'))}"
        lines += ["BEGIN:VEVENT",
                  f"UID:obsada-{_s(match.get('match_id'))}-{key}@bazapodreka.app",
                  f"DTSTAMP:{_stamp(now)}", f"DTSTART:{_stamp(start)}",
                  f"DTEND:{_stamp(start + MATCH_DURATION)}",
                  f"SUMMARY:{_ics_escape(labels[role] + ': ' + title)}",
                  f"DESCRIPTION:{_ics_escape(desc)}"]
        if place:
            lines.append(f"LOCATION:{_ics_escape(place)}")
        lines.append("END:VEVENT")
    lines.append("END:VCALENDAR")
    return "\r\n".join(_fold(line) for line in lines) + "\r\n"


# --- podpisany adres .ics ---------------------------------------------------

def sign_ics(secret: str, province: str, scope: str, key: str, token: str) -> str:
    """Podpis stalego adresu .ics. `token` w materiale: nowy token uniewaznia stare adresy."""
    msg = "|".join([province, scope, key, token]).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()[:32]


def verify_ics(secret: str, province: str, scope: str, key: str, token: str, sig: Any) -> bool:
    return hmac.compare_digest(sign_ics(secret, province, scope, key, token), _s(sig))


def safe_key(value: Any) -> bool:
    return bool(re.fullmatch(r"[a-z0-9~-]{1,120}", _s(value)))
