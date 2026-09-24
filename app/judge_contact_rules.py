"""
Adres e-mail sędziego do powiadomień okręgu - skąd go brać.

Decyzja użytkownika z 24.09.2026: potwierdzone konta ProEla to ZŁE źródło dla
maili obsady (mało kto ma tam konto, a numer bywa niedowiedziony). Kolejność:

  1. `login_records` - profil sędziego z logowania w aplikacji BAZA (adres
     w kolumnie `email`, gdy kiedyś powstanie, albo w `config_json`),
  2. kontakty sędziów - ten sam plik, który pokazuje ekran „Kontakty"
     w aplikacji (`json_files`, klucz `kontakty`), dopasowany po okręgu,
     imieniu i nazwisku (`official_roster.person_key` - bez ogonków,
     w dowolnej kolejności członów).

Zero zgadywania: dwa różne adresy pod tym samym nazwiskiem to brak adresu,
a nie losowy wybór - lepiej nie napisać, niż napisać na cudzą skrzynkę.

MODUŁ-LIŚĆ: bez bazy i sieci.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping, Optional

from app.official_roster import fold as roster_fold
from app.official_roster import person_key

SOURCE_LOGIN = "login"
SOURCE_CONTACTS = "contacts"

_EMAIL_RE = re.compile(r"^[^@\s;,]+@[^@\s;,]+\.[^@\s;,]+$")

#: Klucze w `config_json` profilu, pod którymi aplikacja mogła zapisać adres.
_CONFIG_KEYS = ("email", "mail", "contact_email", "user_email", "e_mail")
_CONFIG_NESTS = ("profile", "contact", "user", "account")
#: Pola kontaktu, w których bywa okręg.
_PROVINCE_FIELDS = ("province", "wojewodztwo", "województwo", "okreg", "okręg")


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def emails_in(value: Any) -> list[str]:
    """Poprawne adresy z pola, które bywa listą „a@x;b@y" - małymi literami, bez powtórek."""
    out: list[str] = []
    for part in re.split(r"[;,\s]+", _s(value)):
        text = part.strip().lower()
        if text and _EMAIL_RE.match(text) and text not in out:
            out.append(text)
    return out


def _as_dict(value: Any) -> dict:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return {}
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def login_email(row: Mapping[str, Any]) -> str:
    """Adres z profilu logowania: kolumna `email` albo `config_json`."""
    direct = emails_in(row.get("email")) if "email" in row else []
    if direct:
        return direct[0]
    config = _as_dict(row.get("config_json"))
    for key in _CONFIG_KEYS:
        found = emails_in(config.get(key))
        if found:
            return found[0]
    for nest in _CONFIG_NESTS:
        inner = _as_dict(config.get(nest))
        for key in _CONFIG_KEYS:
            found = emails_in(inner.get(key))
            if found:
                return found[0]
    return ""


def _is_referee(contact: Mapping[str, Any]) -> bool:
    """Kontakt sędziego: znacznik `isReferee` albo rola bez znacznika drużyny."""
    if contact.get("isTeam") is True:
        return False
    if "isReferee" in contact:
        return bool(contact.get("isReferee"))
    return True


def _contact_province(contact: Mapping[str, Any]) -> str:
    for key in _PROVINCE_FIELDS:
        text = _s(contact.get(key))
        if text:
            return roster_fold(text)
    return ""


def contact_index(contacts: Any, province: Any) -> dict[str, Optional[str]]:
    """
    Klucz osoby -> adres z kontaktów sędziów okręgu; `None`, gdy pod tym samym
    nazwiskiem stoją dwa różne adresy (niejednoznaczne = brak adresu).

    Kontakt z wpisanym okręgiem musi pasować do okręgu; bez okręgu przechodzi
    (plik kontaktów prowadzi okręg dla swoich sędziów).
    """
    wanted = roster_fold(province)
    out: dict[str, Optional[str]] = {}
    for contact in contacts if isinstance(contacts, (list, tuple)) else ():
        if not isinstance(contact, Mapping) or not _is_referee(contact):
            continue
        own = _contact_province(contact)
        if own and wanted and own != wanted:
            continue
        key = person_key(f"{_s(contact.get('name'))} {_s(contact.get('surname'))}")
        found = emails_in(contact.get("email"))
        if not key or not found:
            continue
        if key in out and out[key] != found[0]:
            out[key] = None
            continue
        out.setdefault(key, found[0])
    return out


def resolve_emails(
    judges: Mapping[str, str],
    *,
    login_rows: Iterable[Mapping[str, Any]],
    contacts: Any,
    province: Any,
    same_judge: Any = None,
) -> dict[str, tuple[str, str]]:
    """
    Numer sędziego -> (adres, źródło) dla sędziów z `judges` (numer -> imię
    i nazwisko). Najpierw profil logowania, potem kontakty po nazwisku.

    `same_judge(a, b)` porównuje numery (zero wiodące itp.); domyślnie równość.
    `login_rows` z innym okręgiem niż `province` nie dają adresu.
    """
    match = same_judge or (lambda a, b: _s(a) == _s(b))
    wanted = roster_fold(province)
    out: dict[str, tuple[str, str]] = {}
    rows = list(login_rows)
    for judge_id in judges:
        for row in rows:
            if not match(row.get("judge_id"), judge_id):
                continue
            row_province = roster_fold(row.get("province"))
            if row_province and wanted and row_province != wanted:
                continue
            email = login_email(row)
            if email:
                out[judge_id] = (email, SOURCE_LOGIN)
                break
    index = contact_index(contacts, province)
    for judge_id, name in judges.items():
        if judge_id in out:
            continue
        email = index.get(person_key(name))
        if email:
            out[judge_id] = (email, SOURCE_CONTACTS)
    return out
