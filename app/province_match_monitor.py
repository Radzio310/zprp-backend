from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from bs4 import BeautifulSoup
from httpx import AsyncClient
from sqlalchemy import and_, delete, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import (
    database,
    province_match_events,
    province_match_judges,
    province_match_notifications,
    province_match_sync_runs,
    province_match_sync_leases,
    province_matches,
    province_judges,
    push_tokens,
)
from app.deps import get_settings
# Konta wojewódzkie mieszkają w liściu, bo pytają o nie także moduł giełdy
# meczów i panel administratora - a żadne z nich nie ma po co ciągnąć za sobą
# całego crawlera. Nazwy zmiennych i reguła schodzenia do konta monitora są
# tam opisane w jednym miejscu.
from app.zprp_accounts import (  # noqa: F401  (re-eksport dla zgodności)
    PROVINCE_ENV_SUFFIXES,
    configured_provinces,
    normalize_province,
)
from app.utils import fetch_with_correct_encoding
from app.zprp.officials import (
    _build_judge_matches_path,
    _parse_match_rows_from_soup,
)
from app.zprp.schedule import (
    _detect_sex_from_kategoria_value,
    _login_zprp_and_get_cookies,
    _parse_matches_table,
    _parse_select_options,
    _pick_season_id,
)

logger = logging.getLogger("app.province_match_monitor")
WARSAW = ZoneInfo("Europe/Warsaw")

EVENT_NOTIFICATION_TITLES: Dict[str, str] = {
    "match_added": "🆕 Nowy mecz w obsadzie",
    "match_removed": "🗑️ Mecz usunięty",
    "assignment_removed": "🗑️ Zmiana w Twojej obsadzie",
    "match_date_changed": "🕒 Zmieniono termin meczu",
    "lineup_changed": "👥 Zmieniono obsadę meczu",
    "match_data_changed": "✏️ Zmieniono dane meczu",
}


def notification_title(event_type: str) -> str:
    return EVENT_NOTIFICATION_TITLES.get(event_type, "🔔 Zmiana w Twoim meczu")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _str(value: Any) -> str:
    return "" if value is None else str(value).strip()


def parse_match_at(value: Any) -> Optional[datetime]:
    raw = _str(value)
    if not raw:
        return None
    raw = raw.replace("T", " ").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=WARSAW)
    return dt.astimezone(timezone.utc)


def is_eligible_for_refresh(state: Dict[str, Any], approved: bool = False, now: Optional[datetime] = None) -> bool:
    if approved or _str(state.get("protocol_status")) == "approved":
        return False
    match_at = parse_match_at(state.get("data_fakt") or state.get("data_prop"))
    if match_at is None:
        return True
    return match_at >= (now or _now()) - timedelta(days=31)


#: Okno „goracego" przebiegu - mecze, ktore odbywaja sie lada dzien.
#:
#: Czternascie dni do przodu i dwa wstecz. Wstecz, bo po meczu jeszcze dlugo
#: zmienia sie wynik i status protokolu, a to tez sa powiadomienia.
_HOT_DAYS = max(1, int(os.getenv("ZPRP_MATCH_MONITOR_HOT_DAYS", "14")))
_HOT_PAST_DAYS = max(0, int(os.getenv("ZPRP_MATCH_MONITOR_HOT_PAST_DAYS", "2")))

#: Zasieg „cieplego" przebiegu - reszta znanego sezonu.
_WARM_DAYS = max(_HOT_DAYS + 1, int(os.getenv("ZPRP_MATCH_MONITOR_WARM_DAYS", "120")))

#: Ile meczow odpytujemy w jednym przebiegu publicznym.
#:
#: Bezpiecznik, nie miara. Po drugiej stronie stoi serwis calego zwiazku i
#: jestesmy tam gosciem - lepiej dokonczyc w nastepnym przebiegu niz zrobic
#: szturm. Mecze ida od najblizszych, wiec przyciecie zabiera te najmniej pilne.
_PUBLIC_LIMIT = max(10, int(os.getenv("ZPRP_MATCH_MONITOR_PUBLIC_LIMIT", "150")))

FINGERPRINT_FIELDS: Sequence[str] = (
    "RozgrywkiCode",
    "data_fakt",
    "ID_zespoly_gosp_ZespolNazwa",
    "ID_zespoly_gosc_ZespolNazwa",
    "NrSedzia_pierwszy_nazwisko",
    "NrSedzia_drugi_nazwisko",
    "NrSedzia_sekretarz_nazwisko",
    "NrSedzia_czas_nazwisko",
    "NrSedzia_delegat_nazwisko",
    "NrSedzia_delegat2_nazwisko",
    "delegate_note",
    "Hala_nazwa",
    "Hala_miasto",
    "Hala_ulica",
    "Hala_numer",
    "host_contact",
    "guest_contact",
    "host_swapped",
    "wynik_gosp_full",
    "wynik_gosc_full",
    "wynik_gosp_pol",
    "wynik_gosc_pol",
    "dogrywka_karne_gosp",
    "dogrywka_karne_gosc",
    "karne_ile_gosp",
    "karne_bramki_gosp",
    "karne_ile_gosc",
    "karne_bramki_gosc",
    "timeout1_gosp",
    "timeout2_gosp",
    "timeout3_gosp",
    "timeout1_gosc",
    "timeout2_gosc",
    "timeout3_gosc",
    "widzowie",
    "protocol_status",
)

LIGHT_FIELDS: Sequence[str] = (
    "RozgrywkiCode",
    "data_fakt",
    "ID_zespoly_gosp_ZespolNazwa",
    "ID_zespoly_gosc_ZespolNazwa",
    "NrSedzia_pierwszy_nazwisko",
    "NrSedzia_drugi_nazwisko",
    "NrSedzia_sekretarz_nazwisko",
    "NrSedzia_czas_nazwisko",
    "NrSedzia_delegat_nazwisko",
    "NrSedzia_delegat2_nazwisko",
    "delegate_note",
    "Hala_nazwa",
    "Hala_miasto",
    "Hala_ulica",
    "Hala_numer",
    "host_contact",
    "guest_contact",
    "host_swapped",
    "wynik_gosp_full",
    "wynik_gosc_full",
    "wynik_gosp_pol",
    "wynik_gosc_pol",
    "dogrywka_karne_gosp",
    "dogrywka_karne_gosc",
)


def fingerprint(state: Dict[str, Any]) -> str:
    canonical = {key: state.get(key, "") for key in FINGERPRINT_FIELDS}
    raw = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _projection_changed(old: Dict[str, Any], new: Dict[str, Any], fields: Sequence[str]) -> bool:
    return any(old.get(key, "") != new.get(key, "") for key in fields)


def _merge_partial_state(old: Optional[Dict[str, Any]], partial: Dict[str, Any]) -> Dict[str, Any]:
    if not old:
        return dict(partial)
    return {**old, **partial}


def _private_to_state(match: Dict[str, Any]) -> Dict[str, Any]:
    hall = match.get("hall") or {}
    venue = hall.get("venue") or {}
    teams = match.get("teams") or {}
    result = match.get("result") or {}
    full = result.get("full") or {}
    half = result.get("half") or {}
    pens = result.get("penalties") or {}
    officials = match.get("officials") or {}
    return {
        "Id": _str(match.get("IdZawody")),
        "RozgrywkiCode": _str(match.get("match_code")),
        "season": _str(match.get("season")),
        "data_fakt": _str(match.get("data_fakt")),
        "ID_zespoly_gosp_ZespolNazwa": _str(teams.get("host")),
        "ID_zespoly_gosc_ZespolNazwa": _str(teams.get("guest")),
        "NrSedzia_pierwszy_nazwisko": _str(officials.get("referee1")),
        "NrSedzia_drugi_nazwisko": _str(officials.get("referee2")),
        "NrSedzia_sekretarz_nazwisko": _str(officials.get("secretary")),
        "NrSedzia_czas_nazwisko": _str(officials.get("timekeeper")),
        "NrSedzia_delegat_nazwisko": _str(officials.get("delegate")),
        "NrSedzia_delegat2_nazwisko": _str(officials.get("delegate2")),
        "delegate_note": _str(match.get("delegate_note")),
        "Hala_nazwa": _str(venue.get("name")),
        "Hala_miasto": _str(venue.get("city")),
        "Hala_ulica": _str(venue.get("street")),
        "Hala_numer": _str(venue.get("number")),
        "host_contact": match.get("host_contact") or {},
        "guest_contact": match.get("guest_contact") or {},
        "host_swapped": bool(result.get("host_swapped")),
        "wynik_gosp_full": _str(full.get("host")),
        "wynik_gosc_full": _str(full.get("guest")),
        "wynik_gosp_pol": _str(half.get("host")),
        "wynik_gosc_pol": _str(half.get("guest")),
        "dogrywka_karne_gosp": _str(pens.get("host")),
        "dogrywka_karne_gosc": _str(pens.get("guest")),
    }


def _schedule_to_state(match: Dict[str, Any]) -> Dict[str, Any]:
    state = dict(match)
    state["Id"] = _str(match.get("IdZawody") or match.get("Id"))
    state["RozgrywkiCode"] = _str(match.get("RozgrywkiCode"))
    return state


def _api_to_state(payload: Dict[str, Any], base: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rows = payload.get("0")
    match = rows[0] if isinstance(rows, list) and rows else None
    if not isinstance(match, dict):
        return None
    state = dict(base)
    for key, value in match.items():
        state[key] = _str(value) if not isinstance(value, (dict, list)) else value
    state["Id"] = _str(match.get("Id") or base.get("Id"))
    state["RozgrywkiCode"] = _str(match.get("RozgrywkiCode") or base.get("RozgrywkiCode"))
    state["data_fakt"] = _str(match.get("data_fakt") or match.get("data_prop") or base.get("data_fakt"))
    state["host_swapped"] = _str(match.get("zamiana")) == "1"
    state["protocol_status"] = "approved" if _str(match.get("protokol_zatwierdz")) == "1" else "before_approval"
    for key in ("delegate_note", "host_contact", "guest_contact", "season", "runda", "kolejka"):
        if not state.get(key) and base.get(key):
            state[key] = base[key]
    return state


def _changed(old: Dict[str, Any], new: Dict[str, Any], *keys: str) -> bool:
    return any(old.get(k, "") != new.get(k, "") for k in keys)


def _display_match_at(value: Any) -> str:
    match_at = parse_match_at(value)
    return match_at.astimezone(WARSAW).strftime("%d.%m.%Y, %H:%M") if match_at else _str(value)


def _match_details(state: Dict[str, Any]) -> str:
    parts: List[str] = []
    teams = " – ".join(
        filter(
            None,
            [
                _str(state.get("ID_zespoly_gosp_ZespolNazwa")),
                _str(state.get("ID_zespoly_gosc_ZespolNazwa")),
            ],
        )
    )
    if teams:
        parts.append(teams)
    match_at = _display_match_at(state.get("data_fakt") or state.get("data_prop"))
    if match_at:
        parts.append(match_at)
    venue = ", ".join(
        filter(
            None,
            [
                _str(state.get("Hala_nazwa")),
                _str(state.get("Hala_miasto")),
            ],
        )
    )
    if venue:
        parts.append(venue)
    return " • ".join(parts)


def build_change_events(old: Dict[str, Any], new: Dict[str, Any]) -> List[Dict[str, str]]:
    code = _str(new.get("RozgrywkiCode") or old.get("RozgrywkiCode"))
    events: List[Dict[str, str]] = []
    if _changed(old, new, "data_fakt"):
        body = f"Zmieniono datę meczu {code}"
        if _str(new.get("data_fakt")):
            body += f" na {_display_match_at(new.get('data_fakt'))}"
        events.append({"event_type": "match_date_changed", "body": body})
    if _changed(old, new, "NrSedzia_pierwszy_nazwisko", "NrSedzia_drugi_nazwisko"):
        names = ", ".join(filter(None, [_str(new.get("NrSedzia_pierwszy_nazwisko")), _str(new.get("NrSedzia_drugi_nazwisko"))]))
        events.append({"event_type": "lineup_changed", "body": f"Zmieniono sędziów głównych w meczu {code}: {names}".rstrip(": ")})
    role_fields = (
        ("NrSedzia_sekretarz_nazwisko", "sędziego sekretarza"),
        ("NrSedzia_czas_nazwisko", "sędziego mierzącego czas"),
        ("NrSedzia_delegat_nazwisko", "delegata"),
        ("NrSedzia_delegat2_nazwisko", "drugiego delegata"),
    )
    for field, label in role_fields:
        if _changed(old, new, field):
            value = _str(new.get(field))
            verb = "Zmieniono" if value else "Usunięto"
            suffix = f" na {value}" if value else ""
            events.append({"event_type": "lineup_changed", "body": f"{verb} {label} w meczu {code}{suffix}"})
    if _changed(old, new, "delegate_note"):
        events.append({"event_type": "lineup_changed", "body": f"Zmieniono ocenę delegata w meczu {code}"})
    if bool(new.get("host_swapped")) and _changed(old, new, "host_swapped"):
        events.append({"event_type": "match_data_changed", "body": f"Zmieniono gospodarza zawodów w meczu {code}"})
    if _changed(old, new, "Hala_nazwa", "Hala_miasto", "Hala_ulica", "Hala_numer"):
        address = ", ".join(filter(None, [_str(new.get("Hala_nazwa")), _str(new.get("Hala_miasto")), " ".join(filter(None, [_str(new.get("Hala_ulica")), _str(new.get("Hala_numer"))]))]))
        events.append({"event_type": "match_data_changed", "body": f"Zmieniono adres hali w meczu {code}" + (f" na {address}" if address else "")})
    if _changed(old, new, "RozgrywkiCode"):
        events.append({"event_type": "match_data_changed", "body": f"Zmieniono numer meczu na {code}"})
    if _changed(old, new, "host_contact"):
        events.append({"event_type": "match_data_changed", "body": f"Zmieniono dane teleadresowe Gospodarza w meczu {code}"})
    if _changed(old, new, "guest_contact"):
        events.append({"event_type": "match_data_changed", "body": f"Zmieniono dane teleadresowe Gościa w meczu {code}"})
    result_fields = [key for key in FINGERPRINT_FIELDS if key.startswith(("wynik_", "dogrywka_", "karne_", "timeout"))] + ["widzowie"]
    if _changed(old, new, *result_fields):
        score = ":".join(filter(None, [_str(new.get("wynik_gosp_full")), _str(new.get("wynik_gosc_full"))]))
        suffix = f": {score}" if score else ""
        events.append({"event_type": "match_data_changed", "body": f"Edytowano wynik skrócony meczu {code}{suffix}"})
    # Jeden przebieg może wykryć wiele pól; identyczne komunikaty usuwamy.
    return list({(e["event_type"], e["body"]): e for e in events}.values())


def _prefs_allow(prefs: Any, event_type: str) -> bool:
    if not isinstance(prefs, dict):
        return True
    if prefs.get("enabled") is False:
        return False
    types = prefs.get("notificationTypes")
    if not isinstance(types, dict):
        return True
    if event_type in ("match_added", "match_removed", "assignment_removed"):
        return types.get("newMatchAdded", True) is not False
    if event_type == "lineup_changed":
        return types.get("changeLineup", True) is not False
    return types.get("changeMatchData", True) is not False


async def _active_judge_ids(province: str) -> List[str]:
    token_rows = await database.fetch_all(
        select(push_tokens.c.judge_id, push_tokens.c.province)
        .where(push_tokens.c.app_variant == "baza")
        .where(push_tokens.c.judge_id.is_not(None))
    )
    judge_ids = sorted({_str(row["judge_id"]) for row in token_rows if _str(row["judge_id"])})
    known_rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.province).where(
            province_judges.c.judge_id.in_(judge_ids or ["__none__"])
        )
    )
    known_provinces = {
        _str(row["judge_id"]): normalize_province(row["province"])
        for row in known_rows
    }
    return sorted(
        {
            _str(row["judge_id"])
            for row in token_rows
            if _str(row["judge_id"])
            and (
                normalize_province(row["province"]) == province
                or known_provinces.get(_str(row["judge_id"])) == province
            )
        }
    )


async def _target_judges(province: str, match_id: str) -> List[str]:
    rows = await database.fetch_all(
        select(province_match_judges.c.judge_id)
        .where(province_match_judges.c.province == province)
        .where(province_match_judges.c.match_id == match_id)
        .where(province_match_judges.c.active.is_(True))
    )
    return sorted({_str(row["judge_id"]) for row in rows if _str(row["judge_id"])})


async def _create_event(
    province: str,
    match_id: str,
    match_code: str,
    event_type: str,
    body: str,
    judge_ids: Iterable[str],
    state_fp: str,
) -> int:
    targets = sorted({_str(j) for j in judge_ids if _str(j)})
    if not targets:
        return 0
    event_key_raw = f"{province}|{match_id}|{event_type}|{body}|{state_fp}"
    event_key = hashlib.sha256(event_key_raw.encode("utf-8")).hexdigest()
    data = {
        "kind": "province_match_change",
        "event_type": event_type,
        "province": province,
        "match_id": match_id,
        "matchNumber": match_code,
        "event_key": event_key,
    }
    title = notification_title(event_type)
    stmt = (
        pg_insert(province_match_events)
        .values(
            event_key=event_key,
            province=province,
            match_id=match_id,
            match_code=match_code,
            event_type=event_type,
            title=title,
            body=body,
            data_json=data,
            target_judge_ids=targets,
        )
        .on_conflict_do_nothing(index_elements=[province_match_events.c.event_key])
        .returning(province_match_events.c.id)
    )
    event_id = await database.fetch_val(stmt)
    if not event_id:
        event_id = await database.fetch_val(
            select(province_match_events.c.id).where(
                province_match_events.c.event_key == event_key
            )
        )
    if not event_id:
        return 0
    devices = await database.fetch_all(
        select(
            push_tokens.c.installation_id,
            push_tokens.c.judge_id,
            push_tokens.c.notification_prefs,
        )
        .where(push_tokens.c.judge_id.in_(targets))
        .where(push_tokens.c.app_variant == "baza")
    )
    for device in devices:
        delivery_status = (
            "pending"
            if _prefs_allow(device["notification_prefs"], event_type)
            else "suppressed"
        )
        await database.execute(
            pg_insert(province_match_notifications)
            .values(
                event_id=int(event_id),
                installation_id=device["installation_id"],
                judge_id=_str(device["judge_id"]),
                title=title,
                body=body,
                data_json=data,
                status=delivery_status,
            )
            .on_conflict_do_nothing(
                constraint="uq_province_match_notification_event_installation"
            )
        )
    return 1


async def _fetch_public_details(client: AsyncClient, match_id: str) -> Optional[Dict[str, Any]]:
    retries = max(0, int(os.getenv("ZPRP_MATCH_MONITOR_DETAIL_RETRIES", "2")))
    url = "https://rozgrywki.zprp.pl/api/pokaz_mecze_szczegoly.php"
    for attempt in range(retries + 1):
        try:
            response = await client.get(url, params={"Zawody": match_id}, timeout=30.0)
            if response.status_code in (408, 425, 429, 500, 502, 503, 504) and attempt < retries:
                await asyncio.sleep(0.4 * (2**attempt))
                continue
            response.raise_for_status()
            payload = response.json()
            return payload if isinstance(payload, dict) else None
        except Exception:
            if attempt >= retries:
                return None
            await asyncio.sleep(0.4 * (2**attempt))
    return None


async def _fetch_details_many(client: AsyncClient, items: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    limit = max(1, int(os.getenv("ZPRP_MATCH_MONITOR_DETAIL_CONCURRENCY", "6")))
    semaphore = asyncio.Semaphore(limit)
    output: Dict[str, Dict[str, Any]] = {}

    async def one(match_id: str, base: Dict[str, Any]) -> None:
        async with semaphore:
            payload = await _fetch_public_details(client, match_id)
        state = _api_to_state(payload or {}, base)
        if state:
            output[match_id] = state

    await asyncio.gather(*(one(match_id, base) for match_id, base in items.items()))
    return output


async def _upsert_match(
    province: str,
    match_id: str,
    state: Dict[str, Any],
    deep: bool,
    *,
    seen_in_schedule: bool = True,
) -> tuple[bool, int]:
    """Zapisuje stan meczu i wysyla powiadomienia o tym, co sie zmienilo.

    `seen_in_schedule=False` ustawiaja przebiegi publiczne (hot/warm). One pytaja
    o KONKRETNE identyfikatory, wiec fakt, ze API odpowiedzialo, nie znaczy, ze
    mecz nadal wisi w terminarzu wojewodztwa. Gdyby zerowaly `missing_full_runs`,
    mecz przeniesiony do innego okregu nigdy by u nas nie wygasl - pelny przebieg
    liczylby jego nieobecnosc od zera po kazdym szybkim odpytaniu.
    """
    now = _now()
    old_row = await database.fetch_one(
        select(province_matches).where(
            and_(province_matches.c.province == province, province_matches.c.match_id == match_id)
        )
    )
    new_fp = fingerprint(state)
    approved = _str(state.get("protocol_status")) == "approved"
    values = {
        "season": _str(state.get("season")) or None,
        "match_at": parse_match_at(state.get("data_fakt") or state.get("data_prop")),
        "match_code": _str(state.get("RozgrywkiCode")) or None,
        "state_json": state,
        "fingerprint": new_fp,
        "approved": approved,
        "last_seen_at": now,
        "updated_at": now,
        **({"active": True, "missing_full_runs": 0} if seen_in_schedule else {}),
        **({"last_deep_checked_at": now} if deep else {}),
    }
    if not old_row:
        await database.execute(insert(province_matches).values(province=province, match_id=match_id, **values))
        return True, 0
    old = dict(old_row["state_json"] or {})
    await database.execute(
        update(province_matches)
        .where(and_(province_matches.c.province == province, province_matches.c.match_id == match_id))
        .values(**values)
    )
    if old_row["fingerprint"] == new_fp:
        return False, 0
    targets = await _target_judges(province, match_id)
    created = 0
    for event in build_change_events(old, state):
        created += await _create_event(
            province,
            match_id,
            _str(state.get("RozgrywkiCode")),
            event["event_type"],
            event["body"],
            targets,
            new_fp,
        )
    return False, created


async def _upsert_assignment(province: str, match_id: str, judge_id: str, season: str, notify: bool, state: Dict[str, Any]) -> int:
    now = _now()
    existing = await database.fetch_one(
        select(province_match_judges).where(
            and_(
                province_match_judges.c.province == province,
                province_match_judges.c.match_id == match_id,
                province_match_judges.c.judge_id == judge_id,
            )
        )
    )
    await database.execute(
        pg_insert(province_match_judges)
        .values(
            province=province,
            match_id=match_id,
            judge_id=judge_id,
            season=season or None,
            active=True,
            missing_runs=0,
            first_seen_at=now,
            last_seen_at=now,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=[
                province_match_judges.c.province,
                province_match_judges.c.match_id,
                province_match_judges.c.judge_id,
            ],
            set_={"season": season or None, "active": True, "missing_runs": 0, "last_seen_at": now, "updated_at": now},
        )
    )
    if notify and (not existing or not existing["active"]):
        code = _str(state.get("RozgrywkiCode"))
        details = _match_details(state)
        return await _create_event(
            province,
            match_id,
            code,
            "match_added",
            f"Dodano nowy mecz {code}" + (f" • {details}" if details else ""),
            [judge_id],
            fingerprint(state),
        )
    return 0


async def _mark_missing_assignments(province: str, judge_id: str, seen_ids: set[str]) -> int:
    cutoff = _now() - timedelta(days=31)
    rows = await database.fetch_all(
        select(province_match_judges, province_matches.c.match_code, province_matches.c.fingerprint)
        .select_from(
            province_match_judges.join(
                province_matches,
                and_(
                    province_match_judges.c.province == province_matches.c.province,
                    province_match_judges.c.match_id == province_matches.c.match_id,
                ),
            )
        )
        .where(province_match_judges.c.province == province)
        .where(province_match_judges.c.judge_id == judge_id)
        .where(province_match_judges.c.active.is_(True))
        .where(province_matches.c.approved.is_(False))
        .where((province_matches.c.match_at.is_(None)) | (province_matches.c.match_at >= cutoff))
    )
    created = 0
    for row in rows:
        match_id = _str(row["match_id"])
        if match_id in seen_ids:
            continue
        missing = int(row["missing_runs"] or 0) + 1
        active = missing < 2
        await database.execute(
            update(province_match_judges)
            .where(
                and_(
                    province_match_judges.c.province == province,
                    province_match_judges.c.match_id == match_id,
                    province_match_judges.c.judge_id == judge_id,
                )
            )
            .values(missing_runs=missing, active=active, updated_at=_now())
        )
        if not active:
            code = _str(row["match_code"])
            created += await _create_event(
                province,
                match_id,
                code,
                "assignment_removed",
                f"Usunięto Twój mecz {code}",
                [judge_id],
                _str(row["fingerprint"]),
            )
    return created


async def _province_has_baseline(province: str) -> bool:
    value = await database.fetch_val(
        select(func.count()).select_from(province_matches).where(province_matches.c.province == province)
    )
    return int(value or 0) > 0


async def _run_light(province: str, username: str, password: str) -> Dict[str, int]:
    judge_ids = await _active_judge_ids(province)
    if not judge_ids:
        return {"matches_seen": 0, "details_fetched": 0, "events_created": 0}
    settings = get_settings()
    baseline = await _province_has_baseline(province)
    matches_seen = details_fetched = events_created = 0
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as private_client, AsyncClient(follow_redirects=True) as public_client:
        cookies = await _login_zprp_and_get_cookies(private_client, username, password)
        for judge_id in judge_ids:
            path = _build_judge_matches_path(judge_id, None)
            _, html = await fetch_with_correct_encoding(private_client, path, method="GET", cookies=cookies)
            parsed = _parse_match_rows_from_soup(BeautifulSoup(html, "html.parser"))
            seen_ids: set[str] = set()
            candidates: Dict[str, Dict[str, Any]] = {}
            for item in (parsed.get("matches") or {}).values():
                match_id = _str(item.get("IdZawody"))
                if not match_id or not match_id.isdigit():
                    continue
                state = _private_to_state(item)
                old = await database.fetch_one(
                    select(
                        province_matches.c.fingerprint,
                        province_matches.c.approved,
                        province_matches.c.state_json,
                    ).where(
                        and_(province_matches.c.province == province, province_matches.c.match_id == match_id)
                    )
                )
                old_state = dict(old["state_json"] or {}) if old else {}
                old_approved_needs_assessment = bool(
                    old
                    and old["approved"]
                    and (
                        _str(old_state.get("NrSedzia_delegat_nazwisko"))
                        or _str(old_state.get("NrSedzia_delegat2_nazwisko"))
                    )
                    and not _str(old_state.get("delegate_note"))
                )
                if not old_approved_needs_assessment and not is_eligible_for_refresh(
                    state, bool(old and old["approved"])
                ):
                    continue
                seen_ids.add(match_id)
                matches_seen += 1
                if not old or _projection_changed(old_state, state, LIGHT_FIELDS):
                    candidates[match_id] = state
                else:
                    await database.execute(
                        update(province_matches)
                        .where(and_(province_matches.c.province == province, province_matches.c.match_id == match_id))
                        .values(last_seen_at=_now(), active=True, missing_full_runs=0)
                    )
                events_created += await _upsert_assignment(
                    province, match_id, judge_id, _str(state.get("season")), baseline, state
                )
            deep_states = await _fetch_details_many(public_client, candidates)
            details_fetched += len(deep_states)
            for match_id, shallow in candidates.items():
                chosen = deep_states.get(match_id)
                if chosen is None:
                    old = await database.fetch_one(
                        select(province_matches.c.state_json).where(
                            and_(province_matches.c.province == province, province_matches.c.match_id == match_id)
                        )
                    )
                    chosen = _merge_partial_state(dict(old["state_json"] or {}) if old else None, shallow)
                _, created = await _upsert_match(province, match_id, chosen, match_id in deep_states)
                events_created += created
            events_created += await _mark_missing_assignments(province, judge_id, seen_ids)
    return {"matches_seen": matches_seen, "details_fetched": details_fetched, "events_created": events_created}


async def _public_window_states(
    province: str, since: datetime, until: datetime, limit: int
) -> Dict[str, Dict[str, Any]]:
    """Mecze, o ktore warto pytac publiczne API w tym oknie czasu.

    Dwa zawezenia, oba swiadome:

    * tylko mecze, przy ktorych stoi CZYNNY sedzia z naszego wojewodztwa - to
      jedyni ludzie, do ktorych i tak poszloby powiadomienie, a odpytywanie
      reszty terminarza byloby obciazaniem cudzego serwera bez adresata;
    * tylko mecze niezatwierdzone - po zatwierdzeniu protokolu nic sie w nich
      juz nie zmieni, a `is_eligible_for_refresh` mowi to samo.

    Zwraca stan ZAPISANY, bo to on jest podstawa scalania: odpowiedz publicznego
    API nadpisuje wylacznie pola, ktore naprawde przyslala.
    """
    # „Stoi przy nim czynny sedzia" to WARUNEK, a nie zrodlo kolumn - stad
    # EXISTS zamiast zlaczenia.
    #
    # Wczesniej bylo tu zlaczenie z `province_match_judges`, ktore mnozylo
    # wiersze (kilku sedziow przy jednym meczu), wiec trzeba bylo dolozyc
    # `DISTINCT`. A Postgres na `SELECT DISTINCT` wymaga, zeby KAZDE wyrazenie
    # z `ORDER BY` stalo w liscie kolumn - `match_at` tam nie stalo i zapytanie
    # wywracalo sie za kazdym razem:
    #
    #   asyncpg.exceptions.InvalidColumnReferenceError: for SELECT DISTINCT,
    #   ORDER BY expressions must appear in select list
    #
    # Czyli szybki przebieg publiczny (`hot`/`warm`) nie odpytal ani jednego
    # meczu. EXISTS nie mnozy wierszy, wiec `DISTINCT` znika razem z problemem,
    # a sortowanie po godzinie meczu zostaje.
    stoi_przy_nim_czynny_sedzia = (
        select(province_match_judges.c.match_id)
        .where(province_match_judges.c.province == province_matches.c.province)
        .where(province_match_judges.c.match_id == province_matches.c.match_id)
        .where(province_match_judges.c.active.is_(True))
        .exists()
    )
    rows = await database.fetch_all(
        select(
            province_matches.c.match_id,
            province_matches.c.state_json,
            province_matches.c.approved,
        )
        .where(province_matches.c.province == province)
        .where(province_matches.c.active.is_(True))
        .where(province_matches.c.approved.is_(False))
        .where(stoi_przy_nim_czynny_sedzia)
        .where(province_matches.c.match_at.is_not(None))
        .where(province_matches.c.match_at >= since)
        .where(province_matches.c.match_at < until)
        .order_by(province_matches.c.match_at.asc())
        .limit(limit)
    )
    now = _now()
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        state = dict(row["state_json"] or {})
        if not is_eligible_for_refresh(state, bool(row["approved"]), now):
            continue
        out[_str(row["match_id"])] = state
    return out


async def _run_public(province: str, mode: str) -> Dict[str, int]:
    """Szybki przebieg BEZ LOGOWANIA - publiczne API po znanych numerach meczow.

    To jest sedno trzech predkosci. Lekki przebieg musi sie zalogowac do bazy
    zwiazku i przejsc liste meczow KAZDEGO sedziego z osobna, wiec jego koszt
    rosnie z liczba sedziow, a nie meczow. Tutaj pytamy wprost o identyfikatory,
    ktore juz znamy, publicznym API bez sesji i bez ciasteczek - dziesiec razy
    taniej i bez ryzyka, ze wygasla sesja wstrzyma powiadomienia.

    Czego ten przebieg NIE robi: nie wykrywa meczow, o ktorych jeszcze nie wiemy,
    i nie prowadzi tabeli przypisan sedziow. Nowy mecz w terminarzu znajdzie
    dopiero pelny przebieg - i to jest przyjeta cena, bo mecz dopisany na
    przyszly miesiac moze poczekac godziny, a zmiana terminu meczu za trzy dni
    nie moze.

    DOPISANIE SEDZIEGO do meczu, ktory juz znamy, lapie sie tutaj, bo obsada
    jest w odpowiedzi publicznego API. To najpilniejszy przypadek i zostaje
    szybki.
    """
    now = _now()
    if mode == "hot":
        since = now - timedelta(days=_HOT_PAST_DAYS)
        until = now + timedelta(days=_HOT_DAYS)
    else:
        since = now + timedelta(days=_HOT_DAYS)
        until = now + timedelta(days=_WARM_DAYS)

    known = await _public_window_states(province, since, until, _PUBLIC_LIMIT)
    if not known:
        return {"matches_seen": 0, "details_fetched": 0, "events_created": 0}

    async with AsyncClient(follow_redirects=True) as public_client:
        fresh = await _fetch_details_many(public_client, known)

    events = 0
    for match_id, state in fresh.items():
        # `seen_in_schedule=False`: odpowiedz API nie jest dowodem, ze mecz
        # nadal nalezy do terminarza tego wojewodztwa.
        _, created = await _upsert_match(
            province, match_id, state, True, seen_in_schedule=False
        )
        events += created
    return {
        "matches_seen": len(known),
        "details_fetched": len(fresh),
        "events_created": events,
    }


async def _scrape_full_schedule(client: AsyncClient, cookies: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    _, html0 = await fetch_with_correct_encoding(client, "/index.php?a=terminarz", method="GET", cookies=cookies)
    soup0 = BeautifulSoup(html0, "html.parser")
    seasons = _parse_select_options(soup0.find("select", attrs={"name": "Filtr_sezon"}))
    season = _pick_season_id(seasons, None)
    cats = [x for x in _parse_select_options(soup0.find("select", attrs={"name": "Filtr_kategoria"})) if x[0] and x[0] != "0"]
    if not cats:
        raise RuntimeError("ZPRP full sync returned no categories")
    output: Dict[str, Dict[str, Any]] = {}
    for cat_value, cat_label, _ in cats:
        path_cat = "/index.php?" + urlencode({"a": "terminarz", "Filtr_sezon": season, "Filtr_kategoria": cat_value, "IdRundy": "ALL"})
        _, html_cat = await fetch_with_correct_encoding(client, path_cat, method="GET", cookies=cookies)
        soup_cat = BeautifulSoup(html_cat, "html.parser")
        competitions = [x for x in _parse_select_options(soup_cat.find("select", attrs={"name": "IdRozgr"})) if x[0] and x[0] != "0"]
        for competition, _, _ in competitions:
            path = "/index.php?" + urlencode({"a": "terminarz", "Filtr_sezon": season, "Filtr_kategoria": cat_value, "IdRozgr": competition, "IdRundy": "ALL"})
            _, html = await fetch_with_correct_encoding(client, path, method="GET", cookies=cookies)
            parsed = _parse_matches_table(html, context_prefix=f"{season}|{cat_value}|{competition}")
            for match_id, item in parsed.items():
                if _str(item.get("IdZawody")).isdigit():
                    output[_str(item.get("IdZawody"))] = _schedule_to_state(item)
    return output


async def _mark_missing_full_matches(province: str, seen_ids: set[str]) -> int:
    cutoff = _now() - timedelta(days=31)
    rows = await database.fetch_all(
        select(province_matches)
        .where(province_matches.c.province == province)
        .where(province_matches.c.active.is_(True))
        .where(province_matches.c.approved.is_(False))
        .where((province_matches.c.match_at.is_(None)) | (province_matches.c.match_at >= cutoff))
    )
    created = 0
    for row in rows:
        match_id = _str(row["match_id"])
        if match_id in seen_ids:
            continue
        missing = int(row["missing_full_runs"] or 0) + 1
        active = missing < 2
        await database.execute(
            update(province_matches)
            .where(and_(province_matches.c.province == province, province_matches.c.match_id == match_id))
            .values(missing_full_runs=missing, active=active, updated_at=_now())
        )
        if not active:
            targets = await _target_judges(province, match_id)
            created += await _create_event(
                province,
                match_id,
                _str(row["match_code"]),
                "match_removed",
                f"Usunięto Twój mecz {_str(row['match_code'])}",
                targets,
                _str(row["fingerprint"]),
            )
    return created


async def _run_full(province: str, username: str, password: str) -> Dict[str, int]:
    settings = get_settings()
    baseline = await _province_has_baseline(province)
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as private_client, AsyncClient(follow_redirects=True) as public_client:
        cookies = await _login_zprp_and_get_cookies(private_client, username, password)
        schedule = await _scrape_full_schedule(private_client, cookies)
        if baseline and not schedule:
            # Pusty wynik przy istniejącej bazie jest znacznie częściej zmianą
            # HTML/błędem źródła niż faktycznym usunięciem całego województwa.
            raise RuntimeError("ZPRP full sync returned an empty schedule for an existing province")
        eligible: Dict[str, Dict[str, Any]] = {}
        seen_ids: set[str] = set()
        for match_id, state in schedule.items():
            old = await database.fetch_one(
                select(province_matches.c.approved).where(
                    and_(province_matches.c.province == province, province_matches.c.match_id == match_id)
                )
            )
            if not is_eligible_for_refresh(state, bool(old and old["approved"])):
                continue
            seen_ids.add(match_id)
            eligible[match_id] = state
        deep_states = await _fetch_details_many(public_client, eligible)
        events_created = 0
        for match_id, shallow in eligible.items():
            chosen = deep_states.get(match_id)
            if chosen is None:
                old = await database.fetch_one(
                    select(province_matches.c.state_json).where(
                        and_(province_matches.c.province == province, province_matches.c.match_id == match_id)
                    )
                )
                chosen = _merge_partial_state(dict(old["state_json"] or {}) if old else None, shallow)
            _, created = await _upsert_match(province, match_id, chosen, match_id in deep_states)
            events_created += created if baseline else 0
        events_created += await _mark_missing_full_matches(province, seen_ids)
        return {
            "matches_seen": len(eligible),
            "details_fetched": len(deep_states),
            "events_created": events_created,
        }


async def _claim_run(province: str, mode: str, interval_seconds: int) -> Optional[int]:
    slot = int(_now().timestamp()) // interval_seconds
    cycle_key = f"{province}:{mode}:{slot}"
    stmt = (
        pg_insert(province_match_sync_runs)
        .values(province=province, mode=mode, cycle_key=cycle_key, status="running")
        .on_conflict_do_nothing(index_elements=[province_match_sync_runs.c.cycle_key])
        .returning(province_match_sync_runs.c.id)
    )
    run_id = await database.fetch_val(stmt)
    return int(run_id) if run_id else None


async def _acquire_province_lease(province: str, holder: str, max_wait_seconds: int) -> bool:
    deadline = asyncio.get_running_loop().time() + max_wait_seconds
    while True:
        now = _now()
        stmt = (
            pg_insert(province_match_sync_leases)
            .values(
                province=province,
                holder=holder,
                locked_until=now + timedelta(minutes=3),
                updated_at=now,
            )
            .on_conflict_do_update(
                index_elements=[province_match_sync_leases.c.province],
                set_={
                    "holder": holder,
                    "locked_until": now + timedelta(minutes=3),
                    "updated_at": now,
                },
                where=province_match_sync_leases.c.locked_until < now,
            )
            .returning(province_match_sync_leases.c.holder)
        )
        acquired = await database.fetch_val(stmt)
        if acquired == holder:
            return True
        if asyncio.get_running_loop().time() >= deadline:
            return False
        await asyncio.sleep(5)


async def _heartbeat_province_lease(province: str, holder: str) -> None:
    while True:
        await asyncio.sleep(60)
        await database.execute(
            update(province_match_sync_leases)
            .where(province_match_sync_leases.c.province == province)
            .where(province_match_sync_leases.c.holder == holder)
            .values(locked_until=_now() + timedelta(minutes=3), updated_at=_now())
        )


async def _release_province_lease(province: str, holder: str) -> None:
    await database.execute(
        delete(province_match_sync_leases)
        .where(province_match_sync_leases.c.province == province)
        .where(province_match_sync_leases.c.holder == holder)
    )


async def _execute_run(province: str, credentials: tuple[str, str], mode: str, interval: int) -> None:
    holder = f"{mode}:{uuid.uuid4().hex}"
    # Szybkie przebiegi NIE stoja w kolejce. Gdy wojewodztwo jest akurat zajete
    # pelnym crawlem, hot pomija cykl i wroci za piec minut - czekanie
    # zbudowaloby ogon przebiegow, ktore i tak pytaja o to samo.
    if mode in ("hot", "warm"):
        max_wait = 20
    elif mode == "light":
        max_wait = 60
    else:
        max_wait = min(900, interval)
    if not await _acquire_province_lease(province, holder, max_wait):
        return
    run_id = await _claim_run(province, mode, interval)
    if not run_id:
        await _release_province_lease(province, holder)
        return
    heartbeat = asyncio.create_task(_heartbeat_province_lease(province, holder))
    try:
        if mode == "full":
            result = await _run_full(province, *credentials)
        elif mode in ("hot", "warm"):
            # Bez danych logowania - publiczne API po znanych identyfikatorach.
            result = await _run_public(province, mode)
        else:
            result = await _run_light(province, *credentials)
        await database.execute(
            update(province_match_sync_runs)
            .where(province_match_sync_runs.c.id == run_id)
            .values(status="success", finished_at=_now(), **result)
        )
        logger.info("Province match sync %s/%s finished: %s", province, mode, result)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.exception("Province match sync %s/%s failed", province, mode)
        await database.execute(
            update(province_match_sync_runs)
            .where(province_match_sync_runs.c.id == run_id)
            .values(status="failed", error=str(exc)[:1800], finished_at=_now())
        )
    finally:
        heartbeat.cancel()
        try:
            await heartbeat
        except asyncio.CancelledError:
            pass
        await _release_province_lease(province, holder)


async def run_province_match_monitor() -> None:
    if os.getenv("ZPRP_MATCH_MONITOR_ENABLED", "true").strip().lower() not in ("1", "true", "yes", "on"):
        logger.info("Province match monitor disabled")
        return
    # TRZY PREDKOSCI. Kazda odpowiada na inne pytanie i kosztuje co innego:
    #
    #   hot  - „czy cos sie zmienilo w meczu, ktory jest lada dzien". Publiczne
    #          API, bez logowania, tylko mecze z obsada z naszego wojewodztwa.
    #          Najczestszy i najtanszy.
    #   warm - to samo dla reszty sezonu. Rzadziej, bo mecz za dwa miesiace nie
    #          zmienia sie co kwadrans.
    #   light- jedyny przebieg, ktory prowadzi tabele przypisan sedziow. Musi
    #          sie logowac i chodzi po liscie meczow KAZDEGO sedziego, wiec jego
    #          koszt rosnie z liczba sedziow. Odkad zmiany wykrywa hot, jego
    #          zadaniem jest juz tylko utrzymanie przypisan.
    #   full - odkrywanie NOWYCH meczow i wygaszanie zniknietych. Najdrozszy,
    #          najrzadszy.
    hot_interval = max(120, int(os.getenv("ZPRP_MATCH_MONITOR_HOT_SECONDS", "300")))
    warm_interval = max(hot_interval, int(os.getenv("ZPRP_MATCH_MONITOR_WARM_SECONDS", "2700")))
    light_interval = max(300, int(os.getenv("ZPRP_MATCH_MONITOR_LIGHT_SECONDS", "900")))
    full_interval = max(light_interval, int(os.getenv("ZPRP_MATCH_MONITOR_FULL_SECONDS", "14400")))
    max_provinces = max(1, int(os.getenv("ZPRP_MATCH_MONITOR_PROVINCE_CONCURRENCY", "2")))
    full_concurrency = max(1, int(os.getenv("ZPRP_MATCH_MONITOR_FULL_PROVINCE_CONCURRENCY", "1")))
    public_concurrency = max(
        1, int(os.getenv("ZPRP_MATCH_MONITOR_PUBLIC_PROVINCE_CONCURRENCY", "3"))
    )

    async def mode_loop(mode: str, interval: int, concurrency: int, initial_delay: int = 0) -> None:
        if initial_delay:
            await asyncio.sleep(initial_delay)
        semaphore = asyncio.Semaphore(concurrency)
        while True:
            started = asyncio.get_running_loop().time()
            credentials = configured_provinces()

            async def one(province: str, creds: tuple[str, str]) -> None:
                async with semaphore:
                    await _execute_run(province, creds, mode, interval)

            try:
                await asyncio.gather(*(one(p, c) for p, c in credentials.items()))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Province match monitor %s loop failed", mode)
            elapsed = asyncio.get_running_loop().time() - started
            await asyncio.sleep(max(1.0, interval - elapsed))

    # Pełny crawler nie blokuje lekkich sprawdzeń. Ma osobny, domyślnie
    # pojedynczy worker, więc nawet przy 16 województwach nie robi szturmu.
    #
    # Przebiegi publiczne startują z przesunięciem, żeby cztery pętle nie
    # ruszały w tej samej sekundzie po restarcie procesu.
    await asyncio.gather(
        mode_loop("hot", hot_interval, public_concurrency),
        mode_loop("warm", warm_interval, public_concurrency, initial_delay=45),
        mode_loop("light", light_interval, max_provinces, initial_delay=15),
        mode_loop("full", full_interval, full_concurrency, initial_delay=90),
    )
