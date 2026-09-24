"""
Powiadomienia okręgu z Obsady - trasy ustawień, próbna wysyłka, pętla w tle
i zaczep dla monitora meczów.

Dwa alerty: MECZ BEZ OBSADY i KOLIZJA PO ZMIANIE TERMINU. Reguły (kto, kiedy,
co napisać) siedzą w liściu `district_alert_rules`, szablony maili
w `district_alert_emails`, schemat w `district_alert_tables`.

Ustawienia są WSPÓLNE dla okręgu (jeden wiersz pod kluczem kanonicznym) - edytuje
je każde konto z uprawnieniem „Obsada" (`PANEL_ASSIGNMENTS`, ta sama reguła co
zapis w Obsadzie). Odczyt też wymaga tego uprawnienia, bo niesie adresy e-mail.

KIEDY SIĘ SPRAWDZA:
  - pętla co 15 minut: mecze bez obsady, kolizje (bezpiecznik) i kolejka pushy
    czekających na koniec ciszy nocnej,
  - monitor meczów przy zmianie terminu (`note_match_moved`) - po krótkim
    odczekaniu (kilka zmian z jednego pobrania idzie razem) sprawdza kolizje
    od razu, bez czekania na pętlę.
Zmianę terminu rozpoznajemy po WŁASNEJ tabeli ostatnich terminów
(`province_district_alert_times`), a nie po zdarzeniu monitora - dzięki temu
pętla i zaczep mówią to samo, a pierwsze włączenie tylko zapamiętuje terminy.

PODWÓJNA WYSYŁKA przy kilku instancjach serwera: każde ogłoszenie zaczyna się
od `INSERT … ON CONFLICT DO NOTHING RETURNING` znacznika deduplikacji - kto nie
wstawił, ten nie wysyła. Push z kolejki przechodzi przez warunkowy UPDATE
statusu („queued" -> „sending").
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app import district_alert_rules as R
from app import collision_rules as CR
from app import district_alert_emails as E
from app.beach.brevo_email import EmailDeliveryError
from app.beach.email_config import get_email_config
from app.deps import get_jwt_payload
from app.province_alert_emails import delivery_message, send_alert_email
from app.province_alert_rules import AlertRuleError, normalize_emails, plural
from app.province_panel_access import PANEL_ASSIGNMENTS, panel_write_refusal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/district-alerts", tags=["district_alerts"])

SWEEP_EVERY_SECONDS = 15 * 60
#: Zamek sprawdzenia okręgu - krócej niż obrót pętli, żeby nie gubić obrotów.
CLAIM_MINUTES = 10
#: Ile czekamy po zmianie terminu, zanim sprawdzimy kolizje (paczka zmian).
MOVE_DEBOUNCE_SECONDS = 45
TEST_COOLDOWN_SECONDS = 30
#: Okno równego podziału dla propozycji Automatu w mailu.
SUGGEST_WINDOW_DAYS = 14

_test_sent: dict[str, float] = {}
_locks: dict[str, asyncio.Lock] = {}
_pending_moves: dict[str, asyncio.Task] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _json(raw: Any, default: Any) -> Any:
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw or "")
    except (TypeError, ValueError):
        return default


def _lock(key: str) -> asyncio.Lock:
    if key not in _locks:
        _locks[key] = asyncio.Lock()
    return _locks[key]


def _canonical(province: Any) -> str:
    from app.settlement_province import canonical

    return canonical(province)


# ---------------------------------------------------------------------------
# Dostęp
# ---------------------------------------------------------------------------

async def _refusal(payload: dict, province: str) -> str:
    from app.province_panel_guard import _lookup

    is_admin, vip = await _lookup(payload)
    return panel_write_refusal(
        panel=PANEL_ASSIGNMENTS,
        province=province,
        account_type=_s(payload.get("account_type")),
        judge_id=_s(payload.get("judge_id")),
        login=_s(payload.get("sub")),
        is_admin=is_admin,
        vip=vip,
    )


async def _require(payload: dict, province: str) -> str:
    """Klucz okręgu po sprawdzeniu uprawnienia „Obsada" - albo 400/403."""
    key = _canonical(province)
    if not key:
        raise HTTPException(400, f"Nieznane województwo: {province}")
    reason = await _refusal(payload, key)
    if reason:
        raise HTTPException(403, f"Powiadomienia okręgu: {reason}")
    return key


# ---------------------------------------------------------------------------
# Ustawienia w bazie
# ---------------------------------------------------------------------------

async def _row(key: str) -> Optional[dict]:
    """
    Wiersz ustawień okręgu spod WSZYSTKICH pisowni.

    Wygrywa wiersz pod kluczem kanonicznym, bez niego - najświeższy. Duplikat
    ŚLĄSKIE/SLASKIE nie może dać dwóch różnych konfiguracji naraz.
    """
    from sqlalchemy import select

    from app.db import database, province_district_alert_settings as T
    from app.settlement_province import spellings

    rows = [dict(r) for r in await database.fetch_all(select(T).where(T.c.province.in_(spellings(key) or [key])))]
    if not rows:
        return None
    floor = datetime.min.replace(tzinfo=timezone.utc)
    return max(rows, key=lambda row: (_s(row["province"]) == key, _aware(row.get("updated_at")) or floor))


def _config_of(row: Optional[dict]) -> dict:
    return R.normalize_config(_json((row or {}).get("config"), {}))


async def collision_rules_for(province: Any) -> CR.CollisionRules:
    """
    Reguła „zdąży z meczu na mecz" okręgu - sekcja `timing` ustawień
    powiadomień. Czyta ją też Automat obsady; bez zapisu (albo przy awarii
    odczytu) wartości domyślne, a ślad awarii idzie do logu.
    """
    key = _canonical(province)
    if not key:
        return CR.CollisionRules()
    try:
        return CR.rules_from_config(_config_of(await _row(key)).get("timing"))
    except Exception:  # noqa: BLE001 - domyślna reguła jest bezpieczna
        logger.exception("[district-alerts] %s: ustawienia czasu meczów", key)
        return CR.CollisionRules()


async def _finish(key: str, *, status: str, error: Optional[str] = None, sent: bool = False) -> None:
    from sqlalchemy import update

    from app.db import database, province_district_alert_settings as T

    values: dict[str, Any] = {"last_status": status[:600], "last_error": (error or None) and error[:600]}
    if sent:
        values["last_sent_at"] = _now()
    await database.execute(update(T).where(T.c.province == key).values(**values))


# ---------------------------------------------------------------------------
# Odbiorcy
# ---------------------------------------------------------------------------

def _id_key(value: Any) -> str:
    from app.calendar_feed_rules import judge_key

    return judge_key(value)


async def _managers(key: str) -> list[dict]:
    """Obsadowi okręgu (odznaka `APPROVER_BADGE`) - numer i „NAZWISKO Imię"."""
    from sqlalchemy import select

    from app.db import database, province_judges
    from app.match_market_access import APPROVER_BADGE, has_approver_badge
    from app.settlement_province import spellings

    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.badges).where(
            province_judges.c.province.in_(spellings(key) or [key])
        )
    )
    out: dict[str, dict] = {}
    for row in rows:
        judge_id = _s(row["judge_id"])
        if judge_id and has_approver_badge(row["badges"], [APPROVER_BADGE]):
            out.setdefault(judge_id, {"judge_id": judge_id, "name": R.judge_label(row["full_name"])})
    return sorted(out.values(), key=lambda item: item["name"])


async def _with_app(judge_ids: Iterable[str]) -> set[str]:
    """Kto ma aplikację BAZA z tokenem push (numer w postaci z listy okręgu)."""
    from sqlalchemy import or_, select

    from app.db import database, push_tokens

    ids = [_s(item) for item in judge_ids if _s(item)]
    if not ids:
        return set()
    wanted = {_id_key(item): item for item in ids}
    rows = await database.fetch_all(
        select(push_tokens.c.judge_id)
        .where(push_tokens.c.judge_id.is_not(None))
        .where(push_tokens.c.token_type == "device_fcm")
        .where(or_(push_tokens.c.app_variant == "baza", push_tokens.c.app_variant.is_(None)))
    )
    return {wanted[_id_key(row["judge_id"])] for row in rows if _id_key(row["judge_id"]) in wanted}


async def _judge_email_detail(
    key: str,
    judge_ids: Iterable[str],
    names: Optional[dict[str, str]] = None,
) -> dict[str, tuple[str, str]]:
    """
    Adresy sędziów do maili okręgu: numer -> (adres, źródło).

    Najpierw profil logowania w aplikacji (`login_records`), potem kontakty
    sędziów z ekranu „Kontakty" (`json_files` / `kontakty`) po okręgu, imieniu
    i nazwisku - reguła w `judge_contact_rules`. Konta ProEla NIE są już
    źródłem (decyzja użytkownika z 24.09.2026).
    """
    from sqlalchemy import select

    from app import judge_contact_rules as JC
    from app.db import database, json_files, login_records, province_judges
    from app.settlement_province import spellings

    ids = [_s(item) for item in judge_ids if _s(item)]
    if not ids:
        return {}
    people: dict[str, str] = {}
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name).where(
            province_judges.c.province.in_(spellings(key) or [key])
        )
    )
    wanted = {_id_key(item): item for item in ids}
    for row in rows:
        own = wanted.get(_id_key(row["judge_id"]))
        if own and _s(row["full_name"]):
            people.setdefault(own, _s(row["full_name"]))
    for judge_id in ids:
        if judge_id not in people and _s((names or {}).get(judge_id)):
            people[judge_id] = _s((names or {}).get(judge_id))
        people.setdefault(judge_id, "")

    variants = sorted({v for item in ids for v in (item, _id_key(item)) if v})
    login_rows: list[dict] = []
    try:
        login_rows = [
            dict(row)
            for row in await database.fetch_all(
                select(login_records).where(login_records.c.judge_id.in_(variants))
            )
        ]
    except Exception:  # noqa: BLE001 - bez profili zostają kontakty
        logger.exception("[district-alerts] %s: profile logowania", key)
    contacts: Any = []
    try:
        row = await database.fetch_one(select(json_files.c.content).where(json_files.c.key == "kontakty"))
        contacts = _json(row["content"], []) if row is not None else []
    except Exception:  # noqa: BLE001 - bez kontaktów zostają profile
        logger.exception("[district-alerts] %s: kontakty sędziów", key)
    return JC.resolve_emails(
        people,
        login_rows=login_rows,
        contacts=contacts,
        province=key,
        same_judge=lambda a, b: _id_key(a) == _id_key(b),
    )


async def _judge_emails(
    key: str,
    judge_ids: Iterable[str],
    names: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Numer sędziego -> adres (patrz `_judge_email_detail`)."""
    return {judge_id: email for judge_id, (email, _source) in (await _judge_email_detail(key, judge_ids, names)).items()}


# ---------------------------------------------------------------------------
# Znaczniki i kolejka
# ---------------------------------------------------------------------------

async def _claim_mark(key: str, dedupe_key: str, *, alert: str, match_id: str = "", judge_id: str = "") -> bool:
    """Wstawia znacznik „ogłoszone". False = ktoś już to ogłosił."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import database, province_district_alert_marks as M

    stmt = (
        pg_insert(M)
        .values(
            province=key,
            dedupe_key=R.short_key(dedupe_key),
            alert=alert,
            match_id=match_id or None,
            judge_id=judge_id or None,
            created_at=_now(),
        )
        .on_conflict_do_nothing(index_elements=[M.c.province, M.c.dedupe_key])
        .returning(M.c.dedupe_key)
    )
    return (await database.fetch_one(stmt)) is not None


async def _drop_marks(key: str, keys: Iterable[str]) -> None:
    from sqlalchemy import and_, delete

    from app.db import database, province_district_alert_marks as M

    wanted = [R.short_key(item) for item in keys]
    if wanted:
        await database.execute(delete(M).where(and_(M.c.province == key, M.c.dedupe_key.in_(wanted))))


async def _log(
    key: str,
    *,
    alert: str,
    channel: str,
    audience: str,
    recipients: list[str],
    title: str,
    body: str,
    match_id: str = "",
    data: Optional[dict] = None,
    due_at: Optional[datetime] = None,
    status: str = "queued",
    detail: str = "",
) -> None:
    from sqlalchemy import insert

    from app.db import database, province_district_alert_outbox as Q

    now = _now()
    await database.execute(
        insert(Q).values(
            province=key,
            alert=alert,
            channel=channel,
            audience=audience,
            match_id=match_id or None,
            recipients=json.dumps(recipients, ensure_ascii=False),
            title=title[:300],
            body=body[:2000],
            data=json.dumps(data or {}, ensure_ascii=False),
            due_at=due_at or now,
            status=status,
            detail=detail[:600] or None,
            created_at=now,
            sent_at=now if status != "queued" else None,
        )
    )


def _report_text(report: dict) -> tuple[str, str]:
    """Status wpisu i opis po ludzku z raportu `send_push_to_judges_report`."""
    requested = int(report.get("requestedJudges") or 0)
    accepted = int(report.get("acceptedJudges") or 0)
    devices = int(report.get("acceptedDevices") or 0)
    if report.get("status") == "error":
        return "failed", f"Wysyłka nieudana ({report.get('errorStage') or 'błąd'})."
    if not accepted:
        return "no_device", f"Nikt z {requested} {plural(requested, 'osoby', 'osób', 'osób')} nie ma aplikacji z włączonymi powiadomieniami."
    return "sent", (
        f"Dotarło do {accepted} z {requested} {plural(requested, 'osoby', 'osób', 'osób')} "
        f"({devices} {plural(devices, 'urządzenie', 'urządzenia', 'urządzeń')})."
    )


async def flush_outbox(key: str) -> int:
    """Wysyła pushe, którym minęła cisza nocna. Zwraca liczbę wysłanych."""
    from sqlalchemy import and_, select, update

    from app.db import database, province_district_alert_marks as M, province_district_alert_outbox as Q
    from app.push.push import send_push_to_judges_report

    now = _now()
    rows = await database.fetch_all(
        select(Q)
        .where(and_(Q.c.province == key, Q.c.status == "queued", Q.c.channel == "push", Q.c.due_at <= now))
        .order_by(Q.c.id)
        .limit(100)
    )
    sent = 0
    for row in rows:
        took = await database.fetch_one(
            update(Q)
            .where(and_(Q.c.id == row["id"], Q.c.status == "queued"))
            .values(status="sending")
            .returning(Q.c.id)
        )
        if took is None:
            continue
        if row["alert"] == R.UNASSIGNED and _s(row["match_id"]) and "|" not in _s(row["match_id"]):
            # Mecz obsadzony w czasie ciszy nocnej - znaczniki zgasły, push nie ma sensu.
            still = await database.fetch_one(
                select(M.c.dedupe_key).where(
                    and_(M.c.province == key, M.c.alert == R.UNASSIGNED, M.c.match_id == row["match_id"])
                )
            )
            if still is None:
                await database.execute(
                    update(Q).where(Q.c.id == row["id"]).values(
                        status="cancelled", sent_at=now, detail="Mecz obsadzony, zanim minęła cisza nocna."
                    )
                )
                continue
        ids = [_s(item) for item in _json(row["recipients"], []) if _s(item)]
        try:
            report = await send_push_to_judges_report(
                ids, row["title"], row["body"], _json(row["data"], {}), app_variant="baza"
            )
        except Exception as exc:  # noqa: BLE001 - jedna wysyłka nie zatrzymuje reszty
            report = {"status": "error", "errorStage": type(exc).__name__}
        status, detail = _report_text(report)
        await database.execute(
            update(Q).where(Q.c.id == row["id"]).values(status=status, sent_at=_now(), detail=detail)
        )
        sent += 1 if status == "sent" else 0
    return sent


async def _enqueue_push(
    key: str,
    cfg: dict,
    *,
    alert: str,
    audience: str,
    judge_ids: list[str],
    title: str,
    body: str,
    data: dict,
    match_id: str,
    match_at: Optional[datetime],
) -> None:
    ids = sorted({_s(item) for item in judge_ids if _s(item)})
    if not ids:
        return
    due = R.push_due_at(_now(), match_at, cfg.get("quiet") or {})
    await _log(
        key,
        alert=alert,
        channel="push",
        audience=audience,
        recipients=ids,
        title=title,
        body=body,
        match_id=match_id,
        data=data,
        due_at=due,
        status="queued",
        detail="" if due <= _now() else f"Cisza nocna - wyjdzie {R.when_text(due)}.",
    )


async def _send_mail(
    key: str,
    *,
    alert: str,
    audience: str,
    to: list[str],
    bcc: list[str],
    subject: str,
    html_body: str,
    text_body: str,
    match_id: str = "",
    test: bool = False,
) -> Optional[str]:
    """Mail + wpis w dzienniku. Zwraca komunikat błędu albo None."""
    everyone = [*to, *[item for item in bcc if item.lower() not in {x.lower() for x in to}]]
    try:
        await send_alert_email(
            to, subject, html_body, text_body, test=test, sender=E.sender_name(), tag=E.TAG, bcc=bcc
        )
    except EmailDeliveryError as exc:
        message = delivery_message(exc)
        if not test:
            await _log(
                key, alert=alert, channel="email", audience=audience, recipients=everyone,
                title=subject, body="", match_id=match_id, status="failed", detail=message,
            )
        return message
    if not test:
        await _log(
            key, alert=alert, channel="email", audience=audience, recipients=everyone,
            title=subject, body="", match_id=match_id, status="sent",
            detail=f"{len(everyone)} {plural(len(everyone), 'adres', 'adresy', 'adresów')}.",
        )
    return None


# ---------------------------------------------------------------------------
# Mecz bez obsady
# ---------------------------------------------------------------------------

SLOT_LABELS = {
    "pierwszy": "Sędzia 1",
    "drugi": "Sędzia 2",
    "sekretarz": "Sekretarz",
    "czas": "Mierzący czas",
}


async def _window_items(key: str, hours: int) -> list[dict]:
    """Mecze z listy obsadowego (bez II ligi) z terminem w najbliższych `hours` h."""
    from app.province_assignments import match_list_payload

    now = _now()
    today = R.local(now).date()
    listing = await match_list_payload(
        key,
        date_from=today,
        date_to=today + timedelta(days=hours // 24 + 2),
        when="dated",
        include_league=False,
        limit=None,
    )
    out = []
    for item in listing.get("matches") or []:
        try:
            at = datetime.fromisoformat(_s(item.get("match_at")).replace("Z", "+00:00"))
        except ValueError:
            continue
        at = _aware(at)
        if at is None or at <= now or at > now + timedelta(hours=hours):
            continue
        out.append({**item, "match_at_dt": at})
    return out


async def _suggestions(key: str, match_ids: list[str]) -> dict[str, dict]:
    """
    Trzech najlepszych kandydatów Automatu dla pierwszej pustej grupy gniazd.

    Te same reguły co „Obsadź automatycznie" (`province_assignment_board.suggest`):
    aktywni sędziowie, niedyspozycje, przerwy, kolizje dnia, pary, kilometry,
    równy podział. Niczego nie zapisuje.
    """
    if not match_ids:
        return {}
    from sqlalchemy import and_, select

    from app.assignment_auto import _candidates, _explain
    from app.assignment_context import build_context, distance_pairs, inactive_judges, load_busy, need_from_state
    from app.assignment_distances import fill_missing
    from app.db import database, province_matches
    from app.match_market_rules import state_dict
    from app.province_assignment_board import _world
    from app.settlement_province import spellings

    out: dict[str, dict] = {}
    try:
        world = await _world(key)
        roster, book = world.roster, world.book
    except Exception:  # noqa: BLE001 - bez propozycji mail i tak ma sens
        logger.exception("[district-alerts] świat Automatu %s", key)
        return {mid: {"kind": "", "picks": [], "note": "Automat chwilowo niedostępny."} for mid in match_ids}
    if not roster.judges:
        return {mid: {"kind": "", "picks": [], "note": "Okręg nie ma jeszcze listy sędziów."} for mid in match_ids}

    rows = await database.fetch_all(
        select(province_matches).where(
            and_(
                province_matches.c.province.in_(spellings(key) or [key]),
                province_matches.c.match_id.in_(match_ids),
            )
        )
    )
    needs = []
    for row in rows:
        state = state_dict(row["state_json"]) or {}
        code = _s(state.get("RozgrywkiCode") or row["match_code"])
        need = need_from_state(_s(row["match_id"]), state, code, row["match_at"], roster)
        if not need.host_city:
            out[need.match_id] = {"kind": "", "picks": [], "note": "Mecz bez hali - najpierw uzupełnij halę, wtedy Automat policzy dojazd."}
            continue
        if need.field_needed or need.table_needed:
            needs.append(need)
    if not needs:
        return out
    days = [need.day for need in needs if need.day]
    center_from = min(days) if days else _now().date()
    center_to = max(days) if days else _now().date()
    busy, load = await load_busy(
        key,
        roster,
        date_from=center_from - timedelta(days=SUGGEST_WINDOW_DAYS),
        date_to=center_to + timedelta(days=SUGGEST_WINDOW_DAYS),
    )
    try:
        await asyncio.wait_for(fill_missing(book, distance_pairs(needs, roster), budget=60), timeout=6.0)
    except Exception:  # noqa: BLE001 - brak odległości to kara punktowa, nie błąd
        logger.info("[district-alerts] %s: odległości bez dopytania Google", key)
    inactive = inactive_judges(key, _now(), roster)
    season_counts, month_counts = world.counts()
    ctx = build_context(
        roster,
        book,
        busy=busy,
        load=load,
        inactive=inactive,
        season_field={judge_id: int(item.get("field", 0)) for judge_id, item in season_counts.items()},
        season_counts=season_counts,
        month_counts=month_counts,
        collision=world.collision,
    )
    for need in needs:
        kind = "field" if need.field_needed else "table"
        crew = need.crew_field if kind == "field" else need.crew_table
        open_slots = need.field_needed if kind == "field" else need.table_needed
        ranked, refused = _candidates(
            ctx,
            need,
            kind=kind,
            partner=crew[0] if crew else None,
            round_no=2,
            load=load,
            taken_ids=set(need.crew_ids),
            open_count=len(open_slots),
        )
        picks = []
        for score, judge, reasons, km in ranked[: R.SUGGESTIONS]:
            why = [reason for reason in reasons if not reason.endswith(" km")][:3]
            picks.append({"judge_id": judge.judge_id, "name": R.judge_label(judge.name), "km": km, "why": ", ".join(why)})
        out[need.match_id] = {
            "kind": kind,
            "picks": picks,
            "note": "" if picks else f"Nikt wolny nie przechodzi twardych reguł: {_explain(refused)}.",
        }
    return out


def _card(hit: R.UnassignedHit, suggestion: Optional[dict]) -> E.UnassignedCard:
    from app import assignment_rules as AR

    item = hit.item
    crew = item.get("crew") or {}
    needs = item.get("needs") or {}
    field_need = int(needs.get("field") or 0)
    table_need = int(needs.get("table") or 0)
    club_table = int(needs.get("club_table") or 0)
    slots: list[E.SlotLine] = []
    for index, slot in enumerate(AR.FIELD_SLOTS):
        person = crew.get(slot)
        if index >= field_need and not person:
            continue
        slots.append(E.SlotLine(SLOT_LABELS[slot], R.judge_label(person.get("name")) if person else None, required=index < field_need))
    for index, slot in enumerate(AR.TABLE_SLOTS):
        person = crew.get(slot)
        from_club = table_need <= index < table_need + club_table
        if index >= table_need and not person and not from_club:
            continue
        slots.append(
            E.SlotLine(
                SLOT_LABELS[slot],
                R.judge_label(person.get("name")) if person else None,
                required=index < table_need,
                from_club=from_club and not person,
            )
        )
    suggestion = suggestion or {}
    return E.UnassignedCard(
        match_id=hit.match_id,
        code=hit.code,
        teams=R.teams_text(item.get("host"), item.get("guest")),
        when=R.when_long(hit.match_at),
        hours_left=hit.hours_left,
        left_text=R.hours_left_text(hit.hours_left),
        competition=_s(item.get("competition_label")) or _s(item.get("category")),
        hall=_s(item.get("hall")),
        city=_s(item.get("city")),
        address=_s(item.get("address")),
        missing=dict(hit.missing),
        slots=slots,
        suggestions=[E.Suggestion(name=p["name"], km=p.get("km"), why=p.get("why") or "") for p in suggestion.get("picks") or []],
        suggest_kind=_s(suggestion.get("kind")),
        suggest_note=_s(suggestion.get("note")),
    )


async def _unassigned_done(key: str) -> set[str]:
    from sqlalchemy import and_, select

    from app.db import database, province_district_alert_marks as M

    rows = await database.fetch_all(
        select(M.c.dedupe_key).where(and_(M.c.province == key, M.c.alert == R.UNASSIGNED))
    )
    return {_s(row["dedupe_key"]) for row in rows}


async def run_unassigned(key: str, cfg: dict) -> tuple[str, Optional[str], bool]:
    """Jedno sprawdzenie „mecz bez obsady". Zwraca (opis, błąd, czy coś wysłano)."""
    from sqlalchemy import and_, delete

    from app.db import database, province_district_alert_marks as M
    from app.settlement_province import display

    section = cfg[R.UNASSIGNED]
    threshold = int(section["threshold_hours"])
    now = _now()
    items = await _window_items(key, threshold)
    plan = R.plan_unassigned(items, await _unassigned_done(key), section, now)
    if plan.rearm:
        await database.execute(
            delete(M).where(and_(M.c.province == key, M.c.alert == R.UNASSIGNED, M.c.match_id.in_(plan.rearm)))
        )

    hits: list[R.UnassignedHit] = []
    for hit in plan.hits:
        took = [
            stage
            for stage in hit.stages
            if await _claim_mark(key, R.unassigned_key(hit.match_id, stage), alert=R.UNASSIGNED, match_id=hit.match_id)
        ]
        if took:
            hit.stages = took
            hit.email = hit.email and R.STAGE_THRESHOLD in took
            hits.append(hit)
    if not hits:
        quiet = plan.open_in_window
        return (
            f"Bez obsady w oknie {threshold} h: {quiet} {plural(quiet, 'mecz', 'mecze', 'meczów')} (już ogłoszone)."
            if quiet
            else f"Wszystkie mecze w oknie {threshold} h mają komplet wymaganej obsady."
        ), None, False

    managers = await _managers(key)
    manager_ids = [item["judge_id"] for item in managers]
    error: Optional[str] = None
    mailed = [hit for hit in hits if hit.email]
    if section["email"] and mailed:
        bcc = list((await _judge_emails(key, manager_ids)).values()) if section["email_managers"] else []
        to = list(section["emails"])
        if to or bcc:
            suggestions = await _suggestions(key, [hit.match_id for hit in mailed])
            cards = [_card(hit, suggestions.get(hit.match_id)) for hit in mailed]
            subject, html_body, text_body = E.build_unassigned_message(
                province_key=key, province_display=display(key), threshold=threshold, cards=cards
            )
            error = await _send_mail(
                key, alert=R.UNASSIGNED, audience="manager", to=to, bcc=bcc,
                subject=subject, html_body=html_body, text_body=text_body,
            )
            if error:
                # Znaczniki gasną - następne sprawdzenie spróbuje jeszcze raz.
                await _drop_marks(key, [R.unassigned_key(hit.match_id, stage) for hit in hits for stage in hit.stages])
                return "Nie udało się wysłać maila o meczach bez obsady.", error, False

    if section["push"] and manager_ids:
        if len(hits) >= R.SUMMARY_FROM:
            title, body = R.unassigned_summary_push(hits, threshold)
            first = hits[0]
            data = R.push_data(
                alert=R.UNASSIGNED, audience="manager", province=key, match_id=first.match_id,
                code=first.code, title=title, body=body, extra={"count": len(hits), "bazaWebUrl": E.obsada_url()},
            )
            await _enqueue_push(
                key, cfg, alert=R.UNASSIGNED, audience="manager", judge_ids=manager_ids, title=title,
                body=body, data=data, match_id="|".join(hit.match_id for hit in hits)[:250], match_at=first.match_at,
            )
        else:
            for hit in hits:
                title, body = R.unassigned_push(hit)
                data = R.push_data(
                    alert=R.UNASSIGNED, audience="manager", province=key, match_id=hit.match_id,
                    code=hit.code, title=title, body=body,
                    extra={
                        "teams": R.teams_text(hit.item.get("host"), hit.item.get("guest")),
                        "when": R.when_long(hit.match_at),
                        "place": ", ".join(p for p in (_s(hit.item.get("hall")), _s(hit.item.get("city"))) if p),
                        "missing": R.missing_text(hit.missing),
                        "bazaWebUrl": E.obsada_url(hit.match_id),
                    },
                )
                await _enqueue_push(
                    key, cfg, alert=R.UNASSIGNED, audience="manager", judge_ids=manager_ids, title=title,
                    body=body, data=data, match_id=hit.match_id, match_at=hit.match_at,
                )
    count = len(hits)
    return (
        f"Ogłoszono {count} {plural(count, 'mecz', 'mecze', 'meczów')} bez obsady"
        f"{f' ({len(mailed)} w mailu)' if mailed and section['email'] else ''}."
    ), None, True


# ---------------------------------------------------------------------------
# Kolizje
# ---------------------------------------------------------------------------

async def _scope(key: str):
    """Zakres meczów okręgu: (powierzone prefiksy, własne prefiksy)."""
    from app.province_assignments import _managed_prefixes, own_prefixes_of

    return await _managed_prefixes(key), await own_prefixes_of(key)


def _in_scope(code: str, managed: Any, own: set[str]) -> bool:
    from app import settlement_origin as SO
    from app import settlement_rates as SR
    from app.match_market_rules import is_managed_by_province

    if not code or SR.is_test_competition(code):
        return False
    return is_managed_by_province(code, managed) and not SO.is_other_district(code, own)


def _info(row: Any, state: dict) -> R.MatchInfo:
    return R.MatchInfo(
        match_id=_s(row["match_id"]),
        code=_s(state.get("RozgrywkiCode") or row["match_code"]),
        moment=R.local(row["match_at"]) if row["match_at"] else None,
        city=_s(state.get("Hala_miasto")),
        hall=_s(state.get("Hala_nazwa")),
        host=_s(state.get("ID_zespoly_gosp_ZespolNazwa")),
        guest=_s(state.get("ID_zespoly_gosc_ZespolNazwa")),
        venue=CR.venue_of(state),
    )


async def _match_rows(key: str) -> list:
    from sqlalchemy import and_, or_, select

    from app.db import database, province_matches
    from app.settlement_province import spellings

    now = _now()
    return await database.fetch_all(
        select(
            province_matches.c.match_id,
            province_matches.c.match_code,
            province_matches.c.match_at,
            province_matches.c.state_json,
        ).where(
            and_(
                province_matches.c.province.in_(spellings(key) or [key]),
                province_matches.c.active.is_(True),
                or_(
                    province_matches.c.match_at.is_(None),
                    and_(
                        province_matches.c.match_at >= now - timedelta(days=2),
                        province_matches.c.match_at <= now + timedelta(days=R.COLLISION_HORIZON_DAYS + 2),
                    ),
                ),
            )
        )
    )


def _crew_of(state: dict) -> dict[str, str]:
    """Numer -> nazwisko wszystkich z obsady (także delegaci)."""
    from app import assignment_rules as AR

    out: dict[str, str] = {}
    for slot in AR.SLOTS:
        person = AR.slot_person(state, slot)
        if person and _s(person.get("number")):
            out.setdefault(_s(person.get("number")), _s(person.get("name")))
    return out


async def _collisions_for(
    key: str,
    rows: list,
    moved_ids: dict[str, Optional[datetime]],
    kinds: Iterable[str],
    rules: Optional[CR.CollisionRules] = None,
) -> list[R.Collision]:
    """Kolizje sędziów z obsady meczów `moved_ids` (numer meczu -> poprzedni termin)."""
    from app.assignment_context import load_roster
    from app.assignment_distances import load_book
    from app.match_market_rules import state_dict

    roster = await load_roster(key)
    book = await load_book(key)
    busy: dict[str, list[R.MatchInfo]] = defaultdict(list)
    infos: dict[str, tuple[R.MatchInfo, dict]] = {}
    for row in rows:
        state = state_dict(row["state_json"]) or {}
        info = _info(row, state)
        crew = _crew_of(state)
        infos[info.match_id] = (info, crew)
        for judge_id in crew:
            busy[judge_id].append(info)
    out: list[R.Collision] = []
    for match_id, previous in moved_ids.items():
        if match_id not in infos:
            continue
        info, crew = infos[match_id]
        for judge_id, crew_name in crew.items():
            judge = roster.judges.get(judge_id)
            name = judge.name if judge else crew_name
            out.extend(
                R.find_collisions(
                    judge_id,
                    name,
                    info,
                    busy.get(judge_id, []),
                    roster.offtimes.get(judge_id, []),
                    book.km,
                    kinds,
                    previous=R.local(previous) if previous else None,
                    rules=rules,
                )
            )
    return out


def _collision_cards(items: list[R.Collision], *, personal: bool = False) -> list[E.CollisionCard]:
    grouped: dict[str, list[R.Collision]] = defaultdict(list)
    for item in items:
        grouped[item.moved.match_id].append(item)
    cards = []
    for group in grouped.values():
        moved = group[0].moved
        rows = []
        for item in group:
            sentence = R.collision_sentence(item, you=personal)
            headline = sentence.split(", a ", 1)[1] if ", a " in sentence else sentence.split(" - ", 1)[-1]
            headline = headline[:1].upper() + headline[1:]
            detail = ""
            if item.kind == R.KIND_OVERLAP and item.other is not None:
                if item.same_hall:
                    missing = f", mecze w tej samej hali nakładają się o ok. {item.short_minutes} min." if item.short_minutes else "."
                else:
                    missing = f", brakuje ok. {item.short_minutes} min na mecz, dojazd i zapas." if item.short_minutes else "."
                detail = (
                    f"Tamten mecz: {item.other.code} {item.other.teams}. "
                    f"Między początkami {item.gap_minutes // 60} h {item.gap_minutes % 60:02d} min" + missing
                )
            elif item.kind == R.KIND_CITY and item.other is not None:
                detail = f"Tamten mecz: {item.other.code} {item.other.teams}, {item.other.hall or item.other.city}."
            elif item.kind == R.KIND_OFFTIME and item.offtime is not None:
                detail = "Wpis z kalendarza niedyspozycji sędziego (okręgowy, centralny albo podpięty kalendarz)."
            rows.append(E.CollisionRow(judge=R.judge_label(item.judge_name), kind=item.kind, headline=headline, detail=detail))
        previous = group[0].previous
        cards.append(
            E.CollisionCard(
                match_id=moved.match_id,
                code=moved.code,
                teams=moved.teams,
                when=R.when_long(moved.moment),
                previous=R.when_long(previous) if previous else "",
                hall=moved.hall,
                city=moved.city,
                rows=rows,
            )
        )
    return cards


def _same_time(a: Optional[datetime], b: Optional[datetime]) -> bool:
    a, b = _aware(a), _aware(b)
    if a is None or b is None:
        return a is None and b is None
    return abs((a - b).total_seconds()) < 60


async def run_collisions(key: str, cfg: dict) -> tuple[str, Optional[str], bool]:
    """Porównanie terminów z zapamiętanymi i alert o kolizjach po zmianie."""
    from sqlalchemy import select
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import database, province_district_alert_times as TT
    from app.match_market_rules import state_dict
    from app.settlement_province import display

    section = cfg[R.COLLISION]
    now = _now()
    rows = await _match_rows(key)
    known = {
        _s(row["match_id"]): row["match_at"]
        for row in await database.fetch_all(select(TT.c.match_id, TT.c.match_at).where(TT.c.province == key))
    }
    first_run = not known
    changed: dict[str, Optional[datetime]] = {}
    to_store: list[tuple[str, Optional[datetime]]] = []
    for row in rows:
        match_id = _s(row["match_id"])
        if match_id not in known:
            to_store.append((match_id, row["match_at"]))
        elif not _same_time(known[match_id], row["match_at"]):
            changed[match_id] = known[match_id]
            to_store.append((match_id, row["match_at"]))

    async def remember() -> None:
        for match_id, at in to_store:
            stmt = pg_insert(TT).values(province=key, match_id=match_id, match_at=at, seen_at=now)
            await database.execute(
                stmt.on_conflict_do_update(
                    index_elements=[TT.c.province, TT.c.match_id], set_={"match_at": at, "seen_at": now}
                )
            )

    if first_run:
        await remember()
        return f"Zapamiętano terminy {len(to_store)} meczów - kolizje sprawdzamy od następnej zmiany terminu.", None, False
    if not changed:
        await remember()
        return "Żaden mecz nie zmienił terminu od ostatniego sprawdzenia.", None, False

    managed, own = await _scope(key)
    moved: dict[str, Optional[datetime]] = {}
    by_id = {_s(row["match_id"]): row for row in rows}
    for match_id, previous in changed.items():
        row = by_id.get(match_id)
        if row is None or row["match_at"] is None:
            continue
        at = _aware(row["match_at"])
        if at <= now or at > now + timedelta(days=R.COLLISION_HORIZON_DAYS):
            continue
        state = state_dict(row["state_json"]) or {}
        code = _s(state.get("RozgrywkiCode") or row["match_code"])
        if not _in_scope(code, managed, own):
            continue
        from app import assignment_rules as AR

        if AR.is_bye(state):
            continue
        if not R.scope_allows(section, AR.competition_key(code), AR.match_category(code)):
            continue
        moved[match_id] = previous

    rules = CR.rules_from_config(cfg.get("timing"))
    found = await _collisions_for(key, list(rows), moved, section["kinds"], rules) if moved else []
    fresh = [
        item
        for item in found
        if await _claim_mark(key, item.key, alert=R.COLLISION, match_id=item.moved.match_id, judge_id=item.judge_id)
    ]
    await remember()
    if not fresh:
        count = len(moved)
        return (
            f"{count} {plural(count, 'mecz zmienił', 'mecze zmieniły', 'meczów zmieniło')} termin - bez nowych kolizji."
            if count
            else "Zmiany terminów poza zakresem okręgu - bez alertu."
        ), None, False

    managers = await _managers(key)
    manager_ids = [item["judge_id"] for item in managers]
    province_display = display(key)
    error: Optional[str] = None
    if section["email"]:
        bcc = list((await _judge_emails(key, manager_ids)).values()) if section["email_managers"] else []
        to = list(section["emails"])
        if to or bcc:
            subject, html_body, text_body = E.build_collision_message(
                province_key=key, province_display=province_display, cards=_collision_cards(fresh)
            )
            error = await _send_mail(
                key, alert=R.COLLISION, audience="manager", to=to, bcc=bcc,
                subject=subject, html_body=html_body, text_body=text_body,
            )
        if section["email_judge"]:
            emails = await _judge_emails(
                key,
                {item.judge_id for item in fresh},
                {item.judge_id: item.judge_name for item in fresh},
            )
            for judge_id, email in emails.items():
                own_items = [item for item in fresh if item.judge_id == judge_id]
                subject, html_body, text_body = E.build_collision_message(
                    province_key=key, province_display=province_display,
                    cards=_collision_cards(own_items, personal=True), personal=True,
                )
                problem = await _send_mail(
                    key, alert=R.COLLISION, audience="judge", to=[email], bcc=[],
                    subject=subject, html_body=html_body, text_body=text_body,
                    match_id=own_items[0].moved.match_id,
                )
                error = error or problem

    if section["push_judge"]:
        for item in fresh:
            title, body = R.judge_push(item)
            data = R.push_data(
                alert=R.COLLISION, audience="judge", province=key, match_id=item.moved.match_id,
                code=item.moved.code, title=title, body=body,
                # Numer sędziego: aplikacja odrzuci dotknięcie na cudzym koncie.
                extra={"collision": item.kind, "judgeId": item.judge_id},
            )
            await _enqueue_push(
                key, cfg, alert=R.COLLISION, audience="judge", judge_ids=[item.judge_id], title=title,
                body=body, data=data, match_id=item.moved.match_id, match_at=R.to_utc(item.moved.moment),
            )
    if section["push_managers"] and manager_ids:
        grouped: dict[str, list[R.Collision]] = defaultdict(list)
        for item in fresh:
            grouped[item.moved.match_id].append(item)
        for match_id, items in grouped.items():
            title, body = R.manager_push(items)
            moved_info = items[0].moved
            data = R.push_data(
                alert=R.COLLISION, audience="manager", province=key, match_id=match_id,
                code=moved_info.code, title=title, body=body,
                extra={
                    "teams": moved_info.teams,
                    "when": R.when_long(moved_info.moment),
                    "place": ", ".join(p for p in (moved_info.hall, moved_info.city) if p),
                    "bazaWebUrl": E.obsada_url(match_id),
                },
            )
            await _enqueue_push(
                key, cfg, alert=R.COLLISION, audience="manager", judge_ids=manager_ids, title=title,
                body=body, data=data, match_id=match_id, match_at=R.to_utc(moved_info.moment),
            )
    count = len(fresh)
    return f"Ogłoszono {count} {plural(count, 'kolizję', 'kolizje', 'kolizji')} po zmianie terminu.", error, True


# ---------------------------------------------------------------------------
# Pętla i zaczep monitora
# ---------------------------------------------------------------------------

async def _claim_check(key: str) -> bool:
    from sqlalchemy import and_, or_, update

    from app.db import database, province_district_alert_settings as T

    now = _now()
    stmt = (
        update(T)
        .where(
            and_(
                T.c.province == key,
                T.c.enabled.is_(True),
                or_(T.c.last_check_at.is_(None), T.c.last_check_at <= now - timedelta(minutes=CLAIM_MINUTES)),
            )
        )
        .values(last_check_at=now)
        .returning(T.c.province)
    )
    return (await database.fetch_one(stmt)) is not None


async def _prune(key: str) -> None:
    """Sprzątanie: stare terminy, znaczniki i dziennik nie mają po co rosnąć."""
    from sqlalchemy import and_, delete

    from app.db import (
        database,
        province_district_alert_marks as M,
        province_district_alert_outbox as Q,
        province_district_alert_times as TT,
    )

    now = _now()
    await database.execute(
        delete(TT).where(and_(TT.c.province == key, TT.c.match_at.is_not(None), TT.c.match_at < now - timedelta(days=7)))
    )
    await database.execute(delete(M).where(and_(M.c.province == key, M.c.created_at < now - timedelta(days=180))))
    await database.execute(
        delete(Q).where(and_(Q.c.province == key, Q.c.status != "queued", Q.c.created_at < now - timedelta(days=90)))
    )


async def check_province(key: str, *, collisions_only: bool = False) -> None:
    """Pełne sprawdzenie okręgu (pod zamkiem procesu)."""
    async with _lock(key):
        row = await _row(key)
        if row is None or _s(row["province"]) != key:
            return
        cfg = _config_of(row)
        parts: list[str] = []
        errors: list[str] = []
        sent = False
        jobs = []
        if cfg[R.UNASSIGNED]["enabled"] and not collisions_only:
            jobs.append(("Brak obsady", run_unassigned))
        if cfg[R.COLLISION]["enabled"]:
            jobs.append(("Kolizje", run_collisions))
        for label, job in jobs:
            try:
                text, error, did = await job(key, cfg)
                parts.append(f"{label}: {text}")
                if error:
                    errors.append(f"{label}: {error}")
                sent = sent or did
            except Exception as exc:  # noqa: BLE001 - jeden alert nie zatrzymuje drugiego
                logger.exception("[district-alerts] %s %s", key, label)
                errors.append(f"{label}: sprawdzenie nie powiodło się ({type(exc).__name__}).")
        try:
            await flush_outbox(key)
            if not collisions_only:
                await _prune(key)
        except Exception:  # noqa: BLE001
            logger.exception("[district-alerts] kolejka %s", key)
        if parts or errors:
            await _finish(key, status=" ".join(parts) or "Sprawdzenie nie powiodło się.", error=" ".join(errors) or None, sent=sent)


async def sweep() -> int:
    from sqlalchemy import select

    from app.db import database, province_district_alert_settings as T

    rows = await database.fetch_all(select(T.c.province).where(T.c.enabled.is_(True)))
    done = 0
    for row in rows:
        key = _canonical(row["province"])
        if not key or key != _s(row["province"]):
            continue  # stara pisownia - zapis przenosi ją pod klucz kanoniczny
        try:
            if not await _claim_check(key):
                continue
            await check_province(key)
            done += 1
        except Exception:  # noqa: BLE001 - jeden okręg nie zatrzymuje reszty
            logger.exception("[district-alerts] %s", key)
    return done


def note_match_moved(province: Any, match_id: Any = None) -> None:
    """
    Zaczep monitora: termin meczu się zmienił - sprawdź kolizje zaraz.

    Nie blokuje monitora: zakłada jedno zadanie na okręg, które odczekuje chwilę
    (paczka zmian z jednego pobrania idzie razem) i sprawdza, czy alert jest
    w ogóle włączony. Brak pętli zdarzeń albo błąd - pętla co 15 minut i tak
    to wyłapie.
    """
    try:
        loop = asyncio.get_running_loop()
        key = _canonical(province)
        if not key:
            return
        task = _pending_moves.get(key)
        if task is not None and not task.done():
            return
        _pending_moves[key] = loop.create_task(_after_move(key))
    except Exception:  # noqa: BLE001 - zaczep nie może wywrócić monitora
        logger.debug("[district-alerts] zaczep monitora pominięty", exc_info=True)


async def _after_move(key: str) -> None:
    try:
        await asyncio.sleep(MOVE_DEBOUNCE_SECONDS)
        row = await _row(key)
        if row is None or not row.get("enabled") or not _config_of(row)[R.COLLISION]["enabled"]:
            return
        await check_province(key, collisions_only=True)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001
        logger.exception("[district-alerts] kolizje po zmianie terminu %s", key)


async def run_district_alert_scheduler() -> None:
    await asyncio.sleep(150)  # niech serwer najpierw wstanie
    while True:
        try:
            await sweep()
        except Exception:  # noqa: BLE001
            logger.exception("[district-alerts] pętla")
        await asyncio.sleep(SWEEP_EVERY_SECONDS)


_task: Optional[asyncio.Task] = None


def start_district_alert_scheduler() -> None:
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(run_district_alert_scheduler())


async def stop_district_alert_scheduler() -> None:
    global _task
    for task in list(_pending_moves.values()):
        task.cancel()
    if _task is None:
        return
    _task.cancel()
    try:
        await _task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass
    _task = None


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------

class SettingsRequest(BaseModel):
    province: str
    config: dict = {}
    updated_by: Optional[str] = None


class TestRequest(BaseModel):
    province: str
    alert: str
    config: dict = {}


async def _facets(key: str) -> dict:
    """Rozgrywki i kategorie do filtra - z listy obsadowego bieżącego sezonu."""
    from app.province_assignments import match_list_payload

    try:
        listing = await match_list_payload(key, when="all", include_league=False, limit=0)
    except Exception:  # noqa: BLE001 - filtr bez podpowiedzi to nie awaria
        logger.exception("[district-alerts] rozgrywki %s", key)
        return {"competitions": [], "categories": []}
    return {
        "competitions": [
            {"key": item["key"], "label": item.get("label") or item["key"], "matches": item.get("matches", 0)}
            for item in listing.get("competitions") or []
        ],
        "categories": [
            {"key": item["key"], "label": item.get("label") or item["key"], "matches": item.get("matches", 0)}
            for item in listing.get("categories") or []
        ],
    }


async def _recent(key: str, limit: int = 20) -> list[dict]:
    from sqlalchemy import desc, select

    from app.db import database, province_district_alert_outbox as Q

    rows = await database.fetch_all(select(Q).where(Q.c.province == key).order_by(desc(Q.c.id)).limit(limit))
    return [
        {
            "id": row["id"],
            "alert": row["alert"],
            "channel": row["channel"],
            "audience": row["audience"],
            "match_id": _s(row["match_id"]) or None,
            "title": row["title"],
            "body": row["body"],
            "recipients": len(_json(row["recipients"], [])),
            "status": row["status"],
            "detail": _s(row["detail"]) or None,
            "due_at": _iso(row["due_at"]),
            "created_at": _iso(row["created_at"]),
            "sent_at": _iso(row["sent_at"]),
        }
        for row in rows
    ]


async def _settings_json(key: str, row: Optional[dict]) -> dict:
    from app.settlement_province import display

    cfg = get_email_config()
    managers = await _managers(key)
    ids = [item["judge_id"] for item in managers]
    with_app = await _with_app(ids)
    with_email = await _judge_email_detail(key, ids)
    return {
        "province": key,
        "display": display(key),
        "saved": row is not None,
        "config": _config_of(row),
        "thresholds": list(R.THRESHOLDS),
        "kinds": [{"key": kind, "label": R.KIND_LABELS[kind]} for kind in R.KINDS],
        "managers": [
            {
                **item,
                "app": item["judge_id"] in with_app,
                "email": item["judge_id"] in with_email,
                # Skąd adres: "login" (profil w aplikacji) albo "contacts" (Kontakty).
                "email_source": with_email[item["judge_id"]][1] if item["judge_id"] in with_email else None,
            }
            for item in managers
        ],
        "email_summary": {
            "with_email": sum(1 for item in managers if item["judge_id"] in with_email),
            "total": len(managers),
            "sources": ["login", "contacts"],
        },
        # Reguła „zdąży z meczu na mecz" (sekcja `timing`) - etykiety i granice pól.
        "timing_options": {
            "categories": [
                {"key": k, "label": CR.CATEGORY_LABELS[k], "default": CR.DEFAULT_DURATIONS[k]}
                for k in CR.CATEGORY_KEYS
            ],
            "travel_kmh": {"default": CR.DEFAULT_TRAVEL_KMH, "min": CR.TRAVEL_KMH_RANGE[0], "max": CR.TRAVEL_KMH_RANGE[1]},
            "margin_minutes": {"default": CR.DEFAULT_MARGIN_MINUTES, "min": CR.MARGIN_RANGE[0], "max": CR.MARGIN_RANGE[1]},
            "duration": {"min": CR.DURATION_RANGE[0], "max": CR.DURATION_RANGE[1]},
        },
        "facets": await _facets(key),
        "recent": await _recent(key),
        "mail_configured": bool(cfg.brevo_api_key and cfg.from_email),
        "sender_name": E.sender_name(),
        "sender_email": cfg.from_email or None,
        "last_check_at": _iso((row or {}).get("last_check_at")),
        "last_sent_at": _iso((row or {}).get("last_sent_at")),
        "last_status": _s((row or {}).get("last_status")) or None,
        "last_error": _s((row or {}).get("last_error")) or None,
        "updated_at": _iso((row or {}).get("updated_at")),
        "updated_by": _s((row or {}).get("updated_by")) or None,
        "sweep_minutes": SWEEP_EVERY_SECONDS // 60,
        "max_emails": 10,
    }


@router.get("/settings", summary="Powiadomienia okręgu z Obsady - ustawienia (wspólne dla okręgu)")
async def get_settings(province: str, payload: dict = Depends(get_jwt_payload)):
    key = await _require(payload, province)
    return await _settings_json(key, await _row(key))


@router.put("/settings", summary="Zapis ustawień powiadomień okręgu")
async def put_settings(body: SettingsRequest, payload: dict = Depends(get_jwt_payload)):
    from sqlalchemy import and_, delete, update
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import (
        database,
        province_district_alert_marks as M,
        province_district_alert_outbox as Q,
        province_district_alert_settings as T,
        province_district_alert_times as TT,
    )
    from app.settlement_province import spellings

    key = await _require(payload, body.province)
    try:
        clean = R.validate_config(body.config)
    except AlertRuleError as exc:
        raise HTTPException(400, str(exc)) from None

    before = _config_of(await _row(key))
    now = _now()
    who = _s(body.updated_by) or _s(payload.get("sub")) or None
    values = {
        "config": json.dumps(clean, ensure_ascii=False),
        "enabled": R.any_enabled(clean),
        "updated_by": who,
        "updated_at": now,
    }
    turned_on = R.any_enabled(clean) and not R.any_enabled(before)
    if turned_on:
        # Pierwsze sprawdzenie przy najbliższym obrocie pętli.
        values.update(last_check_at=None, last_status=None, last_error=None)
    await database.execute(
        pg_insert(T).values(province=key, **values).on_conflict_do_update(index_elements=[T.c.province], set_=values)
    )
    others = [name for name in (spellings(key) or []) if name != key]
    if others:
        # Wiersz spod starej pisowni przeszedł pod klucz kanoniczny.
        await database.execute(delete(T).where(T.c.province.in_(others)))
    if clean.get("timing") != before.get("timing"):
        # Czasy meczów i dojazdu czyta też Automat - jego świat do przebudowy.
        from app.assignment_board_cache import bump

        bump(key)
    for alert in R.ALERTS:
        if before[alert]["enabled"] and not clean[alert]["enabled"]:
            # Wyłączony alert nie wysyła już nic, także z kolejki ciszy nocnej.
            await database.execute(
                update(Q)
                .where(and_(Q.c.province == key, Q.c.alert == alert, Q.c.status == "queued"))
                .values(status="cancelled", sent_at=now, detail="Alert wyłączony przed wysyłką.")
            )
        if clean[alert]["enabled"] and not before[alert]["enabled"] and alert == R.UNASSIGNED:
            # Czysta karta: mecz, który jest pusty od tygodnia, też ma przyjść.
            await database.execute(delete(M).where(and_(M.c.province == key, M.c.alert == alert)))
        if clean[alert]["enabled"] and not before[alert]["enabled"] and alert == R.COLLISION:
            # Terminy zapamiętane przed wyłączeniem są nieaktualne - każdy mecz
            # przeniesiony w przerwie udawałby świeżą zmianę. Pierwsze
            # sprawdzenie po włączeniu tylko zapamiętuje terminy od nowa.
            await database.execute(delete(TT).where(TT.c.province == key))
    return {"success": True, **(await _settings_json(key, await _row(key)))}


@router.post("/test", summary="Próbne powiadomienie (mail na podane adresy i push na własny telefon)")
async def send_test(body: TestRequest, payload: dict = Depends(get_jwt_payload)):
    from app.settlement_province import display

    key = await _require(payload, body.province)
    alert = _s(body.alert)
    if alert not in R.ALERTS:
        raise HTTPException(400, "Nieznany rodzaj powiadomienia.")
    cfg = R.normalize_config(body.config or _config_of(await _row(key)))
    section = cfg[alert]
    try:
        emails = normalize_emails(section.get("emails") or [])
    except AlertRuleError as exc:
        raise HTTPException(400, str(exc)) from None
    judge_id = _s(payload.get("judge_id"))
    if not emails and not judge_id:
        raise HTTPException(
            400,
            "Dopisz adres e-mail - próbny mail idzie tylko na adresy z listy. Push próbny dostaje "
            "wyłącznie konto sędziego zalogowane w aplikacji BAZA, a to konto nim nie jest.",
        )
    stamp = f"{key}|{alert}"
    left = TEST_COOLDOWN_SECONDS - (time.monotonic() - _test_sent.get(stamp, -1e9))
    if left > 0:
        raise HTTPException(429, f"Próbne powiadomienie poszło przed chwilą. Następne za {int(left) + 1} s.")
    _test_sent[stamp] = time.monotonic()

    province_display = display(key)
    push_title = push_body = ""
    push_data: dict = {}
    note = ""
    if alert == R.UNASSIGNED:
        threshold = int(section["threshold_hours"])
        now = _now()
        items = await _window_items(key, threshold)
        plan = R.plan_unassigned(items, set(), section, now)
        hits = plan.hits[:5]
        if hits:
            note = (
                f"Teraz bez obsady w oknie {threshold} h jest {len(plan.hits)} "
                f"{plural(len(plan.hits), 'mecz', 'mecze', 'meczów')} - prawdziwe powiadomienie powie o każdym raz."
                + (" W próbce pierwsze pięć." if len(plan.hits) > 5 else "")
            )
        else:
            wide = R.plan_unassigned(await _window_items(key, 24 * 21), set(), {**section, "threshold_hours": 24 * 21}, now)
            hits = wide.hits[:2]
            note = (
                f"W najbliższych {threshold} h wszystkie mecze mają komplet, więc dla przykładu pokazujemy "
                "najbliższe mecze z brakami z kolejnych trzech tygodni."
                if hits
                else "W najbliższych trzech tygodniach żaden mecz nie ma braków - tak wygląda mail bez meczów."
            )
        suggestions = await _suggestions(key, [hit.match_id for hit in hits])
        cards = [_card(hit, suggestions.get(hit.match_id)) for hit in hits]
        subject, html_body, text_body = E.build_unassigned_message(
            province_key=key, province_display=province_display, threshold=threshold,
            cards=cards, test=True, preview_note=note,
        )
        if hits:
            push_title, push_body = R.unassigned_push(hits[0])
            push_data = R.push_data(
                alert=R.UNASSIGNED, audience="manager", province=key, match_id=hits[0].match_id,
                code=hits[0].code, title=push_title, body=push_body,
                extra={
                    "teams": R.teams_text(hits[0].item.get("host"), hits[0].item.get("guest")),
                    "when": R.when_long(hits[0].match_at),
                    "place": ", ".join(p for p in (_s(hits[0].item.get("hall")), _s(hits[0].item.get("city"))) if p),
                    "missing": R.missing_text(hits[0].missing),
                    "bazaWebUrl": E.obsada_url(hits[0].match_id),
                },
            )
    else:
        rows = await _match_rows(key)
        now = _now()
        from app.match_market_rules import state_dict

        upcoming = {
            _s(row["match_id"]): None
            for row in rows
            if row["match_at"] is not None
            and now < _aware(row["match_at"]) <= now + timedelta(days=14)
            and _crew_of(state_dict(row["state_json"]) or {})
        }
        found = await _collisions_for(key, list(rows), upcoming, section["kinds"]) if upcoming else []
        seen: set[str] = set()
        unique = []
        for item in found:
            if item.key not in seen:
                seen.add(item.key)
                unique.append(item)
        cards = _collision_cards(unique)[:5]
        note = (
            f"To nie są zmiany terminu, tylko kolizje, które są w terminarzu TERAZ "
            f"({len(unique)} w najbliższych dwóch tygodniach). Prawdziwe powiadomienie przychodzi, gdy mecz zmieni termin."
            if unique
            else "W najbliższych dwóch tygodniach nikt z obsady nie ma kolizji - tak wygląda mail bez kolizji."
        )
        subject, html_body, text_body = E.build_collision_message(
            province_key=key, province_display=province_display, cards=cards, test=True, preview_note=note
        )
        if unique:
            push_title, push_body = R.manager_push([item for item in unique if item.moved.match_id == unique[0].moved.match_id])
            push_data = R.push_data(
                alert=R.COLLISION, audience="manager", province=key, match_id=unique[0].moved.match_id,
                code=unique[0].moved.code, title=push_title, body=push_body,
                extra={
                    "teams": unique[0].moved.teams,
                    "when": R.when_long(unique[0].moved.moment),
                    "place": ", ".join(p for p in (unique[0].moved.hall, unique[0].moved.city) if p),
                    "bazaWebUrl": E.obsada_url(unique[0].moved.match_id),
                },
            )

    result: dict[str, Any] = {"success": True, "sent_to": [], "note": note, "subject": subject, "push": None}
    if emails:
        problem = await _send_mail(
            key, alert=alert, audience="manager", to=emails, bcc=[], subject=subject,
            html_body=html_body, text_body=text_body, test=True,
        )
        if problem:
            raise HTTPException(502, problem)
        result["sent_to"] = emails
    if judge_id:
        if not push_title:
            push_title = "Powiadomienia okręgu działają"
            push_body = "To próbny push z Obsady. Teraz nie ma czego pokazać, więc przyszedł sam komunikat."
            push_data = R.push_data(
                alert=alert, audience="manager", province=key, match_id="", code="",
                title=push_title, body=push_body, extra={"bazaWebUrl": E.obsada_url()},
            )
        from app.push.push import send_push_to_judges_report

        push_data["is_test"] = "true"
        try:
            report = await send_push_to_judges_report(
                [judge_id], f"TEST · {push_title}", push_body, push_data, app_variant="baza"
            )
        except Exception as exc:  # noqa: BLE001
            report = {"status": "error", "errorStage": type(exc).__name__}
        status, detail = _report_text(report)
        result["push"] = {"status": status, "detail": detail}
    return result
