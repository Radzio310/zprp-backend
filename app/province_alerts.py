"""
Alerty mailowe o saldzie klubów - trasy ustawień, próbny mail i pętla w tle.

Ustawienia należą do KONTA zalogowanego w BAZA_web (login VIP albo numer
sędziego-administratora) w danym okręgu. Każda trasa wymaga tokenu (401 bez
niego) i tego samego uprawnienia, co zapis w panelu klubów - konto VIP okręgu
z uprawnieniem „Rozliczenia" albo administrator aplikacji
(`province_panel_access.panel_write_refusal`). Pętla sprawdza to uprawnienie
jeszcze raz przed każdą wysyłką: konto, któremu odebrano Rozliczenia, przestaje
dostawać maile bez ruszania jego ustawień.

Reguły (kto dostaje mail, „raz przy przekroczeniu", tempo) siedzą w liściu
`province_alert_rules`, szablon w `province_alert_emails`, schemat w
`province_alert_tables`.

SALDA BUDŻETÓW: `province_club_budgets.season_budgets(province, season)` -
wspólne budżety klubów. Gdy tego modułu nie ma (albo się wyłoży), każdy klub
z `province_clubs._season_clubs` jest własnym budżetem - to samo saldo, co
w panelu klubów przed wprowadzeniem wspólnych budżetów.

PODWÓJNA WYSYŁKA przy kilku instancjach serwera: sprawdzenie zaczyna się od
warunkowego UPDATE `last_check_at` z RETURNING („zajmij, jeśli nikt nie zajął
w tym odstępie"). Druga instancja widzi już świeży stempel i nic nie dostaje.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from app import province_alert_rules as A
from app.beach.brevo_email import EmailDeliveryError
from app.beach.email_config import get_email_config
from app.deps import get_jwt_payload
from app.province_alert_emails import (
    BudgetCard,
    build_message,
    delivery_message,
    send_alert_email,
    sender_name,
)
from app.province_panel_access import PANEL_SETTLEMENTS, panel_write_refusal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/alerts", tags=["province_alerts"])

WARSAW = ZoneInfo("Europe/Warsaw")
SWEEP_EVERY_SECONDS = 15 * 60
TEST_COOLDOWN_SECONDS = 30
LOGO_DIR = Path(__file__).resolve().parent / "templates" / "okregi"

_test_sent: dict[str, float] = {}
_logo_cache: dict[str, bytes] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _emails(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [_s(item) for item in raw if _s(item)]
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return [_s(item) for item in value if _s(item)] if isinstance(value, list) else []


# ---------------------------------------------------------------------------
# Dostęp
# ---------------------------------------------------------------------------

async def _refusal(payload: dict, province: str) -> str:
    from app.province_panel_guard import _lookup

    is_admin, vip = await _lookup(payload)
    return panel_write_refusal(
        panel=PANEL_SETTLEMENTS,
        province=province,
        account_type=_s(payload.get("account_type")),
        judge_id=_s(payload.get("judge_id")),
        login=_s(payload.get("sub")),
        is_admin=is_admin,
        vip=vip,
    )


async def _require(payload: dict, province: str) -> str:
    """Klucz okręgu (np. „SLASKIE") po sprawdzeniu uprawnienia - albo 400/403."""
    from app.province_settlements import require_province

    key = require_province(province)
    reason = await _refusal(payload, key)
    if reason:
        raise HTTPException(403, f"Alerty o saldzie klubów: {reason}")
    return key


def _account_label(row: Any) -> str:
    name = _s(row.get("display_name")) if row else ""
    login = _s(row.get("login")) if row else ""
    judge = _s(row.get("judge_id")) if row else ""
    return name or login or (f"sędzia {judge}" if judge else "")


# ---------------------------------------------------------------------------
# Migawka budżetów okręgu
# ---------------------------------------------------------------------------

@dataclass
class Snapshot:
    budgets: dict[str, dict]
    charges: dict[str, list[tuple[Any, float]]]
    entries: dict[str, list[dict]]
    source: str


async def _snapshot(key: str, season: str) -> Snapshot:
    from app import club_charges as C
    from app.province_clubs import _entries, _season_clubs

    data = await _season_clubs(key, season)
    budgets: Optional[dict[str, dict]] = None
    source = "budgets"
    try:
        # Moduł wspólnych budżetów. `merged_clubs` scala TE SAME kluby, które już
        # policzyliśmy (to samo, co robi w środku `season_budgets`), więc silnik
        # rozliczeń nie liczy sezonu drugi raz.
        from app import province_club_budgets as budgets_module
    except ImportError:
        budgets_module = None  # type: ignore[assignment]
    if budgets_module is not None:
        try:
            if hasattr(budgets_module, "merged_clubs"):
                budgets = await budgets_module.merged_clubs(key, data["clubs"])
            else:
                budgets = await budgets_module.season_budgets(key, season)
        except Exception:  # noqa: BLE001 - alert ma działać na saldach klubów
            logger.exception("[alerts] budżety %s %s - biorę salda klubów", key, season)
            budgets = None
    if budgets is None:
        source = "clubs"
        budgets = {club_id: {**club, "member_ids": [club_id]} for club_id, club in data["clubs"].items()}

    owner: dict[str, str] = {}
    for budget_id, budget in budgets.items():
        members = [_s(item) for item in (budget.get("member_ids") or []) if _s(item)] or [budget_id]
        for club_id in members + [budget_id]:
            owner.setdefault(club_id, budget_id)

    charges: dict[str, list[tuple[Any, float]]] = {}
    for row in data["charges"]:
        if row.status != C.CHARGED or not row.club_id:
            continue
        budget_id = owner.get(row.club_id)
        if budget_id:
            charges.setdefault(budget_id, []).append((row.day, float(row.amount or 0)))

    entries: dict[str, list[dict]] = {}
    for row in await _entries(key, season):
        budget_id = owner.get(_s(row.get("club_id")))
        if budget_id:
            entries.setdefault(budget_id, []).append(row)

    return Snapshot(budgets=budgets, charges=charges, entries=entries, source=source)


def _teams_label(budget: dict) -> str:
    members = [item for item in (budget.get("member_ids") or []) if _s(item)]
    teams = budget.get("teams") or []
    parts = []
    if len(members) > 1:
        parts.append(f"wspólny budżet {len(members)} {A.plural(len(members), 'klubu', 'klubów', 'klubów')}")
    if teams:
        parts.append(f"{len(teams)} {A.plural(len(teams), 'drużyna', 'drużyny', 'drużyn')}")
    return " · ".join(parts)


def _card(snapshot: Snapshot, budget_id: str, today) -> BudgetCard:
    budget = snapshot.budgets[budget_id]
    balance = float(budget.get("balance") or 0)
    return BudgetCard(
        budget_id=budget_id,
        name=_s(budget.get("name")) or budget_id,
        balance=balance,
        charged=float(budget.get("charged") or 0),
        matches=int(budget.get("matches") or 0),
        last_payment=A.last_payment(snapshot.entries.get(budget_id, [])),
        pace=A.spending_pace(balance, snapshot.charges.get(budget_id, []), today),
        teams_label=_teams_label(budget),
    )


def _today():
    return _now().astimezone(WARSAW).date()


def _season() -> str:
    from app.settlement_seasons import season_of

    return season_of(_now().astimezone(WARSAW))


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------

class SettingsRequest(BaseModel):
    province: str
    enabled: bool = False
    threshold: float = A.DEFAULT_THRESHOLD
    interval_hours: int = A.DEFAULT_INTERVAL
    emails: list[str] = []
    display_name: Optional[str] = None


class TestRequest(BaseModel):
    province: str
    threshold: float = A.DEFAULT_THRESHOLD
    emails: list[str] = []
    display_name: Optional[str] = None


async def _row(account: str, key: str):
    from sqlalchemy import and_, select

    from app.db import database, province_alert_settings as T

    row = await database.fetch_one(
        select(T).where(and_(T.c.account_key == account, T.c.province == key))
    )
    return dict(row) if row else None


def _settings_json(key: str, account: str, row: Optional[dict]) -> dict:
    from app.settlement_province import display

    now = _now()
    cfg = get_email_config()
    enabled = bool(row and row.get("enabled"))
    interval = int((row or {}).get("interval_hours") or A.DEFAULT_INTERVAL)
    last_check = (row or {}).get("last_check_at")
    return {
        "province": key,
        "display": display(key),
        "account_key": account,
        "saved": row is not None,
        "enabled": enabled,
        "threshold": float((row or {}).get("threshold") or A.DEFAULT_THRESHOLD),
        "interval_hours": interval,
        "emails": _emails((row or {}).get("emails")),
        "intervals": list(A.INTERVALS),
        "max_emails": A.MAX_EMAILS,
        "last_check_at": _iso(last_check),
        "next_check_at": _iso(A.next_check_at(last_check, interval, now)) if enabled else None,
        "last_sent_at": _iso((row or {}).get("last_sent_at")),
        "last_status": _s((row or {}).get("last_status")) or None,
        "last_error": _s((row or {}).get("last_error")) or None,
        "updated_at": _iso((row or {}).get("updated_at")),
        "mail_configured": bool(cfg.brevo_api_key and cfg.from_email),
        "sender_name": sender_name(),
        "sender_email": cfg.from_email or None,
        "sweep_minutes": SWEEP_EVERY_SECONDS // 60,
    }


@router.get("/settings", summary="Ustawienia alertów o saldzie klubów dla zalogowanego konta")
async def get_settings(province: str, payload: dict = Depends(get_jwt_payload)):
    key = await _require(payload, province)
    account = A.account_key(payload)
    return _settings_json(key, account, await _row(account, key))


@router.put("/settings", summary="Zapis ustawień alertów o saldzie klubów")
async def put_settings(body: SettingsRequest, payload: dict = Depends(get_jwt_payload)):
    from sqlalchemy import and_, delete
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import database, province_alert_settings as T, province_alert_state as S

    key = await _require(payload, body.province)
    account = A.account_key(payload)
    try:
        clean = A.validate_settings(
            enabled=body.enabled,
            threshold=body.threshold,
            interval_hours=body.interval_hours,
            emails=body.emails,
        )
    except A.AlertRuleError as exc:
        raise HTTPException(400, str(exc)) from None

    before = await _row(account, key)
    was_enabled = bool(before and before.get("enabled"))
    now = _now()
    values = {
        "account_type": _s(payload.get("account_type")) or None,
        "login": _s(payload.get("sub")) or None,
        "judge_id": _s(payload.get("judge_id")) or None,
        "display_name": _s(body.display_name) or None,
        "enabled": clean.enabled,
        "threshold": clean.threshold,
        "interval_hours": clean.interval_hours,
        "emails": json.dumps(clean.emails, ensure_ascii=False),
        "updated_at": now,
    }
    if clean.enabled and not was_enabled:
        # Świeże włączenie: pierwsze sprawdzenie przy najbliższym obrocie pętli
        # i czysta karta - klub, który jest pod progiem od tygodnia, też ma
        # przyjść w pierwszym mailu.
        values.update(last_check_at=None, last_status=None, last_error=None)
    stmt = pg_insert(T).values(account_key=account, province=key, **values)
    await database.execute(
        stmt.on_conflict_do_update(index_elements=[T.c.account_key, T.c.province], set_=values)
    )
    if clean.enabled and not was_enabled:
        await database.execute(delete(S).where(and_(S.c.account_key == account, S.c.province == key)))
    return {"success": True, **_settings_json(key, account, await _row(account, key))}


def _preview(snapshot: Snapshot, threshold: float) -> tuple[list[str], str]:
    """Budżety do maila próbnego i dopisek, skąd się wzięły."""
    watched = A.watched_budgets(snapshot.budgets)
    below = sorted(
        (item for item, budget in watched.items() if float(budget.get("balance") or 0) < threshold),
        key=lambda item: float(watched[item].get("balance") or 0),
    )
    if below:
        return below, (
            f"Poniżej progu jest teraz {len(below)} {A.plural(len(below), 'klub', 'kluby', 'klubów')} - "
            "prawdziwy alert napisze o każdym z nich tylko raz."
        )
    if not watched:
        return [], (
            "Żaden klub nie spełnia jeszcze warunków alertu: rozliczanie przez okręg "
            "i co najmniej jedna wpłata w tym sezonie."
        )
    lowest = sorted(watched, key=lambda item: float(watched[item].get("balance") or 0))[:3]
    return lowest, (
        "Teraz żaden klub nie jest poniżej progu, więc dla przykładu pokazujemy kluby "
        "z najniższym saldem."
    )


@router.post("/test", summary="Próbny mail z alertem na podane adresy")
async def send_test(body: TestRequest, payload: dict = Depends(get_jwt_payload)):
    from app.settlement_province import display

    key = await _require(payload, body.province)
    account = A.account_key(payload)
    try:
        emails = A.normalize_emails(body.emails)
        threshold = A.normalize_threshold(body.threshold)
    except A.AlertRuleError as exc:
        raise HTTPException(400, str(exc)) from None
    if not emails:
        raise HTTPException(400, "Dodaj co najmniej jeden adres, na który ma pójść próbny mail.")

    stamp = f"{account}|{key}"
    left = TEST_COOLDOWN_SECONDS - (time.monotonic() - _test_sent.get(stamp, -1e9))
    if left > 0:
        raise HTTPException(429, f"Próbny mail poszedł przed chwilą. Następny za {int(left) + 1} s.")

    snapshot = await _snapshot(key, _season())
    ids, note = _preview(snapshot, threshold)
    today = _today()
    cards = [_card(snapshot, item, today) for item in ids]
    subject, html_body, text_body = build_message(
        province_key=key,
        province_display=display(key),
        threshold=threshold,
        cards=cards,
        account_label=_s(body.display_name) or _s(payload.get("sub")),
        test=True,
        preview_note=note,
    )
    try:
        await send_alert_email(emails, subject, html_body, text_body, test=True)
    except EmailDeliveryError as exc:
        raise HTTPException(502, delivery_message(exc)) from None
    _test_sent[stamp] = time.monotonic()
    return {"success": True, "sent_to": emails, "clubs": len(cards), "note": note, "subject": subject}


@router.get("/logo/{province}.png", summary="Herb okręgu do nagłówka maila (publiczny)")
async def province_logo(province: str):
    from app import settlement_rates as R

    slug = R.province_key(province).lower()
    if not slug:
        raise HTTPException(404, "Nieznane województwo")
    if slug not in _logo_cache:
        path = next(
            (p for p in sorted(LOGO_DIR.glob("*.png")) if p.stem.lower().replace("_", "") == slug),
            None,
        )
        if path is None:
            raise HTTPException(404, "Brak herbu dla tego okręgu")
        try:
            import io

            from PIL import Image

            image = Image.open(path)
            image.thumbnail((168, 168), Image.LANCZOS)
            buffer = io.BytesIO()
            image.save(buffer, format="PNG", optimize=True)
            _logo_cache[slug] = buffer.getvalue()
        except Exception:  # noqa: BLE001 - bez Pillow oddajemy oryginał
            _logo_cache[slug] = path.read_bytes()
    return Response(
        content=_logo_cache[slug],
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=604800"},
    )


# ---------------------------------------------------------------------------
# Pętla w tle
# ---------------------------------------------------------------------------

async def _claim(row: dict, now: datetime) -> bool:
    """Optymistyczny zamek: zajmuje sprawdzenie tylko temu, kto zdąży pierwszy."""
    from sqlalchemy import and_, or_, update

    from app.db import database, province_alert_settings as T

    cutoff = now - timedelta(hours=int(row["interval_hours"] or A.DEFAULT_INTERVAL)) + A.DUE_SLACK
    stmt = (
        update(T)
        .where(
            and_(
                T.c.account_key == row["account_key"],
                T.c.province == row["province"],
                T.c.enabled.is_(True),
                or_(T.c.last_check_at.is_(None), T.c.last_check_at <= cutoff),
            )
        )
        .values(last_check_at=now)
        .returning(T.c.account_key)
    )
    return (await database.fetch_one(stmt)) is not None


async def _finish(row: dict, *, status: str, error: Optional[str] = None, sent_at: Optional[datetime] = None) -> None:
    from sqlalchemy import and_, update

    from app.db import database, province_alert_settings as T

    values: dict[str, Any] = {"last_status": status[:500], "last_error": (error or None) and error[:500]}
    if sent_at:
        values["last_sent_at"] = sent_at
    await database.execute(
        update(T)
        .where(and_(T.c.account_key == row["account_key"], T.c.province == row["province"]))
        .values(**values)
    )


async def check_one(row: dict, snapshots: dict[str, Snapshot], now: datetime) -> None:
    """Jedno sprawdzenie jednego konta w jednym okręgu (po zajęciu zamka)."""
    from sqlalchemy import and_, delete, select
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import database, province_alert_state as S
    from app.province_settlement_sync import module_enabled
    from app.settlement_province import display

    key = row["province"]
    account = row["account_key"]
    reason = await _refusal(
        {"sub": row.get("login"), "judge_id": row.get("judge_id"), "account_type": row.get("account_type")},
        key,
    )
    if reason:
        await _finish(row, status="Wstrzymane - konto straciło dostęp do Rozliczeń.", error=reason)
        return
    if not await module_enabled(key, "settlements"):
        await _finish(row, status="Wstrzymane - moduł Rozliczeń jest w tym okręgu wyłączony.")
        return
    emails = _emails(row.get("emails"))
    if not emails:
        await _finish(row, status="Wstrzymane - brak adresów e-mail.")
        return

    if key not in snapshots:
        snapshots[key] = await _snapshot(key, _season())
    snapshot = snapshots[key]
    threshold = float(row.get("threshold") or A.DEFAULT_THRESHOLD)

    alerted_rows = await database.fetch_all(
        select(S.c.budget_id).where(and_(S.c.account_key == account, S.c.province == key))
    )
    decision = A.decide(snapshot.budgets, [r["budget_id"] for r in alerted_rows], threshold)
    if decision.rearm:
        await database.execute(
            delete(S).where(
                and_(S.c.account_key == account, S.c.province == key, S.c.budget_id.in_(decision.rearm))
            )
        )
    watched = len(A.watched_budgets(snapshot.budgets))
    if not decision.alert:
        quiet = len(decision.still_below)
        tail = (
            f", {quiet} nadal poniżej progu (mail już poszedł)" if quiet else ", wszystkie powyżej progu"
        )
        await _finish(row, status=f"Sprawdzono {watched} {A.plural(watched, 'klub', 'kluby', 'klubów')}{tail}.")
        return

    today = _today()
    cards = sorted(
        (_card(snapshot, item, today) for item in decision.alert),
        key=lambda card: card.balance,
    )
    subject, html_body, text_body = build_message(
        province_key=key,
        province_display=display(key),
        threshold=threshold,
        cards=cards,
        account_label=_account_label(row),
    )
    try:
        await send_alert_email(emails, subject, html_body, text_body)
    except EmailDeliveryError as exc:
        # Stanu NIE zapisujemy - przy następnym sprawdzeniu spróbujemy znowu.
        await _finish(row, status="Nie udało się wysłać alertu.", error=delivery_message(exc))
        return

    for card in cards:
        stmt = pg_insert(S).values(
            account_key=account,
            province=key,
            budget_id=card.budget_id,
            alerted_at=now,
            balance=card.balance,
            threshold=threshold,
        )
        await database.execute(
            stmt.on_conflict_do_update(
                index_elements=[S.c.account_key, S.c.province, S.c.budget_id],
                set_={"alerted_at": now, "balance": card.balance, "threshold": threshold},
            )
        )
    count = len(cards)
    await _finish(
        row,
        status=f"Wysłano alert: {count} {A.plural(count, 'klub', 'kluby', 'klubów')} poniżej progu.",
        sent_at=now,
    )


async def sweep() -> int:
    """Jeden obrót pętli. Zwraca liczbę wykonanych sprawdzeń."""
    from sqlalchemy import select

    from app.db import database, province_alert_settings as T

    now = _now()
    rows = [dict(r) for r in await database.fetch_all(select(T).where(T.c.enabled.is_(True)))]
    snapshots: dict[str, Snapshot] = {}
    done = 0
    for row in rows:
        if not A.is_due(row.get("last_check_at"), int(row.get("interval_hours") or A.DEFAULT_INTERVAL), now):
            continue
        try:
            if not await _claim(row, now):
                continue
            await check_one(row, snapshots, now)
            done += 1
        except Exception as exc:  # noqa: BLE001 - jedno konto nie zatrzymuje reszty
            logger.exception("[alerts] %s %s", row.get("account_key"), row.get("province"))
            try:
                await _finish(row, status="Sprawdzenie nie powiodło się.", error=str(exc)[:300])
            except Exception:  # noqa: BLE001
                pass
    return done


async def run_alert_scheduler() -> None:
    await asyncio.sleep(120)  # niech serwer najpierw wstanie
    while True:
        try:
            await sweep()
        except Exception:  # noqa: BLE001
            logger.exception("[alerts] pętla alertów")
        await asyncio.sleep(SWEEP_EVERY_SECONDS)


_task: Optional[asyncio.Task] = None


def start_alert_scheduler() -> None:
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(run_alert_scheduler())


async def stop_alert_scheduler() -> None:
    global _task
    if _task is None:
        return
    _task.cancel()
    try:
        await _task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass
    _task = None
