"""
Podział puli sędziego na listy sędziowskie - warstwa HTTP i most do rozliczeń.

Cała reguła (kto na której liście, suma do grosza, podatek każdej listy
osobno, różnica wobec rachunku bez podziału) siedzi w liściu
`settlement_split_rules`; tutaj tylko baza, numeracja w księdze dokumentów
i PDF-y.

GDZIE TO WCHODZI - dwa mosty:
  - `apply_splits` - wołane w `province_settlements.load_settlement`: sędzia
    z WYDANYMI i aktualnymi listami ma w zestawieniu koszty, podatek i netto
    jako sumę list. Tym samym rachunkiem liczą się `/judge/{id}`, `/judges`,
    `/me` (aplikacja sędziego) i PDF zestawienia,
  - `split_month_deltas` - poprawka siatki miesięcy (`/months`), żeby kafel
    miesiąca mówił to samo co ekran po kliknięciu.

CYKL ŻYCIA: szkic (edytowalny) -> wydane (numery w księdze, zamknięte) ->
odblokowanie (numery zostają w księdze jako „anulowana", podział wraca do
szkicu) -> ponowne wydanie z NOWYMI numerami. Numer nigdy nie wraca do puli.

Zapis przechodzi przez tę samą bramkę co reszta Rozliczeń (konto VIP
z uprawnieniem „Rozliczenia") - patrz `province_panel_guard`.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_cache as SC
from app import settlement_engine as E
from app import settlement_split_rules as S
from app.db import database, province_settlement_documents, province_settlement_splits
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate
from app.settlement_money import money
from app.settlement_province import spellings

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/settlements/splits",
    tags=["province_settlements"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Podział puli sędziego na listy"))],
)

T = province_settlement_splits

MONTHS_PL = (
    "", "styczeń", "luty", "marzec", "kwiecień", "maj", "czerwiec",
    "lipiec", "sierpień", "wrzesień", "październik", "listopad", "grudzień",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _json(raw: Any, fallback: Any) -> Any:
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except ValueError:
            return fallback
    return fallback


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if value else None


# ---------------------------------------------------------------------------
# Odczyt z bazy
# ---------------------------------------------------------------------------

def _pick(rows: list, key: str) -> Optional[dict]:
    """
    Wiersz pod kanonicznym kluczem okręgu, a gdy go nie ma - pod starą
    pisownią (ŚLĄSKIE/SLASKIE). Dwa wiersze tego samego sędziego nie mogą
    mówić dwóch rzeczy - wygrywa kanoniczny.
    """
    if not rows:
        return None
    rows = [dict(r) for r in rows]
    return next((r for r in rows if r["province"] == key), rows[0])


async def _row(key: str, year: int, month: int, judge_id: str) -> Optional[dict]:
    rows = await database.fetch_all(
        select(T).where(
            and_(
                T.c.province.in_(spellings(key)),
                T.c.period_year == int(year),
                T.c.period_month == int(month),
                T.c.judge_id == str(judge_id),
            )
        )
    )
    return _pick(list(rows), key)


async def _rows_of_month(key: str, year: int, month: int) -> dict[str, dict]:
    rows = await database.fetch_all(
        select(T).where(
            and_(
                T.c.province.in_(spellings(key)),
                T.c.period_year == int(year),
                T.c.period_month == int(month),
                T.c.status != S.STATUS_VOID,
            )
        )
    )
    by_judge: dict[str, list] = {}
    for row in rows:
        by_judge.setdefault(str(row["judge_id"]), []).append(row)
    return {judge: _pick(items, key) for judge, items in by_judge.items()}


def pool_matches(entry: Optional[E.JudgeSettlement]) -> list[dict]:
    """Mecze puli sędziego w kształcie, który rozumie reguła i ekran."""
    if entry is None:
        return []
    out = []
    for match in entry.matches:
        out.append(
            {
                "match_key": match.match_key,
                "match_at": _iso(match.match_at),
                "day": match.day.isoformat() if match.day else None,
                "code": match.match_code,
                "category": match.category,
                "role": match.role + (" x3" if match.triple_table else ""),
                "city": match.city,
                "home_city": match.home_city,
                "teams": match.teams,
                "gross": match.gross,
                "travel": match.travel,
                "travel_shared": match.travel_shared,
                "future": match.future,
                "tournament_key": match.tournament_key,
                "rate_shared": match.rate_shared,
            }
        )
    return out


def _state_of(row: dict, matches: list[dict]) -> tuple[list[dict], Optional[dict]]:
    lists = S.normalize_lists(_json(row.get("lists_json"), []))
    if row.get("status") != S.STATUS_ISSUED:
        return lists, None
    snapshot = _json(row.get("snapshot_json"), {})
    return lists, S.issued_state(snapshot.get("lists") or [], lists, matches)


# ---------------------------------------------------------------------------
# Mosty do rozliczeń
# ---------------------------------------------------------------------------

async def apply_splits(
    key: str, year: int, month: int, entries: list[E.JudgeSettlement]
) -> None:
    """
    Dokłada podział do wierszy miesiąca (w miejscu - wołane przed pamięcią).

    Tylko WYDANE i aktualne listy zmieniają kwoty; szkic i listy nieaktualne
    dostają sam znacznik z powodem, a kwoty zostają z rachunku bez podziału.
    """
    if not entries:
        return
    try:
        rows = await _rows_of_month(key, year, month)
    except Exception as exc:  # pragma: no cover - brak tabeli przed pierwszym startem
        logger.warning("[splits] %s %s/%s: odczyt podziałów: %s", key, month, year, exc)
        return
    for entry in entries:
        row = rows.get(entry.judge_id)
        if not row:
            continue
        lists, state = _state_of(row, pool_matches(entry))
        numbers = [str(n) for n in _json(row.get("numbers_json"), [])]
        entry.split = S.list_badge(str(row["status"]), lists, numbers, state)
        if state and state["current"]:
            values = S.applied_values(state["calc"])
            entry.costs = values["costs"]
            entry.taxable = values["taxable"]
            entry.tax = values["tax"]
            entry.net = values["net"]
            entry.total = values["total"]


async def split_month_deltas(
    key: str,
    *,
    assignments: list,
    common: dict,
    judge_id: Optional[str] = None,
) -> dict[tuple[int, int], dict[str, float]]:
    """
    Ile wydane listy zmieniają sumy miesiąca (koszty, podatek, netto, razem).

    `assignments` - obsady tego samego płatnika, co w siatce (bez meczów
    płaconych przez klub), `common` - argumenty `settle_judges` bez dat.
    """
    query = select(T).where(
        and_(T.c.province.in_(spellings(key)), T.c.status == S.STATUS_ISSUED)
    )
    if judge_id:
        query = query.where(T.c.judge_id == str(judge_id))
    try:
        rows = [dict(r) for r in await database.fetch_all(query)]
    except Exception as exc:  # pragma: no cover
        logger.warning("[splits] %s: odczyt podziałów do siatki: %s", key, exc)
        return {}
    out: dict[tuple[int, int], dict[str, float]] = {}
    import calendar

    for row in rows:
        year, month = int(row["period_year"]), int(row["period_month"])
        judge = str(row["judge_id"])
        entries = E.settle_judges(
            [a for a in assignments if a.judge_id == judge],
            date_from=date(year, month, 1),
            date_to=date(year, month, calendar.monthrange(year, month)[1]),
            **common,
        )
        entry = next((e for e in entries if e.judge_id == judge), None)
        if entry is None:
            continue
        _, state = _state_of(row, pool_matches(entry))
        if not state or not state["current"]:
            continue
        values = S.applied_values(state["calc"])
        slot = out.setdefault((year, month), {"costs": 0, "taxable": 0, "tax": 0, "net": 0.0, "total": 0.0})
        slot["costs"] += values["costs"] - entry.costs
        slot["taxable"] += values["taxable"] - entry.taxable
        slot["tax"] += values["tax"] - entry.tax
        slot["net"] = money(slot["net"] + values["net"] - entry.net)
        slot["total"] = money(slot["total"] + values["total"] - entry.total)
    return out


# ---------------------------------------------------------------------------
# Numeracja
# ---------------------------------------------------------------------------

async def _next_seq(key: str, year: int, month: int) -> int:
    row = await database.fetch_one(
        select(province_settlement_documents.c.seq)
        .where(province_settlement_documents.c.province == key)
        .where(province_settlement_documents.c.kind == S.DOCUMENT_KIND)
        .where(province_settlement_documents.c.period_year == year)
        .where(province_settlement_documents.c.period_month == month)
        .order_by(province_settlement_documents.c.seq.desc())
        .limit(1)
    )
    return int(row["seq"]) + 1 if row else 1


def _number(key: str, year: int, month: int, seq: int) -> str:
    # Własny wyróżnik „LS" (decyzja 25.09.2026): listy mają osobny licznik,
    # więc bez niego pierwsza lista miesiąca nosiłaby numer Zestawienia.
    return f"LS/{month:02d}/{year}/{seq}"


async def _peek_numbers(key: str, year: int, month: int, count: int) -> list[str]:
    """Numery, które PADNĄ przy wydaniu - bez rezerwacji."""
    start = await _next_seq(key, year, month)
    return [_number(key, year, month, start + i) for i in range(max(0, count))]


# ---------------------------------------------------------------------------
# Treść odpowiedzi
# ---------------------------------------------------------------------------

async def _month_entry(
    key: str, judge_id: str, year: int, month: int, include_future: bool, include_zprp: bool
) -> tuple[dict, Optional[E.JudgeSettlement]]:
    from app.province_settlements import cached_settlement

    data = await cached_settlement(
        key, year=year, month=month, include_future=include_future, include_zprp=include_zprp
    )
    entry = next((e for e in data["entries"] if e.judge_id == judge_id), None)
    return data, entry


async def _judge_name(key: str, judge_id: str, entry: Optional[E.JudgeSettlement]) -> str:
    if entry is not None and entry.judge_name:
        return E.display_judge_name(entry.judge_name)
    from app.province_settlements import _base

    names = (await _base(key))["names"]
    return E.display_judge_name(names.get(judge_id, "")) or judge_id


async def _payload(
    key: str,
    judge_id: str,
    year: int,
    month: int,
    *,
    include_future: bool,
    include_zprp: bool,
    row: Optional[dict] = None,
    fetched: bool = False,
) -> dict:
    if not fetched:
        row = await _row(key, year, month, judge_id)
    issued = bool(row and row.get("status") == S.STATUS_ISSUED)
    if issued:
        # Wydane listy oglądamy z przełącznikami, z którymi je wydano.
        include_future = bool(row.get("include_future"))
        include_zprp = bool(row.get("include_zprp"))
    _, entry = await _month_entry(key, judge_id, year, month, include_future, include_zprp)
    matches = pool_matches(entry)
    keys = [m["match_key"] for m in matches]

    notes: list[str] = []
    state = None
    suggested = False
    if row and row.get("status") != S.STATUS_VOID:
        if issued:
            lists, state = _state_of(row, matches)
        else:
            lists, notes = S.reconcile(_json(row.get("lists_json"), []), keys)
    else:
        lists = S.default_lists(keys, 2)
        suggested = True

    calc = state["calc"] if state else S.compute(lists, matches)
    numbers = [str(n) for n in _json(row.get("numbers_json"), [])] if row else []
    voided = _json(row.get("voided_json"), []) if row else []
    split = None
    if row and row.get("status") != S.STATUS_VOID:
        split = {
            "status": row["status"],
            "rev": int(row.get("rev") or 0),
            "lists": lists,
            "numbers": numbers,
            "numbers_label": S.numbers_label(numbers),
            "issued_at": _iso(row.get("issued_at")),
            "issued_by": row.get("issued_by"),
            "updated_at": _iso(row.get("updated_at")),
            "updated_by": row.get("updated_by"),
            "include_future": bool(row.get("include_future")),
            "include_zprp": bool(row.get("include_zprp")),
            "current": state["current"] if state else None,
            "reasons": state["reasons"] if state else [],
        }
    return {
        "province": key,
        "judge_id": judge_id,
        "name": await _judge_name(key, judge_id, entry),
        "period": {"year": year, "month": month, "label": f"{MONTHS_PL[month]} {year}"},
        "include_future": include_future,
        "include_zprp": include_zprp,
        "pool": {
            "gross": calc["pool"]["gross"],
            "travel": calc["pool"]["travel"],
            "matches": matches,
        },
        "split": split,
        "lists": lists,
        "suggested": suggested,
        "calc": calc,
        "problems": S.problems(lists, matches, for_issue=True) if matches else [
            "Sędzia nie ma w tym miesiącu meczów rozliczanych przez okręg - nie ma czego dzielić."
        ],
        "notes": notes,
        "voided": voided,
        "max_lists": S.MAX_LISTS,
        "next_numbers": [] if issued else await _peek_numbers(key, year, month, len(lists)),
    }


def _require(province: str) -> str:
    from app.province_settlements import month_range, require_province  # noqa: F401

    return require_province(province)


async def _require_module(key: str) -> None:
    from app.province_settlement_sync import module_enabled

    if not await module_enabled(key, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")


def _check_period(year: int, month: int) -> None:
    from app.province_settlements import month_range

    month_range(year, month)


def _check_rev(row: Optional[dict], rev: Optional[int]) -> None:
    if row is None or rev is None:
        return
    current = int(row.get("rev") or 0)
    if current != int(rev):
        who = row.get("updated_by") or "ktoś inny"
        raise HTTPException(
            409,
            f"Ten podział zmienił w międzyczasie {who} (wersja {current}, Twoja {rev}). "
            "Zamknij okno i otwórz je ponownie, żeby zobaczyć jego zmiany.",
        )


# ---------------------------------------------------------------------------
# Trasy - same literalne ścieżki (bez parametrów w adresie)
# ---------------------------------------------------------------------------

class SplitBody(BaseModel):
    province: str
    judge_id: str
    year: int
    month: int
    include_future: bool = False
    include_zprp: bool = False
    #: [{letter?, match_keys[], manual_shift}] - litery nadaje serwer po kolei.
    lists: list[dict] = []
    #: Wersja, na której pracował klient (`split.rev`); brak = nowy podział.
    rev: Optional[int] = None
    user: Optional[str] = None


class UnlockBody(BaseModel):
    province: str
    judge_id: str
    year: int
    month: int
    rev: Optional[int] = None
    reason: Optional[str] = None
    user: Optional[str] = None


class ReprintBody(BaseModel):
    province: str
    judge_id: str
    year: int
    month: int
    user: Optional[str] = None


@router.get("", summary="Podział puli sędziego na listy - stan i rachunek")
async def get_split(
    province: str = Query(...),
    judge_id: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    include_future: bool = Query(False),
    include_zprp: bool = Query(False),
):
    key = _require(province)
    await _require_module(key)
    _check_period(year, month)
    return await _payload(
        key, str(judge_id).strip(), year, month,
        include_future=include_future, include_zprp=include_zprp,
    )


async def _save_draft(key: str, body: SplitBody, lists: list[dict], row: Optional[dict]) -> None:
    values = {
        "status": S.STATUS_DRAFT,
        "rev": int((row or {}).get("rev") or 0) + 1,
        "lists_json": _dump(lists),
        "include_future": body.include_future,
        "include_zprp": body.include_zprp,
        "updated_by": body.user,
        "updated_at": _now(),
    }
    if row is not None:
        await database.execute(update(T).where(T.c.id == row["id"]).values(province=key, **values))
        return
    await database.execute(
        pg_insert(T)
        .values(
            province=key,
            period_year=body.year,
            period_month=body.month,
            judge_id=body.judge_id,
            **values,
        )
        .on_conflict_do_update(
            index_elements=[T.c.province, T.c.period_year, T.c.period_month, T.c.judge_id],
            set_=values,
        )
    )


def _structural(lists: list[dict]) -> None:
    """Czego nie da się zapisać nawet jako szkicu - reszta idzie jako uwagi."""
    if not lists:
        raise HTTPException(400, "Podział musi mieć co najmniej jedną listę.")
    if len(lists) > S.MAX_LISTS:
        raise HTTPException(400, f"Najwięcej {S.MAX_LISTS} list w podziale - jest {len(lists)}.")


@router.put("", summary="Zapisz szkic podziału")
async def save_split(body: SplitBody):
    key = _require(body.province)
    await _require_module(key)
    _check_period(body.year, body.month)
    body.judge_id = str(body.judge_id).strip()
    row = await _row(key, body.year, body.month, body.judge_id)
    if row and row.get("status") == S.STATUS_ISSUED:
        raise HTTPException(
            409,
            f"Listy {S.numbers_label(_json(row.get('numbers_json'), []))} są już wydane - "
            "żeby zmienić podział, najpierw go odblokuj.",
        )
    _check_rev(row, body.rev)
    lists = S.normalize_lists(body.lists)
    _structural(lists)
    await _save_draft(key, body, lists, row)
    SC.bump(key, base=False, reason="podział na listy: szkic")
    return await _payload(
        key, body.judge_id, body.year, body.month,
        include_future=body.include_future, include_zprp=body.include_zprp,
    )


@router.delete("", summary="Zrezygnuj z podziału (tylko szkic)")
async def discard_split(
    province: str = Query(...),
    judge_id: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    user: Optional[str] = Query(None),
):
    key = _require(province)
    await _require_module(key)
    _check_period(year, month)
    judge_id = str(judge_id).strip()
    row = await _row(key, year, month, judge_id)
    if row is None or row.get("status") == S.STATUS_VOID:
        return {"ok": True, "message": "Ten sędzia nie ma podziału - rozliczenie idzie jednym rachunkiem."}
    if row.get("status") == S.STATUS_ISSUED:
        raise HTTPException(
            409,
            "Listy są wydane - najpierw odblokuj podział (numery zostaną w księdze jako anulowane).",
        )
    if _json(row.get("voided_json"), []):
        # Historia unieważnionych numerów zostaje - wiersz tylko przestaje działać.
        await database.execute(
            update(T).where(T.c.id == row["id"]).values(
                status=S.STATUS_VOID, lists_json="[]", rev=int(row.get("rev") or 0) + 1,
                updated_by=user, updated_at=_now(),
            )
        )
    else:
        await database.execute(delete(T).where(T.c.id == row["id"]))
    SC.bump(key, base=False, reason="podział na listy: rezygnacja")
    return {"ok": True, "message": "Podział usunięty - sędzia rozlicza się jednym rachunkiem."}


@router.post("/issue", summary="Wydaj listy: numery w księdze + PDF-y")
async def issue_split(body: SplitBody):
    key = _require(body.province)
    await _require_module(key)
    _check_period(body.year, body.month)
    body.judge_id = str(body.judge_id).strip()
    row = await _row(key, body.year, body.month, body.judge_id)
    if row and row.get("status") == S.STATUS_ISSUED:
        raise HTTPException(
            409,
            f"Listy {S.numbers_label(_json(row.get('numbers_json'), []))} są już wydane. "
            "Duplikat PDF pobierzesz przyciskiem „Pobierz ponownie”.",
        )
    _check_rev(row, body.rev)
    lists = S.normalize_lists(body.lists)
    _structural(lists)

    _, entry = await _month_entry(
        key, body.judge_id, body.year, body.month, body.include_future, body.include_zprp
    )
    matches = pool_matches(entry)
    if not matches:
        raise HTTPException(400, "Sędzia nie ma w tym miesiącu meczów rozliczanych przez okręg - nie ma czego dzielić.")
    bad = S.problems(lists, matches, for_issue=True)
    if bad:
        raise HTTPException(400, "Nie da się wydać list: " + " ".join(bad))
    calc = S.compute(lists, matches)
    name = await _judge_name(key, body.judge_id, entry)

    from app import province_settlement_pdf as P

    lock = f"settlement-lista:{key}:{body.year}:{body.month}"
    async with database.transaction():
        # Dwa wydania naraz w tym samym okręgu i miesiącu nie dostaną tego
        # samego numeru - drugie czeka na koniec pierwszego.
        await database.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))").bindparams(k=lock))
        start = await _next_seq(key, body.year, body.month)
        numbers = [_number(key, body.year, body.month, start + i) for i in range(len(lists))]
        snapshot = _snapshot(key, body, name, matches, calc, numbers)
        # PDF-y powstają PRZED zapisem numerów - nieudany wydruk cofa całą
        # transakcję i w księdze nie zostaje dziura.
        documents = _render_all(P, key, snapshot, reprint=False)
        doc_ids: list[int] = []
        for index, item in enumerate(calc["lists"]):
            doc_ids.append(
                await database.fetch_val(
                    insert(province_settlement_documents)
                    .values(
                        province=key,
                        kind=S.DOCUMENT_KIND,
                        period_year=body.year,
                        period_month=body.month,
                        seq=start + index,
                        number=numbers[index],
                        date_from=date(body.year, body.month, 1),
                        date_to=date.fromisoformat(snapshot["period"]["to"]),
                        include_future=body.include_future,
                        judge_ids=[body.judge_id],
                        totals_json={
                            "letter": item["letter"],
                            "part": index + 1,
                            "of": len(lists),
                            "gross": item["gross"],
                            "costs": item["costs"],
                            "taxable": item["taxable"],
                            "tax": item["tax"],
                            "net": item["net"],
                            "travel": item["travel"],
                            "matches": item["match_count"],
                            "include_zprp": body.include_zprp,
                        },
                        created_by=body.user,
                    )
                    .returning(province_settlement_documents.c.id)
                )
            )
        values = {
            "status": S.STATUS_ISSUED,
            "rev": int((row or {}).get("rev") or 0) + 1,
            "lists_json": _dump(lists),
            "include_future": body.include_future,
            "include_zprp": body.include_zprp,
            "numbers_json": _dump(numbers),
            "document_ids_json": _dump(doc_ids),
            "snapshot_json": _dump(snapshot),
            "issued_at": _now(),
            "issued_by": body.user,
            "updated_by": body.user,
            "updated_at": _now(),
        }
        if row is not None:
            await database.execute(update(T).where(T.c.id == row["id"]).values(province=key, **values))
        else:
            await database.execute(
                pg_insert(T)
                .values(province=key, period_year=body.year, period_month=body.month, judge_id=body.judge_id, **values)
                .on_conflict_do_update(
                    index_elements=[T.c.province, T.c.period_year, T.c.period_month, T.c.judge_id],
                    set_=values,
                )
            )
    SC.bump(key, base=False, reason="podział na listy: wydanie")
    payload = await _payload(
        key, body.judge_id, body.year, body.month,
        include_future=body.include_future, include_zprp=body.include_zprp,
    )
    return {**payload, "documents": documents}


@router.post("/reprint", summary="Duplikat PDF wydanych list (te same numery)")
async def reprint_split(body: ReprintBody):
    key = _require(body.province)
    await _require_module(key)
    _check_period(body.year, body.month)
    row = await _row(key, body.year, body.month, str(body.judge_id).strip())
    if not row or row.get("status") != S.STATUS_ISSUED:
        raise HTTPException(409, "Listy tego sędziego nie są wydane - nie ma czego drukować ponownie.")
    snapshot = _json(row.get("snapshot_json"), {})
    if not snapshot.get("lists"):
        raise HTTPException(409, "Brak migawki wydanych list - odblokuj podział i wydaj listy ponownie.")
    from app import province_settlement_pdf as P

    return {"ok": True, "documents": _render_all(P, key, snapshot, reprint=True)}


@router.post("/unlock", summary="Odblokuj podział - wydane numery zostają jako anulowane")
async def unlock_split(body: UnlockBody):
    key = _require(body.province)
    await _require_module(key)
    _check_period(body.year, body.month)
    body.judge_id = str(body.judge_id).strip()
    row = await _row(key, body.year, body.month, body.judge_id)
    if not row or row.get("status") != S.STATUS_ISSUED:
        raise HTTPException(409, "Podział nie jest wydany - nie ma czego odblokować.")
    _check_rev(row, body.rev)
    numbers = [str(n) for n in _json(row.get("numbers_json"), [])]
    doc_ids = [int(i) for i in _json(row.get("document_ids_json"), []) if str(i).isdigit()]
    voided = _json(row.get("voided_json"), [])
    voided.append(
        {
            "numbers": numbers,
            "label": S.numbers_label(numbers),
            "voided_at": _now().isoformat(),
            "voided_by": body.user,
            "reason": _s(body.reason) or None,
        }
    )
    async with database.transaction():
        if doc_ids:
            await database.execute(
                update(province_settlement_documents)
                .where(province_settlement_documents.c.id.in_(doc_ids))
                .values(status=S.DOCUMENT_VOID)
            )
        await database.execute(
            update(T).where(T.c.id == row["id"]).values(
                status=S.STATUS_DRAFT,
                rev=int(row.get("rev") or 0) + 1,
                numbers_json="[]",
                document_ids_json="[]",
                snapshot_json="{}",
                voided_json=_dump(voided),
                updated_by=body.user,
                updated_at=_now(),
            )
        )
    SC.bump(key, base=False, reason="podział na listy: odblokowanie")
    payload = await _payload(
        key, body.judge_id, body.year, body.month,
        include_future=bool(row.get("include_future")), include_zprp=bool(row.get("include_zprp")),
    )
    return {**payload, "message": f"Odblokowano. Numery {S.numbers_label(numbers)} zostają w księdze jako anulowane."}


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def _snapshot(
    key: str, body: SplitBody, name: str, matches: list[dict], calc: dict, numbers: list[str]
) -> dict:
    """Wszystko, z czego składa się wydruk - duplikat powstaje z tej migawki."""
    from app.province_settlements import month_range

    date_from, date_to = month_range(body.year, body.month)
    by_key = {m["match_key"]: m for m in matches}
    home = next((m["home_city"] for m in matches if m.get("home_city")), "")
    lists = []
    for index, item in enumerate(calc["lists"]):
        rows = [by_key[k] for k in item["match_keys"] if k in by_key]
        rows.sort(key=lambda m: (m.get("match_at") or "", m["match_key"]))
        lists.append({**item, "number": numbers[index], "matches": rows})
    return {
        "province": key,
        "judge_id": body.judge_id,
        "name": name,
        "home_city": home,
        "period": {
            "year": body.year,
            "month": body.month,
            "from": date_from.isoformat(),
            "to": date_to.isoformat(),
            "label": f"{MONTHS_PL[body.month]} {body.year}",
        },
        "include_future": body.include_future,
        "include_zprp": body.include_zprp,
        "numbers": numbers,
        "numbers_label": S.numbers_label(numbers),
        "pool": calc["pool"],
        "unsplit": calc["unsplit"],
        "split": calc["split"],
        "lists": lists,
        "issued_on": _now().strftime("%d.%m.%Y"),
    }


def _doc_context(snapshot: dict, index: int) -> dict:
    from app.settlement_words import amount_in_words

    item = snapshot["lists"][index]
    rows = []
    for lp, match in enumerate(item.get("matches") or [], start=1):
        day = _s(match.get("day"))
        rows.append(
            {
                "lp": lp,
                "day_label": f"{day[8:10]}.{day[5:7]}.{day[0:4]}" if len(day) >= 10 else "-",
                "code": match.get("code") or "",
                "category": match.get("category") or "",
                "role": match.get("role") or "",
                "city": match.get("city") or "",
                "teams": match.get("teams") or "",
                "gross": money(match.get("gross")),
                "travel": money(match.get("travel")),
                "travel_shared": bool(match.get("travel_shared")),
                "rate_shared": bool(match.get("rate_shared")),
            }
        )
    return {
        "number": item["number"],
        "letter": item["letter"],
        "part": index + 1,
        "parts": len(snapshot["lists"]),
        "rows": rows,
        "matches_gross": money(item.get("matches_gross")),
        "shift": money(item.get("manual_shift")),
        "gross": money(item.get("gross")),
        "costs": int(item.get("costs") or 0),
        "taxable": int(item.get("taxable") or 0),
        "tax": int(item.get("tax") or 0),
        "net": money(item.get("net")),
        "travel": money(item.get("travel")),
        "total": money(item.get("total")),
        "net_in_words": amount_in_words(item.get("net")),
        "costs_granted": money(item.get("gross")) > 200,
    }


def _render_all(P: Any, key: str, snapshot: dict, *, reprint: bool) -> dict:
    """Jeden plik ze wszystkimi listami (do pobrania) i plik na każdą listę."""
    org = P._org(key)
    base = {
        "logo": P._province_logo_b64(key),
        "org_name": org["name"],
        "org_address": org["address"],
        "judge_name": snapshot.get("name") or snapshot.get("judge_id"),
        "judge_id": snapshot.get("judge_id"),
        "home_city": snapshot.get("home_city") or "",
        "period_label": snapshot["period"]["label"],
        "issued_on": snapshot.get("issued_on"),
        "printed_on": _now().strftime("%d.%m.%Y"),
        "reprint": reprint,
        "numbers_label": snapshot.get("numbers_label"),
        "pool_gross": money(snapshot["pool"]["gross"]),
        "include_future": snapshot.get("include_future"),
    }
    docs = [_doc_context(snapshot, i) for i in range(len(snapshot["lists"]))]
    stem = f"listy_{S.numbers_label(snapshot['numbers']).replace('/', '_').replace(', ', '+')}"
    bundle = P._to_pdf(
        P._render("okreg_lista_sedziowska.html", {**base, "docs": docs}),
        "listy",
        f"{stem}.pdf",
    )
    parts = []
    for doc in docs:
        filename = f"lista_{doc['number'].replace('/', '_')}.pdf"
        result = P._to_pdf(
            P._render("okreg_lista_sedziowska.html", {**base, "docs": [doc]}), "lista", filename
        )
        parts.append({"letter": doc["letter"], "number": doc["number"], "filename": filename, **result})
    return {
        "bundle": {"filename": f"{stem}.pdf", "number": snapshot.get("numbers_label"), **bundle},
        "lists": parts,
    }
