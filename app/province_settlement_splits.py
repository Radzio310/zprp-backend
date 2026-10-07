"""
Podział puli sędziego na części - warstwa HTTP i most do rozliczeń.

Cała reguła (kto na której części, suma do grosza, podatek każdej części
osobno, różnica wobec rachunku bez podziału) siedzi w liściu
`settlement_split_rules`; tutaj tylko baza.

OD 06.10.2026 (zgłoszenie Wojtka Kaszni) podział NIE wydaje własnych list
z numerami. Dzieli pulę na części A, B, ... i tyle - numer dostaje dopiero
dokument zbiorczy (Zestawienie), na który człowiek bierze wybrane części
wybranych sędziów (np. same 300 zł z puli 388 zł). Rejestr oficjalnych
dokumentów pilnuje, żeby ta sama część nie trafiła na dwa oficjalne dokumenty
(`settlement_register_rules`).

GDZIE TO WCHODZI - dwa mosty:
  - `apply_splits` - wołane w `province_settlements.load_settlement`: sędzia
    z ZAPISANYM i aktualnym podziałem ma w rozliczeniu koszty, podatek
    i netto jako sumę części, a w `split.parts` kwoty każdej części (z nich
    Zestawienie składa wiersze). Tym samym rachunkiem liczą się `/judge/{id}`,
    `/judges`, `/me` (aplikacja sędziego) i PDF zestawienia,
  - `split_month_deltas` - poprawka siatki miesięcy (`/months`), żeby kafel
    miesiąca mówił to samo co ekran po kliknięciu.

OKRES: podział należy do miesiąca kalendarzowego (`period_id` pusty) albo do
własnego okresu wypłat okręgu (`province_settlement_periods`). Podział
z miesiąca nie przechodzi na okres i odwrotnie.

CYKL ŻYCIA: zapisany (obowiązuje, gdy jest kompletny) -> zablokowany, gdy
którakolwiek część albo cała pula sędziego stoi na OFICJALNYM dokumencie
w rejestrze. Żeby go zmienić, trzeba usunąć tamten dokument z rejestru.

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
from sqlalchemy import and_, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_cache as SC
from app import settlement_engine as E
from app import settlement_split_rules as S
from app.db import database, province_settlement_splits
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


def _pid(period_id: Optional[str]) -> str:
    """Klucz okresu w tabeli - pusty napis = miesiąc kalendarzowy."""
    return _s(period_id).lower()


async def _row(
    key: str, year: int, month: int, judge_id: str, period_id: Optional[str] = None
) -> Optional[dict]:
    rows = await database.fetch_all(
        select(T).where(
            and_(
                T.c.province.in_(spellings(key)),
                T.c.period_year == int(year),
                T.c.period_month == int(month),
                T.c.period_id == _pid(period_id),
                T.c.judge_id == str(judge_id),
            )
        )
    )
    return _pick(list(rows), key)


async def _rows_of_month(
    key: str, year: int, month: int, period_id: Optional[str] = None
) -> dict[str, dict]:
    rows = await database.fetch_all(
        select(T).where(
            and_(
                T.c.province.in_(spellings(key)),
                T.c.period_year == int(year),
                T.c.period_month == int(month),
                T.c.period_id == _pid(period_id),
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
                # „zprp-table" = kilometry z ogólnopolskiej tabeli ZPRP (znacznik na liście).
                "distance_source": match.distance_source,
                "future": match.future,
                "tournament_key": match.tournament_key,
                "rate_shared": match.rate_shared,
            }
        )
    return out


def _state_of(row: dict, matches: list[dict]) -> tuple[list[dict], dict]:
    """Listy zapisanego podziału i to, czy zgadzają się z dzisiejszą pulą."""
    lists = S.normalize_lists(_json(row.get("lists_json"), []))
    return lists, S.split_state(lists, matches)


# ---------------------------------------------------------------------------
# Mosty do rozliczeń
# ---------------------------------------------------------------------------

async def apply_splits(
    key: str,
    year: int,
    month: int,
    entries: list[E.JudgeSettlement],
    period_id: Optional[str] = None,
) -> None:
    """
    Dokłada podział do wierszy miesiąca albo okresu (w miejscu - wołane
    przed pamięcią).

    Tylko kompletny i aktualny podział zmienia kwoty; podział niekompletny
    (np. doszedł mecz spoza części) dostaje sam znacznik z powodem, a kwoty
    zostają z rachunku bez podziału.
    """
    if not entries:
        return
    try:
        rows = await _rows_of_month(key, year, month, period_id)
    except Exception as exc:  # pragma: no cover - brak tabeli przed pierwszym startem
        logger.warning("[splits] %s %s/%s: odczyt podziałów: %s", key, month, year, exc)
        return
    for entry in entries:
        row = rows.get(entry.judge_id)
        if not row:
            continue
        lists, state = _state_of(row, pool_matches(entry))
        entry.split = S.list_badge(str(row["status"]), lists, [], state)
        if state["current"]:
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
    Ile zapisane podziały zmieniają sumy miesiąca (koszty, podatek, netto, razem).

    `assignments` - obsady tego samego płatnika, co w siatce (bez meczów
    płaconych przez klub), `common` - argumenty `settle_judges` bez dat.

    Tylko podziały MIESIĘCY: siatka liczy miesiące kalendarzowe, a lista
    z okresu wypłat (np. 07.09-04.10) nie przekłada się na jeden kafel.
    """
    query = select(T).where(
        and_(
            T.c.province.in_(spellings(key)),
            T.c.status != S.STATUS_VOID,
            T.c.period_id == "",
        )
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
        if not state["current"]:
            continue
        values = S.applied_values(state["calc"])
        slot = out.setdefault((year, month), {"costs": 0, "taxable": 0, "tax": 0, "net": 0.0, "total": 0.0})
        # money(): koszty i podstawa z obsad ZPRP maja grosze (`central_tax_parts`).
        slot["costs"] = money(slot["costs"] + values["costs"] - entry.costs)
        slot["taxable"] = money(slot["taxable"] + values["taxable"] - entry.taxable)
        slot["tax"] += values["tax"] - entry.tax
        slot["net"] = money(slot["net"] + values["net"] - entry.net)
        slot["total"] = money(slot["total"] + values["total"] - entry.total)
    return out


# ---------------------------------------------------------------------------
# Rejestr oficjalnych dokumentów
# ---------------------------------------------------------------------------

async def _documents_of(key: str, year: int, month: int, judge_id: str, period_id: Optional[str]) -> dict[str, str]:
    """Części tego sędziego na oficjalnych zestawieniach okresu: {część: numer}."""
    from app.province_settlement_register import period_taken
    from app import settlement_register_rules as G

    taken = await period_taken(key, G.ZESTAWIENIE, year, month, _pid(period_id))
    return G.judge_view(taken).get(str(judge_id), {})


def _locked_message(documents: dict[str, str]) -> str:
    numbers = sorted(set(documents.values()))
    return (
        f"Pula tego sędziego jest już na oficjalnym dokumencie {', '.join(numbers)} - "
        "żeby zmienić podział, najpierw usuń tamten dokument z Rejestru dokumentów."
    )


# ---------------------------------------------------------------------------
# Treść odpowiedzi
# ---------------------------------------------------------------------------

async def _month_entry(
    key: str,
    judge_id: str,
    year: int,
    month: int,
    include_future: bool,
    include_zprp: bool,
    period_id: Optional[str] = None,
) -> tuple[dict, Optional[E.JudgeSettlement]]:
    from app.province_settlements import cached_settlement

    data = await cached_settlement(
        key,
        year=year,
        month=month,
        include_future=include_future,
        include_zprp=include_zprp,
        period_id=_pid(period_id) or None,
    )
    entry = next((e for e in data["entries"] if e.judge_id == judge_id), None)
    return data, entry


async def _period(key: str, year: int, month: int, period_id: Optional[str]) -> dict:
    """
    Zakres i podpis podziału: miesiąc kalendarzowy albo własny okres wypłat
    (podpis jak na Zestawieniu okresu - same daty).
    """
    from app.province_settlements import settlement_range

    pid = _pid(period_id)
    date_from, date_to, _item = await settlement_range(key, year, month, pid or None)
    label = (
        f"{date_from.strftime('%d.%m.%Y')} - {date_to.strftime('%d.%m.%Y')}"
        if pid
        else f"{MONTHS_PL[month]} {year}"
    )
    return {
        "year": year,
        "month": month,
        "id": pid or None,
        "from": date_from.isoformat(),
        "to": date_to.isoformat(),
        "label": label,
    }


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
    period_id: Optional[str] = None,
) -> dict:
    period = await _period(key, year, month, period_id)
    row = await _row(key, year, month, judge_id, period_id)
    _, entry = await _month_entry(
        key, judge_id, year, month, include_future, include_zprp, period_id
    )
    matches = pool_matches(entry)
    keys = [m["match_key"] for m in matches]

    notes: list[str] = []
    suggested = False
    if row and row.get("status") != S.STATUS_VOID:
        lists, notes = S.reconcile(_json(row.get("lists_json"), []), keys)
        # Ten sam rachunek co rozliczenie (`split_state`): część na minusie po
        # zniknięciu meczów pokrywają przesunięcia innych części.
        notes.extend(S.cover_negative(lists, matches))
    else:
        lists = S.default_lists(keys, 2)
        suggested = True

    calc = S.compute(lists, matches)
    documents = await _documents_of(key, year, month, judge_id, period_id)
    split = None
    if row and row.get("status") != S.STATUS_VOID:
        state = S.split_state(S.normalize_lists(_json(row.get("lists_json"), [])), matches)
        split = {
            "status": row["status"],
            "rev": int(row.get("rev") or 0),
            "lists": lists,
            "updated_at": _iso(row.get("updated_at")),
            "updated_by": row.get("updated_by"),
            "include_future": bool(row.get("include_future")),
            "include_zprp": bool(row.get("include_zprp")),
            "current": state["current"],
            "reasons": state["reasons"],
        }
    return {
        "province": key,
        "judge_id": judge_id,
        "name": await _judge_name(key, judge_id, entry),
        "period": period,
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
            f"Sędzia nie ma w {'tym okresie' if period['id'] else 'tym miesiącu'} meczów "
            "rozliczanych przez okręg - nie ma czego dzielić."
        ],
        "notes": notes,
        "max_lists": S.MAX_LISTS,
        #: Części na oficjalnych zestawieniach okresu ({część: numer}, „" = cała
        #: pula). Niepuste = podział zablokowany.
        "documents": documents,
        "locked": bool(documents),
        "locked_message": _locked_message(documents) if documents else None,
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
    #: Własny okres wypłat (`province_settlement_periods`); brak = miesiąc.
    period_id: Optional[str] = None
    include_future: bool = False
    include_zprp: bool = False
    #: [{letter?, match_keys[], manual_shift}] - litery nadaje serwer po kolei.
    lists: list[dict] = []
    #: Wersja, na której pracował klient (`split.rev`); brak = nowy podział.
    rev: Optional[int] = None
    user: Optional[str] = None


@router.get("", summary="Podział puli sędziego na listy - stan i rachunek")
async def get_split(
    province: str = Query(...),
    judge_id: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    period_id: Optional[str] = Query(None),
    include_future: bool = Query(False),
    include_zprp: bool = Query(False),
):
    key = _require(province)
    await _require_module(key)
    _check_period(year, month)
    return await _payload(
        key, str(judge_id).strip(), year, month,
        include_future=include_future, include_zprp=include_zprp, period_id=period_id,
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
            period_id=_pid(body.period_id),
            judge_id=body.judge_id,
            **values,
        )
        .on_conflict_do_update(index_elements=KEY_COLUMNS, set_=values)
    )


#: Unikalny klucz podziału (`ux_province_settlement_splits_period_key`).
KEY_COLUMNS = [T.c.province, T.c.period_year, T.c.period_month, T.c.period_id, T.c.judge_id]


def _structural(lists: list[dict]) -> None:
    """Czego nie da się zapisać nawet jako szkicu - reszta idzie jako uwagi."""
    if not lists:
        raise HTTPException(400, "Podział musi mieć co najmniej jedną listę.")
    if len(lists) > S.MAX_LISTS:
        raise HTTPException(400, f"Najwięcej {S.MAX_LISTS} list w podziale - jest {len(lists)}.")


@router.put("", summary="Zapisz podział")
async def save_split(body: SplitBody):
    key = _require(body.province)
    await _require_module(key)
    _check_period(body.year, body.month)
    body.judge_id = str(body.judge_id).strip()
    row = await _row(key, body.year, body.month, body.judge_id, body.period_id)
    documents = await _documents_of(key, body.year, body.month, body.judge_id, body.period_id)
    if documents:
        raise HTTPException(409, _locked_message(documents))
    _check_rev(row, body.rev)
    lists = S.normalize_lists(body.lists)
    _structural(lists)
    await _save_draft(key, body, lists, row)
    SC.bump(key, base=False, reason="podział na części: zapis")
    return await _payload(
        key, body.judge_id, body.year, body.month,
        include_future=body.include_future, include_zprp=body.include_zprp,
        period_id=body.period_id,
    )


@router.delete("", summary="Zrezygnuj z podziału")
async def discard_split(
    province: str = Query(...),
    judge_id: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    period_id: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
):
    key = _require(province)
    await _require_module(key)
    _check_period(year, month)
    judge_id = str(judge_id).strip()
    row = await _row(key, year, month, judge_id, period_id)
    if row is None or row.get("status") == S.STATUS_VOID:
        return {"ok": True, "message": "Ten sędzia nie ma podziału - rozliczenie idzie jednym rachunkiem."}
    documents = await _documents_of(key, year, month, judge_id, period_id)
    if documents:
        raise HTTPException(409, _locked_message(documents))
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
    SC.bump(key, base=False, reason="podział na części: rezygnacja")
    return {"ok": True, "message": "Podział usunięty - sędzia rozlicza się jednym rachunkiem."}
