"""
Rejestr oficjalnych dokumentów rozliczeń okręgu - warstwa HTTP i baza.

Reguła (numeracja ciągła w sezonie, zajętość części puli) w liściu
`settlement_register_rules`, schemat w `settlement_register_tables`. Samo
wydanie dokumentu robią trasy PDF (`province_settlement_pdf`) - tutaj jest
przegląd rejestru, ponowne pobranie, usunięcie (numer i pozycje wracają do
puli) i „kontynuacja numeracji" w ustawieniach.

Zapisy przez bramkę panelu Rozliczeń (`province_panel_guard`), jak podział.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_accounting_rules as A
from app import settlement_register_rules as G
from app.db import (
    database,
    province_settlement_doc_settings,
    province_settlement_register,
    province_settlement_register_settings,
)
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/settlements/register",
    tags=["province_settlements"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Rejestr dokumentów rozliczeń"))],
)

T = province_settlement_register
ST = province_settlement_register_settings
DS = province_settlement_doc_settings

#: Domyślny wygląd dokumentów (decyzje z 07.10.2026): liczba meczów UKRYTA,
#: podtytuł i okres widoczne, kara najpierw z listy A, nieobecności na A,
#: kluby rozliczające się same - ukryte (a włączone - na A).
DOC_DEFAULTS = {
    "show_matches": False,
    "show_subtitle": True,
    "period_display": "all",
    "penalty_list": "A",
    "absences_list": "A",
    "show_absences": True,
    "show_outside": False,
    "outside_list": "A",
}


def _letter(value: Any) -> str:
    text = _s(value).upper()
    return text if len(text) == 1 and text.isalpha() else "A"
PERIOD_DISPLAYS = ("all", "main_only", "none")


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


def dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _kind(kind: Any) -> str:
    value = _s(kind).lower()
    if value not in G.KINDS:
        raise HTTPException(400, f"Nieznany rodzaj dokumentu: {kind!r}")
    return value


def _require(province: str) -> str:
    from app.province_settlements import require_province

    return require_province(province)


def _short(key: str) -> str:
    from app.province_settlements import province_short

    return province_short(key)


# ---------------------------------------------------------------------------
# Odczyt - wołane także z tras PDF i podziału
# ---------------------------------------------------------------------------

def _doc_json(row: Any) -> dict:
    items = _json(row["items_json"], [])
    return {
        "id": row["id"],
        "kind": row["kind"],
        "number": row["number"],
        "number_year": row["number_year"],
        #: Wzór numeru (04.11.2026): sezonowy albo kalendarzowy.
        "number_scheme": _scheme_of_row(row),
        #: Sezon numeracji: „2026/27" (rok początku w `number_year`); przy
        #: wzorze kalendarzowym `number_year` to rok wydania.
        "season": row["number_year"],
        "season_label": G.season_label(row["number_year"]),
        "counter_label": G.counter_label(row["number_year"], _scheme_of_row(row)),
        "accounting": _json(_row_get(row, "accounting_json"), {}),
        "seq": row["seq"],
        "period": {
            "year": row["period_year"],
            "month": row["period_month"],
            "id": row["period_id"] or None,
            "label": row["period_label"],
            "from": row["date_from"].isoformat() if row["date_from"] else None,
            "to": row["date_to"].isoformat() if row["date_to"] else None,
        },
        "include_future": bool(row["include_future"]),
        "include_zprp": bool(row["include_zprp"]),
        "items": items,
        "judges": len({_s(i.get("judge_id")) for i in items}),
        "totals": _json(row["totals_json"], {}),
        "created_by": row["created_by"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }


async def period_documents(key: str, kind: str, year: int, month: int, period_id: str) -> list[dict]:
    """Oficjalne dokumenty jednego okresu i rodzaju."""
    rows = await database.fetch_all(
        select(T).where(
            and_(
                T.c.province == key,
                T.c.kind == kind,
                T.c.period_year == int(year),
                T.c.period_month == int(month),
                T.c.period_id == _s(period_id).lower(),
            )
        )
    )
    return [_doc_json(row) for row in rows]


async def period_taken(
    key: str, kind: str, year: int, month: int, period_id: str
) -> dict[tuple[str, str], str]:
    """(sędzia, część) -> numer - pozycje zajęte w okresie."""
    try:
        return G.taken_map(await period_documents(key, kind, year, month, period_id))
    except Exception as exc:  # pragma: no cover - brak tabeli przed pierwszym startem
        logger.warning("[register] %s %s %s/%s: odczyt rejestru: %s", key, kind, month, year, exc)
        return {}


async def season_of_period(key: str, year: int, month: int, period_id: Optional[str]) -> int:
    """Sezon numeracji dla okresu rozliczenia (rok początku sezonu)."""
    from app.province_settlements import settlement_range

    date_from, _date_to, item = await settlement_range(key, year, month, _s(period_id).lower() or None)
    return G.period_season(date_from, (item or {}).get("season")) or int(year)


def _row_get(row: Any, name: str) -> Any:
    try:
        return row[name]
    except (KeyError, IndexError):
        return None


def _scheme_of_row(row: Any) -> str:
    return A.scheme_of(_row_get(row, "number_scheme"))


def calendar_year() -> int:
    """Rok wydania w Polsce - licznik wzoru kalendarzowego („14/S/2026")."""
    from zoneinfo import ZoneInfo

    return datetime.now(ZoneInfo("Europe/Warsaw")).year


async def numbering(key: str, kind: str) -> tuple[str, str]:
    """(wzór numeru, wyróżnik rodzaju) z ustawień „Księgowość" okręgu."""
    extra = (await doc_settings(key)).get("extra") or {}
    scheme = A.scheme_of(extra.get("number_scheme"))
    mark = A.mark_of((extra.get("number_marks") or {}).get(kind), kind)
    return scheme, mark


def counter_year(scheme: str, season: int) -> int:
    """`number_year` licznika: sezon albo - przy wzorze kalendarzowym - rok wydania."""
    return calendar_year() if scheme == G.SCHEME_CALENDAR else int(season)


def _settings_kind(kind: str, scheme: str) -> str:
    """„Kontynuacja numeracji" osobno dla każdego wzoru - wzór kalendarzowy pod „kind@calendar"."""
    return kind if scheme == G.SCHEME_SEASON else f"{kind}@{scheme}"


async def used_seqs(key: str, kind: str, number_year: int, scheme: str = G.SCHEME_SEASON) -> list[int]:
    rows = await database.fetch_all(
        select(T.c.seq).where(
            and_(
                T.c.province == key,
                T.c.kind == kind,
                T.c.number_year == int(number_year),
                T.c.number_scheme == scheme,
            )
        )
    )
    return [int(row["seq"]) for row in rows]


async def start_after(key: str, kind: str, number_year: int, scheme: str = G.SCHEME_SEASON) -> int:
    row = await database.fetch_one(
        select(ST.c.start_after).where(
            and_(
                ST.c.province == key,
                ST.c.kind == _settings_kind(kind, scheme),
                ST.c.number_year == int(number_year),
            )
        )
    )
    return int(row["start_after"]) if row else 0


async def suggestion(key: str, kind: str, season: int) -> dict:
    """
    Numer, który podpowiada ekran przed wydaniem - bez rezerwacji.

    `season` to sezon OKRESU; przy wzorze kalendarzowym licznik idzie po roku
    wydania i `season` w odpowiedzi to ten rok (do „kontynuacji numeracji").
    """
    scheme, mark = await numbering(key, kind)
    year = counter_year(scheme, season)
    used = await used_seqs(key, kind, year, scheme)
    after = await start_after(key, kind, year, scheme)
    seq = G.suggest_seq(used, after)
    short = _short(key)
    return {
        "seq": seq,
        "number": G.number_text(short, year, seq, kind, scheme, mark),
        "prefix": G.number_prefix(short, year, kind, scheme, mark),
        "suffix": G.number_suffix(short, year, kind, scheme, mark),
        "last": max(used) if used else None,
        "start_after": after,
        "season": year,
        "season_label": G.season_label(year) if scheme == G.SCHEME_SEASON else str(year),
        "counter_label": G.counter_label(year, scheme),
        "scheme": scheme,
    }


async def insert_document(
    key: str,
    *,
    kind: str,
    seq: int,
    number: str,
    period: dict,
    include_future: bool,
    include_zprp: bool,
    items: list[dict],
    totals: dict,
    context: dict,
    created_by: Optional[str],
    number_scheme: str = G.SCHEME_SEASON,
    number_year: Optional[int] = None,
) -> int:
    """Wpis w rejestrze - wołać w transakcji z blokadą (`issue_lock`)."""
    from datetime import date

    return await database.fetch_val(
        insert(T)
        .values(
            province=key,
            kind=kind,
            number_year=int(number_year if number_year is not None else period["season"]),
            number_scheme=A.scheme_of(number_scheme),
            seq=int(seq),
            number=number,
            period_year=int(period["year"]),
            period_month=int(period["month"]),
            period_id=_s(period.get("id")).lower(),
            period_label=period.get("label"),
            date_from=date.fromisoformat(period["from"]) if period.get("from") else None,
            date_to=date.fromisoformat(period["to"]) if period.get("to") else None,
            include_future=bool(include_future),
            include_zprp=bool(include_zprp),
            items_json=dump(items),
            totals_json=dump(totals),
            context_json=dump(context),
            created_by=created_by,
        )
        .returning(T.c.id)
    )


def issue_lock(key: str, kind: str) -> str:
    """Klucz blokady doradczej: dwa wydania naraz nie wezmą tego samego numeru."""
    return f"settlement-register:{key}:{kind}"


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------

@router.get("", summary="Rejestr oficjalnych dokumentów okręgu - jeden sezon")
async def list_register(
    province: str = Query(...),
    season: int = Query(..., description="Rok początku sezonu: 2026 = 2026/27"),
    kind: Optional[str] = Query(None),
):
    key = _require(province)
    from app.season_rules import season_start_year

    query = select(T).where(
        and_(
            T.c.province == key,
            T.c.number_year.in_([int(season), int(season) + 1]),
        )
    )
    if kind:
        query = query.where(T.c.kind == _kind(kind))
    rows = await database.fetch_all(query.order_by(T.c.kind, T.c.number_year.desc(), T.c.seq.desc()))
    # Sezonowe - po numerze sezonu; kalendarzowe (04.11.2026) - po sezonie
    # OKRESU, żeby rejestr sezonu pokazywał wszystko, co za ten sezon wydano.
    rows = [
        row
        for row in rows
        if (
            int(row["number_year"]) == int(season)
            if _scheme_of_row(row) == G.SCHEME_SEASON
            else (season_start_year(row["date_from"]) if row["date_from"] else row["number_year"]) == int(season)
        )
    ]
    return {
        "province": key,
        "season": int(season),
        "season_label": G.season_label(season),
        "documents": [_doc_json(row) for row in rows],
        "next": {k: await suggestion(key, k, int(season)) for k in G.KINDS},
    }


@router.get("/period", summary="Zajętość pozycji i podpowiedź numeru dla okresu")
async def period_state(
    province: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    period_id: Optional[str] = Query(None),
):
    key = _require(province)
    pid = _s(period_id).lower()
    season = await season_of_period(key, year, month, pid)
    taken = {}
    documents = {}
    issued = {}
    for kind in G.KINDS:
        docs = await period_documents(key, kind, year, month, pid)
        documents[kind] = [
            {"id": d["id"], "number": d["number"], "created_at": d["created_at"]} for d in docs
        ]
        taken[kind] = G.judge_view(G.taken_map(docs))
        # Ile z okresu jest już na oficjalnych dokumentach - do paska wypłaty
        # (07.10.2026): zestawienia netto (przed karą, jak suma na pasku),
        # przejazdy kwotą.
        field = "net" if kind == G.ZESTAWIENIE else "amount"
        issued[kind] = {
            "amount": round(sum(float((d["totals"] or {}).get(field) or 0) for d in docs), 2),
            "documents": len(docs),
        }
    return {
        "province": key,
        "season": season,
        "season_label": G.season_label(season),
        "taken": taken,
        "documents": documents,
        "issued": issued,
        # Wygląd dokumentów - ekran liczy z niego kary na pasku (lista kar).
        "look": await doc_settings(key),
        "next": {kind: await suggestion(key, kind, season) for kind in G.KINDS},
    }


class DownloadBody(BaseModel):
    province: str
    id: int


@router.post("/download", summary="Pobierz ponownie oficjalny dokument z rejestru")
async def download_document(body: DownloadBody):
    key = _require(body.province)
    row = await database.fetch_one(select(T).where(and_(T.c.province == key, T.c.id == int(body.id))))
    if not row:
        raise HTTPException(404, "Tego dokumentu nie ma w rejestrze - mógł zostać usunięty.")
    from app import province_settlement_pdf as P

    context = _json(row["context_json"], {})
    if not context:
        raise HTTPException(409, "Dokument nie ma zapisanego wydruku.")
    result = P.render_kind(key, row["kind"], context)
    return {"ok": True, "number": row["number"], "kind": row["kind"], **result}


@router.delete("", summary="Usuń dokument z rejestru - numer i pozycje wracają do puli")
async def remove_document(
    province: str = Query(...),
    id: int = Query(...),
    user: Optional[str] = Query(None),
):
    key = _require(province)
    row = await database.fetch_one(select(T).where(and_(T.c.province == key, T.c.id == int(id))))
    if not row:
        raise HTTPException(404, "Tego dokumentu nie ma już w rejestrze.")
    await database.execute(delete(T).where(T.c.id == row["id"]))
    logger.info(
        "[register] %s: usunięto %s %s (wydał %s, usunął %s)",
        key, row["kind"], row["number"], row["created_by"], user,
    )
    return {
        "ok": True,
        "message": f"Usunięto {row['number']} z rejestru - numer i pozycje są znowu wolne.",
    }


class SettingsBody(BaseModel):
    province: str
    kind: str
    #: Rok początku sezonu: 2026 = 2026/27.
    season: int
    #: Ostatni numer wydany poza systemem - 0 = numeracja od 1.
    start_after: int = 0
    user: Optional[str] = None


@router.put("/settings", summary="Kontynuacja numeracji w sezonie")
async def save_settings(body: SettingsBody):
    key = _require(body.province)
    kind = _kind(body.kind)
    if body.start_after < 0 or body.start_after > G.MAX_SEQ:
        raise HTTPException(400, f"Ostatni numer musi być między 0 a {G.MAX_SEQ}.")
    values = {"start_after": int(body.start_after), "updated_by": body.user, "updated_at": _now()}
    scheme, _mark = await numbering(key, kind)
    await database.execute(
        pg_insert(ST)
        .values(province=key, kind=_settings_kind(kind, scheme), number_year=int(body.season), **values)
        .on_conflict_do_update(index_elements=[ST.c.province, ST.c.kind, ST.c.number_year], set_=values)
    )
    return {"ok": True, "next": await suggestion(key, kind, int(body.season))}


async def doc_settings(key: str) -> dict:
    """Wygląd dokumentów okręgu - z bazy albo domyślny (`DOC_DEFAULTS`)."""
    try:
        row = await database.fetch_one(select(DS).where(DS.c.province == key))
    except Exception as exc:  # pragma: no cover - tabela przed pierwszym startem
        logger.warning("[register] %s: ustawienia dokumentów: %s", key, exc)
        row = None
    if not row:
        return {**DOC_DEFAULTS, "extra": A.clean_extra({})}
    display = _s(row["period_display"])
    return {
        # Ustawienia „Księgowość" (04.11.2026) - jeden słownik, żeby dokładanie
        # pól nie wymagało kolumny na każde.
        "extra": A.clean_extra(_json(_row_get(row, "extra_json"), {})),
        "show_matches": bool(row["show_matches"]),
        "show_subtitle": bool(row["show_subtitle"]),
        "period_display": display if display in PERIOD_DISPLAYS else "all",
        "penalty_list": _letter(row["penalty_list"]),
        "absences_list": _letter(row["absences_list"]),
        "show_absences": bool(row["show_absences"]),
        "show_outside": bool(row["show_outside"]),
        "outside_list": _letter(row["outside_list"]),
    }


@router.get("/doc-settings", summary="Wygląd dokumentów okręgu (np. liczba meczów)")
async def get_doc_settings(province: str = Query(...)):
    key = _require(province)
    return {"province": key, **await doc_settings(key)}


class DocSettingsBody(BaseModel):
    province: str
    show_matches: bool = False
    show_subtitle: bool = True
    period_display: str = "all"
    penalty_list: str = "A"
    absences_list: str = "A"
    show_absences: bool = True
    show_outside: bool = False
    outside_list: str = "A"
    user: Optional[str] = None


@router.put("/doc-settings", summary="Zapisz wygląd dokumentów okręgu")
async def save_doc_settings(body: DocSettingsBody):
    key = _require(body.province)
    display = _s(body.period_display)
    if display not in PERIOD_DISPLAYS:
        raise HTTPException(400, "Nieznany sposób pokazywania okresu.")
    letter = _s(body.penalty_list).upper()
    absences = _s(body.absences_list).upper()
    outside = _s(body.outside_list).upper()
    if any(len(x) != 1 or not x.isalpha() for x in (letter, absences, outside)):
        raise HTTPException(400, "Lista kar, nieobecności i klubów to jedna litera (A, B, C...).")
    values = {
        "show_matches": bool(body.show_matches),
        "show_subtitle": bool(body.show_subtitle),
        "period_display": display,
        "penalty_list": letter,
        "absences_list": absences,
        "show_absences": bool(body.show_absences),
        "show_outside": bool(body.show_outside),
        "outside_list": outside,
        "updated_by": body.user,
        "updated_at": _now(),
    }
    await database.execute(
        pg_insert(DS)
        .values(province=key, **values)
        .on_conflict_do_update(index_elements=[DS.c.province], set_=values)
    )
    return {"ok": True, "province": key, **await doc_settings(key)}



class DocExtraBody(BaseModel):
    """Ustawienia „Księgowość" - tylko pola podane w żądaniu się zmieniają."""

    province: str
    tax_formula: Optional[str] = None
    number_scheme: Optional[str] = None
    number_marks: Optional[dict] = None
    show_consent: Optional[bool] = None
    consent_text: Optional[str] = None
    enova: Optional[dict] = None
    user: Optional[str] = None


@router.put("/doc-extra", summary="Zapisz ustawienia Księgowość (formuła, numeracja, klauzula, enova)")
async def save_doc_extra(body: DocExtraBody):
    key = _require(body.province)
    current = (await doc_settings(key)).get("extra") or A.clean_extra({})
    patch = body.model_dump(exclude_none=True, exclude={"province", "user"})
    if "tax_formula" in patch and _s(patch["tax_formula"]).lower() not in A.FORMULAS:
        raise HTTPException(400, "Nieznana formuła podatku.")
    if "number_scheme" in patch and _s(patch["number_scheme"]).lower() not in A.SCHEMES:
        raise HTTPException(400, "Nieznany wzór numeru.")
    merged = dict(current)
    for name, value in patch.items():
        if name in ("number_marks", "enova") and isinstance(value, dict):
            merged[name] = {**(current.get(name) or {}), **value}
        else:
            merged[name] = value
    if "consent_text" in patch and not _s(patch["consent_text"]):
        merged["consent_text"] = A.CONSENT_DEFAULT
    extra = A.clean_extra(merged)
    now = _now()
    await database.execute(
        pg_insert(DS)
        .values(
            province=key,
            **{k: v for k, v in DOC_DEFAULTS.items()},
            extra_json=dump(extra),
            updated_by=body.user,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=[DS.c.province],
            set_={"extra_json": dump(extra), "updated_by": body.user, "updated_at": now},
        )
    )
    logger.info("[register] %s: ustawienia Księgowość zmienił %s: %s", key, body.user, sorted(patch))
    return {"ok": True, "province": key, **await doc_settings(key)}
