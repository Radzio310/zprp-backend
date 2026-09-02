"""Mecze dopisane RECZNIE do statystyk okregowych.

Sa rozgrywki, ktorych ZPRP nie prowadzi w swoim systemie - przede wszystkim
mecze miedzypanstwowe (turnieje EHF w Szczyrku). Sedziowie okregu obsluguja
przy nich stolik, ale ani kaskada rozgrywek, ani eksport terminarza nie wie
o ich istnieniu, wiec bez tego modulu znikaja z kazdego zestawienia.

TRZY ZASADY, ktore nie moga sie zgubic przy dalszych zmianach:

1. Wiersz stad jest ZAWSZE oznaczony jako dopisany recznie. Statystyka, ktora
   miesza dane z ZPRP z danymi wklepanymi z arkusza i nie mowi ktore sa ktore,
   jest gorsza od statystyki niepelnej.
2. Rozliczenie zalezy od RODZAJU dopisku, nie od tego, ze jest reczny:
   - `kind="match"` (EHF) NIE wchodzi do rozliczen wcale. Dla rozgrywek
     miedzypanstwowych nie istnieje zadna tabela stawek ZPRP, a kwota
     zgadnieta wygladalaby dokladnie tak samo jak kwota policzona.
   - `kind="officials"` liczy sie NORMALNIE. Mecz jest prawdziwy i pochodzi
     z ZPRP - data, hala, szczebel, stawka. Reczne jest tylko to, kto siedzial
     przy stoliku, a to akurat okreg wie lepiej niz terminarz.
3. Import jest IDEMPOTENTNY. `source_key` to naturalny klucz wiersza, wiec ten
   sam arkusz wgrany drugi raz niczego nie zdublikuje.
"""

from __future__ import annotations

import json
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.db import database, engine, province_manual_matches

router = APIRouter(
    prefix="/zprp/statystyki/okreg/manual",
    tags=["Statystyki okregowe: dopiski"],
)

DATA_DIR = Path(__file__).resolve().parent / "data"
# Kolejnosc bez znaczenia - kazdy plik niesie swoj `kind`.
SEED_FILES = ("manual_matches_seed.json", "manual_officials_seed.json")

# Terminarz ZPRP i arkusze okregowe podaja godziny lokalne, bez strefy.
WARSAW = ZoneInfo("Europe/Warsaw")

# Bezpiecznik importu. Recznych dopiskow z zalozenia sa dziesiatki, nie tysiace;
# wieksza paczka oznacza pomylke po stronie wysylajacego, nie prawdziwe dane.
MAX_IMPORT = 500


def _ascii(value: str) -> str:
    text = unicodedata.normalize("NFD", str(value or ""))
    text = "".join(c for c in text if not unicodedata.combining(c))
    return text.replace("ł", "l").replace("Ł", "L")


def _slug(value: str) -> str:
    return "".join(ch for ch in _ascii(value).upper() if ch.isalnum())


def source_key(province: str, season: str, date: str, home: str, away: str) -> str:
    """Naturalny klucz wiersza. Ten sam mecz z tego samego arkusza da ten sam."""
    return ".".join(
        [
            "manual",
            _slug(province),
            _slug(season),
            _slug(date),
            _slug(home)[:24],
            _slug(away)[:24],
        ]
    )


def _parse_ts(date: str, time: str) -> Optional[datetime]:
    clock = (time or "").strip() or "00:00"
    raw = (date or "").strip() + " " + clock
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=WARSAW)
        except ValueError:
            continue
    return None


class ManualMatchIn(BaseModel):
    # Wypelniane TYLKO dla `kind="officials"`: numer meczu w ZPRP, do ktorego
    # doklejamy obsade. Dla `kind="match"` numer nadajemy sami.
    code: str = ""
    date: str
    time: str = ""
    home: str = ""
    away: str = ""
    hall: str = ""
    city: str = ""
    sekretarz: str = ""
    mierzacy_czas: str = ""


class ManualImportRequest(BaseModel):
    # "match" - caly mecz spoza systemu ZPRP; "officials" - sama obsada
    # doklejana do meczu, ktory w ZPRP jest, ale ma pusty stolik.
    kind: str = Field(default="match")
    province: str
    season: str
    comp_code: str = Field(default="EHF")
    source: str = ""
    note: str = ""
    matches: List[ManualMatchIn]


class ManualMatchOut(BaseModel):
    id: int
    sourceKey: str
    kind: str
    province: str
    season: str
    comp: str
    code: str
    ts: Optional[int]
    home: str
    away: str
    hall: str
    city: str
    officials: Dict[str, str]
    source: str
    note: str
    # Pole istnieje po to, zeby przegladarka nie musiala wnioskowac z endpointu.
    manual: bool = True


def _row_out(row: Any) -> ManualMatchOut:
    played = row["played_at"]
    officials = row["officials"] or {}
    if isinstance(officials, str):
        try:
            officials = json.loads(officials)
        except ValueError:
            officials = {}
    return ManualMatchOut(
        id=row["id"],
        sourceKey=row["source_key"],
        kind=row["kind"] or "match",
        province=row["province"],
        season=row["season"],
        comp=row["comp_code"],
        code=row["match_code"],
        ts=int(played.timestamp() * 1000) if played else None,
        home=row["home"],
        away=row["away"],
        hall=row["hall"],
        city=row["city"],
        officials={str(k): str(v) for k, v in dict(officials).items() if v},
        source=row["source"],
        note=row["note"],
    )


def _rows_from_payload(payload: ManualImportRequest) -> List[Dict[str, Any]]:
    if len(payload.matches) > MAX_IMPORT:
        raise HTTPException(
            status_code=400, detail="Za duzo pozycji (max %d)." % MAX_IMPORT
        )

    rows: List[Dict[str, Any]] = []
    seen = set()
    # Numeracja idzie po dacie, zeby "EHF/1" oznaczalo zawsze ten sam mecz
    # niezaleznie od kolejnosci wierszy w arkuszu.
    ordered = sorted(payload.matches, key=lambda m: ((m.date or ""), (m.time or "")))
    kind = (payload.kind or "match").strip() or "match"
    comp = payload.comp_code.strip()
    for index, m in enumerate(ordered, start=1):
        if kind == "officials":
            # Latka obsady wskazuje ISTNIEJACY mecz ZPRP, wiec numer przychodzi
            # z arkusza i musi zostac dokladnie taki. Bez niego nie ma czego
            # doklejac, a zgadywanie po druzynach konczyloby sie doklejeniem
            # obsady do rewanzu.
            match_code = m.code.strip()
            if not match_code:
                continue
            comp_code = match_code.rsplit("/", 1)[0] if "/" in match_code else match_code
        else:
            match_code = comp + "/" + str(index)
            comp_code = comp
        key = source_key(payload.province, payload.season, m.date, m.home, m.away)
        if kind == "officials":
            key = key + ".obsada"
        if key in seen:
            continue
        seen.add(key)
        officials = {}
        if m.sekretarz.strip():
            officials["sekretarz"] = m.sekretarz.strip()
        if m.mierzacy_czas.strip():
            officials["mierzacy_czas"] = m.mierzacy_czas.strip()
        rows.append(
            {
                "source_key": key,
                "kind": kind,
                "province": payload.province.strip(),
                "season": payload.season.strip(),
                "comp_code": comp_code,
                "match_code": match_code,
                "played_at": _parse_ts(m.date, m.time),
                "home": m.home.strip(),
                "away": m.away.strip(),
                "hall": m.hall.strip(),
                "city": m.city.strip(),
                "officials": officials,
                "source": payload.source.strip(),
                "note": payload.note.strip(),
            }
        )
    return rows


@router.get("", response_model=List[ManualMatchOut])
async def list_manual_matches(province: str, season: str) -> List[ManualMatchOut]:
    query = (
        select(province_manual_matches)
        .where(province_manual_matches.c.province == province.strip())
        .where(province_manual_matches.c.season == season.strip())
        .order_by(province_manual_matches.c.played_at)
    )
    rows = await database.fetch_all(query)
    return [_row_out(r) for r in rows]


@router.post("/import")
async def import_manual_matches(payload: ManualImportRequest) -> Dict[str, Any]:
    rows = _rows_from_payload(payload)
    inserted = 0
    for row in rows:
        exists = await database.fetch_one(
            select(province_manual_matches.c.id).where(
                province_manual_matches.c.source_key == row["source_key"]
            )
        )
        if exists:
            continue
        await database.execute(province_manual_matches.insert().values(**row))
        inserted += 1
    return {
        "received": len(rows),
        "inserted": inserted,
        "skipped": len(rows) - inserted,
    }


def seed_from_file() -> int:
    """Jednorazowy zaczyn z plikow w repozytorium.

    Wolany przy starcie aplikacji i celowo napisany tak, zeby drugie i kazde
    kolejne uruchomienie nic nie robilo. Uzywa synchronicznego `engine`, bo
    `database` (async) nie jest jeszcze polaczone na tym etapie - to ten sam
    sposob, w ktory `db.py` zaklada tabele.
    """
    rows: List[Dict[str, Any]] = []
    for name in SEED_FILES:
        path = DATA_DIR / name
        if not path.exists():
            continue
        try:
            payload = ManualImportRequest(**json.loads(path.read_text(encoding="utf-8")))
            rows.extend(_rows_from_payload(payload))
        except Exception:
            # Zly plik zaczynu nie moze zatrzymac startu calego backendu ani
            # przeszkodzic pozostalym plikom.
            continue
    if not rows:
        return 0

    inserted = 0
    with engine.connect() as conn:
        for row in rows:
            found = conn.execute(
                select(province_manual_matches.c.id).where(
                    province_manual_matches.c.source_key == row["source_key"]
                )
            ).first()
            if found:
                continue
            conn.execute(province_manual_matches.insert().values(**row))
            inserted += 1
        conn.commit()
    return inserted
