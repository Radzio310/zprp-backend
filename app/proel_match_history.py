"""Historia meczu oczami osób - skład z alarmami, karta zawodnika, raport.

Trzy trasy panelu (Dziennik meczu, poziom „Zawodnicy"):

* `GET /proel/match-history/sklad/{mecz}` - siatka koszulek: kary, bramki,
  liczba ingerencji, poziom alarmu na osobę,
* `GET /proel/match-history/osoba/{mecz}?druzyna=&numer=` - karta osoby
  (życiorys każdej kary, bramki po usunięciu, kontekst, kto, droga protokołu),
* `GET /proel/match-history/raport/{mecz}?druzyna=&numer=` - ten sam raport
  HTML co narzędzie na komputerze; aplikacja drukuje go do PDF.

Analiza to `app/raport_dowodowy` - JEDNA implementacja dla raportu, karty
i skanera alarmów. Wynik trzymamy w pamięci procesu, dopóki mecz nie dostanie
nowej wersji (podpis = ostatnia migawka, ostatni wpis dziennika, `doc_rev`).

⚠ Router stoi PRZED `proel_router` w `main.py` (catch-all `/proel/{nr:path}`).
"""
from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select

from app.proel_admin_guard import proel_admin_guard
from app.proel_auth import Actor, is_admin, proel_actor

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/proel/match-history",
    tags=["ProEl: historia meczu"],
    dependencies=[Depends(proel_admin_guard)],
)

_PAMIEC: "OrderedDict[str, Tuple[tuple, Dict[str, Any], Dict[str, Any]]]" = OrderedDict()
_PAMIEC_MAX = 8
_DRUZYNY = {"host": "host", "guest": "guest", "gospodarze": "host", "goscie": "guest", "goście": "guest"}


async def _podpis(key: str) -> tuple:
    from app.db import database, proel_activity_log as L, proel_match_snapshots as S, saved_matches as M

    s = await database.fetch_one(select(func.max(S.c.id), func.count()).where(S.c.match_number == key))
    j = await database.fetch_val(select(func.max(L.c.id)).where(L.c.match_number == key))
    rev = await database.fetch_val(select(M.c.doc_rev).where(M.c.match_number == key))
    return (s[0] if s else None, s[1] if s else 0, j, rev)


async def analiza_meczu(key: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(zrzut, alarmy) meczu - z pamięci, gdy mecz nie zmienił się od ostatniego razu."""
    from app.proel_evidence import zbierz_zrzut
    from app.raport_dowodowy.alarmy import alarmy_meczu

    podpis = await _podpis(key)
    trafienie = _PAMIEC.get(key)
    if trafienie and trafienie[0] == podpis:
        _PAMIEC.move_to_end(key)
        return trafienie[1], trafienie[2]
    zrzut = await zbierz_zrzut(key)
    if not zrzut.get("mecz") and not zrzut.get("migawki"):
        raise HTTPException(404, detail={"code": "NO_MATCH", "message": "Nie ma zapisu tego meczu w ProElu."})
    alarmy = await asyncio.to_thread(alarmy_meczu, zrzut)
    _PAMIEC[key] = (podpis, zrzut, alarmy)
    _PAMIEC.move_to_end(key)
    while len(_PAMIEC) > _PAMIEC_MAX:
        _PAMIEC.popitem(last=False)
    return zrzut, alarmy


async def _require_admin(actor: Actor) -> None:
    if not await is_admin(actor.judge_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "ADMIN_REQUIRED", "message": "Historia meczu jest dostępna tylko dla administratora."},
        )


def _osoba_params(druzyna: str, numer: str) -> Tuple[str, str]:
    d = _DRUZYNY.get(str(druzyna or "").strip().lower())
    n = str(numer or "").strip()
    if not d or not n:
        raise HTTPException(400, detail={"code": "BAD_PERSON", "message": "Podaj drużynę (host/guest) i numer."})
    return d, n


def _alarm_meczu(alarmy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not alarmy.get("poziom"):
        return None
    return {"level": alarmy["poziom"], "headline": alarmy["naglowek"], "count": alarmy["liczba"]}


def karta_osoby(d: Dict[str, Any]) -> Dict[str, Any]:
    """Teczka osoby do JSON-a - z flagami zamiast tożsamości obiektów."""
    from app.raport_dowodowy import analiza as A

    po = [id(z) for z in d.get("po_usunieciu") or []]
    zyciorysy = []
    for z in d["zyciorysy"]:
        kw = z.get("klucz_wpisu") or z["klucz"]
        zyciorysy.append({
            "rodzaj": z["rodzaj"], "opis": z["opis"], "czas_meczu": z["czas_meczu"],
            "czas_wpisu": A.mmss(kw[3]), "polowa": z["polowa"], "kara": z["kara"],
            "wykluczajaca": z["wykluczajaca"], "w_protokole": z["w_protokole"],
            "wynik_po": z.get("wynik_po", ""), "wpis": z["wpis"],
            "poprawki": [{**{k: v for k, v in p.items() if k not in ("z", "na")},
                          "z": A.mmss(p["z"][3]), "na": A.mmss(p["na"][3]),
                          "z_typ": p["z"][0], "na_typ": p["na"][0]} for p in z["poprawki"]],
            "usuniecie": z["usuniecie"], "przeniesienie": z["przeniesienie"],
            "trwanie_s": z.get("trwanie_s"), "glowne": z is d.get("glowne"),
            "po_usunieciu": id(z) in po, "po_usunieciu_s": z.get("po_usunieciu_s"),
            "decydujaca": bool(z.get("decydujaca")),
            "zdarzen_w_miedzyczasie": z.get("zdarzen_w_miedzyczasie"),
        })
    o = d["osoba"]
    return {
        "mecz": d["mecz"],
        "osoba": {k: o.get(k) for k in ("numer", "nazwisko", "druzyna", "druzyna_nazwa", "strona", "rola", "etykieta", "bramki")},
        "zyciorysy": zyciorysy,
        "kontekst": d["kontekst"],
        "usuniec_w_meczu": d["usuniec_w_meczu"],
        "edytorzy": d["edytorzy"],
        "droga": d["droga"],
        "zatwierdzenie": d["zatwierdzenie"],
        "obsada": d["obsada"],
        "wynik_koncowy": list(d["wynik_koncowy"]),
    }


@router.get("/sklad/{match_number:path}", summary="Skład meczu z alarmami - siatka koszulek")
async def sklad(match_number: str, actor: Actor = Depends(proel_actor)):
    await _require_admin(actor)
    from app.raport_dowodowy import analiza as A
    from app.raport_dowodowy.sklad import sklad_meczu

    key = str(match_number or "").strip()
    zrzut, alarmy = await analiza_meczu(key)
    blob = A._slownik((zrzut.get("mecz") or {}).get("data_json"))
    wynik = await asyncio.to_thread(sklad_meczu, zrzut, alarmy)
    cfg = A.konfiguracja(blob)
    try:
        polowa = int(cfg.get("halfTime") or 30)
    except (TypeError, ValueError):
        polowa = 30
    return {
        "match_number": key,
        "mecz": A._dane_meczu(zrzut, blob, A.Osoby(blob)),
        # Karta alarmu: oś meczu (2 x połowa) i barwy koszulek obu drużyn.
        "polowa_min": polowa if 10 <= polowa <= 45 else 30,
        "barwy": {"host": cfg.get("hostJerseyColor") or None, "guest": cfg.get("guestJerseyColor") or None},
        "wynik": [blob.get("scoreHost"), blob.get("scoreGuest")],
        "alarm": _alarm_meczu(alarmy),
        "alarmy": alarmy.get("osoby") or [],
        **wynik,
    }


@router.get("/osoba/{match_number:path}", summary="Karta osoby - życiorys jej kar i bramek")
async def osoba(
    match_number: str,
    druzyna: str = Query(...),
    numer: str = Query(...),
    actor: Actor = Depends(proel_actor),
):
    await _require_admin(actor)
    from app.raport_dowodowy.dossier import dossier

    key = str(match_number or "").strip()
    d_, n_ = _osoba_params(druzyna, numer)
    zrzut, alarmy = await analiza_meczu(key)
    try:
        d = await asyncio.to_thread(dossier, zrzut, n_, d_, None)
    except ValueError as e:
        raise HTTPException(404, detail={"code": "NO_PERSON", "message": str(e)})
    alarm = next((o for o in alarmy.get("osoby") or [] if o["druzyna"] == d_ and o["numer"] == n_), None)
    return {"match_number": key, "karta": karta_osoby(d), "alarm": alarm}


@router.get("/raport/{match_number:path}", summary="Raport o osobie (HTML do druku)", response_class=HTMLResponse)
async def raport(
    match_number: str,
    druzyna: str = Query(...),
    numer: str = Query(...),
    actor: Actor = Depends(proel_actor),
):
    await _require_admin(actor)
    from app.raport_dowodowy.dossier import dossier
    from app.raport_dowodowy.wydruk_osoby import html_osoby

    key = str(match_number or "").strip()
    d_, n_ = _osoba_params(druzyna, numer)
    zrzut, _alarmy = await analiza_meczu(key)
    try:
        d = await asyncio.to_thread(dossier, zrzut, n_, d_, None)
    except ValueError as e:
        raise HTTPException(404, detail={"code": "NO_PERSON", "message": str(e)})
    return HTMLResponse(await asyncio.to_thread(html_osoby, d))
