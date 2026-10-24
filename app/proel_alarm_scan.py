"""Skaner alarmów meczu - w tle przelicza mecze, które dostały nowe wersje.

Co `SCAN_INTERVAL_S` bierze mecze z migawkami z ostatnich `WINDOW_DAYS` dni,
których ostatnia migawka jest nowsza niż ta, do której liczono, i przelicza
alarmy (`app/raport_dowodowy/alarmy.py`). Wynik ląduje w `proel_match_alarms`
- stąd plakietka na liście Dziennika.

PUSH TYLKO PRZY PODEJRZANYM (decyzja 09.10.2026: „nie każde usunięcie kary
jest podejrzane"), tylko gdy pojawiło się NOWE podejrzane znalezisko (odcisk
zbioru) i tylko świeże (`PUSH_FRESH_H`) - pierwsze uruchomienie po wdrożeniu
nie może zasypać adminów powiadomieniami o meczach sprzed tygodnia.

I TYLKO PRZY MECZU Z TERMINARZA ZPRP (decyzja 24.10.2026): mecz testowy,
ćwiczenie i ręcznie wpisany numer („GG") administratora nie obchodzą. Alarm
takiego meczu dalej liczy się do Dziennika - nie idzie tylko pushem, a stare
wpisy skrzynki o nim są ukrywane (`oficjalne_klucze`).

Partie po `PER_CYCLE` meczów z oddechem między nimi: rozpakowanie historii
meczu to ~100 ms pracy procesora, a w tym samym procesie lecą autozapisy.
Nic tu nie ma prawa wywrócić pętli - błąd jednego meczu jest logowany,
a mecz dostaje wiersz z numerem migawki, żeby nie wracał co cykl.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
import time
from typing import Any, Dict, Iterable, Optional, Set

from sqlalchemy import func, or_, select

logger = logging.getLogger(__name__)

SCAN_INTERVAL_S = 120
WINDOW_DAYS = 8
PER_CYCLE = 25
PUSH_FRESH_H = 24


#: Ile sekund pamiętamy werdykt „oficjalny" - skrzynka pyta o te same mecze
#: przy każdym otwarciu, a mecz nie przechodzi z testu do terminarza co chwilę.
OFICJALNY_TTL_S = 600
_OFICJALNY: Dict[str, tuple] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def oficjalny_mecz(key: Any, config: Any, zprp_match_id: Any, w_terminarzu: bool) -> bool:
    """Czy mecz pochodzi z terminarza ZPRP - reguła w jednym miejscu, z testem.

    Nie szkoleniowy i nie testowy (ta sama reguła co statystyki), a do tego
    znany związkowi: ma numeryczny identyfikator ZPRP (`matchConfig.matchId`,
    przepisany do `zprp_match_id`) albo jego numer stoi w terminarzu okręgu.
    Ręcznie wpisany numer bez żadnego z tych śladów nie jest oficjalny.
    """
    from app.public_stats_rules import is_official_match

    if not is_official_match(key, config):
        return False
    cfg = config if isinstance(config, dict) else {}
    ident = str(zprp_match_id or cfg.get("matchId") or "").strip()
    return ident.isdigit() or bool(w_terminarzu)


async def oficjalne_klucze(keys: Iterable[Any]) -> Set[str]:
    """Które z podanych kluczy meczów są oficjalne. Nigdy nie rzuca - błąd = „nie wiem", czyli tak."""
    from app.proel_training_key import is_training_key, match_number_from_key

    teraz = time.monotonic()
    wszystkie = {str(k or "").strip() for k in keys} - {""}
    out = {k for k in wszystkie if (_OFICJALNY.get(k) or (None, 0))[1] > teraz and _OFICJALNY[k][0]}
    pytaj = sorted(k for k in wszystkie if (_OFICJALNY.get(k) or (None, 0))[1] <= teraz)
    if not pytaj:
        return out
    try:
        from app.db import database, province_matches, saved_matches, zprp_archive_matches

        wiersze = {r["match_number"]: dict(r) for r in await database.fetch_all(
            select(saved_matches.c.match_number, saved_matches.c.zprp_match_id,
                   saved_matches.c.data_json["matchConfig"].label("config"))
            .where(saved_matches.c.match_number.in_(pytaj))
        )}
        numery = sorted({match_number_from_key(k) for k in pytaj if not is_training_key(k)})
        znane: Set[str] = set()
        if numery:
            znane |= {str(r[0]) for r in await database.fetch_all(
                select(province_matches.c.match_code).where(province_matches.c.match_code.in_(numery))
            )}
            znane |= {str(r[0]) for r in await database.fetch_all(
                select(zprp_archive_matches.c.code).where(zprp_archive_matches.c.code.in_(numery))
            )}
    except Exception:  # noqa: BLE001 - lepiej pokazać za dużo niż zgubić alarm
        logger.warning("alarmy: nie sprawdzono, czy mecze są oficjalne", exc_info=True)
        return out | set(pytaj)
    from app.public_stats_rules import _as_mapping

    for k in pytaj:
        w = wiersze.get(k) or {}
        werdykt = oficjalny_mecz(k, _as_mapping(w.get("config")), w.get("zprp_match_id"),
                                 match_number_from_key(k) in znane)
        _OFICJALNY[k] = (werdykt, teraz + OFICJALNY_TTL_S)
        if werdykt:
            out.add(k)
    return out


def opis_meczu(mecz: Dict[str, Any], key: str) -> Dict[str, str]:
    """Numer, drużyny i termin do powiadomienia - „IMB/49" i „SGH – DBAM · 14.11.2026, 19:00"."""
    from app.proel_training_key import match_number_from_key

    numer = match_number_from_key(mecz.get("numer") or key) or key
    druzyny = " – ".join(x for x in (str(mecz.get("gospodarze") or "").strip(),
                                     str(mecz.get("goscie") or "").strip()) if x)
    linia = " · ".join(x for x in (druzyny, str(mecz.get("data") or "").strip()) if x)
    return {"numer": numer, "druzyny": druzyny, "linia": linia}


def should_push(alarmy: Dict[str, Any], pushed_fingerprint: Optional[str], now: datetime) -> bool:
    """Czy wysłać push - reguła w jednym miejscu, z testem."""
    from app.raport_dowodowy.analiza import czas_utc

    if alarmy.get("poziom") != "podejrzane" or not alarmy.get("odcisk"):
        return False
    if alarmy["odcisk"] == (pushed_fingerprint or ""):
        return False
    kiedy = czas_utc(alarmy.get("ostatnie_podejrzane"))
    return bool(kiedy and kiedy >= now - timedelta(hours=PUSH_FRESH_H))


async def _zapisz(key: str, values: Dict[str, Any]) -> None:
    from app.db import database, proel_match_alarms as T

    istnieje = await database.fetch_one(select(T.c.match_number).where(T.c.match_number == key))
    if istnieje is None:
        await database.execute(T.insert().values(match_number=key, **values))
    else:
        await database.execute(T.update().where(T.c.match_number == key).values(**values))


async def przelicz(key: str, last_snapshot_id: Optional[int], poprzedni: Optional[Dict[str, Any]]) -> None:
    from app.proel_match_history import analiza_meczu

    now = _now()
    try:
        zrzut, alarmy = await analiza_meczu(key)
    except Exception:  # noqa: BLE001 - mecz bez zapisu, uszkodzona migawka
        logger.warning("alarmy: nie przeliczono %s", key, exc_info=True)
        await _zapisz(key, {"last_snapshot_id": last_snapshot_id, "computed_at": now})
        return
    values: Dict[str, Any] = {
        "level": alarmy.get("poziom"),
        "headline": alarmy.get("naglowek") or None,
        "findings_json": alarmy.get("osoby") or [],
        "findings_count": int(alarmy.get("liczba") or 0),
        "last_snapshot_id": last_snapshot_id,
        "computed_at": now,
    }
    stary_odcisk = (poprzedni or {}).get("pushed_fingerprint")
    if alarmy.get("poziom") == "podejrzane" and alarmy.get("odcisk") and alarmy["odcisk"] != (stary_odcisk or ""):
        if should_push(alarmy, stary_odcisk, now) and key in await oficjalne_klucze([key]):
            from app.admin_alerts import notify_admins
            from app.raport_dowodowy import analiza as A

            try:
                blob = A._slownik((zrzut.get("mecz") or {}).get("data_json"))
                mecz = opis_meczu(A._dane_meczu(zrzut, blob, A.Osoby(blob)), key)
            except Exception:  # noqa: BLE001 - opis meczu nie może zatrzymać alarmu
                logger.warning("alarmy: brak opisu meczu %s", key, exc_info=True)
                mecz = opis_meczu({}, key)
            naglowek = alarmy.get("naglowek") or "Podejrzana zmiana w protokole"
            await notify_admins(
                "proel_suspicious",
                mecz["numer"],
                f"{mecz['linia']}\n{naglowek}" if mecz["linia"] else naglowek,
                reference=key,
                extra={"matchNumber": mecz["numer"], "matchLine": mecz["linia"]},
            )
            values["pushed_at"] = now
        # Odcisk zapisujemy także bez pushu (stare znalezisko) - inaczej każde
        # następne przeliczenie pytałoby o to samo od nowa.
        values["pushed_fingerprint"] = alarmy["odcisk"]
    await _zapisz(key, values)


async def scan_once(limit: int = PER_CYCLE) -> int:
    from app.db import database, proel_match_alarms as T, proel_match_snapshots as S

    since = _now() - timedelta(days=WINDOW_DAYS)
    ostatnie = await database.fetch_all(
        select(S.c.match_number, func.max(S.c.id).label("last"))
        .where(S.c.received_at >= since)
        .group_by(S.c.match_number)
        .order_by(func.max(S.c.id).desc())
    )
    znane = {r["match_number"]: dict(r) for r in await database.fetch_all(
        select(T.c.match_number, T.c.last_snapshot_id, T.c.pushed_fingerprint)
    )}
    do_zrobienia = [r for r in ostatnie
                    if (znane.get(r["match_number"]) or {}).get("last_snapshot_id") != r["last"]][:limit]
    for r in do_zrobienia:
        await przelicz(r["match_number"], r["last"], znane.get(r["match_number"]))
        await asyncio.sleep(0.2)  # oddech dla autozapisów meczów w toku
    return len(do_zrobienia)


async def run_alarm_scan() -> None:
    """Pętla skanera. Jedna porażka nie kończy pętli."""
    await asyncio.sleep(30)  # po starcie najpierw niech wstanie reszta
    while True:
        try:
            await scan_once()
        except Exception:  # noqa: BLE001
            logger.warning("skaner alarmów meczu: cykl nieudany", exc_info=True)
        await asyncio.sleep(SCAN_INTERVAL_S)
