"""
Pobieranie danych do statystyk sedziego i rozliczen okregu.

DWA ZRODLA, bo okreg placi za dwie rozne rzeczy:

  1. Mecze WLASNE - z `province_matches`, ktore utrzymuje juz
     `province_match_monitor`. Nic nie scrapujemy drugi raz; czytamy `state_json`
     i rozkladamy obsade na role.
  2. Mecze SPOZA okregu - z prywatnej listy meczow KAZDEGO sedziego. Wchodza
     wylacznie role STOLIKOWE: boiskowych na szczeblu centralnym okreg nie
     rozlicza, wiec ciagniecie ich tylko zawyzaloby rachunek i czas pobierania.

Odswiezanie jest DWUTOROWE (decyzja uzytkownika z 09.09.2026): raz na dobe
kontem `sync` z Railway, a na zadanie - poswiadczeniami VIP-a z panelu. Dzieki
temu okreg bez zmiennych srodowiskowych tez dziala, tyle ze recznie.

Trzymamy FAKTY, nie kwoty. Stawka potrafi zmienic sie uchwala wstecz, a
przeliczenie kilkuset wierszy jest darmowe - patrz `settlement_engine`.
"""

from __future__ import annotations

import asyncio
import logging
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlencode

from bs4 import BeautifulSoup
from httpx import AsyncClient
from sqlalchemy import and_, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_rates as R
from app.db import (
    database,
    okreg_distances,
    province_judges,
    province_matches,
    province_modules,
    province_settlement_matches,
    province_settlement_judges,
    province_settlement_runs,
    province_settlement_seasons,
    zprp_match_venues,
)
from app.settlement_seasons import (
    in_scope,
    normalize_season_label,
    plan_seasons,
    season_of,
)
from app.deps import get_settings
from app.settlement_distances import DistanceIndex, resolve_distances
from app.settlement_venues import fetch_venue, looks_like_city, pretty_city
from app.settlement_province import canonical, spellings
from app.settlement_runs import run_is_active
from app.zprp_accounts import configured_provinces, credentials_for
from app.zprp.officials import (  # scrapery, ktore juz istnieja - nie piszemy drugich
    _build_judge_matches_path,
    _extract_menu_href_from_page,
    _login_zprp_and_get_cookies,
    _parse_match_rows_from_soup,
    _parse_officials_page,
    _parse_seasons_from_page,
)
from app.utils import fetch_with_correct_encoding

logger = logging.getLogger(__name__)

#: Ktore sezony pobiera przebieg, decyduje `settlement_seasons.plan_seasons`:
#: pierwsze pobranie okregu - wszystkie od poczatku, potem sam biezacy, a reczne
#: z panelu nadrabia sezony nigdy nie pobrane w calosci. Dotad byla tu stala
#: lista dwoch sezonow, a mecze okregowe sprzed biezacego sezonu nie wchodzily
#: wcale - monitor okregu trzyma tylko biezacy terminarz.

#: Odstep miedzy zapytaniami o liste meczow sedziego. ZPRP to jedna maszyna
#: zwiazku, a nie API z limitem - walenie w nia setka rownoleglych polaczen
#: jest niegrzeczne i konczy sie odcieciem.
JUDGE_REQUEST_DELAY = 0.35

SYNC_INTERVAL_HOURS = 24


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _norm_name(value: Any) -> str:
    text = unicodedata.normalize("NFKD", _s(value)).lower()
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return " ".join(text.split())


def _parse_when(value: Any) -> Optional[datetime]:
    text = _s(value)
    if not text:
        return None
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2}))?", text)
    if not match:
        return None
    year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
    hour = int(match.group(4) or 0)
    minute = int(match.group(5) or 0)
    try:
        return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)
    except ValueError:
        return None


def _state(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        import json
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


# ---------------------------------------------------------------------------
# Wlaczanie modulu
# ---------------------------------------------------------------------------

async def module_enabled(province: str, module: str) -> bool:
    """
    Czy modul jest wlaczony w okregu.

    Pytamy WSZYSTKIMI pisowniami. Pierwsza wersja zapisywala "ŚLĄSKIE", a pytala
    o "SLASKIE" - wlaczony modul odpowiadal wiec „wylaczony", a odswiezanie
    konczylo sie odmowa. Wiersze sprzed poprawki leza w bazie do najblizszego
    przelaczenia (patrz `set_module`).
    """
    names = spellings(province)
    if not names:
        return False
    rows = await database.fetch_all(
        select(province_modules.c.enabled).where(
            and_(
                province_modules.c.province.in_(names),
                province_modules.c.module == module,
            )
        )
    )
    return any(bool(row["enabled"]) for row in rows)


async def enabled_provinces(module: str) -> list[str]:
    rows = await database.fetch_all(
        select(province_modules.c.province).where(
            and_(province_modules.c.module == module, province_modules.c.enabled.is_(True))
        )
    )
    # Klucz kont Railway - z nim porownuje sie `configured_provinces()`.
    return sorted({canonical(row["province"]) for row in rows} - {""})


# ---------------------------------------------------------------------------
# Zrodlo 1: mecze wlasne okregu
# ---------------------------------------------------------------------------

def _district_assignments(state: dict, judges: dict[str, dict]) -> list[dict]:
    """Rozklada obsade jednego meczu na wiersze (sedzia + rola)."""
    out: list[dict] = []
    for id_field, role in (
        ("NrSedzia_pierwszy", R.ROLE_FIELD),
        ("NrSedzia_drugi", R.ROLE_FIELD),
        ("NrSedzia_sekretarz", R.ROLE_TABLE),
        ("NrSedzia_czas", R.ROLE_TABLE),
        ("NrSedzia_delegat", R.ROLE_DELEGATE),
        ("NrSedzia_delegat2", R.ROLE_DELEGATE),
    ):
        judge_id = _s(state.get(id_field))
        # „0" to PUSTE GNIAZDO, nie sedzia - ZPRP tak zapisuje zdjeta obsade.
        if not judge_id or judge_id == "0":
            continue
        if judge_id not in judges:
            continue
        out.append({"judge_id": judge_id, "role": role})
    return out


async def _collect_district(province: str, judges: dict[str, dict]) -> list[dict]:
    rows = await database.fetch_all(
        select(province_matches).where(
            and_(
                province_matches.c.province.in_(spellings(province)),
                province_matches.c.active.is_(True),
            )
        )
    )

    collected: list[dict] = []
    for row in rows:
        state = _state(row["state_json"])
        code = _s(state.get("RozgrywkiCode") or row["match_code"])
        if R.is_test_competition(code):
            continue
        match_id = _s(row["match_id"])
        when = row["match_at"] or _parse_when(state.get("data_fakt"))
        city = _s(state.get("Hala_miasto"))
        hall = _s(state.get("Hala_nazwa"))
        teams = " - ".join(
            x for x in (
                _s(state.get("ID_zespoly_gosp_ZespolNazwa")),
                _s(state.get("ID_zespoly_gosc_ZespolNazwa")),
            ) if x
        )

        for entry in _district_assignments(state, judges):
            collected.append({
                "match_key": f"d:{match_id}",
                "judge_id": entry["judge_id"],
                "season": _s(row["season"] or state.get("season")),
                "match_at": when,
                "match_code": code,
                "role": entry["role"],
                "level": R.match_level(code),
                "origin": "district",
                "city": city,
                "hall": hall,
                "teams": teams,
                "round_text": _s(state.get("runda") or state.get("Runda")) or None,
                "series_text": _s(state.get("kolejka") or state.get("Kolejka")) or None,
                "approved": bool(row["approved"]) if row["approved"] is not None else None,
            })
    return collected


# ---------------------------------------------------------------------------
# Zrodlo 2: stoliki spoza okregu, z prywatnej listy sedziego
# ---------------------------------------------------------------------------

def _role_in_row(record: dict, judge_name: str) -> Optional[str]:
    """
    Rola sedziego w JEGO wlasnym meczu.

    Prywatna lista podaje obsade NAZWISKAMI, nie numerami, wiec dopasowujemy po
    nazwisku - tak samo jak `roleForMatch` w aplikacji. Priorytet delegat ->
    stolikowy -> boiskowy, bo ta sama osoba nie bywa dwoma naraz.
    """
    me = _norm_name(judge_name)
    if not me:
        return None
    officials = record.get("officials") or {}
    if _norm_name(officials.get("delegate")) == me:
        return R.ROLE_DELEGATE
    if _norm_name(officials.get("secretary")) == me or _norm_name(officials.get("timekeeper")) == me:
        return R.ROLE_TABLE
    if _norm_name(officials.get("referee1")) == me or _norm_name(officials.get("referee2")) == me:
        return R.ROLE_FIELD
    return None


async def _judge_season_pages(
    client: AsyncClient, cookies: dict, judge_id: str
) -> tuple[BeautifulSoup, dict[str, str], str]:
    """
    Lista meczow sedziego w sezonie domyslnym i mapa `RRRR/RRRR -> Filtr_sezon`.

    Wartosci `Filtr_sezon` to identyfikatory ZPRP (np. 195 = 2026/2027), wiec
    dopasowujemy po ETYKIECIE sezonu, a nie po kolejnosci na liscie.
    """
    entry_path = _build_judge_matches_path(judge_id, None)
    _, html = await fetch_with_correct_encoding(client, entry_path, method="GET", cookies=cookies)
    soup = BeautifulSoup(html, "html.parser")
    options: dict[str, str] = {}
    selected = ""
    for item in _parse_seasons_from_page(soup) or []:
        label = normalize_season_label(item.get("label")) or normalize_season_label(item.get("value"))
        value = _s(item.get("value"))
        if not label or not value or label in options:
            continue
        options[label] = value
        if item.get("selected"):
            selected = label
    return soup, options, selected


def _records_from_page(soup: BeautifulSoup) -> Optional[dict]:
    """
    Mecze z jednej strony sezonu. `None` = to nie jest lista meczow (awaria).

    Brak tabeli na poprawnej stronie (jest wybor sezonu) to sezon BEZ meczow -
    inaczej sedzia, ktory w danym sezonie nie sedziowal, blokowalby uznanie
    calego sezonu za pobrany.
    """
    try:
        return _parse_match_rows_from_soup(soup).get("matches") or {}
    except Exception:
        return {} if soup.find("select", attrs={"name": "Filtr_sezon"}) else None


async def discover_seasons(client: AsyncClient, cookies: dict, judges: dict[str, dict]) -> set[str]:
    """Sezony dostepne na liscie meczow sedziego - z pierwszej strony, ktora odpowie."""
    for judge_id in list(judges)[:5]:
        try:
            _, options, _ = await _judge_season_pages(client, cookies, judge_id)
        except Exception as exc:
            logger.warning("[settlement] sezony z listy sedziego %s: %s", judge_id, exc)
            continue
        if options:
            return set(options)
    return set()


async def _collect_outside(
    client: AsyncClient,
    cookies: dict,
    judges: dict[str, dict],
    district_ids: set[str],
    *,
    seasons: list[str],
    current: str,
    beat: Any,
) -> tuple[list[dict], dict[str, bool]]:
    """
    Mecze z prywatnych list sedziow - sezon po sezonie, sedzia po sedzi.

    Oddaje wiersze i mape `sezon -> czy KAZDY sedzia dal sie odczytac`. Tylko
    sezon z samymi „tak" wolno uznac za pobrany w calosci.

    Co wchodzi:
      - spoza okregu: TYLKO stoliki (boiskowych centralnych okreg nie rozlicza);
      - mecze okregowe MINIONYCH sezonow: w kazdej roli. Monitor okregu trzyma
        wylacznie biezacy terminarz, wiec dla historii lista sedziego jest
        jedynym zrodlem - bez tego minione sezony mialy same stoliki.

    Mecz, ktory okreg juz zna z wlasnego terminarza, POMIJAMY - inaczej wszedlby
    do rozliczenia dwa razy, raz z kazdego zrodla.
    """
    collected: list[dict] = []
    season_ok = {label: True for label in seasons}

    for judge_id, judge in judges.items():
        name = _s(judge.get("full_name"))
        if not name:
            continue
        try:
            entry_soup, options, selected = await _judge_season_pages(client, cookies, judge_id)
        except Exception as exc:
            # Jeden sedzia bez listy nie moze wywalic calego okregu - ale sezon
            # bez niego nie jest pobrany w calosci.
            logger.warning("[settlement] lista meczow sedziego %s: %s", judge_id, exc)
            for label in seasons:
                season_ok[label] = False
            await beat()
            continue
        if not options:
            logger.warning("[settlement] lista meczow sedziego %s bez wyboru sezonu", judge_id)
            for label in seasons:
                season_ok[label] = False
            await beat()
            continue

        for label in seasons:
            value = options.get(label)
            if not value:
                # Tego sezonu nie ma na liscie sedziego - nie ma w nim meczow.
                continue
            try:
                if label == selected:
                    soup = entry_soup
                else:
                    path = _build_judge_matches_path(judge_id, value)
                    _, html = await fetch_with_correct_encoding(
                        client, path, method="GET", cookies=cookies
                    )
                    soup = BeautifulSoup(html, "html.parser")
            except Exception as exc:
                logger.warning("[settlement] sedzia %s, sezon %s: %s", judge_id, label, exc)
                season_ok[label] = False
                continue

            records = _records_from_page(soup)
            if records is None:
                season_ok[label] = False
                continue

            past = label != current
            for key, record in records.items():
                match_id = _s(record.get("IdZawody")) or _s(key)
                if match_id in district_ids:
                    continue
                code = _s(record.get("match_code"))
                if not code or R.is_test_competition(code):
                    continue
                role = _role_in_row(record, name)
                if not role:
                    continue
                level = R.match_level(code)
                own = past and level in ("district", "cup")
                # ⚠ Spoza okregu TYLKO STOLIKI. Boiskowych centralnych okreg nie rozlicza.
                if not own and role != R.ROLE_TABLE:
                    continue

                venue = ((record.get("hall") or {}).get("venue") or {})
                teams = record.get("teams") or {}
                collected.append({
                    # Klucz „d:" jak w terminarzu okregu - gdyby monitor kiedys
                    # zobaczyl ten mecz, trafi w TEN SAM wiersz, nie w drugi.
                    "match_key": f"{'d' if own else 'o'}:{match_id}",
                    "judge_id": judge_id,
                    "season": label,
                    "match_at": _parse_when(record.get("data_fakt")),
                    "match_code": code,
                    "role": role,
                    "level": level,
                    "origin": "district" if own else "outside",
                    "city": _s(venue.get("city")),
                    "hall": _s(venue.get("name")),
                    "teams": " - ".join(x for x in (_s(teams.get("host")), _s(teams.get("guest"))) if x),
                    "round_text": None,
                    "series_text": None,
                    "approved": None,
                })
            await asyncio.sleep(JUDGE_REQUEST_DELAY)

        # Znak zycia po kazdym sedzim - pobranie wstecz trwa dluzej niz regula
        # „trup po 25 min" liczona od startu.
        await beat()

    return collected, season_ok


# ---------------------------------------------------------------------------
# Sedziowie okregu i ich miasta
# ---------------------------------------------------------------------------

async def _load_judges(client: AsyncClient, cookies: dict, province: str) -> dict[str, dict]:
    """
    Sedziowie okregu z ich miastem zamieszkania.

    Miasto jest niezbedne: bez niego nie ma jak policzyc dojazdu. Bierzemy je
    z zakladki „Sedziowie i Delegaci"; gdy konta na nia nie wpuszczaja, zostaja
    nazwiska z `province_judges` i rozliczenie pokaze „brak dojazdu" zamiast
    zmyslac kilometry.
    """
    judges: dict[str, dict] = {}

    rows = await database.fetch_all(
        select(province_judges).where(province_judges.c.province.in_(spellings(province)))
    )
    for row in rows:
        judges[_s(row["judge_id"])] = {
            "judge_id": _s(row["judge_id"]),
            "full_name": _s(row["full_name"]),
            "city": "",
        }

    try:
        _, home = await fetch_with_correct_encoding(client, "/index.php", method="GET", cookies=cookies)
        href = _extract_menu_href_from_page(
            home,
            label_regex=r"^\s*Sędziowie\s+i\s+Delegaci\s*$",
            href_regex=r"\ba=sedzia\b",
            human_label="Sędziowie i Delegaci",
        )
        _, page = await fetch_with_correct_encoding(client, href, method="GET", cookies=cookies)
        parsed = _parse_officials_page(page, current_offset=0)

        def absorb(payload: dict) -> None:
            for judge_id, item in (payload.get("officials") or {}).items():
                key = _s(judge_id)
                if not key:
                    return
                entry = judges.setdefault(key, {"judge_id": key, "full_name": "", "city": ""})
                entry["full_name"] = _s(item.get("name")) or entry["full_name"]
                # Lista sedziow podaje miasto razem z kodem pocztowym, czasem
                # z ulica po przecinku. Na Liscie kosztow przejazdow ma stac
                # sama miejscowosc, i po niej szuka sie w tabeli odleglosci.
                entry["city"] = pretty_city(item.get("city")) or entry["city"]

        absorb(parsed)

        # Lista sedziow jest STRONICOWANA. Pierwsza strona to zwykle 10 nazwisk,
        # a okreg ma ich pare setek - bez przejscia po offsetach rozliczenie
        # objeloby garstke ludzi i nikt by nie zauwazyl, ze reszty brakuje.
        paging = parsed.get("paging") or {}
        base_qs = dict(parsed.get("base_qs") or {})
        base_qs["a"] = "sedzia"
        base_qs.setdefault("Filtr_archiwum", "1")
        base_qs["count"] = str(int(paging.get("count") or 10))
        for offset in range(1, int(paging.get("max_offset") or 0) + 1):
            qs = dict(base_qs)
            qs["offset"] = str(offset)
            _, extra = await fetch_with_correct_encoding(
                client, "/index.php?" + urlencode(qs, doseq=True), method="GET", cookies=cookies
            )
            absorb(_parse_officials_page(extra, current_offset=offset))
    except Exception as exc:
        logger.warning("[settlement] lista sedziow okregu %s: %s", province, exc)

    return {k: v for k, v in judges.items() if v.get("full_name")}


async def _store_judges(province: str, judges: dict[str, dict]) -> None:
    """
    Kopia nazwisk z listy „Sedziowie i Delegaci".

    ⚠ `province_judges` prowadzi czlowiek w panelu okregu i potrafi nie miec
    kogos, kto ma obsady (sedzia dopisany w ZPRP w trakcie sezonu). Bez tej
    kopii zestawienie pokazywalo goly NUMER sedziego, a taki numer szedl dalej
    na PDF dla ksiegowosci.
    """
    now = _now()
    for judge_id, judge in judges.items():
        name = _s(judge.get("full_name"))
        if not name:
            continue
        values = {
            "province": province,
            "judge_id": _s(judge_id),
            "full_name": name,
            "home_city": _s(judge.get("city")),
            "updated_at": now,
        }
        statement = pg_insert(province_settlement_judges).values(**values)
        await database.execute(
            statement.on_conflict_do_update(
                index_elements=[
                    province_settlement_judges.c.province,
                    province_settlement_judges.c.judge_id,
                ],
                set_={k: v for k, v in values.items() if k not in ("province", "judge_id")},
            )
        )


# ---------------------------------------------------------------------------
# Hale meczow (miasto z publicznego API)
# ---------------------------------------------------------------------------

#: Ile zapytan o hale naraz. Publiczne API rozgrywek to jedna maszyna zwiazku.
VENUE_CONCURRENCY = 6

#: Po tylu dniach pytamy o hale drugi raz - ale TYLKO przy meczach, ktore
#: dopiero maja sie odbyc. Hali rozegranego meczu nikt juz nie zmieni.
VENUE_TTL_DAYS = 14


async def _resolve_venues(
    client: AsyncClient, wanted: dict[str, Optional[datetime]]
) -> dict[str, dict]:
    """
    Miasto i nazwa hali kazdego meczu - z publicznego API, z pamiecia w bazie.

    ⚠ To jest miejsce, w ktorym rozstrzyga sie CALA lista kosztow przejazdow.
    Terminarz podaje hale jednym napisem i scraper zgaduje, gdzie konczy sie
    nazwa obiektu, a zaczyna miasto; przy dwuczlonowej nazwie „miastem" zostawala
    hala i trasa wygladala jak „Bystra-Hala Sportowa-Bystra", a odleglosc szla do
    Google z nazwa obiektu. API podaje `Hala_miasto` wprost.

    Pierwszy przebieg okregu pyta o kazdy mecz swojej obsady raz, nastepne czytaja
    `zprp_match_venues` i pytaja tylko o mecze nowe oraz jeszcze nierozegrane.
    """
    if not wanted:
        return {}

    now = _now()
    cached: dict[str, dict] = {}
    ids = sorted(wanted.keys())
    # Porcjami - `IN` z kilkoma tysiacami wartosci potrafi przekroczyc limit
    # parametrow zapytania.
    for start in range(0, len(ids), 500):
        rows = await database.fetch_all(
            select(zprp_match_venues).where(
                zprp_match_venues.c.match_id.in_(ids[start : start + 500])
            )
        )
        for row in rows:
            cached[_s(row["match_id"])] = dict(row)

    stale: list[str] = []
    for match_id, match_at in wanted.items():
        hit = cached.get(match_id)
        if not hit or not _s(hit.get("city")):
            stale.append(match_id)
            continue
        fetched_at = hit.get("fetched_at")
        upcoming = match_at is None or match_at >= now - timedelta(days=1)
        if upcoming and (fetched_at is None or (now - fetched_at) > timedelta(days=VENUE_TTL_DAYS)):
            stale.append(match_id)

    if stale:
        semaphore = asyncio.Semaphore(VENUE_CONCURRENCY)

        async def one(match_id: str) -> None:
            # Zapytanie I zapis pod tym samym semaforem: bez tego kilkaset zadan
            # naraz siadaloby na pule polaczen do bazy.
            async with semaphore:
                venue = await fetch_venue(client, match_id)
                if not venue:
                    return
                cached[match_id] = {**venue, "match_id": match_id, "fetched_at": now}
                statement = pg_insert(zprp_match_venues).values(
                    match_id=match_id,
                    city=venue["city"],
                    hall=venue["hall"],
                    street=venue["street"],
                    number=venue["number"],
                    fetched_at=now,
                )
                await database.execute(
                    statement.on_conflict_do_update(
                        index_elements=[zprp_match_venues.c.match_id],
                        set_={
                            "city": venue["city"],
                            "hall": venue["hall"],
                            "street": venue["street"],
                            "number": venue["number"],
                            "fetched_at": now,
                        },
                    )
                )

        await asyncio.gather(*(one(match_id) for match_id in stale))

    return cached


# ---------------------------------------------------------------------------
# Zapis
# ---------------------------------------------------------------------------

async def _store(
    province: str,
    rows: list[dict],
    judges: dict[str, dict],
    *,
    scope: Optional[set[str]] = None,
    current: str = "",
) -> int:
    """
    Zapis obsad i gaszenie tych, ktorych przebieg nie widzial.

    ⚠ Gasimy WYLACZNIE w sezonach, ktore przebieg pobieral (`scope`). Przebieg
    samego biezacego sezonu nie widzi historii - bez tej granicy kazde dobowe
    odswiezenie zgasiloby wszystkie minione sezony.
    """
    now = _now()
    seen: set[tuple[str, str]] = set()

    for row in rows:
        judge = judges.get(row["judge_id"]) or {}
        values = {
            "province": province,
            "judge_id": row["judge_id"],
            "match_key": row["match_key"],
            "season": row.get("season"),
            "match_at": row.get("match_at"),
            "match_code": row.get("match_code"),
            "role": row.get("role"),
            "level": row.get("level"),
            "origin": row.get("origin"),
            "city": row.get("city"),
            "hall": row.get("hall"),
            "home_city": _s(judge.get("city")),
            "teams": row.get("teams"),
            "round_text": row.get("round_text"),
            "series_text": row.get("series_text"),
            "distance_km": row.get("distance_km"),
            "distance_source": row.get("distance_source"),
            "approved": row.get("approved"),
            "active": True,
            "last_seen_at": now,
            "updated_at": now,
        }
        statement = pg_insert(province_settlement_matches).values(**values)
        await database.execute(
            statement.on_conflict_do_update(
                index_elements=[
                    province_settlement_matches.c.province,
                    province_settlement_matches.c.judge_id,
                    province_settlement_matches.c.match_key,
                ],
                set_={k: v for k, v in values.items() if k not in ("province", "judge_id", "match_key")},
            )
        )
        seen.add((row["judge_id"], row["match_key"]))

    # Obsady, ktorych ten przebieg NIE widzial, gasna. Nie kasujemy ich: mecz
    # zdjety i przywrocony ma wrocic z ta sama historia, a nie jako nowy.
    stale = await database.fetch_all(
        select(
            province_settlement_matches.c.judge_id,
            province_settlement_matches.c.match_key,
            province_settlement_matches.c.match_at,
        ).where(
            and_(
                province_settlement_matches.c.province == province,
                province_settlement_matches.c.active.is_(True),
            )
        )
    )
    dropped = 0
    for row in stale:
        key = (_s(row["judge_id"]), _s(row["match_key"]))
        if key in seen:
            continue
        # Sezon, ktorego ten przebieg nie pobieral - nie jego sprawa.
        if not in_scope(row["match_at"], scope, current=current):
            continue
        await database.execute(
            update(province_settlement_matches)
            .where(
                and_(
                    province_settlement_matches.c.province == province,
                    province_settlement_matches.c.judge_id == key[0],
                    province_settlement_matches.c.match_key == key[1],
                )
            )
            .values(active=False, updated_at=now)
        )
        dropped += 1
    return dropped


# ---------------------------------------------------------------------------
# Przebieg
# ---------------------------------------------------------------------------

async def start_run(province: str, kind: str) -> int:
    """Wiersz przebiegu, zanim cokolwiek ruszy - jego numer dostaje klient."""
    new_id = await database.execute(
        insert(province_settlement_runs).values(
            province=canonical(province) or province, kind=kind, started_at=_now()
        )
    )
    return int(new_id)


async def refresh_province(
    province: str,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
    kind: str = "cron",
    with_outside: bool = True,
    full_check: bool = False,
    run_id: Optional[int] = None,
) -> dict:
    """
    Odswiezenie danych okregu - SEZONAMI.

    Ktore sezony, decyduje `settlement_seasons.plan_seasons`: pierwsze pobranie
    w historii okregu bierze wszystkie od poczatku, kolejne (takze dobowe) tylko
    biezacy, a `full_check` - reczne puszczenie z panelu - nadrabia sezony
    nigdy nie pobrane w calosci.

    `username`/`password` podaje panel (poswiadczenia VIP-a); bez nich schodzimy
    do konta `sync` z Railway. Brak obu to nie awaria, tylko okreg jeszcze
    nieskonfigurowany - i tak to raportujemy.
    """
    province = canonical(province)
    if not province:
        return {"province": "", "ok": False, "error": "Nieznane województwo"}
    settings = get_settings()

    # Przebieg na zadanie ma juz swoj wiersz - zalozyl go endpoint, zeby od razu
    # oddac klientowi numer do sledzenia. Petla dobowa zaklada go tutaj.
    if run_id is None:
        run_id = await start_run(province, kind)

    async def finish(ok: bool, **fields: Any) -> dict:
        await database.execute(
            update(province_settlement_runs)
            .where(province_settlement_runs.c.id == int(run_id))
            .values(finished_at=_now(), ok=ok, **fields)
        )
        return {"province": province, "ok": ok, **fields}

    credentials = (username, password) if username and password else credentials_for(province, "sync")
    if not credentials or not credentials[0] or not credentials[1]:
        return await finish(False, error="Brak konta ZPRP dla tego okręgu")

    async def beat() -> None:
        """Znak zycia przebiegu - patrz `settlement_runs.run_is_active`."""
        try:
            await database.execute(
                update(province_settlement_runs)
                .where(province_settlement_runs.c.id == int(run_id))
                .values(heartbeat_at=_now())
            )
        except Exception:
            pass  # znak zycia to wygoda, nie warunek przebiegu

    async def pulse() -> None:
        # Co minute przez CALY przebieg - takze na etapie hal i odleglosci,
        # ktory przy pobraniu wszystkich sezonow potrafi trwac dlugo.
        while True:
            await asyncio.sleep(60)
            await beat()

    pulse_task = asyncio.create_task(pulse())

    try:
        async with AsyncClient(
            base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0
        ) as client, AsyncClient(follow_redirects=True, timeout=30.0) as public:
            cookies = await _login_zprp_and_get_cookies(client, credentials[0], credentials[1])

            judges = await _load_judges(client, cookies, province)
            if not judges:
                return await finish(False, error="Nie udało się odczytać listy sędziów okręgu")
            await _store_judges(province, judges)

            # --- ktore sezony ---
            current = season_of(_now())
            done_rows = await database.fetch_all(
                select(province_settlement_seasons.c.season).where(
                    province_settlement_seasons.c.province == province
                )
            )
            completed = {_s(row["season"]) for row in done_rows}
            available = await discover_seasons(client, cookies, judges) if with_outside else set()
            plan = plan_seasons(
                available=available,
                completed=completed,
                current=current,
                full_check=full_check,
            )
            scope = set(plan)
            await database.execute(
                update(province_settlement_runs)
                .where(province_settlement_runs.c.id == int(run_id))
                .values(seasons=",".join(plan), heartbeat_at=_now())
            )
            logger.info(
                "[settlement] %s: sezony %s (pobrane w calosci: %d, reczne sprawdzenie: %s)",
                province, plan, len(completed), full_check,
            )

            # Terminarz okregu tylko z sezonow tego przebiegu - reszta zostaje,
            # jak jest (patrz `_store`).
            district = [
                row for row in await _collect_district(province, judges)
                if in_scope(row.get("match_at"), scope, current=current)
            ]
            district_ids = {row["match_key"].split(":", 1)[1] for row in district}

            outside: list[dict] = []
            season_ok: dict[str, bool] = {}
            if with_outside:
                outside, season_ok = await _collect_outside(
                    client,
                    cookies,
                    judges,
                    district_ids,
                    seasons=plan,
                    current=current,
                    beat=beat,
                )

            rows = district + outside

            # --- miasta hal ---
            # Publiczne API meczu zamiast zgadywania z terminarza. Pytamy tylko
            # o mecze WLASNEJ obsady, wiec to kilkaset zapytan, nie kilka tysiecy.
            wanted_ids: dict[str, Optional[datetime]] = {}
            for row in rows:
                match_id = _s(str(row["match_key"]).split(":", 1)[-1])
                if match_id and match_id not in wanted_ids:
                    wanted_ids[match_id] = row.get("match_at")
            venues = await _resolve_venues(public, wanted_ids)
            for row in rows:
                match_id = _s(str(row["match_key"]).split(":", 1)[-1])
                venue = venues.get(match_id) or {}
                scraped = _s(row.get("city"))
                # API jest zrodlem prawdy; napis z terminarza wchodzi tylko
                # wtedy, gdy w ogole wyglada na miejscowosc. Inaczej mecz zostaje
                # bez dojazdu - to widac i da sie poprawic, w przeciwienstwie do
                # kilometrow policzonych do nazwy hali.
                row["city"] = _s(venue.get("city")) or (
                    pretty_city(scraped) if looks_like_city(scraped) else ""
                )
                row["hall"] = _s(venue.get("hall")) or _s(row.get("hall"))

            # --- odleglosci ---
            distance_row = await database.fetch_one(
                select(okreg_distances.c.content).where(okreg_distances.c.province.in_(spellings(province)))
            )
            index = DistanceIndex(_state(distance_row["content"]) if distance_row else None)

            pairs = []
            for row in rows:
                home = _s((judges.get(row["judge_id"]) or {}).get("city"))
                city = _s(row.get("city"))
                if home and city:
                    pairs.append((home, city))

            resolved = await resolve_distances(pairs, index, client=public)
            for row in rows:
                home = _s((judges.get(row["judge_id"]) or {}).get("city"))
                city = _s(row.get("city"))
                hit = resolved.get((home, city)) if home and city else None
                row["distance_km"] = hit[0] if hit else None
                row["distance_source"] = hit[1] if hit else "none"

            await _store(province, rows, judges, scope=scope, current=current)

            # Rejestr sezonow pobranych w CALOSCI: tylko te, w ktorych lista
            # KAZDEGO sedziego dala sie odczytac. Sezon z dziura zostaje poza
            # rejestrem, wiec reczne puszczenie sprobuje go jeszcze raz.
            for label in plan:
                if not (with_outside and season_ok.get(label)):
                    continue
                count = sum(
                    1 for row in rows
                    if in_scope(row.get("match_at"), {label}, current=current)
                )
                stamp = _now()
                statement = pg_insert(province_settlement_seasons).values(
                    province=province,
                    season=label,
                    completed_at=stamp,
                    run_id=int(run_id),
                    matches=count,
                )
                await database.execute(
                    statement.on_conflict_do_update(
                        index_elements=[
                            province_settlement_seasons.c.province,
                            province_settlement_seasons.c.season,
                        ],
                        set_={"completed_at": stamp, "run_id": int(run_id), "matches": count},
                    )
                )

        return await finish(
            True,
            judges=len(judges),
            matches=len(rows),
            outside_matches=len(outside),
        )
    except Exception as exc:
        logger.exception("[settlement] odświeżanie %s nie powiodło się", province)
        return await finish(False, error=str(exc)[:500])
    finally:
        pulse_task.cancel()


async def last_run(province: str) -> Optional[dict]:
    row = await database.fetch_one(
        select(province_settlement_runs)
        .where(province_settlement_runs.c.province == (canonical(province) or province))
        .order_by(province_settlement_runs.c.started_at.desc())
        .limit(1)
    )
    return dict(row) if row else None


async def run_settlement_sync_scheduler() -> None:
    """
    Dobowa petla.

    Chodzi po wojewodztwach, ktore maja WLACZONY modul (statystyki albo
    rozliczenia) i skonfigurowane konto `sync`. Bledy jednego okregu nie
    zatrzymuja pozostalych.
    """
    await asyncio.sleep(90)  # niech serwer najpierw wstanie
    while True:
        try:
            wanted = set(await enabled_provinces("stats")) | set(await enabled_provinces("settlements"))
            configured = configured_provinces()
            for province in sorted(wanted):
                if province not in configured:
                    logger.info("[settlement] %s: moduł włączony, ale brak konta sync", province)
                    continue
                previous = await last_run(province)
                if previous and run_is_active(
                    previous.get("started_at"),
                    previous.get("finished_at"),
                    _now(),
                    previous.get("heartbeat_at"),
                ):
                    # Ktos wlasnie odswieza z panelu - nie dublujemy przebiegu.
                    continue
                if previous and previous.get("finished_at"):
                    age = _now() - previous["finished_at"]
                    if age < timedelta(hours=SYNC_INTERVAL_HOURS):
                        continue
                logger.info("[settlement] odświeżam %s", province)
                await refresh_province(province, kind="cron")
        except Exception:
            logger.exception("[settlement] pętla dobowa")
        await asyncio.sleep(30 * 60)
