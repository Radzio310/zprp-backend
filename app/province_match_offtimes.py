"""Mecze sędziego jako wpisy kalendarza okręgowego.

MODUŁ-LIŚĆ: sama reguła zamiany meczu na wpis, bez bazy i bez sieci, żeby dało
się ją sprawdzić testem. Jedyna funkcja, która schodzi do bazy
(`province_match_entries`), importuje ją DOPIERO W CIELE - `app/db.py` łączy
się z bazą już przy imporcie.

DLACZEGO TO ISTNIEJE. Kalendarz okręgowy składa się przy odczycie z trzech
źródeł: zapisu z telefonu, centralnego snapshotu ZPRP i kalendarzy sędziego
(iCal). Mecze były w tym zestawie wyjątkiem - trafiały tam WYŁĄCZNIE wtedy,
gdy sędzia sam wszedł w niedyspozycje w aplikacji i nacisnął „Zapisz zmiany".
Kto nie wszedł, ten dla mastera okręgowego wyglądał na wolnego; a to, co
wysłał miesiąc temu, wisiało dalej, nawet gdy mecz odwołano albo przesunięto.

Tymczasem serwer ma te mecze od dawna i świeższe: `province_match_monitor`
czyta prywatną listę meczów KAŻDEGO aktywnego sędziego okręgu co kilkanaście
minut i zapisuje je w `province_matches` / `province_match_judges`. Z tego
samego zbioru żyją Rozliczenia, statystyki okręgowe i obciążenie w automacie
obsadowym. Tutaj dokładamy go jako czwarte źródło kalendarza.

⚠ TELEFON DALEJ SWOJE WYSYŁA i celowo mu tego nie zabieramy - starsza wersja
aplikacji nie zniknie z dnia na dzień. Dlatego przy odczycie odsiewamy te jego
wpisy meczowe, które opisują mecz znany serwerowi (`without_client_duplicates`).
Porównujemy po NUMERZE ZAWODÓW (`IdZawody`), nie po numerze meczu - numer meczu
nie jest kluczem.

⚠ CZAS. `data_fakt` przychodzi ze ZPRP bez strefy i znaczy godzinę POLSKĄ,
`province_matches.match_at` jest już przeliczone na UTC. Oddajemy zawsze UTC
z jawną strefą, tak jak snapshot centralny i kalendarze iCal - przeglądarka
robi z tego `new Date(...)` i pokazuje właściwą godzinę.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional

try:  # zoneinfo jest w bibliotece standardowej od 3.9
    from zoneinfo import ZoneInfo

    WARSAW: Optional[ZoneInfo] = ZoneInfo("Europe/Warsaw")
except Exception:  # pragma: no cover - bez bazy stref zostaje sama ściana zegara
    WARSAW = None  # type: ignore[assignment]

from app.calendar_feed_rules import judge_key

#: Znacznik źródła. Po nim poznajemy wpis meczowy złożony przez serwer -
#: i tylko po nim, bo wpis z telefonu takiego pola nie ma.
MATCH_SOURCE = "ZPRP_MATCH_SYNC"

#: Przedrostek identyfikatora. Własny, żeby wpis serwerowy nigdy nie udawał
#: wpisu ręcznego i żeby dało się go rozpoznać gołym okiem w odpowiedzi.
MATCH_ID_PREFIX = "zprp-match:"

#: Mecz zajmuje w kalendarzu dwie godziny od startu - dokładnie tak liczy to
#: aplikacja (`matchToUnavail`) i reguła dostępności (`offtime_rules`).
MATCH_HOURS = 2

#: Jak głęboko w przeszłość sięgamy. Tyle samo, ile wysyła telefon, więc widok
#: okręgowy nie zmienia zasięgu - zmienia się tylko jego kompletność.
MATCH_PAST_DAYS = 30

#: Nazwa kategorii, gdy ZPRP nie podał kodu rozgrywek. Aplikacja i tak
#: rozpoznaje mecz po `isMatch`, ale „MECZ" jest czytelne na kafelku.
MATCH_FALLBACK_CATEGORY = "MECZ"


def _clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _id_key(value: Any) -> str:
    """Numer zawodów sprowadzony do porównywalnej postaci.

    Ten sam mecz bywa zapisany jako „0123456" i „123456" - telefon bierze go
    z pliku, serwer z listy sędziego. Porównanie znak w znak potrafiłoby po
    cichu nie znaleźć nic i mecz pokazałby się dwa razy.
    """
    text = _clean(value).replace(" ", "")
    if text.isdigit():
        return text.lstrip("0") or "0"
    return text.upper()


def parse_match_moment(value: Any) -> Optional[datetime]:
    """Termin meczu jako moment w UTC - z napisu ZPRP albo z kolumny bazy."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        raw = _clean(value).replace("T", " ").replace("Z", "+00:00")
        if not raw:
            return None
        try:
            moment = datetime.fromisoformat(raw)
        except ValueError:
            try:
                moment = datetime.fromisoformat(raw[:19])
            except ValueError:
                return None
    if moment.tzinfo is None:
        # Bez strefy znaczy czas polski - tak podaje go ZPRP.
        moment = moment.replace(tzinfo=WARSAW or timezone.utc)
    return moment.astimezone(timezone.utc)


def match_window_start(now: Optional[datetime] = None) -> datetime:
    """Od kiedy w przeszłość zbieramy mecze do kalendarza."""
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc) - timedelta(days=MATCH_PAST_DAYS)


def match_venue(state: Mapping[str, Any]) -> str:
    """Miasto i adres hali - puste człony pomijamy, żeby nie zostały przecinki."""
    city = _clean(state.get("Hala_miasto"))
    street = " ".join(
        part
        for part in (_clean(state.get("Hala_ulica")), _clean(state.get("Hala_numer")))
        if part
    )
    return ", ".join(part for part in (city, street) if part)


def match_title(state: Mapping[str, Any]) -> str:
    host = _clean(state.get("ID_zespoly_gosp_ZespolNazwa"))
    guest = _clean(state.get("ID_zespoly_gosc_ZespolNazwa"))
    teams = " - ".join(part for part in (host, guest) if part)
    return teams or MATCH_FALLBACK_CATEGORY


def match_entry(
    match_id: Any,
    state: Mapping[str, Any],
    *,
    match_at: Any = None,
    synced_at: Optional[datetime] = None,
) -> Optional[dict[str, Any]]:
    """Mecz jako wpis kalendarza - kształt wspólny z resztą źródeł.

    Bez terminu nie ma czego wstawiać w kalendarz, więc taki mecz pomijamy
    zamiast zgadywać godzinę.
    """
    identifier = _clean(match_id)
    if not identifier:
        return None

    moment = parse_match_moment(
        state.get("data_fakt") or state.get("data_prop")
    ) or parse_match_moment(match_at)
    if moment is None:
        return None

    stamp = (synced_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    code = _clean(state.get("RozgrywkiCode"))

    return {
        "entry_type": "UNAVAIL",
        "id": f"{MATCH_ID_PREFIX}{identifier}",
        "source": MATCH_SOURCE,
        "source_match_id": identifier,
        "source_synced_at": stamp.isoformat(),
        "from": moment.isoformat(),
        "to": (moment + timedelta(hours=MATCH_HOURS)).isoformat(),
        "info": match_title(state),
        "location": match_venue(state),
        "category_id": None,
        "category_name": code or MATCH_FALLBACK_CATEGORY,
        "category_color": None,
        "color": None,
        "is_manual": False,
        "is_global": True,
        "isMatch": True,
    }


def is_match_entry(item: Any) -> bool:
    """Czy wpis meczowy złożył serwer (a nie telefon)."""
    if not isinstance(item, dict):
        return False
    return _clean(item.get("source")).upper() == MATCH_SOURCE


def client_match_id(item: Any) -> str:
    """Numer zawodów spod MECZOWEGO wpisu z telefonu - inaczej pusty napis.

    Aplikacja zapisuje mecz pod jego `Id` ze ZPRP, czyli tym samym numerem
    zawodów, którego używa monitor. To jedyne, po czym da się poznać, że dwa
    wpisy opisują ten sam mecz.
    """
    if not isinstance(item, dict):
        return ""
    if is_match_entry(item):
        return ""
    if not (item.get("isMatch") or item.get("is_match")):
        return ""
    return _id_key(item.get("id"))


def without_client_duplicates(
    entries: Iterable[Any],
    server_entries: Iterable[Any],
) -> list[dict[str, Any]]:
    """Odsiej z zapisu telefonu te mecze, które serwer zna lepiej.

    Nie odsiewamy wszystkich meczów z telefonu - tylko te, których dokładny
    odpowiednik właśnie dokładamy. Mecz, o którym monitor nie wie (np. spoza
    jego zasięgu), zostaje w kalendarzu, bo lepszy taki niż żaden.
    """
    known = {
        _id_key(item.get("source_match_id"))
        for item in server_entries
        if isinstance(item, dict) and _clean(item.get("source_match_id"))
    }
    known.discard("")

    kept: list[dict[str, Any]] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        key = client_match_id(item)
        if key and key in known:
            continue
        kept.append(item)
    return kept


def entries_by_judge(
    rows: Iterable[Mapping[str, Any]],
    *,
    judge_keys: Optional[Iterable[str]] = None,
    synced_at: Optional[datetime] = None,
) -> dict[str, list[dict[str, Any]]]:
    """Wiersze z bazy jako mapa: numer sędziego -> jego wpisy meczowe."""
    wanted = {judge_key(value) for value in judge_keys} if judge_keys is not None else None
    stamp = synced_at or datetime.now(timezone.utc)

    out: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = judge_key(row["judge_id"])
        if wanted is not None and key not in wanted:
            continue
        entry = match_entry(
            row["match_id"],
            row["state"] if isinstance(row["state"], Mapping) else {},
            match_at=row.get("match_at"),
            synced_at=stamp,
        )
        if entry is None:
            continue
        bucket = out.setdefault(key, [])
        # Ten sam mecz potrafi wisieć u sędziego w kilku rolach naraz.
        if any(existing["id"] == entry["id"] for existing in bucket):
            continue
        bucket.append(entry)

    for bucket in out.values():
        bucket.sort(key=lambda item: (item["from"], item["id"]))
    return out


async def province_match_entries(
    province: Optional[str],
    *,
    judge_keys: Optional[Iterable[str]] = None,
    now: Optional[datetime] = None,
) -> dict[str, list[dict[str, Any]]]:
    """Wpisy meczowe okręgu, prosto z tabel monitora meczów.

    Jedno zapytanie o cały okrąg zamiast pytania na sędziego - okrąg ma ich
    dwustu, a mecze i tak czytamy w całości.
    """
    from sqlalchemy import and_, select

    from app.db import database, province_match_judges, province_matches
    from app.match_market_rules import state_dict
    from app.settlement_province import spellings

    cutoff = match_window_start(now)

    joined = province_match_judges.join(
        province_matches,
        and_(
            province_matches.c.province == province_match_judges.c.province,
            province_matches.c.match_id == province_match_judges.c.match_id,
        ),
    )
    query = (
        select(
            province_match_judges.c.judge_id,
            province_matches.c.match_id,
            province_matches.c.match_at,
            province_matches.c.state_json,
        )
        .select_from(joined)
        .where(
            and_(
                province_match_judges.c.active.is_(True),
                province_matches.c.active.is_(True),
                province_matches.c.match_at.is_not(None),
                province_matches.c.match_at >= cutoff,
            )
        )
    )
    if province:
        # Ten sam okrąg leży w bazie pod kilkoma pisowniami („ŚLĄSKIE",
        # „SLASKIE", „slaskie") - pytamy o wszystkie, tak jak automat obsadowy.
        variants = spellings(province)
        if not variants:
            return {}
        query = query.where(province_matches.c.province.in_(variants))

    rows = await database.fetch_all(query)
    return entries_by_judge(
        (
            {
                "judge_id": row["judge_id"],
                "match_id": row["match_id"],
                "match_at": row["match_at"],
                "state": state_dict(row["state_json"]),
            }
            for row in rows
        ),
        judge_keys=judge_keys,
    )
