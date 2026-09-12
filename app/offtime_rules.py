"""
Niedyspozycje sedziego - czy jest wolny o danej godzinie.

MODUL-LISC: bez bazy i sieci, zeby regula chodzila w tescie.

Dotad cala arytmetyka godzin siedziala w przegladarce
(`BAZA_web/components/unavailability/unavailabilityLogic.ts`), a serwer umial
tylko „ten sam dzien". Automat obsady musi to umiec sam, wiec regula jest tu
przeniesiona 1:1 - te same przypadki, te same krawedzie.

⚠ CZAS. Wpisy niedyspozycji z telefonu przychodza BEZ strefy i znacza czas
POLSKI; centralny snapshot ZPRP ma prawidlowy UTC. Terminy meczow w bazie
(`province_matches.match_at`) to z kolei czas polski PODPISANY jako UTC - tak
zapisuje je pobieranie. Dlatego wszystko sprowadzamy do sciany zegara
w Europe/Warsaw: `as_local` przyjmuje oba ksztalty.

⚠ MECZ w kalendarzu trwa 2 godziny od startu (tak liczy to aplikacja), a wpis
„BAZOWA" i wpis bez godziny koncowej sa CALODNIOWE.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Any, Iterable, Mapping, Optional

try:  # zoneinfo jest w bibliotece standardowej od 3.9
    from zoneinfo import ZoneInfo

    WARSAW = ZoneInfo("Europe/Warsaw")
except Exception:  # pragma: no cover - bez bazy stref liczymy po scianie zegara
    WARSAW = None  # type: ignore[assignment]

#: Mecz w kalendarzu sedziego zajmuje dwie godziny od startu.
MATCH_HOURS = 2

#: Domyslny zapas przy porownaniu z niedyspozycja - tyle samo co w aplikacji.
DEFAULT_TOLERANCE_MINUTES = 30


def _s(value: Any) -> str:
    return str(value or "").strip()


def _fold(value: Any) -> str:
    text = unicodedata.normalize("NFD", _s(value).lower())
    return "".join(ch for ch in text if unicodedata.category(ch) != "Mn").strip()


def as_local(value: Any) -> Optional[datetime]:
    """
    Dowolny zapis czasu jako NAIWNA sciana zegara w Polsce.

    Napis ze strefa idzie przez konwersje do Europe/Warsaw, napis bez strefy
    zostaje jak stoi, a `datetime` z `tzinfo=UTC` z naszej bazy traktujemy jak
    czas polski - bo tak go tam zapisano (patrz naglowek modulu).
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        text = _s(value).replace("Z", "+00:00")
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            try:
                moment = datetime.fromisoformat(text[:19])
            except ValueError:
                return None
    if moment.tzinfo is None:
        return moment
    if WARSAW is not None:
        return moment.astimezone(WARSAW).replace(tzinfo=None)
    return moment.replace(tzinfo=None)


def match_moment(value: Any) -> Optional[datetime]:
    """
    Termin meczu z bazy jako sciana zegara.

    ⚠ `province_matches.match_at` ma `tzinfo=UTC`, ale niesie godzine POLSKA.
    Konwersja stref przesunelaby mecz o dwie godziny, wiec strefe zdejmujemy.
    """
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    return as_local(value)


@dataclass(frozen=True)
class Offtime:
    """Jeden wpis niedyspozycji sprowadzony do przedzialu."""

    start: datetime
    end: datetime
    all_day: bool
    kind: str          # "MATCH" | "BAZOWE" | "NORMAL"
    label: str = ""

    def covers(self, moment: datetime) -> bool:
        return self.start <= moment <= self.end


@dataclass(frozen=True)
class TempCity:
    """Czasowa zmiana miasta sedziego (wyjazd) - liczy sie do kilometrow."""

    start: datetime
    end: datetime
    city: str


def _day_start(moment: datetime) -> datetime:
    return datetime.combine(moment.date(), time.min)


def _day_end(moment: datetime) -> datetime:
    return datetime.combine(moment.date(), time.max)


def _is_temp_city(item: Mapping[str, Any]) -> bool:
    return (
        _s(item.get("entry_type")).upper() == "TEMP_CITY"
        or item.get("is_temp_location") is True
        or bool(_s(item.get("temp_city_name")))
        or bool(_s(item.get("temp_city")))
        or _s(item.get("category_name")).upper() == "TEMP_CITY"
    )


def _is_match(item: Mapping[str, Any]) -> bool:
    return item.get("isMatch") is True or item.get("is_match") is True


def _is_bazowa(name: Any) -> bool:
    return _fold(name) in ("bazowa", "bazowe")


def parse_entries(raw: Any) -> tuple[list[Offtime], list[TempCity]]:
    """Wpisy z `data_json` sedziego jako przedzialy i zmiany miasta."""
    offtimes: list[Offtime] = []
    cities: list[TempCity] = []
    if not isinstance(raw, Iterable) or isinstance(raw, (str, bytes)):
        return offtimes, cities

    for item in raw:
        if not isinstance(item, Mapping):
            continue
        start = as_local(item.get("from"))
        if start is None:
            continue
        end_raw = as_local(item.get("to"))

        if _is_temp_city(item):
            city = _s(item.get("temp_city_name") or item.get("temp_city") or item.get("location"))
            if not city or end_raw is None:
                continue
            cities.append(TempCity(start=_day_start(start), end=_day_end(end_raw), city=city))
            continue

        category = _s(item.get("category_name"))
        match = _is_match(item)
        bazowa = not match and _is_bazowa(category)

        if match:
            kind = "MATCH"
            all_day = False
            end = start + timedelta(hours=MATCH_HOURS)
        elif bazowa:
            kind = "BAZOWE"
            all_day = True
            # „Bazowa" z realnym zakresem trwa do konca dnia `to`; minuta roznicy
            # to zapis jednodniowy, a nie przedzial.
            end = _day_end(end_raw) if end_raw and (end_raw - start) > timedelta(minutes=1) else _day_end(start)
            start = _day_start(start)
        else:
            kind = "NORMAL"
            all_day = end_raw is None
            if all_day:
                end = _day_end(start)
                start = _day_start(start)
            else:
                end = end_raw  # type: ignore[assignment]

        offtimes.append(
            Offtime(start=start, end=end, all_day=all_day, kind=kind, label=category or _s(item.get("info")))
        )

    offtimes.sort(key=lambda item: item.start)
    cities.sort(key=lambda item: item.start)
    return offtimes, cities


def blocking_offtime(
    offtimes: Iterable[Offtime],
    moment: Optional[datetime],
    *,
    tolerance_minutes: int = DEFAULT_TOLERANCE_MINUTES,
) -> Optional[Offtime]:
    """
    Wpis, ktory zajmuje sedziemu ten termin - albo None.

    Zapas dziala TYLKO przy krawedziach: wpis konczacy sie kwadrans przed meczem
    nie blokuje, ale wpis w srodku dnia blokuje niezaleznie od zapasu. Tak samo
    liczy to aplikacja.
    """
    if moment is None:
        return None
    tolerance = timedelta(minutes=max(0, tolerance_minutes))
    for off in offtimes:
        if not off.covers(moment):
            continue
        near_edge = (moment - off.start) <= tolerance or (off.end - moment) <= tolerance
        if not near_edge:
            return off
    return None


def is_available_at(
    offtimes: Iterable[Offtime],
    moment: Optional[datetime],
    *,
    tolerance_minutes: int = DEFAULT_TOLERANCE_MINUTES,
) -> bool:
    """Czy sedzia jest wolny w tym terminie. Brak terminu = nie wiemy, wiec wolny."""
    return blocking_offtime(offtimes, moment, tolerance_minutes=tolerance_minutes) is None


def busy_minutes_on_day(offtimes: Iterable[Offtime], day: date) -> int:
    """Ile minut tego dnia sedzia ma zajete - do mikropodgladu w panelu."""
    start = datetime.combine(day, time.min)
    end = datetime.combine(day, time.max)
    total = 0
    for off in offtimes:
        first = max(off.start, start)
        last = min(off.end, end)
        if last > first:
            total += int((last - first).total_seconds() // 60)
    return min(total, 24 * 60)


def city_at(base_city: str, cities: Iterable[TempCity], moment: Optional[datetime]) -> str:
    """Miasto sedziego w danym dniu - z czasowa zmiana, gdy akurat gdzies wyjechal."""
    if moment is not None:
        for item in cities:
            if item.start <= moment <= item.end:
                return item.city
    return _s(base_city)
