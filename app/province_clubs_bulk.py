"""
Panel klubow - akcje grupowe.

Lisc bez bazy i bez HTTP: tylko regula, co wolno zrobic jednym kliknieciem dla
wielu klubow naraz. Warstwa HTTP (`province_clubs`) zamienia ValueError na 400.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Iterable, Optional

#: Tyle klubow przyjmuje jedna akcja grupowa. Okreg ma ich od kilkudziesieciu
#: do kilkuset - wiecej to juz pomylka w zaznaczeniu, a nie praca.
BULK_LIMIT = 500


def clean_club_ids(raw: Optional[Iterable[Any]]) -> list[str]:
    """Numery klubow z zaznaczenia: bez pustych i powtorzen, w kolejnosci klikniec."""
    out: list[str] = []
    seen: set[str] = set()
    for value in raw or []:
        club_id = str(value or "").strip()
        if club_id and club_id not in seen:
            seen.add(club_id)
            out.append(club_id)
    if not out:
        raise ValueError("Nie zaznaczono żadnego klubu")
    if len(out) > BULK_LIMIT:
        raise ValueError(f"Za dużo klubów naraz - limit to {BULK_LIMIT}")
    return out


def settles_since(settles: bool, since: Optional[date], today: date) -> Optional[date]:
    """
    Od kiedy klub NIE rozlicza sie przez okreg.

    Wlaczenie czysci date - obciazenia wracaja za caly sezon, tak samo jak przy
    pojedynczym klubie. Wylaczenie dziala od podanego dnia, a bez niego od dzis:
    historia zostaje obciazona.
    """
    if settles:
        return None
    return since or today


def table_since(
    table_by_club: int,
    requested: Optional[date],
    previous: int,
    previous_since: Optional[date],
    today: date,
) -> Optional[date]:
    """
    Od kiedy deklaracja „drugiego stolikowego stawia klub" dziala na obciazenia.

    - bez deklaracji data znika - klub placi za cala obsade,
    - podana data wygrywa (np. poczatek sezonu z pisma okregu),
    - deklaracja, ktora juz obowiazywala, ZACHOWUJE swoja date. Zapis z panelu,
      ktory rusza cos innego (miejscowi, notatka), nie moze jej przesunac na
      dzis - inaczej mecze od poczatku sezonu wrocilyby klubowi na rachunek,
    - nowa deklaracja bez daty dziala od dzis: historia zostaje nietknieta.
    """
    if int(table_by_club or 0) <= 0:
        return None
    if requested is not None:
        return requested
    if int(previous or 0) > 0:
        return previous_since
    return today


def parse_club_filter(raw: Optional[str]) -> Optional[set[str]]:
    """`club_ids=12,15,19` z adresu szablonu. Pusty napis znaczy „wszystkie"."""
    if not raw:
        return None
    ids = {part.strip() for part in str(raw).split(",") if part.strip()}
    return ids or None


# ---------------------------------------------------------------------------
# Rozliczenie sezonu poza systemem
# ---------------------------------------------------------------------------

#: Wpis, ktorym sezon rozliczony poza aplikacja schodzi do zera. Wstecz nie
#: dopisujemy klubom wplat (decyzja z 11.09.2026), wiec bez niego kazdy klub
#: minionego sezonu wisial na minusie.
SEASON_CLOSE_SOURCE = "season-close"


def entry_bucket(kind: Any, source: Any) -> str:
    """Trzy kubelki salda: wplata, wyplata i rozliczenie sezonu poza systemem."""
    if str(source or "").strip() == SEASON_CLOSE_SOURCE:
        return "settled"
    return "out" if str(kind or "").strip().lower().startswith("out") else "in"


def closing_amounts(
    balances: dict[str, float],
    existing: dict[str, float],
    selected: Optional[set[str]] = None,
) -> dict[str, float]:
    """
    Kwota wpisu „rozliczenie sezonu" na klub, po ktorej saldo sezonu = 0.

    Saldo juz zawiera poprzedni wpis, wiec nowa kwota to stara MINUS saldo: dlug
    powieksza wpis (mecz doszedl po zamknieciu), nadwyzka go zmniejsza (mecz
    zdjety), nigdy ponizej zera - 0 znaczy, ze wpis znika. Klubu bez dlugu
    i bez wpisu nie ruszamy: nadplaty sie nie zeruje.

    `selected` zaweza do wskazanych klubow; bez niego - kazdy klub na minusie
    i kazdy, kto ma juz wpis.
    """
    if selected is None:
        candidates = {club_id for club_id, value in balances.items() if value < 0} | set(existing)
    else:
        candidates = set(selected)
    out: dict[str, float] = {}
    for club_id in sorted(candidates):
        balance = round(float(balances.get(club_id, 0) or 0), 2)
        before = round(float(existing.get(club_id, 0) or 0), 2)
        if before <= 0 and balance >= 0:
            continue
        out[club_id] = max(0.0, round(before - balance, 2))
    return out


def closing_day(season_end: date, today: date) -> date:
    """Data wpisu: koniec sezonu, a dla sezonu, ktory jeszcze trwa - dzisiaj."""
    return min(season_end, today)


def newest_rule_per_club(rows: Iterable[Any], canonical_key: str) -> dict[str, Any]:
    """
    Jedna deklaracja obsadowa na klub z wierszy pod WSZYSTKIMI pisowniami okręgu.

    `province_club_assignment` bywał zapisywany jako „ŚLĄSKIE" i jako „SLASKIE".
    Odczyty biorą obie pisownie (`spellings`), a słownik po numerze klubu
    zostawiał ten wiersz, który baza oddała jako ostatni - często STARY. Nowy
    zapis ląduje pod kluczem kanonicznym, więc panel pokazywał znowu stare zero
    i wyglądało to, jakby serwer kasował „4. sędziego" (23.09.2026).

    Wygrywa najświeższy `updated_at`; przy remisie albo braku dat - wiersz pod
    kluczem kanonicznym.
    """
    from datetime import datetime, timezone

    floor = datetime.min.replace(tzinfo=timezone.utc)

    def rank(row: Any) -> tuple:
        stamp = row["updated_at"] if "updated_at" in row.keys() else None
        if stamp is not None and stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return (stamp or floor, str(row["province"] or "") == canonical_key)

    out: dict[str, Any] = {}
    for row in rows:
        club_id = str(row["club_id"] or "").strip()
        if not club_id:
            continue
        if club_id not in out or rank(row) > rank(out[club_id]):
            out[club_id] = row
    return out
