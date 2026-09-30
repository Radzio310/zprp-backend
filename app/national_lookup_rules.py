"""Reguła źródeł kilometrów z ogólnopolską tabelą ZPRP - liść bez bazy.

Decyzja użytkownika z 30.09.2026 - JEDNA reguła w aplikacji, w BAZA_web
i na serwerze:

  * mecz OKRĘGOWY: to samo miasto (0 km) -> tabela odległości okręgu ->
    ogólnopolska tabela ZPRP -> Google,
  * mecz szczebla CENTRALNEGO (`settlement_rates.is_central_level_competition`,
    czyli także puchary): to samo miasto -> tabela ZPRP -> Google. Tabela
    okręgu nie służy do meczów centralnych.

Tabela wygrywa wszędzie, także w archiwum (minione sezony przeliczają się
na nowo). Kilometry wpisane ręcznie (źródło „manual") nigdy nie są
nadpisywane - tego pilnują wołający, bo tylko oni wiedzą, co wpisano.

Ogólnopolska tabela to kilometry potwierdzone oficjalnymi ryczałtami PDF
ZPRP (`app/national_distances.py`). Połączenie leży tam raz, pod kluczami
`normalize_city_key` ułożonymi alfabetycznie. Terminarz i lista sędziów
piszą te same miejscowości różnie („Piekary Śl.", „Piekary Śląskie",
„41-940 Piekary Śl., ul. ..."), więc szukamy po kilku wariantach klucza.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional

from app.national_distance_parser import clean_city, normalize_city_key
from app.settlement_distances import normalize_city

SOURCE_SAME_CITY = "same-city"
SOURCE_TABLE = "table"
SOURCE_NATIONAL = "zprp-table"
SOURCE_GOOGLE = "google"
SOURCE_HISTORY = "history"
SOURCE_MANUAL = "manual"
SOURCE_NONE = "none"

#: Podpis źródła tam, gdzie serwer je drukuje.
NATIONAL_LABEL = "wg tabeli odległości ZPRP"
#: Stopka wydruków przy kilometrach z tabeli ZPRP.
NATIONAL_FOOTNOTE = "* km wg tabeli odległości ZPRP (potwierdzone oficjalnymi ryczałtami)"

_DISTRICT_ORDER = (SOURCE_SAME_CITY, SOURCE_TABLE, SOURCE_NATIONAL, SOURCE_GOOGLE)
_CENTRAL_ORDER = (SOURCE_SAME_CITY, SOURCE_NATIONAL, SOURCE_GOOGLE)


def distance_order(is_central: bool) -> list[str]:
    """Kolejność źródeł kilometrów według szczebla meczu."""
    return list(_CENTRAL_ORDER if is_central else _DISTRICT_ORDER)


def lookup_keys(raw: Any) -> list[str]:
    """
    Warianty klucza jednej miejscowości - od najbardziej dosłownego.

    1. `normalize_city_key(clean_city(...))` - dokładnie tak, jak klucz
       zapisuje harvester ryczałtów,
    2. część przed przecinkiem bez kodu pocztowego (adres hali),
    3. rozwinięte skróty jak w tabeli okręgu („Śl." -> „Śląskie"),
    4. te same warianty bez spacji („PiekarySl").
    """
    text = str(raw or "")
    out: list[str] = []

    def put(value: str) -> None:
        if value and value not in out:
            out.append(value)

    put(normalize_city_key(clean_city(text)))
    head = re.sub(r"^\s*\d{2}-\d{3}\s*", "", text.split(",")[0])
    put(normalize_city_key(clean_city(head)))
    base, _ = normalize_city(text)
    put(normalize_city_key(base))
    for key in list(out):
        put(key.replace(" ", ""))
    return out


def _canonical(a: str, b: str) -> tuple[str, str]:
    return (a, b) if a <= b else (b, a)


def expand_pairs(pairs_map: Mapping[tuple[str, str], Any]) -> dict[tuple[str, str], int]:
    """
    Mapa z tabeli ZPRP uzupełniona o warianty kluczy obu miast.

    Budowana RAZ przy wczytaniu tabeli - potem każde zapytanie to kilka
    odczytów słownika. Dosłowny klucz zawsze wygrywa z wariantem: gdy dwa
    różne połączenia dają ten sam wariant, zostaje pierwsze dosłowne.
    """
    out: dict[tuple[str, str], int] = {}
    for (a, b), km in pairs_map.items():
        try:
            value = int(km)
        except (TypeError, ValueError):
            continue
        if not a or not b or a == b:
            continue
        out[_canonical(a, b)] = value
    for (a, b), km in pairs_map.items():
        try:
            value = int(km)
        except (TypeError, ValueError):
            continue
        if not a or not b or a == b:
            continue
        for left in lookup_keys(a):
            for right in lookup_keys(b):
                if left == right:
                    continue
                out.setdefault(_canonical(left, right), value)
    return out


def same_city(a: Any, b: Any) -> bool:
    """To samo miasto - te same porównania co w tabeli okręgu, plus klucze ZPRP."""
    a_base, a_tight = normalize_city(a)
    b_base, b_tight = normalize_city(b)
    if not a_base or not b_base:
        return False
    if a_base == b_base or a_tight == b_tight:
        return True
    return bool(set(lookup_keys(a)) & set(lookup_keys(b)))


def national_km(pairs_map: Mapping[tuple[str, str], Any], a: Any, b: Any) -> Optional[int]:
    """
    Kilometry w jedną stronę z tabeli ZPRP albo None.

    `pairs_map` to {(klucz_a, klucz_b): km} z kluczami ułożonymi rosnąco
    (najlepiej już po `expand_pairs`). To samo miasto zwraca None - to nie
    jest pytanie do tabeli, tylko pierwszy krok reguły (`same_city`).
    """
    if not pairs_map:
        return None
    left_keys = lookup_keys(a)
    right_keys = lookup_keys(b)
    if not left_keys or not right_keys:
        return None
    if set(left_keys) & set(right_keys):
        return None
    for left in left_keys:
        for right in right_keys:
            hit = pairs_map.get(_canonical(left, right))
            if hit is not None:
                try:
                    return int(hit)
                except (TypeError, ValueError):
                    continue
    return None


def pick_distance(
    is_central: bool,
    *,
    home: Any,
    city: Any,
    table_km: Optional[float] = None,
    national: Optional[Mapping[tuple[str, str], Any]] = None,
) -> Optional[tuple[float, str]]:
    """
    Pierwsze źródło z reguły, które zna odpowiedź, albo None.

    None znaczy: tabele milczą, wołający pyta dalej (Google w synchronizacji
    i w ręcznych meczach, historia sędziego w prognozie). `table_km` to wynik
    tabeli okręgu z dnia meczu - dla meczu centralnego jest ignorowany.
    """
    if not str(home or "").strip() or not str(city or "").strip():
        return None
    for source in distance_order(is_central):
        if source == SOURCE_SAME_CITY:
            if same_city(home, city):
                return 0.0, SOURCE_SAME_CITY
        elif source == SOURCE_TABLE:
            if table_km is not None:
                value = float(table_km)
                return value, SOURCE_SAME_CITY if value == 0 else SOURCE_TABLE
        elif source == SOURCE_NATIONAL:
            hit = national_km(national or {}, home, city)
            if hit is not None:
                return float(hit), SOURCE_NATIONAL
    return None


def pairs_version(count: Any, max_updated: Any) -> str:
    """Wersja tabeli do ETag: liczba połączeń i najświeższy znacznik zmiany."""
    stamp = ""
    if max_updated is not None:
        if hasattr(max_updated, "timestamp"):
            stamp = str(int(max_updated.timestamp()))
        else:
            stamp = "".join(ch for ch in str(max_updated) if ch.isalnum())
    return f"{int(count or 0)}-{stamp or '0'}"


def etag_matches(if_none_match: Optional[str], version: str) -> bool:
    """Nagłówek If-None-Match (także lista i słabe ETagi) kontra wersja."""
    if not if_none_match:
        return False
    for part in str(if_none_match).split(","):
        tag = part.strip()
        if tag == "*":
            return True
        if tag.startswith("W/"):
            tag = tag[2:]
        if tag.strip('"') == version:
            return True
    return False


def pairs_rows(rows: Iterable[Any]) -> list[list[Any]]:
    """Wiersze połączeń -> [[a_key, b_key, km, obserwacje], ...] w stałej kolejności."""
    out: list[list[Any]] = []
    for row in rows:
        a, b = str(row["city_a_key"] or ""), str(row["city_b_key"] or "")
        if not a or not b:
            continue
        a, b = _canonical(a, b)
        out.append([a, b, int(row["distance_km"]), int(row["observations"] or 0)])
    out.sort(key=lambda item: (item[0], item[1]))
    return out


# ---------------------------------------------------------------------------
# Status budowy tabeli przez sędziego
# ---------------------------------------------------------------------------

MAX_STATUS_MATCH_IDS = 3000


def clean_match_ids(values: Iterable[Any]) -> list[str]:
    """Tylko liczbowe IdZawody, bez powtórzeń, najwyżej `MAX_STATUS_MATCH_IDS`."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = str(value if value is not None else "").strip()
        if not text.isdigit() or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= MAX_STATUS_MATCH_IDS:
            break
    return out


def judge_status(judge_row: Optional[Mapping[str, Any]], source_at: Any = None, has_source: bool = False) -> dict:
    """
    Czy sędzia zbudował już tabelę: wpis po pełnym pobraniu wygrywa, a gdy go
    nie ma - wystarczy dowolny ryczałt z jego meczów w kolejce serwera
    (sędziowie, którzy czytali ryczałty przed wprowadzeniem wpisu).
    """

    def iso(value: Any) -> Optional[str]:
        return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)

    if judge_row:
        at = judge_row.get("last_full_at") or judge_row.get("first_full_at")
        return {"built": True, "at": iso(at), "reason": "judge"}
    if has_source:
        return {"built": True, "at": iso(source_at), "reason": "sources"}
    return {"built": False, "at": None, "reason": None}
