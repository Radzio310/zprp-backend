"""
Silnik rozliczen sedziowskich - jedyne miejsce, w ktorym serwer liczy kwote.

PORT regul z aplikacji: `BAZA_web/utils/province-stats/rates.ts` oraz
`BAZA/components/RyczaltStats.tsx`. Czyta DOKLADNIE te same dokumenty, ktore
serwer wydaje klientom - `central_rates.content` i `okreg_rates.content` - wiec
telefon, przegladarka i PDF nie maja z czego sie rozjechac.

Dlaczego na serwerze: PDF powstaje tutaj, a rozliczenie musi pokazac te sama
kwote, co ekran sedziego. Dwie implementacje tego samego rachunku juz raz sie
rozjechaly (BAZA_web liczyla caly sezon 2026/2027 stara tabela centralna) i
tego bledu nie powtarzamy.

MODUL-LISC: bez bazy i bez sieci, zeby caly rachunek dalo sie sprawdzic testem.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import date, datetime
from typing import Any, Iterable, Optional

# -------------------------
# Role
# -------------------------

ROLE_FIELD = "Sędzia boiskowy"
ROLE_TABLE = "Sędzia stolikowy"
ROLE_DELEGATE = "Delegat"

ROLES = (ROLE_FIELD, ROLE_TABLE, ROLE_DELEGATE)

#: Pole obsady w rekordzie meczu -> rola rozliczeniowa.
CREW_ROLE_FIELDS: dict[str, str] = {
    "NrSedzia_pierwszy": ROLE_FIELD,
    "NrSedzia_drugi": ROLE_FIELD,
    "NrSedzia_sekretarz": ROLE_TABLE,
    "NrSedzia_czas": ROLE_TABLE,
    "NrSedzia_delegat": ROLE_DELEGATE,
    "NrSedzia_delegat2": ROLE_DELEGATE,
}


def is_table_role(role: Any) -> bool:
    return str(role or "").strip() == ROLE_TABLE


# -------------------------
# Normalizacja
# -------------------------

def strip_dia(value: Any) -> str:
    """Bez ogonkow. „l" MUSI zejsc osobno - NFD go nie rozklada."""
    text = str(value or "").replace("Ł", "L").replace("ł", "l")
    return "".join(
        ch for ch in unicodedata.normalize("NFD", text)
        if unicodedata.category(ch) != "Mn"
    )


def code_key(value: Any) -> str:
    return strip_dia(value).upper().strip()


def province_key(value: Any) -> str:
    return re.sub(r"[^A-Z]", "", strip_dia(value).upper())


# -------------------------
# Rozpoznanie rozgrywek
# -------------------------

#: KOLEJNOSC JEST CALA LOGIKA - dopasowanie idzie przez `in`, wiec kazdy prefiks
#: musi stac przed kazdym swoim podciagiem.
#:
#: „MP" i „PP" MUSZA byc pierwsze: numer meczu mistrzostw niesie w sobie litere
#: kategorii („MPJMM/19"), wiec przy MP na koncu wygrywalo „JMM" i mecz
#: mistrzostw rozliczal sie jak zwykly mecz juniorski.
#: „BSK"/„BSM" MUSZA stac przed „SK"/„SM" - „BSK/1" zawiera „SK".
_PREFIX_ORDER = [
    "MP", "PP", "SPM", "SPK",
    "MLM1213", "MLK1213",
    "IIIM", "IIIK", "IIM", "IIK",
    "MLM", "MLK", "JMM", "JMK", "JK", "JM",
    "DZM", "DZK",
    "BSM", "BSK",
    "IK", "IM", "LCM", "LCK", "OSM", "OSK", "SM", "SK",
    "EHF",
]


def competition_prefix(code: Any) -> str:
    value = code_key(code)
    for prefix in _PREFIX_ORDER:
        if prefix in value:
            return prefix
    return value.split("/")[0] if value else ""


def is_test_competition(code: Any) -> bool:
    """Mecze testowe ZPRP („test/1"). Bez odsiewu wchodza do kazdej statystyki."""
    return bool(re.match(r"^TEST(/|$)", code_key(code)))


def is_provincial_cup(code: Any) -> bool:
    """
    Puchar z poprzedzajacym segmentem („S/PPK/2") to puchar WOJEWODZKI i liczy
    sie stawkami II ligi. Od Pucharu Polski („PPM/23") rozroznia go wylacznie
    to, czy przed „PP" cokolwiek stoi.
    """
    value = code_key(code)
    return "/PP" in value and not value.startswith("PP")


def is_cup_competition(code: Any) -> bool:
    """Puchar centralny rozpoznajemy po POCZATKU numeru, nie po prefiksie."""
    value = code_key(code)
    return value.startswith("MP") or value.startswith("PP")


def is_district_competition(code: Any) -> bool:
    """
    III liga i nizej.

    II liga jest CENTRALNA zawsze, takze w wojewodztwach prowadzacych wlasna
    grupe (IIM4 na Slasku, IIM1 na Dolnym Slasku).
    """
    return bool(
        re.search(r"(MLM1213|MLK1213|MLM|MLK|JMM|JMK|JM|JK|DZM|DZK|IIIM|IIIK)", code_key(code))
    )


def is_children_competition(code: Any) -> bool:
    """Rozgrywki dzieci - jedyne, ktore rozliczaja dojazd zbiorczo."""
    return competition_prefix(code) in ("DZM", "DZK")


def match_level(code: Any) -> str:
    """
    Szczebel meczu: "cup" | "district" | "central" | "unknown".

    ⚠ KOLEJNOSC JEST CALA LOGIKA i dlatego to stoi w osobnej funkcji zamiast
    w trzech wywolaniach obok siebie. `is_district_competition("MPJMM/19")`
    zwraca True, bo w numerze mistrzostw siedzi „JMM" - puchar MUSI wiec zostac
    rozstrzygniety pierwszy. `calculate_gross` robi to samo, ale klasyfikacja
    zdarza sie takze poza rachunkiem (odsiew, statystyki, wybor kilometrowki)
    i tam ta pulapka nie ma jak sie sama obronic.
    """
    if is_provincial_cup(code):
        # Puchar wojewodzki placi stawkami II ligi, wiec liczy sie jak centralny.
        return "central"
    if is_cup_competition(code):
        return "cup"
    if is_district_competition(code):
        return "district"
    if central_category(code):
        return "central"
    return "unknown"


def district_category(code: Any) -> str:
    prefix = competition_prefix(code)
    if prefix in ("MLM1213", "MLK1213"):
        return "Młodzik mł."
    if prefix in ("MLM", "MLK"):
        return "Młodzik"
    if prefix in ("JMM", "JMK"):
        return "Junior mł."
    if prefix in ("JM", "JK"):
        return "Junior"
    if prefix in ("IIIM", "IIIK"):
        return "III liga"
    return "Inne"


def central_category(code: Any) -> Optional[str]:
    prefix = competition_prefix(code)
    if prefix in ("IIM", "IIK") or prefix.startswith("IIM") or prefix.startswith("IIK"):
        return "II liga"
    if prefix in ("IM", "IK"):
        return "I liga"
    if prefix in ("LCM", "LCK", "LC"):
        return "LC"
    # Baraz o Superlige placi stawka tej superligi, o ktora sie gra.
    if prefix == "BSK":
        return "OSK"
    if prefix == "BSM":
        return "OSM"
    if prefix in ("OSM", "OSK", "SM", "SK"):
        return prefix
    # „EHF" - mecz miedzypanstwowy. Rozpoznany, zeby liczyl sie do obciazenia,
    # ale stawki dla niego nie ma w zadnej tabeli ZPRP.
    return None


def category_label(code: Any) -> str:
    district = district_category(code)
    if district != "Inne":
        return district
    central = central_category(code)
    if central:
        return central
    prefix = competition_prefix(code)
    if prefix in ("DZM", "DZK"):
        return "Dzieci"
    return prefix or "Inne"


# -------------------------
# Etap pucharu
# -------------------------

MP_STAGE_FALLBACK = "1/16 i 1/8MP"
PP_STAGE_FALLBACK = "1/16 i 1/8PP"


def cup_stage_from_text(kind: str, round_text: Any, series_text: Any) -> tuple[str, bool]:
    """
    Etap z pol „Runda" i „Kolejka". Port `BAZA/utils/cupStage.ts`.

    Zwraca (etap, rozpoznano). NIEROZPOZNANY dostaje NAJNIZSZY prog, nie final -
    zawyzona kwota w zestawieniu okregu wyglada jak zobowiazanie, ktorego nie ma.
    """
    text = re.sub(r"\s+", " ", f"{strip_dia(round_text)} {strip_dia(series_text)}").strip().lower()
    fallback = MP_STAGE_FALLBACK if kind == "MP" else PP_STAGE_FALLBACK
    if not text:
        return fallback, False

    lowest = "1/16" in text or "1/12" in text or "1/8" in text
    quarter = "1/4" in text
    half = "1/2" in text
    final = "final" in text or "finale" in text

    if kind == "MP":
        if lowest:
            return "1/16 i 1/8MP", True
        # 1/2 nie istnieje w tabeli MP - traktujemy jak cwiercfinal.
        if quarter or half:
            return "1/4MP", True
        if final:
            return "Finał MP", True
        return fallback, False

    if lowest:
        return "1/16 i 1/8PP", True
    if quarter:
        return "1/4 i 1/2PP", True
    # Polfinal PP ma WLASNY klucz: do 31.08.2026 rowny cwiercfinalowi,
    # od 01.09.2026 placi jak final.
    if half:
        return "1/2PP", True
    if final:
        return "Finał PP", True
    return fallback, False


def cup_stage(code: Any, round_text: Any, series_text: Any) -> Optional[tuple[str, bool]]:
    """`None` gdy to nie jest puchar centralny."""
    if is_provincial_cup(code):
        return None
    value = code_key(code)
    if value.startswith("MP"):
        return cup_stage_from_text("MP", round_text, series_text)
    if value.startswith("PP"):
        return cup_stage_from_text("PP", round_text, series_text)
    return None


# -------------------------
# Odczyt tabel
# -------------------------

def _as_dict(value: Any) -> dict:
    """JSONB potrafi wrocic napisem - wtedy trzeba go rozpakowac."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        import json
        try:
            parsed = json.loads(value)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _resolve_pointer(root: Any, ref: Any) -> Any:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    current = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if current is None:
            return None
        current = current.get(part) if isinstance(current, dict) else None
    return current


def deref(root: Any, node: Any, depth: int = 0) -> Any:
    if depth > 6 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str):
        hit = _resolve_pointer(root, ref)
        return node if hit is None else deref(root, hit, depth + 1)
    return node


def day_key(when: date) -> str:
    return "weekend" if when.weekday() >= 5 else "weekday"


def tier_value(node: Any, distance_km: float) -> float:
    """Prog odleglosciowy: `{below100, 100to300, above300}` albo gola liczba."""
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        return float(node)
    if not isinstance(node, dict):
        return 0.0
    if distance_km <= 100:
        return float(node.get("below100") or 0)
    if distance_km <= 300:
        return float(node.get("100to300") or 0)
    return float(node.get("above300") or 0)


def central_gross_for(
    book: Any, category: str, role: str, distance_km: float, when: date
) -> float:
    book = _as_dict(book)
    if not book:
        return 0.0
    key = day_key(when)

    if role == ROLE_FIELD:
        return tier_value((_as_dict(book.get(key)).get("boiskowy") or {}).get(category), distance_km)
    if role == ROLE_TABLE:
        value = (_as_dict(book.get(key)).get("stolikowy") or {}).get(category)
        return float(value or 0) if isinstance(value, (int, float)) else 0.0

    # Delegat: wlasny prog ma tylko Superliga, reszta idzie progami stojacymi
    # bezposrednio w galezi dnia.
    delegate = _as_dict(book.get("delegat")).get(key)
    if not isinstance(delegate, dict):
        return 0.0
    return tier_value(delegate.get(category, delegate), distance_km)


def cup_gross(book: Any, category: str, role: str, distance_km: float, when: date) -> float:
    book = _as_dict(book)
    if not book:
        return 0.0

    if category.endswith("MP"):
        mp = _as_dict(book.get("MP"))
        if role == ROLE_FIELD:
            return tier_value((mp.get("boiskowy") or {}).get(category), distance_km)
        if role == ROLE_TABLE:
            value = (mp.get("stolikowy") or {}).get(category)
            return float(value or 0) if isinstance(value, (int, float)) else 0.0
        # Delegat na MP idzie stawkami ogolnymi delegata, nie tabela MP.
        delegate = _as_dict(book.get("delegat")).get(day_key(when))
        return tier_value(delegate, distance_km)

    # Puchar Polski siedzi w tej samej galezi co ligi.
    return central_gross_for(book, category, role, distance_km, when)


def value_from_node(root: Any, node_raw: Any, distance_km: float, key: str) -> float:
    node = deref(root, node_raw)
    if isinstance(node, dict) and ("weekend" in node or "weekday" in node):
        node = deref(root, node.get(key)) or node
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        return float(node)
    if not isinstance(node, (dict, list)):
        return 0.0

    if isinstance(node, dict):
        if "miejscowy" in node or "zamiejscowy" in node:
            branch = deref(root, node.get("miejscowy") if distance_km == 0 else node.get("zamiejscowy"))
            if isinstance(branch, (int, float)) and not isinstance(branch, bool):
                return float(branch)
            if isinstance(branch, dict):
                value = deref(root, branch.get(key))
                return float(value) if isinstance(value, (int, float)) else 0.0
            return 0.0
        if "below100" in node or "100to300" in node or "above300" in node:
            return tier_value(node, distance_km)
        return 0.0

    for item in node:
        rng = item.get("range") if isinstance(item, dict) else None
        value = item.get("value") if isinstance(item, dict) else None
        if (
            isinstance(rng, list)
            and len(rng) == 2
            and isinstance(value, (int, float))
            and float(rng[0]) <= distance_km <= float(rng[1])
        ):
            return float(value)
    return 0.0


def provincial_gross(
    content: Any, distance_km: float, category: str, role: str, when: date
) -> float:
    root = _as_dict(content)
    if not root:
        return 0.0
    key = day_key(when)
    main = deref(root, root.get("mecze")) or root
    mode = deref(root, main.get(key)) if isinstance(main, dict) and (main.get("weekend") or main.get("weekday")) else main
    role_node = None
    for candidate in (
        (mode or {}).get(role) if isinstance(mode, dict) else None,
        (main or {}).get(role) if isinstance(main, dict) else None,
        (_as_dict(root.get(key)) or {}).get(role),
    ):
        node = deref(root, candidate)
        if isinstance(node, dict):
            role_node = node
            break
    if role_node is None:
        return 0.0
    return value_from_node(root, role_node.get(category), distance_km, key)


def district_fallback(book: Any, distance_km: float, role: str) -> float:
    """Gdy wojewodztwo nie ma wlasnej tabeli - galaz `okregowe` tabeli centralnej."""
    if role == ROLE_DELEGATE:
        return 0.0
    rates = _as_dict(book).get("okręgowe") or {}
    items = rates.get("boiskowy" if role == ROLE_FIELD else "stolikowy")
    if not isinstance(items, list):
        return 0.0
    for item in items:
        rng = item.get("range") if isinstance(item, dict) else None
        value = item.get("value") if isinstance(item, dict) else None
        if (
            isinstance(rng, list)
            and len(rng) == 2
            and isinstance(value, (int, float))
            and float(rng[0]) <= distance_km <= float(rng[1])
        ):
            return float(value)
    return 0.0


def calculate_gross(
    *,
    code: str,
    role: str,
    distance_km: float,
    when: date,
    central_book: Any,
    province_content: Any,
    round_text: Any = None,
    series_text: Any = None,
) -> float:
    """Ryczalt brutto za jeden mecz. Port `calculateGross` z BAZA_web."""
    # Puchar wojewodzki sprawdzamy PRZED etapem pucharowym: „S/PPK/2" ma w sobie
    # „PP", wiec bez tego wpadlby w tabele Pucharu Polski.
    if is_provincial_cup(code):
        return central_gross_for(central_book, "II liga", role, distance_km, when)

    stage = cup_stage(code, round_text, series_text)
    if stage:
        return cup_gross(central_book, stage[0], role, distance_km, when)

    if is_district_competition(code):
        from_province = provincial_gross(
            province_content, distance_km, district_category(code), role, when
        )
        if from_province > 0:
            return from_province
        fallback = district_fallback(central_book, distance_km, role)
        if fallback > 0:
            return fallback

    category = central_category(code)
    if not category:
        return 0.0
    return central_gross_for(central_book, category, role, distance_km, when)


# -------------------------
# Kilometrowka
# -------------------------

CENTRAL_KM_RATE_OLD = 0.5
CENTRAL_KM_RATE_NEW = 0.8
ROUND_TRIP = 2


def is_central_level_competition(code: Any) -> bool:
    """
    Kryterium to samo, ktorym BAZA odroznia „Okreg" od reszty. Puchar wojewodzki
    liczy sie stawkami II ligi, wiec i kilometrowka centralna.
    """
    if is_provincial_cup(code):
        return True
    if is_cup_competition(code):
        return True
    return central_category(code) is not None


def _season_start_year(when: Optional[date]) -> int:
    if not when:
        return 9999
    return when.year if when.month >= 9 else when.year - 1


def kilometer_rate(
    *,
    code: str,
    province: str,
    province_content: Any,
    central_book: Any,
    when: Optional[date],
) -> float:
    """
    Stawka za kilometr W JEDNA STRONE.

    Mecz okregowy idzie stawka WOJEWODZKA (Slaskie 0,70 zl od 01.09.2026),
    a wszystko od II ligi w gore - i stolik, i boiskowy - stawka CENTRALNA
    0,80 zl. Obie siedza w dokumentach z serwera, wiec zmiana uchwaly nie
    wymaga wydawania aplikacji.
    """
    if is_central_level_competition(code):
        # Plik wojewodzki moze nadpisac stawke centralna wlasna wartoscia.
        km_node = _as_dict(province_content).get("kilometrowka")
        if isinstance(km_node, dict) and isinstance(km_node.get("CENTRALA"), (int, float)):
            return float(km_node["CENTRALA"])
        central_km = _as_dict(central_book).get("kilometrowka")
        if isinstance(central_km, dict) and isinstance(central_km.get("CENTRALA"), (int, float)):
            return float(central_km["CENTRALA"])
        if competition_prefix(code) in ("OSM", "OSK"):
            return CENTRAL_KM_RATE_NEW
        return CENTRAL_KM_RATE_NEW if _season_start_year(when) >= 2025 else CENTRAL_KM_RATE_OLD

    local = _province_km_rate(province_content, province)
    if local is not None:
        return local
    central_km = _as_dict(central_book).get("kilometrowka")
    if isinstance(central_km, dict):
        wanted = province_key(province)
        for key, value in central_km.items():
            if province_key(key) == wanted and isinstance(value, (int, float)):
                return float(value)
    return 0.0


def _province_km_rate(content: Any, province: str) -> Optional[float]:
    root = _as_dict(content)
    node = deref(root, root.get("kilometrowka")) or root.get("kilometrowka")
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        return float(node)
    if isinstance(node, dict):
        wanted = province_key(province)
        for key, value in node.items():
            if province_key(key) == wanted and isinstance(value, (int, float)):
                return float(value)
        if isinstance(node.get("default"), (int, float)):
            return float(node["default"])
    return None


def travel_pln(distance_km: float, rate: float) -> int:
    """Dojazd ZAWSZE w obie strony - tak liczy cala aplikacja."""
    return round(distance_km * rate * ROUND_TRIP)


# -------------------------
# Podatek
# -------------------------

def net_parts(gross: float) -> dict[str, int]:
    """
    Koszty uzysku i podatek.

    Prog 200 zl: ponizej niego koszty uzysku nie przysluguja. Ta sama regula,
    ktora stosuje `calculateLacznie` w BAZA i `netParts` w BAZA_web.
    """
    costs = round(0.2 * gross) if gross > 200 else 0
    tax = round(0.12 * (gross - costs))
    return {"gross": round(gross), "costs": costs, "taxable": round(gross) - costs, "tax": tax, "net": round(gross) - tax}


def settle_period(total_gross: float) -> dict[str, int]:
    """
    Rozliczenie ZBIORCZE za okres - jeden wiersz zestawienia.

    ⚠ Koszty uzysku i podatek licza sie od SUMY sedziego za caly miesiac, a nie
    mecz po meczu (decyzja uzytkownika z 09.09.2026). Prog 200 zl wypada wiec
    RAZ, na sumie - dokladnie tak, jak czyta sie papierowe zestawienie
    ekwiwalentow. Przy pojedynczym meczu ponizej progu daje to inna kwote niz
    `net_parts`, i to jest zamierzone.
    """
    gross = round(total_gross)
    costs = round(0.2 * gross) if gross > 200 else 0
    taxable = gross - costs
    tax = round(0.12 * taxable)
    return {"gross": gross, "costs": costs, "taxable": taxable, "tax": tax, "net": gross - tax}


# -------------------------
# Wybor wersji tabeli
# -------------------------

def _day_number(value: Any) -> Optional[int]:
    text = str(value or "").strip()
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})", text)
    if not match:
        return None
    return int(match.group(1) + match.group(2) + match.group(3))


def pick_version(versions: Iterable[Any], when: Optional[date]) -> Any:
    """
    Wersja tabeli obowiazujaca w DNIU MECZU, nie dzisiaj.

    Ta sama regula co `pickCentralVersion` w BAZA_web i `pickCentralVersion`
    w BAZA. Mecz bez daty zostaje przy NAJSTARSZEJ wersji.
    """
    items = [v for v in versions or []]
    if not items:
        return None

    def enabled(item: Any) -> bool:
        value = item.get("enabled") if isinstance(item, dict) else getattr(item, "enabled", True)
        return value is not False

    pool = [v for v in items if enabled(v)] or items

    def field(item: Any, name: str) -> Any:
        return item.get(name) if isinstance(item, dict) else getattr(item, name, None)

    def start(item: Any) -> int:
        return _day_number(field(item, "valid_from")) or 0

    ordered = sorted(pool, key=lambda item: (start(item), field(item, "id") or 0))
    if when is None:
        return ordered[0]

    day = int(when.strftime("%Y%m%d"))
    matching = [
        item for item in ordered
        if (_day_number(field(item, "valid_from")) or 0) <= day
        and day <= (_day_number(field(item, "valid_to")) or 99999999)
    ]
    if matching:
        return matching[-1]
    before = [item for item in ordered if (_day_number(field(item, "valid_from")) or 0) <= day]
    if before:
        return before[-1]
    return ordered[0]


def as_date(value: Any) -> Optional[date]:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})", text)
    if not match:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None
