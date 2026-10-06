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
from decimal import Decimal, ROUND_HALF_UP
import unicodedata
from datetime import date, datetime
from typing import Any, Iterable, Optional

from app.protocol_category import is_regional_cup_qualifier

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
    Prefiks wojewodztwa przed PM/PK lub PPM/PPK oznacza eliminacje PP.
    """
    return is_regional_cup_qualifier(code)


def is_cup_competition(code: Any) -> bool:
    """Puchar centralny rozpoznajemy po POCZATKU numeru, nie po prefiksie."""
    value = code_key(code)
    return value.startswith(("MP", "PP", "PM/", "PK/"))


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
    """Rozgrywki dzieci (DzM/DzK) - turniej: stawka za mecz, dojazd raz."""
    return competition_prefix(code) in ("DZM", "DZK")


def is_regional_youth_competition(code: Any) -> bool:
    """
    Mlodzicy regionalni: czlon numeru „MłMR" / „MłKR" (takze z rocznikiem,
    „MłM1213R", i z numerem grupy po literze R).

    Rozpoznajemy po CALYM czlonie miedzy ukosnikami, a nie przez
    `competition_prefix`: ten szuka podciagu i „MLKR" zamienia w zwykle
    „MLK" - litera R, ktora odroznia rozgrywki regionalne, ginie.
    """
    return any(
        re.fullmatch(r"ML[MK](1213)?R\d*", part)
        for part in code_key(code).split("/")
    )


def shares_trip_travel(code: Any) -> bool:
    """
    Rozgrywki grane turniejowo - wiele meczow jednego dnia w jednej hali, na
    ktore sedzia przyjezdza RAZ. Dojazd placi tylko pierwszy mecz dnia.

    Dzieci od 09.09.2026, mlodzicy regionalni od 29.09.2026 (decyzje
    uzytkownika). Ta sama lista stoi w `BAZA/utils/tripTravel.ts` i w
    `BAZA_web/utils/province-stats/rates.ts` (`sharesTripTravel`).
    """
    return is_children_competition(code) or is_regional_youth_competition(code)


#: Kategoria stawek turnieju dzieci (DzM/DzK). W danych stawek jest dopiero od
#: 01.09.2026 - starsze wersje jej nie maja i `calculate_gross` schodzi wtedy
#: do "Inne", tak jak liczono te mecze wczesniej.
CHILDREN_CATEGORY = "Dzieci"


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
        # Eliminacje PP mają własną stawkę centralną.
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
    if prefix in ("DZM", "DZK"):
        return CHILDREN_CATEGORY
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
    if is_provincial_cup(code):
        return "el. PP"
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
# Kto rozlicza obsade
# -------------------------

#: Powody, dla ktorych obsada NIE wchodzi do rozliczenia okregu.
ZPRP_FIELD = "zprp_field"
ZPRP_DELEGATE = "zprp_delegate"
ZPRP_MP_TABLE = "zprp_mp_table"
ZPRP_OOM = "zprp_oom"
#: Nie ZPRP, ale tez nie okreg: mecz zdjety z rozliczen w panelu klubow
#: („Nie obciazaj klubow" - decyzja z 06.10.2026: nikt u nas za niego nie placi).
NOT_PAID_EXCLUDED = "district_excluded"

#: Opis powodu dla czlowieka - ten sam tekst w aplikacji, na webie i w PDF.
ZPRP_REASONS: dict[str, str] = {
    ZPRP_FIELD: "sędzia boiskowy na meczu obsadzanym przez ZPRP",
    ZPRP_DELEGATE: "delegat na meczu obsadzanym przez ZPRP",
    ZPRP_MP_TABLE: "stolik na Mistrzostwach Polski, rozliczany osobno przez ZPRP",
    ZPRP_OOM: "Ogólnopolska Olimpiada Młodzieży, rozliczana przez ZPRP",
    NOT_PAID_EXCLUDED: "mecz zdjęty z rozliczeń okręgu w panelu klubów - okręg go nie wypłaca",
}

#: Rozgrywki ZPRP bez stawki w zadnej tabeli (Superpuchar, mecze EHF) -
#: `match_level` widzi je jako "unknown", a obsadza je centrala.
_ZPRP_ONLY_PREFIXES = ("SPM", "SPK", "EHF")

#: Ogolnopolska Olimpiada Mlodziezy: „OOM/3", „OOMK/1". Bliznieta: `OOM_CODE`
#: w BAZA_web (`rates.ts`) i w aplikacji (`utils/zprpPayroll.ts`).
_OOM_CODE = re.compile(r"(^|[^A-Z0-9])OOM[KM]?($|[^A-Z0-9])")


#: Od tego dnia boiskowych II ligi POWIERZONEJ okregowi (IIM4 i IIK4 na Slasku)
#: placi okreg i obciaza nimi gospodarza - decyzja uzytkownika z 06.10.2026,
#: z moca od poczatku sezonu 2026/2027. Wczesniejsze mecze zostaja, jak je
#: rozliczono (obsada ZPRP), bo tamte sezony sa zamkniete.
MANAGED_FIELD_SINCE = date(2026, 9, 1)


def province_pays_field(code: Any, managed_prefixes: Iterable[Any], day: Any) -> bool:
    """
    Czy boiskowego TEGO meczu placi okreg, bo to II liga powierzona okregowi.

    Lista powierzonych grup to ta sama lista, z ktorej korzysta Obsada i gielda
    (`match_market_rules.managed_prefixes_for`: katalog albo nadpisanie z panelu).
    Liczy sie wylacznie II liga („IIM4/1" przy „IIM4") - wyzsze ligi obsadza
    i rozlicza zwiazek zawsze. Delegaci tej reguly nie dotyczy.
    """
    when = day.date() if isinstance(day, datetime) else day
    if not isinstance(when, date) or when < MANAGED_FIELD_SINCE:
        return False
    head = str(code or "").strip().upper().split("/", 1)[0].strip()
    if not head.startswith(("IIM", "IIK")):
        return False
    return any(
        head.startswith(str(prefix or "").strip().upper())
        for prefix in (managed_prefixes or ())
        if str(prefix or "").strip()
    )


def zprp_settlement_reason(code: Any, role: Any, *, province_field: bool = False) -> Optional[str]:
    """
    Powod, dla ktorego te obsade rozlicza ZPRP, a nie okreg - albo None.

    `province_field` - boiskowy II ligi powierzonej okregowi, ktorego od sezonu
    2026/2027 placi okreg (`province_pays_field`, decyzja z 06.10.2026).

    Decyzja uzytkownika z 10.09.2026. Z rozliczenia okregu wypada wszystko,
    co obsadza ZPRP: boiskowi i delegaci na meczach centralnych (ligi od II
    w gore, baraze, Mistrzostwa Polski, Puchar Polski, Superpuchar, EHF) oraz
    stoliki Mistrzostw Polski, ktore ZPRP rozlicza osobno. Zostaja mecze
    okregowe w kazdej roli, puchar wojewodzki i stoliki lig oraz Pucharu Polski.

    ⚠ Eliminacje PP („S/PPK/2") mają osobną stawkę „el. PP", a `match_level`
    widzi go jako "central" - ale to mecz OKREGU i zostaje. Dlatego rozstrzyga
    sie go tu pierwszy.
    """
    if is_provincial_cup(code):
        return None
    # OOM obsadza i rozlicza ZPRP w kazdej roli (decyzja z 30.09.2026).
    if _OOM_CODE.search(code_key(code)):
        return ZPRP_OOM
    if match_level(code) not in ("central", "cup") and competition_prefix(code) not in _ZPRP_ONLY_PREFIXES:
        return None
    role_text = str(role or "").strip()
    if role_text == ROLE_FIELD:
        return None if province_field else ZPRP_FIELD
    if role_text == ROLE_DELEGATE:
        return ZPRP_DELEGATE
    if role_text == ROLE_TABLE and code_key(code).startswith("MP"):
        return ZPRP_MP_TABLE
    return None


# -------------------------
# Potrojny ryczalt stolikowego
# -------------------------

#: Ile razy wiecej dostaje stolikowy, ktory zostal przy stoliku sam.
TRIPLE_TABLE_FACTOR = 3

#: Okregi z ta opcja. Na razie tylko Slask (decyzja uzytkownika z 10.09.2026);
#: wlaczenie kolejnego okregu to dopisanie klucza, bez zmian w regule.
TRIPLE_TABLE_PROVINCES = frozenset({"SLASKIE"})


def triple_table_allowed(code: Any, role: Any, province: Any) -> bool:
    """
    Czy dla tej obsady wolno wlaczyc potrojny ryczalt.

    Sytuacja: na meczu OKREGOWYM stolik prowadzi jedna osoba, bo stolikowy
    z klubu sie nie stawil. Sedzia robi wtedy robote za trzech i tyle dostaje;
    dojazd zostaje normalny, a klub gospodarza placi te sama trzykrotnosc.

    ⚠ Tylko stoliki OKREGOWE. Stoliki lig centralnych (II liga w gore) i puchar
    wojewodzki z własną stawką „el. PP" są poza tą opcją.
    """
    if str(role or "").strip() != ROLE_TABLE:
        return False
    if is_provincial_cup(code) or match_level(code) != "district":
        return False
    return province_key(province) in TRIPLE_TABLE_PROVINCES


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
    if value.startswith(("PP", "PM/", "PK/")):
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


def children_rate_defined(content: Any, role: str, when: date) -> bool:
    """Czy wersja stawek okregu zna kategorie turnieju dzieci.

    To jest przelacznik miedzy DWOMA sposobami rozliczania turnieju:

    * ZNA (Slaskie od 01.09.2026) - kazdy mecz placi swoja stawke dziecieca
      (40 zl), a wspolny jest tylko dojazd,
    * NIE ZNA (wszystkie starsze wersje) - turniej placi JEDNA stawke okregowa
      za caly dzien. Wczesniej kazdy mecz liczyl sie wtedy jak pelny mecz
      okregowy i dzien dzieci wychodzil kilkaset zlotych.

    Regula jest OGOLNA, nie slaska: okreg, ktory dopisze sobie stawke dzieciec,
    automatycznie przechodzi na rozliczanie za mecz.
    """
    root = _as_dict(content)
    if not root:
        return False
    key = day_key(when)
    main = deref(root, root.get("mecze")) or root
    mode = deref(root, main.get(key)) if isinstance(main, dict) and (main.get("weekend") or main.get("weekday")) else main
    for candidate in (
        (mode or {}).get(role) if isinstance(mode, dict) else None,
        (main or {}).get(role) if isinstance(main, dict) else None,
        (_as_dict(root.get(key)) or {}).get(role),
    ):
        node = deref(root, candidate)
        if isinstance(node, dict):
            return node.get(CHILDREN_CATEGORY) is not None
    return False


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
        return central_gross_for(central_book, "el. PP", role, distance_km, when)

    stage = cup_stage(code, round_text, series_text)
    if stage:
        return cup_gross(central_book, stage[0], role, distance_km, when)

    if is_district_competition(code):
        category = district_category(code)
        from_province = provincial_gross(province_content, distance_km, category, role, when)
        if not from_province and category == CHILDREN_CATEGORY:
            # Stawka turnieju dzieci obowiazuje od 01.09.2026; wersja sprzed tej
            # daty jej nie ma i mecz dzieci liczy sie tam jak "Inne".
            from_province = provincial_gross(province_content, distance_km, "Inne", role, when)
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
    Kryterium to samo, ktorym BAZA odroznia „Okreg" od reszty. Eliminacje PP
    mają własną stawkę „el. PP" i kilometrówkę centralną.
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


def travel_pln(distance_km: float, rate: float) -> float:
    """Dojazd w obie strony, rozliczony do grosza (bez obcinania do pelnych zl)."""
    amount = Decimal(str(distance_km)) * Decimal(str(rate)) * ROUND_TRIP
    return float(amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


# -------------------------
# Podatek
# -------------------------

def _whole_pln(value: float) -> int:
    """
    Do pelnych zlotych „od polowy w gore" - jak w ordynacji podatkowej (art. 63).

    Tylko dla kosztow uzysku, podstawy i zaliczki na podatek. Przy calkowitym
    brutto daje dokladnie to, co dawne `round(...)` (polowka nie wypada).
    """
    # Najpierw do groszy: 0,2 x 252,50 to w float 50,4999..., a ma byc 50,50 -> 51.
    cents = Decimal(str(float(value or 0))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return int(cents.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _grosze(value: float) -> float:
    """Brutto i netto zostaja z groszami - zaokraglenie tylko do 0,01 zl."""
    return float(Decimal(str(float(value or 0))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)) + 0.0


def _tax_parts(gross: float) -> dict[str, float]:
    """
    Wspolny rachunek `net_parts` i `settle_period`.

    ⚠ ZAMIERZONE zaokraglenia do zlotowki: koszty uzysku, podstawa i zaliczka
    na podatek - tak liczy kalkulator urzedowy. Brutto i netto NIE: reczny mecz
    wpisany jako 150,50 zl ma w rozliczeniu 150,50 zl, a nie 151 zl (decyzja
    uzytkownika z 24.09.2026, „nigdzie tak nie moze byc").
    """
    gross = _grosze(gross)
    costs = _whole_pln(0.2 * gross) if gross > 200 else 0
    taxable = _whole_pln(gross - costs)
    tax = _whole_pln(0.12 * taxable)
    return {
        "gross": gross,
        "costs": costs,
        "taxable": taxable,
        "tax": tax,
        "net": _grosze(gross - tax),
    }


def net_parts(gross: float) -> dict[str, float]:
    """
    Koszty uzysku i podatek.

    Prog 200 zl: ponizej niego koszty uzysku nie przysluguja. Ta sama regula,
    ktora stosuje `calculateLacznie` w BAZA i `netParts` w BAZA_web.
    """
    return _tax_parts(gross)


def settle_period(total_gross: float) -> dict[str, float]:
    """
    Rozliczenie ZBIORCZE za okres - jeden wiersz zestawienia.

    ⚠ Koszty uzysku i podatek licza sie od SUMY sedziego za caly miesiac, a nie
    mecz po meczu (decyzja uzytkownika z 09.09.2026). Prog 200 zl wypada wiec
    RAZ, na sumie - dokladnie tak, jak czyta sie papierowe zestawienie
    ekwiwalentow. Przy pojedynczym meczu ponizej progu daje to inna kwote niz
    `net_parts`, i to jest zamierzone.
    """
    return _tax_parts(total_gross)


def _cents_of(value: Any) -> int:
    """Kwota w groszach jako liczba całkowita - od połowy grosza w górę."""
    return int(Decimal(str(float(value or 0))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) * 100)


def central_tax_parts(gross: float) -> dict[str, float]:
    """
    Koszty uzysku i podatek na rachunku ZPRP - mecze CENTRALNE (II liga w górę,
    MP, PP, Superpuchar, EHF), czyli obsady, które rozlicza ZPRP
    (`zprp_settlement_reason`).

    Wzór z prawdziwego rachunku ZPRP (brutto 389 zł, przejazd 2 x 122 km po 0,80):
    koszty 20% = 77,80 zł (DO GROSZA), dochód = 311,20 zł, podatek 12% = 37 zł
    (PEŁNE ZŁOTE, połówka W GÓRĘ jak Math.round/Excel), netto = 352,00 zł,
    przejazd 195,20 zł, do wypłaty 547,20 zł.

    Inaczej niż `_tax_parts` (okręg): tam koszty i dochód idą do pełnych złotych.
    Próg 200 zł brutto zostaje ten sam.

    Liczone w CAŁKOWITYCH groszach, bez float i bez `round()` (bankierski):
    koszty = (2 x brutto_gr + 5) // 10, podatek = (12 x dochód_gr + 5000) // 10000.

    ⚠ BLIŹNIAKI - zmiana tu to zmiana tam: `centralNetParts` w
    `BAZA_web/utils/province-stats/rates.ts` i odpowiednik w aplikacji
    `BAZA/utils/...` (rachunek sędziego w telefonie).
    """
    gross_c = _cents_of(gross)
    costs_c = (2 * gross_c + 5) // 10 if gross_c > 20000 else 0
    taxable_c = gross_c - costs_c
    tax = (12 * taxable_c + 5000) // 10000 if taxable_c > 0 else 0
    return {
        "gross": gross_c / 100 + 0.0,
        "costs": costs_c / 100 + 0.0,
        "taxable": taxable_c / 100 + 0.0,
        "tax": int(tax),
        "net": (gross_c - tax * 100) / 100 + 0.0,
    }


def settle_by_payer(district_gross: float, zprp_bills: Iterable[float] = ()) -> dict[str, float]:
    """
    Jeden wiersz sędziego, gdy w okresie są obsady OBU płatników.

    Część okręgowa idzie `settle_period` od SUMY okresu (bez zmian). Część
    rozliczana przez ZPRP - RACHUNEK PO RACHUNKU: ZPRP wystawia rachunek za
    każdy mecz osobno, więc `zprp_bills` to brutto kolejnych rachunków,
    a koszty, podatek i netto są sumą ZAOKRĄGLONYCH kwot każdego z nich
    (`central_tax_parts`), nie zaokrągleniem sumy.
    Rachunek na 0 zł (brak stawki, brak odległości) nic nie wnosi.
    """
    bills = [b for b in (zprp_bills or ()) if _cents_of(b) != 0]
    parts = []
    if district_gross or not bills:
        parts.append(settle_period(district_gross))
    parts.extend(central_tax_parts(b) for b in bills)
    if len(parts) == 1:
        return parts[0]

    def total(name: str) -> float:
        return sum(_cents_of(p[name]) for p in parts) / 100 + 0.0

    return {
        "gross": total("gross"),
        "costs": total("costs"),
        "taxable": total("taxable"),
        "tax": int(sum(int(p["tax"]) for p in parts)),
        "net": total("net"),
    }


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
