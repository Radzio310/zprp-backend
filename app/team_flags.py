"""Flagi reprezentacji na planszach (13.11.2026): drużyna bez logo, której nazwa to kraj, dostaje flagę zamiast tarczy z inicjałami.

Te same dane i zasady co w aplikacji (`utils/countries.ts`, flagi `assets/flags`, pakiet flag-icons na licencji MIT - plik
w `app/flags`). Dopasowanie ŚCISŁE: po zdjęciu dopisków („Reprezentacja”, „U-21”, „K”...) z nazwy ma zostać dokładnie nazwa
kraju, nigdy podciąg - „Czarni Polska Cerekiew” i „Słowenia Team Kielce” to kluby. Lepsza tarcza na reprezentacji niż flaga
na klubie. Czyste: bez bazy i sieci; obraz flagi to PNG 256x256 z dysku.
"""

from __future__ import annotations

import functools
import os
import re
import unicodedata
from typing import Dict, Optional, Tuple

FLAG_DIR = os.path.join(os.path.dirname(__file__), "flags")

#: (iso, polska nazwa, angielska, dopełniacz, inne nazwy) - kolejność jak w aplikacji.
COUNTRIES: Tuple[Tuple[str, str, str, str, Tuple[str, ...]], ...] = (
    ('pl', 'Polska', 'Poland', 'Polski', ()),
    ('de', 'Niemcy', 'Germany', 'Niemiec', ()),
    ('dk', 'Dania', 'Denmark', 'Danii', ()),
    ('fr', 'Francja', 'France', 'Francji', ()),
    ('es', 'Hiszpania', 'Spain', 'Hiszpanii', ()),
    ('se', 'Szwecja', 'Sweden', 'Szwecji', ()),
    ('no', 'Norwegia', 'Norway', 'Norwegii', ()),
    ('is', 'Islandia', 'Iceland', 'Islandii', ()),
    ('hr', 'Chorwacja', 'Croatia', 'Chorwacji', ()),
    ('si', 'Słowenia', 'Slovenia', 'Słowenii', ()),
    ('rs', 'Serbia', 'Serbia', 'Serbii', ()),
    ('me', 'Czarnogóra', 'Montenegro', 'Czarnogóry', ()),
    ('mk', 'Macedonia Północna', 'North Macedonia', 'Macedonii Północnej', ('Macedonia',)),
    ('ba', 'Bośnia i Hercegowina', 'Bosnia and Herzegovina', 'Bośni i Hercegowiny', ('Bośnia', 'Bosnia')),
    ('hu', 'Węgry', 'Hungary', 'Węgier', ()),
    ('cz', 'Czechy', 'Czechia', 'Czech', ('Czech Republic', 'Republika Czeska')),
    ('sk', 'Słowacja', 'Slovakia', 'Słowacji', ()),
    ('at', 'Austria', 'Austria', 'Austrii', ()),
    ('ch', 'Szwajcaria', 'Switzerland', 'Szwajcarii', ()),
    ('nl', 'Holandia', 'Netherlands', 'Holandii', ('Niderlandy', 'Holland')),
    ('be', 'Belgia', 'Belgium', 'Belgii', ()),
    ('lu', 'Luksemburg', 'Luxembourg', 'Luksemburga', ()),
    ('pt', 'Portugalia', 'Portugal', 'Portugalii', ()),
    ('it', 'Włochy', 'Italy', 'Włoch', ()),
    ('gr', 'Grecja', 'Greece', 'Grecji', ()),
    ('ro', 'Rumunia', 'Romania', 'Rumunii', ()),
    ('bg', 'Bułgaria', 'Bulgaria', 'Bułgarii', ()),
    ('ua', 'Ukraina', 'Ukraine', 'Ukrainy', ()),
    ('by', 'Białoruś', 'Belarus', 'Białorusi', ()),
    ('ru', 'Rosja', 'Russia', 'Rosji', ()),
    ('lt', 'Litwa', 'Lithuania', 'Litwy', ()),
    ('lv', 'Łotwa', 'Latvia', 'Łotwy', ()),
    ('ee', 'Estonia', 'Estonia', 'Estonii', ()),
    ('fi', 'Finlandia', 'Finland', 'Finlandii', ()),
    ('tr', 'Turcja', 'Turkey', 'Turcji', ('Türkiye',)),
    ('cy', 'Cypr', 'Cyprus', 'Cypru', ()),
    ('il', 'Izrael', 'Israel', 'Izraela', ()),
    ('ge', 'Gruzja', 'Georgia', 'Gruzji', ()),
    ('xk', 'Kosowo', 'Kosovo', 'Kosowa', ()),
    ('al', 'Albania', 'Albania', 'Albanii', ()),
    ('md', 'Mołdawia', 'Moldova', 'Mołdawii', ()),
    ('fo', 'Wyspy Owcze', 'Faroe Islands', 'Wysp Owczych', ()),
    ('gb', 'Wielka Brytania', 'Great Britain', 'Wielkiej Brytanii', ('United Kingdom',)),
    ('ie', 'Irlandia', 'Ireland', 'Irlandii', ()),
    ('eg', 'Egipt', 'Egypt', 'Egiptu', ()),
    ('tn', 'Tunezja', 'Tunisia', 'Tunezji', ()),
    ('dz', 'Algieria', 'Algeria', 'Algierii', ()),
    ('ma', 'Maroko', 'Morocco', 'Maroka', ()),
    ('ao', 'Angola', 'Angola', 'Angoli', ()),
    ('cv', 'Republika Zielonego Przylądka', 'Cape Verde', 'Republiki Zielonego Przylądka', ('Cabo Verde',)),
    ('cm', 'Kamerun', 'Cameroon', 'Kamerunu', ()),
    ('sn', 'Senegal', 'Senegal', 'Senegalu', ()),
    ('qa', 'Katar', 'Qatar', 'Kataru', ()),
    ('bh', 'Bahrajn', 'Bahrain', 'Bahrajnu', ()),
    ('sa', 'Arabia Saudyjska', 'Saudi Arabia', 'Arabii Saudyjskiej', ()),
    ('kw', 'Kuwejt', 'Kuwait', 'Kuwejtu', ()),
    ('ae', 'Zjednoczone Emiraty Arabskie', 'United Arab Emirates', 'Zjednoczonych Emiratów Arabskich', ('Emiraty Arabskie',)),
    ('ir', 'Iran', 'Iran', 'Iranu', ()),
    ('jp', 'Japonia', 'Japan', 'Japonii', ()),
    ('kr', 'Korea Południowa', 'South Korea', 'Korei Południowej', ('Korea', 'Republika Korei')),
    ('cn', 'Chiny', 'China', 'Chin', ()),
    ('kz', 'Kazachstan', 'Kazakhstan', 'Kazachstanu', ()),
    ('br', 'Brazylia', 'Brazil', 'Brazylii', ()),
    ('ar', 'Argentyna', 'Argentina', 'Argentyny', ()),
    ('cl', 'Chile', 'Chile', 'Chile', ()),
    ('uy', 'Urugwaj', 'Uruguay', 'Urugwaju', ()),
    ('cu', 'Kuba', 'Cuba', 'Kuby', ()),
    ('mx', 'Meksyk', 'Mexico', 'Meksyku', ()),
    ('us', 'Stany Zjednoczone', 'United States', 'Stanów Zjednoczonych', ('USA',)),
    ('ca', 'Kanada', 'Canada', 'Kanady', ()),
    ('au', 'Australia', 'Australia', 'Australii', ()),
)


class FlagCrest(bytes):
    """PNG flagi w miejscu herbu. Rysunek planszy kładzie go na całą powierzchnię kamyka/medalionu (jak `CountryFlag` w
    aplikacji), zamiast wycinać tło jak z logo klubu."""

    iso: str = ""

    def __new__(cls, data: bytes, iso: str) -> "FlagCrest":
        out = super().__new__(cls, data)
        out.iso = iso
        return out


def is_flag(raw: object) -> bool:
    return isinstance(raw, FlagCrest)


def norm(text: object) -> str:
    """Małe litery, bez polskich znaków i akcentów, interpunkcja jako spacja (jak `norm` w aplikacji)."""
    value = str(text or "").lower().replace("ł", "l")
    value = "".join(ch for ch in unicodedata.normalize("NFD", value) if not unicodedata.combining(ch))
    value = value.replace("&", " and ")
    return re.sub(r"[^a-z0-9]+", " ", value).strip()


_PREFIX = re.compile(r"^(?:(?:mlodziezowa|juniorska|kadetowa|seniorska|narodowa) )?(?:reprezentacja|repr|kadra|national team(?: of)?)(?: narodowa)? ")
_SUFFIX = re.compile(" (?:" + "|".join([
    r"u ?\d{2}",
    r"under \d{2}",
    r"do lat \d{2}",
    r"do \d{2} lat",
    r"(?:rocznik |r )?(?:19|20)\d{2}",
    "k|m|w|a|b|ii|2",
    "kobiety|kobiet|mezczyzni|mezczyzn|women|men",
    "seniorzy|seniorki|seniorow|seniorek|seniors",
    "juniorzy|juniorki|juniorow|juniorek|juniors|junior",
    "mlodzicy|mlodziczki|mlodzikow|mlodziczek",
    "kadeci|kadetki|kadetow|kadetek|youth",
    "mlodziez|mlodziezowa|mlodziezowi|mlodziezowy|mlodziezowcy",
    "mlodsi|mlodsze|mlodszy|mlodsza|starsi|starsze|starszy|starsza",
    "national team",
]) + ")$")


@functools.lru_cache(maxsize=1)
def _indexes() -> Tuple[Dict[str, str], Dict[str, str]]:
    names: Dict[str, str] = {}
    genitives: Dict[str, str] = {}
    for iso, pl, en, genitive, aliases in COUNTRIES:
        for name in (pl, en, *aliases):
            names[norm(name)] = iso
        genitives[norm(genitive)] = iso
    return names, genitives


@functools.lru_cache(maxsize=2048)
def flag_iso(name: object) -> Optional[str]:
    """Kod flagi, gdy nazwa drużyny to reprezentacja („Polska”, „Reprezentacja Słowenii”, „Niemcy U-21”); klub = None."""
    text = norm(name)
    if not text:
        return None
    prev = None
    while prev != text:
        prev = text
        text = _SUFFIX.sub("", text)
    names, genitives = _indexes()
    stripped = _PREFIX.sub("", text)
    if stripped != text:
        return names.get(stripped) or genitives.get(stripped)
    return names.get(text)


@functools.lru_cache(maxsize=96)
def flag_png(iso: str) -> Optional[FlagCrest]:
    """PNG flagi z dysku albo None (kraj bez pliku)."""
    key = re.sub(r"[^a-z]", "", str(iso or "").lower())
    path = os.path.join(FLAG_DIR, f"{key}.png")
    if not key or not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        return FlagCrest(handle.read(), key)


def team_flag(name: object) -> Optional[FlagCrest]:
    iso = flag_iso(name)
    return flag_png(iso) if iso else None
