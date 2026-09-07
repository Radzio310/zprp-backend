# app/protocol_category.py
#
# Kratka „ZAWODY" w nagłówku protokołu: rodzaj rozgrywek, wiek i płeć z numeru
# meczu.
#
# PO CO. Górna kratka protokołu (SUPERLIGA / I LIGA / ..., K / M, SENIORZY /
# JUNIORZY / ...) była dotąd pusta - sędzia stawiał krzyżyki długopisem już po
# wydruku. Numer meczu mówi wszystko, co trzeba: człon literowy to rozgrywki
# („IIM4/1" = II liga mężczyzn, grupa 4), a ostatnia litera tego członu - płeć.
#
# JAK CZYTAMY NUMER. Numer dzielimy po „/" i w każdym członie szukamy
# NAJDŁUŻSZEGO znanego kodu na jego początku. Dzięki temu „IIIM" nie myli się
# z „IIM", „SPK" ze „SK", a „MłM1213" z „MłM"; „IMD/3" (I liga, grupa D) i
# „S/PPK/2" (numer z przedrostkiem okręgu) też przechodzą. Wielkość liter ma
# znaczenie, bo tak pisze ZPRP: „JmM" to junior młodszy, „JM" - junior. Gdy
# kilka członów pasuje, wygrywa ten z literą płci: „MP" bywa i Mistrzostwami
# Polski, i przedrostkiem okręgu, a „MP/JM/12" to mecz juniorów.
#
# CZEGO KRATKA NIE MA. Ligi Centralnej, Superpucharu, III ligi, Mistrzostw
# Polski ani młodzika młodszego. Dla nich nadpisujemy najbliższy napis
# (SUPERLIGA w V3 albo MŁODZICY w AH6) i stawiamy krzyżyk przed nim. Nadpisany
# napis bywa dłuższy niż oryginał, więc dostaje własny rozmiar czcionki,
# liczony względem tego, co w szablonie NA PEWNO się mieści („PUCHAR POLSKI"
# przy 5 pt w lewej kolumnie, „JUNIORZY MŁ." przy 6 pt w prawej) - patrz
# `fit_label`. Napis, który nie mieści się nawet przy 4 pt, łamiemy na dwa
# wiersze zamiast schodzić do nieczytelnych 3 pt; wiersz kratki ma 13,2 pt,
# dwie linie po 5 pt wchodzą.
#
# CZEGO NIE ZGADUJEMY. Środkowej kolumny (finał / eliminacje) i baraży - numer
# meczu o tym nie mówi. Nierozpoznany numer (OOM, mecz testowy, pusty) zostawia
# kratkę tak, jak drukowała się do tej pory: pustą. Wiek przy Mistrzostwach
# Polski też zostaje pusty: w bazie ZPRP to zwykle turnieje finałowe młodzieży,
# a numer nie mówi której.
#
# PŁEĆ BEZ LITERY W KODZIE (LC, MP, PP) czytamy ze składów. ZPRP pisze
# „KOWALSKA Anna": nazwisko wielkimi literami, imię zwykłym pismem. Kobieta,
# gdy imię kończy się na „a" albo nazwisko na „-ska/-cka". Liczymy obie
# drużyny razem: co najmniej 2/3 kobiecych to K, co najwyżej 1/3 to M, pomiędzy
# nic - lepiej nie zaznaczyć niż zaznaczyć źle.
#
# ADRESY. Wszystkie adresy w tym module są FIZYCZNE, czyli takie, jak w Excelu
# (U3, V3, AA7, AD7, AG3...). Kod wypełniający protokół adresuje arkusz przez
# nakładkę z przesunięciem o kolumnę (`ShiftedWS`), więc te adresy pisze do
# `ws.raw`, nie do nakładki.
#
# Moduł-liść: bez openpyxl, bez sieci - do sprawdzenia testem.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Rozgrywki z numeru meczu
# ---------------------------------------------------------------------------

#: Kod z numeru meczu -> (rodzaj rozgrywek, płeć). Płeć pusta, gdy kod jej nie
#: niesie (LC, MP, PP) - wtedy rozstrzygają składy.
COMPETITION_TOKENS: Dict[str, Tuple[str, str]] = {
    "SM": ("superliga", "M"),
    "SK": ("superliga", "K"),
    "OSM": ("superliga", "M"),
    "OSK": ("superliga", "K"),
    "LSM": ("superliga", "M"),
    "LSK": ("superliga", "K"),
    "SPM": ("superpuchar", "M"),
    "SPK": ("superpuchar", "K"),
    "LCM": ("liga_centralna", "M"),
    "LCK": ("liga_centralna", "K"),
    "LC": ("liga_centralna", ""),
    "IM": ("i_liga", "M"),
    "IK": ("i_liga", "K"),
    "IIM": ("ii_liga", "M"),
    "IIK": ("ii_liga", "K"),
    "IIIM": ("iii_liga", "M"),
    "IIIK": ("iii_liga", "K"),
    "MPM": ("mp", "M"),
    "MPK": ("mp", "K"),
    "MP": ("mp", ""),
    "PPM": ("pp", "M"),
    "PPK": ("pp", "K"),
    "PP": ("pp", ""),
    "JM": ("junior", "M"),
    "JK": ("junior", "K"),
    "JmM": ("junior_ml", "M"),
    "JmK": ("junior_ml", "K"),
    "MłM": ("mlodzik", "M"),
    "MłK": ("mlodzik", "K"),
    "MłM1213": ("mlodzik_ml", "M"),
    "MłK1213": ("mlodzik_ml", "K"),
    "DzM": ("dzieci", "M"),
    "DzK": ("dzieci", "K"),
}

#: Kody od najdłuższego - pierwsze trafienie jest najdłuższym.
_TOKENS_LONGEST_FIRST: Tuple[str, ...] = tuple(
    sorted(COMPETITION_TOKENS, key=len, reverse=True)
)

#: Nazwa rozgrywek po polsku - do dziennika i testów, nie na wydruk.
COMPETITION_LABELS: Dict[str, str] = {
    "superliga": "Superliga",
    "superpuchar": "Superpuchar",
    "liga_centralna": "Liga Centralna",
    "i_liga": "I liga",
    "ii_liga": "II liga",
    "iii_liga": "III liga",
    "mp": "Mistrzostwa Polski",
    "pp": "Puchar Polski",
    "junior": "Junior",
    "junior_ml": "Junior mł.",
    "mlodzik": "Młodzik",
    "mlodzik_ml": "Młodzik mł.",
    "dzieci": "Dzieci",
}

#: Wiek zawodników wynikający z rodzaju rozgrywek. Puchar Polski i Superpuchar
#: grają seniorzy; przy Mistrzostwach Polski numer nie mówi, która to młodzież.
AGE_OF_COMPETITION: Dict[str, str] = {
    "superliga": "seniorzy",
    "superpuchar": "seniorzy",
    "liga_centralna": "seniorzy",
    "i_liga": "seniorzy",
    "ii_liga": "seniorzy",
    "iii_liga": "seniorzy",
    "pp": "seniorzy",
    "mp": "",
    "junior": "juniorzy",
    "junior_ml": "juniorzy_ml",
    "mlodzik": "mlodzicy",
    "mlodzik_ml": "mlodzicy_ml",
    "dzieci": "dzieci",
}


@dataclass(frozen=True)
class MatchKind:
    """Co numer meczu mówi o rozgrywkach."""

    competition: str = ""
    gender: str = ""
    token: str = ""

    @property
    def known(self) -> bool:
        return bool(self.competition)


def _token_of_segment(segment: str) -> str:
    for token in _TOKENS_LONGEST_FIRST:
        if segment.startswith(token):
            return token
    return ""


def classify_match_code(code: object) -> MatchKind:
    """Rodzaj rozgrywek i płeć z numeru meczu; pusty `MatchKind`, gdy nie wiemy."""
    text = str(code or "").strip()
    if not text:
        return MatchKind()
    best: Optional[MatchKind] = None
    for segment in text.split("/"):
        token = _token_of_segment(segment.strip())
        if not token:
            continue
        competition, gender = COMPETITION_TOKENS[token]
        kind = MatchKind(competition=competition, gender=gender, token=token)
        # Człon z literą płci jest pewniejszy niż goły „MP"/„PP"/„LC" - tamte
        # bywają przedrostkiem okręgu w numerze (patrz nagłówek pliku).
        if best is None or (gender and not best.gender):
            best = kind
    return best or MatchKind()


# ---------------------------------------------------------------------------
# Płeć ze składów
# ---------------------------------------------------------------------------

_FEMALE_SURNAME = re.compile(r"(ska|cka|dzka)$")

#: Progi z decyzji Radka (2026-09-07): co najmniej 2/3 kobiecych = K, co
#: najwyżej 1/3 = M, pomiędzy nic.
FEMALE_SHARE_FOR_K = 2 / 3
FEMALE_SHARE_FOR_M = 1 / 3


def looks_female(full_name: object) -> Optional[bool]:
    """Czy nazwisko wygląda na kobiece; `None`, gdy nie ma czego czytać.

    ZPRP pisze „KOWALSKA Anna" - nazwisko wielkimi, imię zwykłym pismem - więc
    imię to człon, który NIE jest w całości wielkimi literami. Gdy cały wpis
    jest jednym pismem (ręczny skład), kolejności nie znamy: bierzemy każdy
    człon kończący się na „a". Nazwisko na „-ska/-cka" jest kobiece z natury
    (mężczyzna miałby „-ski/-cki"), więc rozstrzyga samo.
    """
    tokens = [t for t in re.split(r"[\s,]+", str(full_name or "").strip()) if t]
    if not tokens:
        return None
    if any(_FEMALE_SURNAME.search(t.lower()) for t in tokens):
        return True
    plain = [t for t in tokens if not t.isupper()]
    if plain and len(plain) < len(tokens):
        return plain[0].lower().endswith("a")
    return any(t.lower().endswith("a") for t in tokens)


def gender_from_names(names: Iterable[object]) -> str:
    """„K", „M" albo pusty napis, gdy składy nie rozstrzygają."""
    votes = [v for v in (looks_female(n) for n in names) if v is not None]
    if not votes:
        return ""
    share = sum(1 for v in votes if v) / len(votes)
    if share >= FEMALE_SHARE_FOR_K:
        return "K"
    if share <= FEMALE_SHARE_FOR_M:
        return "M"
    return ""


# ---------------------------------------------------------------------------
# Dopasowanie nadpisanego napisu do pola
# ---------------------------------------------------------------------------

#: Względne szerokości znaków (w jednostkach „em", z Arial - szerszego niż
#: DIN Pro z szablonu, więc oszacowanie jest ostrożne). Liczy się tylko
#: stosunek do tekstu odniesienia, nie wartość bezwzględna.
_GLYPH_EM: Dict[str, float] = {
    "A": 0.667, "B": 0.667, "C": 0.722, "D": 0.722, "E": 0.667, "F": 0.611,
    "G": 0.778, "H": 0.722, "I": 0.278, "J": 0.500, "K": 0.667, "L": 0.556,
    "M": 0.833, "N": 0.722, "O": 0.778, "P": 0.667, "Q": 0.778, "R": 0.722,
    "S": 0.667, "T": 0.611, "U": 0.722, "V": 0.667, "W": 0.944, "X": 0.667,
    "Y": 0.667, "Z": 0.611,
    "Ą": 0.667, "Ć": 0.722, "Ę": 0.667, "Ł": 0.556, "Ń": 0.722, "Ó": 0.778,
    "Ś": 0.667, "Ź": 0.611, "Ż": 0.611,
    "0": 0.556, "1": 0.556, "2": 0.556, "3": 0.556, "4": 0.556, "5": 0.556,
    "6": 0.556, "7": 0.556, "8": 0.556, "9": 0.556,
    " ": 0.278, ".": 0.278, "-": 0.333, "/": 0.278,
}
_GLYPH_DEFAULT_EM = 0.722


def text_width(text: str, size_pt: float) -> float:
    """Szacunkowa szerokość napisu w punktach (tylko do porównań)."""
    return sum(_GLYPH_EM.get(ch, _GLYPH_DEFAULT_EM) for ch in str(text or "")) * size_pt


#: Teksty odniesienia: napisy z szablonu, które w swoim polu mieszczą się na
#: pewno, razem z rozmiarem, jaki nadał im autor szablonu.
LABEL_BUDGETS: Dict[str, float] = {
    # V3:Z3 - lewa kolumna; „PUCHAR POLSKI" ma tam 5 pt (reszta 6 pt).
    "left": text_width("PUCHAR POLSKI", 5.0),
    # AH3:AL7 - prawa kolumna; „JUNIORZY MŁ." ma tam 6 pt.
    "right": text_width("JUNIORZY MŁ.", 6.0),
}

_ONE_LINE_SIZES: Tuple[float, ...] = (6.0, 5.5, 5.0, 4.5, 4.0)
#: Dwie linie w wierszu 13,2 pt: 5 pt to granica, przy której obie wchodzą.
_TWO_LINE_SIZES: Tuple[float, ...] = (5.0, 4.5, 4.0)


@dataclass(frozen=True)
class FittedLabel:
    text: str
    size_pt: float
    wrap: bool = False


def _split_two_lines(text: str) -> Optional[Tuple[str, str]]:
    """Podział przy spacji tak, by dłuższa linia była jak najkrótsza."""
    words = text.split(" ")
    if len(words) < 2:
        return None
    best: Optional[Tuple[str, str]] = None
    best_len = float("inf")
    for i in range(1, len(words)):
        head, tail = " ".join(words[:i]), " ".join(words[i:])
        longest = max(text_width(head, 1.0), text_width(tail, 1.0))
        if longest < best_len:
            best, best_len = (head, tail), longest
    return best


def fit_label(text: str, column: str) -> FittedLabel:
    """Napis z rozmiarem czcionki, przy którym mieści się w polu kratki.

    Największy rozmiar z drabinki, przy którym szacowana szerokość nie
    przekracza budżetu pola; gdy nie mieści się nawet przy 4 pt - dwie linie.
    """
    budget = LABEL_BUDGETS[column]
    text = str(text or "").strip()
    for size in _ONE_LINE_SIZES:
        if text_width(text, size) <= budget:
            return FittedLabel(text=text, size_pt=size)
    lines = _split_two_lines(text)
    if lines:
        for size in _TWO_LINE_SIZES:
            if max(text_width(lines[0], size), text_width(lines[1], size)) <= budget:
                return FittedLabel(text="\n".join(lines), size_pt=size, wrap=True)
    return FittedLabel(text=text, size_pt=_ONE_LINE_SIZES[-1])


# ---------------------------------------------------------------------------
# Kratka
# ---------------------------------------------------------------------------

#: Lewa kolumna kratki: rozgrywki, które mają własne pole -> komórka krzyżyka.
LEFT_CROSS: Dict[str, str] = {
    "superliga": "U3",
    "i_liga": "U4",
    "ii_liga": "U5",
    "pp": "U6",
}

#: Lewa kolumna: rozgrywki bez własnego pola -> napis zamiast SUPERLIGA w V3,
#: krzyżyk w U3.
LEFT_LABEL_CELL = "V3"
LEFT_LABEL_CROSS = "U3"
LEFT_OVERRIDES: Dict[str, str] = {
    "liga_centralna": "LIGA CENTRALNA",
    "superpuchar": "SUPERPUCHAR",
    "iii_liga": "III LIGA",
    "mp": "MISTRZOSTWA POLSKI",
}

#: Środek kratki, wiersz 7: „K" w AB7 z krzyżykiem w AA7, „M" w AE7 z AD7.
GENDER_CROSS: Dict[str, str] = {"K": "AA7", "M": "AD7"}

#: Prawa kolumna: wiek -> komórka krzyżyka.
AGE_CROSS: Dict[str, str] = {
    "seniorzy": "AG3",
    "juniorzy": "AG4",
    "juniorzy_ml": "AG5",
    "mlodzicy": "AG6",
    "dzieci": "AG7",
}

#: Prawa kolumna: wiek bez własnego pola -> (komórka napisu, napis, krzyżyk).
#: Młodzik młodszy dostaje pole młodzików (decyzja Radka, 2026-09-07).
RIGHT_OVERRIDES: Dict[str, Tuple[str, str, str]] = {
    "mlodzicy_ml": ("AH6", "MŁODZICY MŁ.", "AG6"),
}


@dataclass(frozen=True)
class LabelWrite:
    cell: str
    text: str
    size_pt: float
    wrap: bool


@dataclass
class HeaderMarks:
    """Co wpisać do kratki: krzyżyki i nadpisane napisy (adresy fizyczne)."""

    competition: str = ""
    age: str = ""
    gender: str = ""
    #: „code" (litera z numeru), „names" (ze składów) albo pusty.
    gender_source: str = ""
    crosses: List[str] = field(default_factory=list)
    labels: List[LabelWrite] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.crosses and not self.labels


def header_marks(match_number: object, player_names: Iterable[object] = ()) -> HeaderMarks:
    """Krzyżyki i napisy kratki dla numeru meczu (i składów, gdy trzeba)."""
    kind = classify_match_code(match_number)
    marks = HeaderMarks(competition=kind.competition)
    if not kind.known:
        return marks

    if kind.competition in LEFT_CROSS:
        marks.crosses.append(LEFT_CROSS[kind.competition])
    elif kind.competition in LEFT_OVERRIDES:
        fitted = fit_label(LEFT_OVERRIDES[kind.competition], "left")
        marks.labels.append(
            LabelWrite(LEFT_LABEL_CELL, fitted.text, fitted.size_pt, fitted.wrap)
        )
        marks.crosses.append(LEFT_LABEL_CROSS)

    age = AGE_OF_COMPETITION.get(kind.competition, "")
    marks.age = age
    if age in AGE_CROSS:
        marks.crosses.append(AGE_CROSS[age])
    elif age in RIGHT_OVERRIDES:
        cell, text, cross = RIGHT_OVERRIDES[age]
        fitted = fit_label(text, "right")
        marks.labels.append(LabelWrite(cell, fitted.text, fitted.size_pt, fitted.wrap))
        marks.crosses.append(cross)

    gender = kind.gender
    source = "code" if gender else ""
    if not gender:
        gender = gender_from_names(player_names)
        source = "names" if gender else ""
    marks.gender = gender
    marks.gender_source = source
    if gender in GENDER_CROSS:
        marks.crosses.append(GENDER_CROSS[gender])
    return marks
