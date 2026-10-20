"""Tożsamość osoby po nazwisku - jedna reguła dla całego serwera.

Wszystkie porównania nazwisk (giełda, obsady, bomby, role w meczu) liczyły
ZBIÓR członów, żeby „NOWAK Jan" i „Jan Nowak" były tym samym człowiekiem. Część
z nich dodatkowo wyrzucała jednoliterowe człony („inicjały nie odróżniają
nikogo"), a część uznawała podzbiór za trafienie. W obu wypadkach ojciec i syn
o tym samym imieniu przestawali się różnić: w Dolnośląskiem „Karol ZAJĄC"
(ID 288) i „Karol R. ZAJĄC" (ID 5601, w formularzu ZPRP „ZAJĄC Karol R.")
wychodzili na jedną osobę - giełda nie umiała zapisać wymiany („pasuje do
kilku sędziów"), a „mój mecz" syna świecił się ojcu.

Reguła: inicjał i dopisek pokoleniowy („Jr", „Sr") są ZNAKIEM ROZRÓŻNIAJĄCYM.
Dwa zapisy wskazują tę samą osobę tylko wtedy, gdy mają te same znaki - reszta
członów porównuje się jak dotąd. ZPRP dopisuje inicjał właśnie po to, żeby
rozdzielić imienników, więc nie wolno go gubić.
"""

from __future__ import annotations

import functools
import re
import unicodedata
from typing import Any, FrozenSet, List, Tuple

#: Litery, których NFD nie rozkłada na literę i ogonek.
_HARD_FOLD = str.maketrans({"ł": "l", "Ł": "L", "ø": "o", "Ø": "O", "đ": "d", "Đ": "D"})

#: Dopiski pokoleniowe sprowadzone do jednego zapisu.
_GENERATION = {
    "jr": "jr",
    "junior": "jr",
    "jun": "jr",
    "mlodszy": "jr",
    "sr": "sr",
    "senior": "sr",
    "sen": "sr",
    "starszy": "sr",
}


def _fold(text: Any) -> str:
    return _fold_text(str(text or ""))


@functools.lru_cache(maxsize=65536)
def _fold_text(text: str) -> str:
    raw = text.translate(_HARD_FOLD)
    raw = unicodedata.normalize("NFD", raw)
    raw = "".join(ch for ch in raw if unicodedata.category(ch) != "Mn")
    return raw.lower().strip()


def split_name(text: Any) -> Tuple[List[str], FrozenSet[str]]:
    """(człony nazwiska posortowane, znaki rozróżniające).

    „ZAJĄC Karol R." -> (["karol", "zajac"], {"r"}),
    „Zając Karol Jr" -> (["karol", "zajac"], {"jr"}).
    """
    parts: List[str] = []
    marks = set()
    for token in re.sub(r"[^a-z0-9]+", " ", _fold(text)).split():
        if token in _GENERATION:
            marks.add(_GENERATION[token])
        elif len(token) == 1 and token.isalpha():
            marks.add(token)
        else:
            parts.append(token)
    return sorted(parts), frozenset(marks)


def person_name_key(text: Any) -> str:
    """Stały klucz osoby: człony bez kolejności + znaki rozróżniające.

    „NOWAK Jan" i „Jan Nowak" -> ten sam klucz; „ZAJĄC Karol" i
    „ZAJĄC Karol R." -> różne.
    """
    parts, marks = split_name(text)
    if not parts:
        return ""
    return " ".join(parts + [f"~{m}" for m in sorted(marks)])


def same_marks(a: Any, b: Any) -> bool:
    """Czy oba zapisy niosą te same znaki rozróżniające (inicjały, Jr/Sr)."""
    return split_name(a)[1] == split_name(b)[1]


def names_match(a: Any, b: Any) -> bool:
    """Ta sama osoba mimo innej kolejności członów.

    Krótszy zbiór członów musi zawierać się w dłuższym (drugie imię albo
    dwuczłonowe nazwisko po jednej stronie), ale przy co najmniej dwóch
    członach - samo „Nowak" pasowałoby do każdego Nowaka. Znaki rozróżniające
    muszą być identyczne.
    """
    pa, ma = split_name(a)
    pb, mb = split_name(b)
    if not pa or not pb or ma != mb:
        return False
    if pa == pb:
        return True
    if len(pa) < 2 or len(pb) < 2:
        return False
    shorter, longer = (pa, pb) if len(pa) <= len(pb) else (pb, pa)
    return all(part in longer for part in shorter)
