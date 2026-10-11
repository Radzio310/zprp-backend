"""Skład meczu do siatki koszulek w Dzienniku - kto ile ma kar, bramek i zmian.

Liść bez bazy. Każda osoba (zawodnik albo osoba towarzysząca z jakimkolwiek
zdarzeniem) dostaje kafel: numer, nazwisko, kary z końcowego protokołu,
bramki, liczbę ingerencji w jej zdarzenia i poziom alarmu (`alarmy.py`).
Ingerencja to wszystko poza zwykłym dopisaniem: poprawka czasu, zmiana
rodzaju, przeniesienie, usunięcie.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Tuple

from . import analiza as A
from .dossier import osoba_towarzyszaca


def _klucz_sortu(numer: str) -> Tuple[int, int, str]:
    return (0, int(numer), "") if str(numer).isdigit() else (1, 0, str(numer))


def sklad_meczu(zrzut: Dict[str, Any], alarmy: Dict[str, Any]) -> Dict[str, Any]:
    blob = A._slownik((zrzut.get("mecz") or {}).get("data_json"))
    osoby = A.Osoby(blob)
    koncowe = [A.klucz_zdarzenia(e) for e in A.przebieg(blob)]

    zmiany: Counter = Counter()
    for _pm, _m, rem, add, _pb, _b in A.kroki(list(zrzut.get("migawki") or [])):
        if not rem:
            continue
        for z in A.klasyfikuj(rem, add):
            if z["rodzaj"] == "dodane":
                continue
            # Raz na zmianę na osobę - poprawka czasu ma obie strony u tej samej osoby.
            for para in {(k[1], k[2]) for k in (z["stare"], z["nowe"]) if k is not None}:
                zmiany[para] += 1

    poziomy = {(o["druzyna"], o["numer"]): o["poziom"] for o in alarmy.get("osoby") or []}
    druzyny = []
    for d in ("host", "guest"):
        numery = dict(osoby.karty.get(d, {}))
        for k in koncowe:
            if k[1] == d and k[2] and k[2] not in numery:
                numery[k[2]] = ""  # zdarzenie bez karty: osoba towarzysząca albo skład ręczny
        for (dd, nr) in list(zmiany) + list(poziomy):
            if dd == d and nr and nr not in numery:
                numery[nr] = ""
        zawodnicy: List[Dict[str, Any]] = []
        for nr in sorted(numery, key=_klucz_sortu):
            moje = sorted((k for k in koncowe if k[1] == d and k[2] == nr), key=lambda k: k[3])
            towarzyszaca = not nr.isdigit()
            if towarzyszaca and not moje and (d, nr) not in zmiany:
                continue
            zawodnicy.append({
                "numer": nr,
                "nazwisko": numery[nr] or (osoba_towarzyszaca(blob, d, nr) if towarzyszaca else ""),
                "towarzyszaca": towarzyszaca,
                "bramki": sum(1 for k in moje if k[0] in A.BRAMKI),
                "kary": [A.KROTKO.get(k[0], k[0]) for k in moje if k[0] in A.KARY],
                "zmiany": zmiany.get((d, nr), 0),
                "poziom": poziomy.get((d, nr)),
            })
        druzyny.append({"strona": d, "nazwa": osoby.druzyna(d), "osoby": zawodnicy})
    return {"druzyny": druzyny}
