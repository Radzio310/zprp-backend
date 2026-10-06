"""
Podpowiedzi zdjęcia meczu z rozliczeń - sama reguła.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

ZASADA (decyzja użytkownika z 06.10.2026). Mecz NIGDY nie znika z rozliczenia
sam z powodu numeru - zdejmuje go tylko człowiek („Nie obciążaj klubów"
w Panelu klubów albo „Nie naliczaj" w Rozliczeniach; oba zdejmują CAŁY mecz).
Panel się jednak uczy: gdy z rozliczeń zdejmowano już mecze jakichś rozgrywek
INNEGO okręgu (np. „E/JmK" - mecze Wiktorii Więcław w Piotrkowie), każdy
kolejny mecz tych rozgrywek, u dowolnego naszego sędziego, dostaje
podpowiedź „zdjąć?" i trafia do licznika „do decyzji". Sam z siebie nie
znika - człowiek zdejmuje go jednym kliknięciem albo zostawia („Zostaw").

Tylko rozgrywki z CUDZYM przedrostkiem: zdjęcie jednego meczu naszej ligi
(„S/MłK") to pojedynczy wyjątek i nie może oflagować setek meczów okręgu.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from app.settlement_origin import is_other_district


def competition_label(code: Any) -> str:
    """„E/JmK/3" -> „E/JmK": numer bez numeru meczu."""
    parts = [p.strip() for p in str(code or "").split("/") if p.strip()]
    if len(parts) >= 2 and parts[-1].isdigit():
        parts = parts[:-1]
    return "/".join(parts)


def competition_key(code: Any) -> str:
    """Klucz rozgrywek do porównań - bez wielkości liter."""
    return competition_label(code).upper()


def excluded_competitions(codes: Iterable[Any], own: Iterable[str]) -> dict[str, int]:
    """
    Rozgrywki innych okręgów, z których zdejmowano mecze: {klucz: ile meczów}.

    `codes` - numery meczów zdjętych z rozliczeń (po jednym na mecz).
    """
    mine = set(own or ())
    out: dict[str, int] = {}
    for code in codes:
        if not is_other_district(code, mine):
            continue
        key = competition_key(code)
        if key:
            out[key] = out.get(key, 0) + 1
    return out


def hint(code: Any, excluded: dict[str, int], own: Iterable[str]) -> Optional[str]:
    """Zdanie podpowiedzi dla meczu w rozliczeniu - albo None."""
    if not excluded or not is_other_district(code, set(own or ())):
        return None
    count = excluded.get(competition_key(code))
    if not count:
        return None
    label = competition_label(code)
    word = "mecz" if count == 1 else ("mecze" if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14 else "meczów")
    return f"Z rozgrywek {label} zdjęto już {count} {word} - zdjąć też ten?"
