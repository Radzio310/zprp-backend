"""
Uprawnienia sedziow do szczebli - zbierane z formularza obsady ZPRP.

Litery w nawiasach przy nazwisku na liscie wyboru sedziego to jedyne miejsce,
w ktorym baza zwiazku mowi nam, kto ma jakie uprawnienia: (SL) Superliga,
(LC) ligi centralne, (PP) Puchar Polski, (MP) Mistrzostwa Polski, (I) (II) (III)
ligi, (Mł) mlodziez. Automat obsady bez nich nie odrozni stolika ligowego od
okregowego - a osobnej listy uprawnien ZPRP nie wystawia.

Zbieramy je WIEC PRZY OKAZJI: za kazdym razem, gdy panel otwiera formularz
meczu, zapamietujemy to, co w nim stalo. Nic nie kasujemy - brak kogos na
JEDNEJ liscie (filtr potrafi ja przyciac) nie znaczy, ze stracil uprawnienia.

⚠ Kluczem jest NAZWISKO, nie numer: `value` opcji w tym formularzu nie jest
stalym numerem sedziego (ZPRP przenumerowuje opcje zaleznie od filtra). Klucz
liczy `name_key`, wiec „NOWAK Jan" i „Jan Nowak" trafiaja w to samo miejsce.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping

from app.assignment_people import letter_key, name_key

logger = logging.getLogger(__name__)

#: Litery, ktore cokolwiek znacza dla automatu. Reszta („[MECZ]", smieci
#: z formatowania) nie ma po co zajmowac miejsca w tabeli.
KNOWN_LETTERS = frozenset(
    letter_key(item) for item in ("SL", "LC", "PP", "MP", "I", "II", "III", "Mł")
)


def options_grades(parsed: Mapping[str, Any]) -> dict[str, tuple[str, list[str]]]:
    """
    Sparsowany formularz -> `{klucz nazwiska: (nazwisko, litery)}`.

    Ta sama osoba stoi w kilku gniazdach naraz, wiec litery z nich SUMUJEMY:
    lista dla stolika bywa przyciagnieta filtrem i pokazuje mniej niz boiskowa.
    """
    out: dict[str, tuple[str, set[str]]] = {}
    slots = parsed.get("slots") if isinstance(parsed, Mapping) else None
    for slot in (slots or {}).values():
        for option in (slot or {}).get("options") or ():
            name = str((option or {}).get("name") or "").strip()
            key = name_key(name)
            if not key:
                continue
            letters = {
                letter_key(item)
                for item in ((option or {}).get("badges") or ())
                if letter_key(item) in KNOWN_LETTERS
            }
            known_name, known = out.get(key, (name, set()))
            out[key] = (known_name or name, known | letters)
    return {key: (name, sorted(letters)) for key, (name, letters) in out.items() if letters}


async def remember_grades(parsed: Mapping[str, Any]) -> int:
    """
    Zapisuje zebrane uprawnienia. Oddaje, ilu ludzi dotyczyl zapis.

    Osloniete: to czynnosc uboczna przy otwieraniu formularza. Gdyby zapis
    padl, obsadowy ma zobaczyc formularz, a nie blad - automat przy nastepnym
    otwarciu dowie sie tego samego.
    """
    grades = options_grades(parsed)
    if not grades:
        return 0
    try:
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        from app.db import database, zprp_judge_grades

        for key, (full_name, letters) in grades.items():
            await database.execute(
                pg_insert(zprp_judge_grades)
                .values(name_key=key, full_name=full_name, letters=letters)
                .on_conflict_do_update(
                    index_elements=[zprp_judge_grades.c.name_key],
                    set_={"full_name": full_name, "letters": letters},
                )
            )
        return len(grades)
    except Exception:
        logger.exception("obsada: nie udało się zapamiętać uprawnień z formularza")
        return 0
