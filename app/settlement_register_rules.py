"""
Rejestr oficjalnych dokumentów rozliczeń - sama reguła.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby numeracja i zajętość chodziły w teście.
Schemat w `settlement_register_tables`, trasy w `province_settlement_register`.

ZASADY (decyzje użytkownika z 06.10.2026):
  - Szkic nie zużywa numeru i nie trafia do rejestru. Numer dostaje tylko
    dokument OFICJALNY.
  - Numeracja jest ciągła w SEZONIE (sierpień-lipiec, `season_rules`) i osobna
    dla każdego rodzaju dokumentu (decyzja z 07.10.2026): zestawienia
    „SL/2026_27/14", przejazdy „SLP/2026_27/3". O sezonie decyduje OKRES
    rozliczenia, nie dzień wydania - zestawienie za lipiec wydane we wrześniu
    należy do sezonu, który się w lipcu kończył.
  - Podpowiedź = najwyższy numer w rejestrze (albo „kontynuacja" z ustawień,
    gdy większa) + 1. Człowiek może ją przed wydaniem zmienić - byle numer nie
    był zajęty w tym roku i rodzaju.
  - Usunięcie z rejestru zwalnia numer i pozycje.
  - Pozycja to sędzia i CZĘŚĆ jego puli (litera listy z podziału, pusty napis
    = cała pula). Ta sama część tego samego sędziego w tym samym okresie może
    stać tylko na jednym oficjalnym dokumencie danego rodzaju. Cała pula
    wyklucza każdą część i odwrotnie.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Iterable, Optional

from app.season_rules import season_start_year
from app.settlement_money import money

ZESTAWIENIE = "zestawienie"
PRZEJAZDY = "przejazdy"
KINDS = (ZESTAWIENIE, PRZEJAZDY)

#: Część puli „cała pula" - sędzia bez podziału albo przejazdy.
WHOLE = ""

#: Najwyższy numer, jaki da się wpisać - literówka „1400" zamiast „14" nie
#: powinna przesunąć podpowiedzi o tysiąc numerów bez ostrzeżenia.
MAX_SEQ = 9999


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


# ---------------------------------------------------------------------------
# Numeracja
# ---------------------------------------------------------------------------

#: Wyróżnik rodzaju dokumentu za skrótem okręgu: przejazdy „SLP/...", żeby
#: dwa dokumenty nigdy nie nosiły tego samego numeru.
KIND_MARK = {ZESTAWIENIE: "", PRZEJAZDY: "P"}


def season_tag(season: int) -> str:
    """2026 -> „2026_27" (sezon 2026/2027)."""
    return f"{int(season)}_{(int(season) + 1) % 100:02d}"


def season_label(season: int) -> str:
    """2026 -> „2026/27" - podpis na ekranie."""
    return f"{int(season)}/{(int(season) + 1) % 100:02d}"


def number_prefix(short: str, season: int, kind: str = ZESTAWIENIE) -> str:
    """To, co stoi przed numerem kolejnym: „SL/2026_27/" - do pola edycji."""
    return f"{short}{KIND_MARK.get(kind, '')}/{season_tag(season)}/"


def number_text(short: str, season: int, seq: int, kind: str = ZESTAWIENIE) -> str:
    """„SL/2026_27/14" (zestawienie), „SLP/2026_27/3" (przejazdy)."""
    return f"{number_prefix(short, season, kind)}{int(seq)}"


def period_season(date_from: Optional[date], configured: Any = None) -> Optional[int]:
    """
    Sezon okresu rozliczenia (rok jego początku).

    Własny okres wypłat okręgu niesie sezon wprost („2026/2027") i to on
    rozstrzyga. Miesiąc kalendarzowy - sezon pierwszego dnia okresu
    (granica sierpniowa `season_rules`).
    """
    text = str(configured or "").strip()
    if len(text) >= 4 and text[:4].isdigit():
        return int(text[:4])
    return season_start_year(date_from)


def suggest_seq(used: Iterable[int], start_after: int = 0) -> int:
    """Ostatni oficjalny (albo kontynuacja z ustawień) + 1."""
    top = max([int(s) for s in used] or [0])
    return max(top, int(start_after or 0)) + 1


def seq_problem(seq: Any, used: Iterable[int]) -> Optional[str]:
    """Czemu tego numeru nie da się wydać - albo None."""
    try:
        value = int(seq)
    except (TypeError, ValueError):
        return "Numer dokumentu musi być liczbą."
    if value < 1:
        return "Numer dokumentu musi być większy od zera."
    if value > MAX_SEQ:
        return f"Numer {value} jest podejrzanie duży - najwyżej {MAX_SEQ}."
    if value in {int(s) for s in used}:
        return f"Numer {value} jest już w rejestrze w tym sezonie - wybierz inny albo usuń tamten dokument."
    return None


# ---------------------------------------------------------------------------
# Zajętość pozycji
# ---------------------------------------------------------------------------

def taken_map(documents: Iterable[dict]) -> dict[tuple[str, str], str]:
    """
    (sędzia, część) -> numer dokumentu, który ją zajmuje.

    `documents`: [{"number", "items": [{"judge_id", "part"}]}] - dokumenty
    jednego okresu i rodzaju.
    """
    out: dict[tuple[str, str], str] = {}
    for doc in documents:
        for item in doc.get("items") or []:
            key = (_s(item.get("judge_id")), _s(item.get("part")))
            if key[0]:
                out.setdefault(key, _s(doc.get("number")))
    return out


def taken_by(judge_id: str, part: str, taken: dict[tuple[str, str], str]) -> Optional[str]:
    """
    Numer dokumentu, który blokuje tę pozycję - albo None.

    Cała pula blokuje każdą część, a każda część blokuje całą pulę: inaczej ten
    sam mecz dałoby się wypłacić dwa razy (raz w całości, raz w części).
    """
    judge_id, part = _s(judge_id), _s(part)
    hit = taken.get((judge_id, part))
    if hit:
        return hit
    if part == WHOLE:
        return next((n for (j, p), n in sorted(taken.items()) if j == judge_id), None)
    return taken.get((judge_id, WHOLE))


def judge_view(taken: dict[tuple[str, str], str]) -> dict[str, dict[str, str]]:
    """Zajętość pod ekran: {sędzia: {część: numer}} („" = cała pula)."""
    out: dict[str, dict[str, str]] = {}
    for (judge_id, part), number in taken.items():
        out.setdefault(judge_id, {})[part] = number
    return out


# ---------------------------------------------------------------------------
# Wybór pozycji
# ---------------------------------------------------------------------------

def wanted_parts(available: list[str], requested: Optional[Iterable[Any]]) -> list[str]:
    """
    Części, które człowiek chce wziąć od sędziego z podziałem.

    Brak wyboru = wszystkie części. Litera spoza podziału znika po cichu - ekran
    mógł pokazywać podział sprzed zmiany.
    """
    if requested is None:
        return list(available)
    asked = {_s(p).upper() for p in requested}
    return [letter for letter in available if letter in asked]


def allocate_penalty(parts: list[dict], penalty: float) -> dict[str, float]:
    """
    Kara sędziego rozłożona na części: najpierw z A, reszta z B i dalej.

    Kara schodzi z kwoty do wypłaty, a części mogą trafić na różne dokumenty -
    stała kolejność sprawia, że każdy dokument wie, ile kary jest jego, bez
    patrzenia na pozostałe.
    """
    left = money(penalty)
    out: dict[str, float] = {}
    for part in parts:
        letter = _s(part.get("letter"))
        take = money(min(left, max(0.0, money(part.get("net"))))) if left > 0 else 0.0
        out[letter] = take
        left = money(left - take)
    if left > 0 and parts:
        # Więcej kary niż netto wszystkich części - nadwyżka zostaje na A,
        # tak jak `penalty_left` zostaje przy sędzim.
        first = _s(parts[0].get("letter"))
        out[first] = money(out.get(first, 0.0) + left)
    return out


def select_items(
    candidates: list[dict],
    taken: dict[tuple[str, str], str],
    *,
    skip_taken: bool,
) -> tuple[list[dict], list[dict]]:
    """
    Pozycje dokumentu i to, co pominięto, bo już stoi na innym dokumencie.

    `candidates`: [{"judge_id", "part", ...}] - kolejność zostaje.
    `skip_taken`: szkic bierze wszystko (zajętość pokazuje tylko jako uwagę),
    oficjalny pomija zajęte.
    """
    items: list[dict] = []
    skipped: list[dict] = []
    for item in candidates:
        blocker = taken_by(item["judge_id"], item.get("part") or WHOLE, taken)
        if blocker and skip_taken:
            skipped.append({**item, "taken_by": blocker})
            continue
        items.append({**item, "taken_by": blocker} if blocker else dict(item))
    return items, skipped


def part_label(part: str, part_of: int) -> str:
    """Dopisek pod nazwiskiem: „część A z 2"."""
    return f"część {part} z {part_of}" if part else ""
