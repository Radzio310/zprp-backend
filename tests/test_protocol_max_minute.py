"""Ostatnia minuta okresu nie przeskakuje na nastepna.

Akcja z 60:00 przy polowach 2 x 30 drukowala sie w przebiegu jako 61' - minuta,
ktorej w tym meczu nie bylo. Zegar na koncu okresu STAJE na pelnej minucie,
wiec zdarzenie nalezy jeszcze do niej.

Sufit dotyczy OKRESU, w ktorym lezy zdarzenie, a nie kazdej pelnej minuty:
30:00 na koncu pierwszej polowy to 30', ale 30:00 na starcie drugiej to nadal
31' - i tak ma zostac.
"""
from __future__ import annotations

import pytest

from app.results import _event_minute_from_ms

MIN = 60_000


@pytest.mark.parametrize(
    "ms, period_end_ms, expected, why",
    [
        (0, 30 * MIN, 1, "pierwszy gwizdek to 1 minuta"),
        (59_999, 30 * MIN, 1, "0:59 nalezy jeszcze do 1 minuty"),
        (60_000, 30 * MIN, 2, "1:00 zaczyna 2 minute"),
        (29 * MIN + 59_000, 30 * MIN, 30, "29:59 pierwszej polowy"),
        # ─ sedno poprawki ─
        (30 * MIN, 30 * MIN, 30, "koniec I polowy 2 x 30 nie skacze na 31"),
        (60 * MIN, 60 * MIN, 60, "koniec meczu 2 x 30 nie skacze na 61"),
        (20 * MIN, 20 * MIN, 20, "koniec I polowy przy 2 x 20"),
        (40 * MIN, 40 * MIN, 40, "koniec meczu przy 2 x 20"),
        (15 * MIN, 15 * MIN, 15, "koniec I polowy przy 2 x 15"),
        (30 * MIN, 30 * MIN, 30, "koniec meczu przy 2 x 15"),
        # ─ sufit nalezy do okresu, nie do zegara ─
        (30 * MIN, 60 * MIN, 31, "30:00 na starcie II polowy to 31 minuta"),
        (59 * MIN + 59_000, 60 * MIN, 60, "59:59 to 60 minuta"),
        # ─ przypadki brzegowe ─
        (61 * MIN, 60 * MIN, 60, "czas ponad koniec meczu nie wychodzi poza sufit"),
        (10 * MIN, 0, 11, "bez podanego okresu liczy jak dawniej"),
        (-5_000, 30 * MIN, 1, "ujemny czas traktujemy jak zero"),
    ],
)
def test_event_minute_caps_at_period_end(
    ms: int, period_end_ms: int, expected: int, why: str
) -> None:
    assert _event_minute_from_ms(ms, period_end_ms) == expected, why


def test_signature_stays_backward_compatible() -> None:
    """Wywolanie bez sufitu ma dzialac jak przed zmiana."""
    assert _event_minute_from_ms(53 * MIN + 12_000) == 54


@pytest.mark.parametrize(
    "value, max_minute, expected, why",
    [
        ("61", 60, "60", "zapis sprzed poprawki schodzi do ostatniej minuty"),
        ("61'", 60, "60'", "sufiks zostaje nietkniety"),
        ("60", 60, "60", "ostatnia minuta meczu jest poprawna"),
        ("12", 60, "12", "zwykla minuta zostaje bez zmian"),
        ("41", 40, "40", "przy polowach 2 x 20 sufitem jest 40"),
        ("", 60, "", "puste zostaje puste"),
        ("brak", 60, "brak", "tekst, ktory nie jest minuta, zostaje"),
        ("61", 0, "61", "bez podanego sufitu nic nie ruszamy"),
    ],
)
def test_warning_minute_is_capped(
    value: str, max_minute: int, expected: str, why: str
) -> None:
    from app.results import _cap_minute_text

    assert _cap_minute_text(value, max_minute) == expected, why
