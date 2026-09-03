# app/training_spk_entries.py
#
# Kto naprawdę wszedł na boisko w meczu wzorcowym.
#
# PO CO TO KOMU. Prowadzenie w aplikacji rozdaje zadania „oznacz wejście", ale
# do niedawna umiało wskazać tylko tych, którzy w prezentacji COŚ ROBIĄ -
# strzelili, dostali karę, upomnienie. Zawodnik, który wszedł i przez pół
# godziny nie zrobił nic zauważalnego dla protokołu, nie dostawał zadania i
# ćwiczący kończył mecz z sześcioma pustymi rubrykami wejścia na drużynę,
# choć prowadził go „za rękę".
#
# ŹRÓDŁEM JEST PROTOKÓŁ, NIE SKŁAD. Skład z ZPRP to szesnaście zgłoszonych
# nazwisk; weszła z nich część. Rubrykę wejścia wypełnili sędziowie tego meczu
# i to ich wpis (`entered` w statystykach zawodnika) mówi, kto rzeczywiście
# grał. Gdyby wzorzec pochodził ze starszego zapisu bez tej rubryki, wychodzi
# lista pusta - i telefon zostaje przy tym, co umiał wcześniej, czyli przy
# wejściach wyczytanych z akcji.
#
# OSOBA TOWARZYSZĄCA NIE WCHODZI NA BOISKO. „A"-„E" siedzą na ławce i rubryki
# wejścia nie mają, więc numery nieliczbowe wypadają.

from __future__ import annotations

from typing import Any, Dict, List

#: Klucze statystyk w dokumencie meczu - po jednym na drużynę.
STATS_KEYS = {"host": "hostPlayerStats", "guest": "guestPlayerStats"}


def _number(value: Any) -> str:
    """Numer zawodnika jako tekst; pusto, gdy to nie numer."""
    if value is None:
        return ""
    text = str(value).strip()
    if text.endswith(".0"):
        text = text[:-2]
    return text if text.isdigit() else ""


def entered_players(blob: Any) -> Dict[str, List[str]]:
    """Numery z oznaczonym wejściem, po drużynach, rosnąco."""
    out: Dict[str, List[str]] = {"host": [], "guest": []}
    if not isinstance(blob, dict):
        return out

    for team, key in STATS_KEYS.items():
        raw = blob.get(key)
        if not isinstance(raw, list):
            continue
        seen: set[str] = set()
        for item in raw:
            if not isinstance(item, dict) or not item.get("entered"):
                continue
            number = _number(item.get("number"))
            if number and number not in seen:
                seen.add(number)
                out[team].append(number)
        out[team].sort(key=int)
    return out
