"""
Do którego kubełka statystyk okręgowych należy obsada.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

SKĄD TO SIĘ WZIĘŁO. Statystyki okręgowe dzieliły mecze po polu `origin`, a pod
spodem podpisywały ten podział „Rozgrywki okręgowe" - i to była nieprawda.
`origin` mówi, SKĄD WIEMY o meczu (z terminarza okręgu czy z prywatnej listy
sędziego), a nie jakiego jest szczebla. Mecz I ligi rozgrywany w naszym
województwie stoi w terminarzu okręgu, więc miał `origin="district"` i wpadał
pod napis o rozgrywkach okręgowych - choć nie jest okręgowy i okręg go nie
rozlicza. Zgłoszone przez użytkownika 13.09.2026 na własnych dwóch meczach.

TRZY KUBEŁKI, BO TAKIE SĄ TRZY RÓŻNE SPRAWY:

  * ``district``     - mecz OKRĘGU: rozgrywki okręgowe, puchar wojewódzki
                       i turnieje centralne, które okręg rozlicza w każdej roli,
  * ``league_table`` - mecz ligowy (centralny), w którym sędzia siedział
                       PRZY STOLIKU. Okręg rozlicza go, choć rozgrywki są cudze,
  * ``league_other`` - reszta meczów ligowych: boiskowy albo delegat na
                       szczeblu centralnym. Okręg ich nie rozlicza i domyślnie
                       nie ma ich w statystykach.

GRANICA „MECZU OKRĘGU" JEST TA SAMA, CO W ``settlement_origin``. Świadomie
przepisana zamiast wymyślona od nowa: tam rozstrzyga, co z listy minionego
sezonu liczy się jak własne, tutaj - co wchodzi do statystyk. Dwie różne
odpowiedzi na to samo pytanie rozjechałyby zestawienie z rozliczeniem.

⚠ Puchar wojewódzki („S/PPK/2") ma szczebel ``central``, bo płaci stawkami
II ligi - ale jest meczem OKRĘGU i okręg rozlicza go w każdej roli. Bez
osobnego warunku wpadłby do ``league_other`` i zniknąłby z domyślnych
statystyk.
"""

from __future__ import annotations

from typing import Any

from app import settlement_rates as R

#: Kubełek meczów okręgu - patrz nagłówek.
DISTRICT = "district"
#: Stolik na meczu ligowym (centralnym).
LEAGUE_TABLE = "league_table"
#: Pozostałe role na meczu ligowym.
LEAGUE_OTHER = "league_other"

#: Kolejność do podsumowań - od tego, czego jest najwięcej, po to, co dochodzi
#: dopiero po włączeniu przełącznika.
BUCKETS = (DISTRICT, LEAGUE_TABLE, LEAGUE_OTHER)

#: Co wchodzi do statystyk, dopóki sędzia nie poprosi o resztę.
DEFAULT_BUCKETS = (DISTRICT, LEAGUE_TABLE)

#: Szczeble, które są meczem OKRĘGU. Ta sama krotka co `_OWN_LEVELS`
#: w `settlement_origin` - i z tego samego powodu.
_OWN_LEVELS = ("district", "cup")


def is_own_match(code: Any) -> bool:
    """Czy to mecz okręgu - niezależnie od roli sędziego."""
    return R.match_level(code) in _OWN_LEVELS or R.is_provincial_cup(code)


def bucket_of(code: Any, role: Any) -> str:
    """
    Kubełek jednej obsady. Nie rzuca - nieznany numer trafia tam, gdzie reszta
    meczów ligowych, czyli poza domyślne statystyki.
    """
    if is_own_match(code):
        return DISTRICT
    return (
        LEAGUE_TABLE
        if str(role or "").strip() == R.ROLE_TABLE
        else LEAGUE_OTHER
    )


def counts(items: Any) -> dict[str, int]:
    """Ile obsad w każdym kubełku. Wejście: cokolwiek z polem `bucket`."""
    out = {name: 0 for name in BUCKETS}
    for item in items or ():
        name = str((item or {}).get("bucket") or "")
        if name in out:
            out[name] += 1
    return out
