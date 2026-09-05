"""Skrót nagrania SPK/1: kotwice czasu wideo dla zegara meczu.

PO CO. Skrót drugiej połowy trwa niecałe dziewięć minut, a mecz trzydzieści.
Sędzia ćwiczący przy skrócie nie może prowadzić zegara ręcznie, bo między
akcjami czas gry ucieka o minuty. Telefon liczy więc czas WIDEO od chwili
naciśnięcia „START CZAS" (razem z play na laptopie) i tuż przed każdą
kotwicą przeskakuje zegar meczu na minutę, w której ta akcja naprawdę
padła. Regułę przeskoków trzyma aplikacja (`utils/videoClock.ts`); tu
powstają same pary „czas wideo -> czas meczu".

SKĄD DANE. Z arkusza `SPK1_excel.xlsx` przepisanego raz, na stałe - taka
była decyzja. Arkusz ma trzy sekcje: przebieg bramek (minuta meczu podana
CAŁKOWITA), kary 2 minut i upomnienia ławek (czas dokładny „MM:SS") oraz
czasy dla drużyny (czas dokładny). Wartości poniżej są w milisekundach.

CO WYCHODZI NA TELEFON. Wyłącznie pary czasów. Ani bramki, ani kary, ani
kto je dostał: skrót jest oceniany, a treść zdarzeń to klucz odpowiedzi,
który nie ma prawa leżeć w telefonie przed podejściem.

MINUTA BRAMKI JEST PRZYBLIŻONA. Arkusz mówi „31", a bramka padła gdzieś
między 30:00 a 31:00. Dlatego czas bramek DOCIĄGAMY ze wzorca: kolejna
bramka tej samej drużyny i tego samego zawodnika w drugiej połowie
oficjalnego protokołu ma czas co do sekundy. Gdy wzorzec jej nie zna,
zostaje środek minuty.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

#: Początek drugiej połowy w czasie gry.
HALF_START_MS = 30 * 60_000
HALF_END_MS = 60 * 60_000


def _ms(mm: int, ss: int = 0) -> int:
    return (mm * 60 + ss) * 1000


#: Bramki skrótu: (czas wideo, minuta meczu z arkusza, drużyna, numer, z karnego).
#: Drużyna „A" to gospodarz protokołu (host), „B" - gość (guest).
GOALS: Tuple[Tuple[int, int, str, int, bool], ...] = (
    (_ms(0, 47), 31, "host", 3, False),
    (_ms(1, 0), 32, "guest", 28, False),
    (_ms(1, 11), 34, "guest", 28, False),
    (_ms(1, 18), 34, "host", 34, False),
    (_ms(1, 27), 34, "guest", 36, False),
    (_ms(2, 3), 35, "host", 34, True),
    (_ms(2, 14), 36, "host", 10, False),
    (_ms(2, 25), 37, "host", 34, False),
    (_ms(3, 15), 40, "host", 13, False),
    (_ms(3, 26), 40, "host", 17, False),
    (_ms(3, 44), 41, "guest", 28, False),
    (_ms(3, 56), 42, "guest", 22, False),
    (_ms(4, 14), 43, "host", 3, True),
    (_ms(4, 28), 43, "guest", 2, False),
    (_ms(4, 41), 44, "host", 34, False),
    (_ms(4, 55), 44, "guest", 28, False),
    (_ms(5, 1), 44, "host", 17, False),
    (_ms(5, 19), 48, "guest", 42, False),
    (_ms(5, 42), 50, "guest", 28, True),
    (_ms(5, 58), 51, "guest", 28, False),
    (_ms(7, 23), 53, "host", 10, True),
    (_ms(7, 40), 54, "guest", 66, True),
    (_ms(7, 48), 54, "host", 13, False),
    (_ms(7, 55), 56, "host", 20, False),
    (_ms(8, 11), 56, "host", 20, False),
    # Arkusz podaje tu czas wideo 7:47 przy 57. minucie - między wierszami
    # 8:11 (56.) i 8:37 (60.). To nie może być prawdą, bo wideo nie cofa się
    # do wcześniejszej akcji; wpis stoi w środku sąsiadów, do poprawki w
    # arkuszu, gdy nagranie się zmieni.
    (_ms(8, 24), 57, "guest", 36, False),
    (_ms(8, 37), 60, "host", 3, True),
    (_ms(8, 46), 60, "host", 8, False),
)

#: Kary 2 minut: (czas wideo, czas meczu, drużyna, numer).
PENALTIES: Tuple[Tuple[int, int, str, int], ...] = (
    (_ms(1, 38), _ms(34, 51), "guest", 36),
    (_ms(2, 35), _ms(37, 28), "host", 17),
    (_ms(3, 5), _ms(38, 42), "host", 14),
    (_ms(5, 32), _ms(49, 4), "host", 7),
    (_ms(6, 47), _ms(52, 12), "guest", 28),
)

#: Upomnienia ławek: (czas wideo, czas meczu, drużyna, litera osoby).
#: W arkuszu „A2"/„B2": litera to drużyna, cyfra to POZYCJA osoby w składzie
#: (2 = osoba B).
BENCH_WARNINGS: Tuple[Tuple[int, int, str, str], ...] = (
    (_ms(6, 29), _ms(51, 51), "host", "B"),
    (_ms(7, 1), _ms(52, 12), "guest", "B"),
)

#: Czasy dla drużyny: (czas wideo, czas meczu, drużyna).
TIMEOUTS: Tuple[Tuple[int, int, str], ...] = (
    (_ms(5, 8), _ms(46, 38), "guest"),
    (_ms(6, 3), _ms(51, 15), "host"),
    (_ms(8, 17), _ms(58, 51), "host"),
)

_GOAL_TYPES = frozenset({"goal", "penaltyKickScored"})


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _second_half_goals(timeline: Optional[Iterable[Any]]) -> List[Dict[str, Any]]:
    """Bramki drugiej połowy wzorca, po czasie."""
    out: List[Dict[str, Any]] = []
    for ev in timeline or []:
        if not isinstance(ev, dict) or ev.get("shootout"):
            continue
        if str(ev.get("type") or "") not in _GOAL_TYPES:
            continue
        time_ms = _int(ev.get("time"), -1)
        half = ev.get("half")
        in_second = _int(half, 0) == 2 if half is not None else time_ms >= HALF_START_MS
        if not in_second or time_ms < 0:
            continue
        out.append(
            {
                "time": time_ms,
                "team": str(ev.get("team") or ""),
                "player": _int(ev.get("player"), -1),
            }
        )
    out.sort(key=lambda e: e["time"])
    return out


def _minute_midpoint(minute: int) -> int:
    """„31. minuta" arkusza to przedział 30:00-31:00; bierzemy jego środek."""
    return max(HALF_START_MS, (minute - 1) * 60_000 + 30_000)


def goal_anchor_times(timeline: Optional[Iterable[Any]]) -> List[Tuple[int, int]]:
    """Pary (czas wideo, czas meczu) dla bramek - ze wzorca, gdy się da.

    Dopasowanie idzie PO KOLEI: każda bramka arkusza bierze pierwszą jeszcze
    niewziętą bramkę wzorca tej samej drużyny i tego samego zawodnika, która
    leży w jej minucie albo minutę obok. Kolejność chroni przed pomyleniem
    dwóch bramek tego samego zawodnika.
    """
    ref = _second_half_goals(timeline)
    used = [False] * len(ref)
    out: List[Tuple[int, int]] = []
    for video_ms, minute, team, player, _pen in GOALS:
        lo = (minute - 2) * 60_000
        hi = (minute + 1) * 60_000
        pick: Optional[int] = None
        for i, ev in enumerate(ref):
            if used[i] or ev["team"] != team or ev["player"] != player:
                continue
            if lo <= ev["time"] < hi:
                pick = i
                break
        if pick is None:
            out.append((video_ms, _minute_midpoint(minute)))
        else:
            used[pick] = True
            out.append((video_ms, ref[pick]["time"]))
    return out


def clock_anchors(timeline: Optional[Iterable[Any]] = None) -> List[List[int]]:
    """Wszystkie kotwice skrótu, po czasie wideo, z rosnącym czasem meczu.

    Kotwica, która cofałaby zegar względem poprzedniej, jest odrzucana:
    zegar meczu przy skrócie idzie tylko do przodu, a pojedynczy błąd
    arkusza nie ma prawa go zatrzymać ani cofnąć.
    """
    pairs: List[Tuple[int, int]] = list(goal_anchor_times(timeline))
    pairs += [(v, m) for v, m, _t, _p in PENALTIES]
    pairs += [(v, m) for v, m, _t, _l in BENCH_WARNINGS]
    pairs += [(v, m) for v, m, _t in TIMEOUTS]
    pairs.sort(key=lambda p: (p[0], p[1]))

    out: List[List[int]] = []
    last_match = HALF_START_MS
    last_video = -1
    for video_ms, match_ms in pairs:
        match_ms = min(match_ms, HALF_END_MS)
        if match_ms < last_match:
            continue
        if video_ms == last_video:
            # Dwie akcje w tej samej sekundzie wideo - zostaje późniejsza
            # minuta meczu, bo do niej i tak zaraz przeskoczymy.
            out[-1][1] = match_ms
        else:
            out.append([video_ms, match_ms])
        last_match = match_ms
        last_video = video_ms
    return out


def video_clock(timeline: Optional[Iterable[Any]] = None) -> Dict[str, Any]:
    """To, co dostaje telefon: same pary czasów i początek połowy."""
    return {"halfStartMs": HALF_START_MS, "anchors": clock_anchors(timeline)}


def condensed_events() -> Dict[str, Sequence[Any]]:
    """Pełna treść arkusza - dla panelu i testów, NIGDY dla telefonu."""
    return {
        "goals": GOALS,
        "penalties": PENALTIES,
        "benchWarnings": BENCH_WARNINGS,
        "timeouts": TIMEOUTS,
    }
