"""Zegar meczu a zegar ścienny - z czasu meczu na prawdziwą godzinę (liść).

PO CO. Znacznik z protokołu ProEla niesie czas MECZU („12:34"), a nagranie
liczy czas ŚCIENNY: zegar meczu staje przy każdej karze, czasie dla drużyny
i przerwie, film idzie dalej. Samo „początek meczu w nagraniu + czas meczu"
gubi pod koniec połowy kilka minut. Żeby trafić w akcję, trzeba wiedzieć,
O KTÓREJ GODZINIE zegar meczu pokazywał 12:34.

SKĄD TO WIEMY. Protokół nie zapisuje godziny zdarzeń, ale każdy zapis meczu
niesie parę (`savedAtMs`, `mainTime`) - prawdziwą chwilę zapisu na telefonie
i stan zegara meczu w tej chwili - oraz `isFirstHalf` i `isGameRunning`.
Migawki (`proel_match_snapshots`) trzymają KAŻDY zapis, który coś zmienił:
co ~60 s, gdy zegar idzie, i przy każdej akcji sędziego. Z takiego szeregu
punktów da się odtworzyć ruch zegara.

JAK. Zegar meczu chodzi z prędkością 1 albo stoi - nigdy szybciej. Dla
szukanego czasu meczu T bierzemy dwa sąsiednie punkty (ten tuż przed
osiągnięciem T i pierwszy, który T już pokazał):

    lo = w_przed + (T - m_przed)   (wcześniej się nie dało - zegar nie przyspiesza)
    hi = w_po    - (m_po - T)      (później też nie - od T do m_po musiał biec)

Prawdziwa chwila leży w [lo, hi]. Gdy punkt „przed" miał zegar w ruchu,
najpewniej biegł dalej aż do T (każde zatrzymanie i każda akcja sędziego
dają nowy zapis) - wtedy bierzemy `lo`. W przeciwnym razie środek przedziału,
a połowa jego szerokości to deklarowany błąd (`err_ms`).

DWA TRYBY:
  * „arrive" (zdarzenie) - chwila, w której zegar DOSZEDŁ do T. Kara przy
    zatrzymanym zegarze to moment zatrzymania, nie wznowienia;
  * „leave" (pierwszy gwizdek, wznowienie po przerwie) - chwila, w której
    zegar RUSZYŁ z T. Przed meczem zegar stoi na 0:00 godzinami.

Połowy liczone osobno - punkty z flagą `isFirstHalf`. Bez tego bramka
z 30:00 II połowy wpadałaby w koniec I (patrz utils/matchHalf.ts w aplikacji).
"""

from __future__ import annotations

from statistics import median
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

#: Rozjazd zegara telefonu względem serwera, poniżej którego nie poprawiamy -
#: to zwykłe opóźnienie sieci, nie przestawiony zegar.
SKEW_THRESHOLD_MS = 15_000
#: Najwięcej punktów w zapamiętanym śladzie jednego meczu.
TRACE_CAP = 2000
#: Do jakiego błędu wynik uznajemy za dokładny (bez „≈" w aplikacji).
EXACT_ERR_MS = 45_000
#: Ile zakładamy błędu, gdy zegar „przed" szedł i biegł dalej do T.
RUNNING_ERR_MS = 8_000

# Punkt: (ściana ms UTC, czas meczu ms, połowa 1/2/0, zegar w ruchu 0/1)
Point = Tuple[int, int, int, int]


def _num(value: Any) -> Optional[float]:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return n if n == n else None


def point_from_blob(blob: Any, *, fallback_wall_ms: Optional[int] = None) -> Optional[Point]:
    """Punkt z treści zapisu meczu albo `None`, gdy treść go nie niesie."""
    if not isinstance(blob, Mapping):
        return None
    main = _num(blob.get("mainTime"))
    wall = _num(blob.get("savedAtMs"))
    if wall is None or wall <= 0:
        wall = float(fallback_wall_ms) if fallback_wall_ms else None
    if main is None or wall is None or main < 0:
        return None
    half = 0
    if "isFirstHalf" in blob:
        half = 1 if blob.get("isFirstHalf") else 2
    running = 1 if blob.get("isGameRunning") else 0
    return (int(wall), int(main), half, running)


def skew_by_writer(samples: Iterable[Tuple[str, int, int]]) -> Dict[str, int]:
    """Poprawka zegara telefonu: mediana (czas serwera - czas telefonu).

    `samples` to (urządzenie, chwila odbioru na serwerze, `savedAtMs`) dla
    zapisów, które przyszły od razu (źródło „server"). Mediana odporna na
    pojedyncze zapisy z kolejki po ciszy sieciowej. Mniej niż 3 próbki albo
    rozjazd poniżej progu - bez poprawki.
    """
    by: Dict[str, List[int]] = {}
    for writer, server_ms, phone_ms in samples:
        by.setdefault(str(writer or ""), []).append(int(server_ms) - int(phone_ms))
    out: Dict[str, int] = {}
    for writer, diffs in by.items():
        if len(diffs) < 3:
            continue
        mid = int(median(diffs))
        if abs(mid) >= SKEW_THRESHOLD_MS:
            out[writer] = mid
    return out


def merge_points(*groups: Iterable[Sequence[int]]) -> List[Point]:
    """Zbiór punktów bez powtórek, posortowany po ścianie, przycięty do limitu."""
    seen: Dict[Tuple[int, int], Point] = {}
    for group in groups:
        for raw in group or ():
            try:
                wall, main, half, running = (int(raw[0]), int(raw[1]), int(raw[2]), int(raw[3]))
            except (TypeError, ValueError, IndexError):
                continue
            if wall <= 0 or main < 0:
                continue
            seen[(wall, main)] = (wall, main, half if half in (0, 1, 2) else 0, 1 if running else 0)
    points = sorted(seen.values())
    if len(points) > TRACE_CAP:
        # Przerzedzamy równo, ale pierwszy i ostatni zostają.
        step = len(points) / TRACE_CAP
        points = [points[int(i * step)] for i in range(TRACE_CAP - 1)] + [points[-1]]
    return points


def _half_of(point: Point, half_ms: int) -> int:
    if point[2] in (1, 2):
        return point[2]
    if point[1] < half_ms:
        return 1
    if point[1] > half_ms:
        return 2
    return 0


def wall_at(
    points: Sequence[Point],
    match_ms: int,
    half: Optional[int],
    *,
    half_ms: int,
    mode: str = "arrive",
) -> Optional[Tuple[int, int]]:
    """(chwila ścienna ms, błąd ms) dla czasu meczu - albo `None` bez danych."""
    T = int(match_ms)
    h = half if half in (1, 2) else (1 if T < half_ms else 2)
    pts = [p for p in points if _half_of(p, half_ms) == h]
    if not pts:
        return None
    pts.sort()
    leave = mode == "leave"

    def reached(p: Point) -> bool:
        return p[1] > T if leave else p[1] >= T

    j = next((i for i, p in enumerate(pts) if reached(p)), None)
    if j is None:
        # Zegar nigdy tam nie doszedł w zapisanych punktach - ekstrapolacja
        # od ostatniego. Błąd rośnie z odległością (przerwy, których nie znamy).
        last = pts[-1]
        gap = max(0, T - last[1])
        return last[0] + gap, 60_000 + gap // 6
    after = pts[j]
    hi = after[0] - (after[1] - T)
    if j == 0:
        # Pierwszy punkt połowy już był za T. Dla II połowy ograniczenie
        # z dołu daje koniec I połowy - wznowienie nie mogło być wcześniej.
        lo = None
        if h == 2:
            firsts = [p[0] for p in points if _half_of(p, half_ms) == 1]
            if firsts:
                lo = max(firsts) + max(0, T - half_ms)
        if lo is None or lo > hi:
            gap = max(0, after[1] - T)
            return hi, 60_000 + gap // 6 if gap else RUNNING_ERR_MS
        return (lo + hi) // 2, max(RUNNING_ERR_MS, (hi - lo) // 2)
    before = pts[j - 1]
    lo = before[0] + (T - before[1])
    if lo > hi:
        # Szum: opóźnienie zapisu albo poprawiony zegar. Środek i uczciwy błąd.
        return (lo + hi) // 2, max(RUNNING_ERR_MS, (lo - hi) // 2)
    if leave:
        # Ruszył z T. Gdy punkt „po" ma zegar w ruchu i jest blisko T, to
        # bieg od wznowienia do tego punktu był ciągły - liczymy od niego.
        if after[3] and after[1] - T <= 90_000:
            return hi, min(RUNNING_ERR_MS, (hi - lo) // 2 or RUNNING_ERR_MS)
        return (lo + hi) // 2, (hi - lo) // 2
    if before[3]:
        # Zegar szedł - biegł dalej do T (zatrzymanie dałoby nowy zapis).
        return lo, min((hi - lo) // 2, RUNNING_ERR_MS) if hi > lo else RUNNING_ERR_MS
    return (lo + hi) // 2, (hi - lo) // 2


def annotate_timeline(timeline: Dict[str, Any], points: Sequence[Point]) -> Dict[str, Any]:
    """Dokłada godzinę ścienną do zdarzeń osi meczu (`wall_ms`, `wall_err_s`).

    Zwraca też chwilę pierwszego gwizdka i wznowienia II połowy - aplikacja
    zapamiętuje je w synchronizacji nagrania, bo migawki z czasem wygasają.
    """
    half_ms = int(timeline.get("half_minutes") or 30) * 60_000
    out = dict(timeline)
    events = []
    timed = 0
    for event in timeline.get("events") or []:
        e = dict(event)
        hit = wall_at(points, int(e.get("match_ms") or 0), e.get("half"), half_ms=half_ms, mode="arrive") if points else None
        if hit:
            e["wall_ms"], err = hit
            e["wall_err_s"] = int(round(err / 1000))
            timed += 1
        else:
            e["wall_ms"] = None
            e["wall_err_s"] = None
        events.append(e)
    out["events"] = events
    kickoff = wall_at(points, 0, 1, half_ms=half_ms, mode="leave") if points else None
    second = wall_at(points, half_ms, 2, half_ms=half_ms, mode="leave") if points else None
    out["clock"] = {
        "source": "proel" if timed else None,
        "points": len(points),
        "timed_events": timed,
        "kickoff_wall_ms": kickoff[0] if kickoff else None,
        "kickoff_err_s": int(round(kickoff[1] / 1000)) if kickoff else None,
        "second_half_wall_ms": second[0] if second else None,
        "second_half_err_s": int(round(second[1] / 1000)) if second else None,
    }
    return out
