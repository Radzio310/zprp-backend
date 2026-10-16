"""Zegar meczu -> godzina ścienna: symulacja meczu z przerwami w grze.

Mecz 2 x 30 min, przerwa 12 min, ~20 zdarzeń. Zegar staje przy karach,
rzutach karnych i czasach dla drużyn (różne długości), migawki powstają
tak, jak w ProElu: takt co 60 s przy biegnącym zegarze (stojący daje tę samą
treść i odpada w odsiewie) oraz zapis przy każdej akcji sędziego - wpisanej
z kilkusekundowym opóźnieniem. Cel z zamówienia: błąd < 3 min; mierzymy < 1 min.
"""

from __future__ import annotations

import random

from app.match_clock_rules import (
    EXACT_ERR_MS,
    annotate_timeline,
    merge_points,
    point_from_blob,
    skew_by_writer,
    wall_at,
)
from app.link_preview_rules import iso_to_ms, stream_start_from_api, stream_start_from_html, youtube_watch_url
from app.mentor_video_rules import clean_markers, clean_sync

HALF = 30 * 60_000
KICKOFF = 1_791_650_700_000  # 2026-10-10 16:45:00 UTC


def simulate(seed: int = 7, *, ticks: bool = True):
    """(punkty migawek, zdarzenia [(T, połowa, typ)], prawda {(T, połowa): ściana})."""
    rng = random.Random(seed)
    # Zdarzenia: (czas meczu, połowa, zatrzymuje zegar?, długość przerwy w grze s)
    plan = []
    for half in (1, 2):
        base = 0 if half == 1 else HALF
        times = sorted(rng.sample(range(40_000, HALF - 20_000, 1000), 10))
        for t in times:
            kind = rng.choice(["goal", "goal", "penalty1", "teamTime", "penaltyKickScored", "warning"])
            stop = kind != "goal"
            pause = {"penalty1": rng.randint(15, 45), "teamTime": 60 + rng.randint(5, 20), "penaltyKickScored": rng.randint(20, 50), "warning": rng.randint(8, 25)}.get(kind, 0)
            plan.append((base + t, half, kind, stop, pause))
    plan.sort(key=lambda e: (e[1], e[0]))

    points = []
    truth = {}
    seen_hashes = set()

    def snap(wall, main, half, running):
        # Odsiew po treści: stojący zegar w tej samej chwili meczu to ta sama treść.
        key = (main, half, running, len([1 for k in truth if k[0] <= main and k[1] <= half]))
        if not running and key in seen_hashes:
            return
        seen_hashes.add(key)
        points.append((int(wall), int(main), half, 1 if running else 0))

    snap(KICKOFF - 25 * 60_000, 0, 1, False)  # założenie meczu
    snap(KICKOFF - 3 * 60_000, 0, 1, False)  # skład dopisany przed meczem
    wall = KICKOFF
    for half in (1, 2):
        main = 0 if half == 1 else HALF
        end = HALF if half == 1 else 2 * HALF
        if half == 2:
            # „II połowa" naciśnięta minutę przed wznowieniem.
            snap(wall - 60_000, HALF, 2, False)
        snap(wall + 2_000, main + 2_000, half, True)  # pierwszy takt po gwizdku
        next_tick = wall + 60_000
        for t, h, kind, stop, pause in [e for e in plan if e[1] == half] + [(end, half, "end", True, 0)]:
            # Bieg do T z taktami co 60 s.
            while ticks and next_tick < wall + (t - main):
                snap(next_tick, main + (next_tick - wall), half, True)
                next_tick += 60_000
            wall += t - main
            main = t
            if kind == "end":
                snap(wall + 3_000, main, half, False)
                break
            truth[(t, h)] = wall
            delay = rng.randint(3, 25) * 1000
            if stop:
                snap(wall + delay, main, half, False)  # akcja przy stojącym zegarze
                wall += pause * 1000
                next_tick = max(next_tick, wall + 60_000)
            else:
                snap(wall + delay, main + delay, half, True)  # bramka: zegar biegnie
        if half == 1:
            wall += 12 * 60_000
    events = [(t, h, kind) for t, h, kind, _s, _p in plan]
    return merge_points(points), events, truth


def test_dwadziescia_zdarzen_trafia_ponizej_minuty():
    for seed in (1, 7, 42, 2026):
        points, events, truth = simulate(seed)
        errors = []
        for t, h, _kind in events:
            hit = wall_at(points, t, h, half_ms=HALF)
            assert hit is not None
            errors.append(abs(hit[0] - truth[(t, h)]))
        assert len(events) == 20
        assert max(errors) < 60_000, (seed, max(errors))


def test_pierwszy_gwizdek_i_wznowienie_po_przerwie():
    points, _events, truth = simulate(3)
    kick = wall_at(points, 0, 1, half_ms=HALF, mode="leave")
    assert kick and abs(kick[0] - KICKOFF) <= 2_000
    second = wall_at(points, HALF, 2, half_ms=HALF, mode="leave")
    # Wznowienie po przerwie = koniec I połowy + przerwy w grze + 12 min.
    assert second and second[0] > KICKOFF + HALF + 12 * 60_000


def test_bez_taktow_tylko_akcje_dalej_ponizej_trzech_minut():
    """Telefon bez zasięgu dosłał tylko zapisy akcji - takty przepadły."""
    points, events, truth = simulate(11, ticks=False)
    worst = max(abs(wall_at(points, t, h, half_ms=HALF)[0] - truth[(t, h)]) for t, h, _k in events)
    assert worst < 180_000


def test_bramka_z_30_00_po_przerwie_nie_wpada_w_koniec_pierwszej():
    points = [
        (1000_000, 0, 1, 0),
        (1060_000, 60_000, 1, 1),
        (1000_000 + HALF + 30_000, HALF, 1, 0),  # koniec I połowy
        (1000_000 + HALF + 15 * 60_000, HALF, 2, 0),  # „II połowa"
        (1000_000 + HALF + 16 * 60_000 + 5_000, HALF + 5_000, 2, 1),
    ]
    first = wall_at(points, HALF, 1, half_ms=HALF)
    second = wall_at(points, HALF, 2, half_ms=HALF, mode="leave")
    assert first[0] < 1000_000 + HALF + 60_000
    assert second[0] == 1000_000 + HALF + 16 * 60_000


def test_annotate_dokleja_godziny_i_kotwice():
    points, events, truth = simulate(5)
    timeline = {
        "available": True,
        "half_minutes": 30,
        "break_minutes": 10,
        "events": [{"key": f"e{i}", "match_ms": t, "half": h} for i, (t, h, _k) in enumerate(events)],
    }
    out = annotate_timeline(timeline, points)
    assert out["clock"]["source"] == "proel"
    assert out["clock"]["timed_events"] == 20
    assert abs(out["clock"]["kickoff_wall_ms"] - KICKOFF) <= 2_000
    assert all(e["wall_ms"] for e in out["events"])
    assert sum(1 for e in out["events"] if e["wall_err_s"] * 1000 <= EXACT_ERR_MS) >= 15


def test_bez_punktow_nie_zmysla():
    out = annotate_timeline({"available": True, "half_minutes": 30, "events": [{"match_ms": 1000, "half": 1}]}, [])
    assert out["events"][0]["wall_ms"] is None
    assert out["clock"]["source"] is None


def test_poprawka_przestawionego_zegara_telefonu():
    samples = [("A", 1_000_000 + i * 60_000 + 90_000, 1_000_000 + i * 60_000) for i in range(5)]
    samples += [("B", 5_000 + i, 5_000) for i in range(5)]
    assert skew_by_writer(samples) == {"A": 90_000}


def test_punkt_z_tresci_zapisu():
    assert point_from_blob({"mainTime": 61000, "savedAtMs": 1_791_650_700_000, "isFirstHalf": False, "isGameRunning": True}) == (
        1_791_650_700_000,
        61000,
        2,
        1,
    )
    assert point_from_blob({"mainTime": 5}, fallback_wall_ms=None) is None


def test_godzina_startu_transmisji_ze_strony_youtube():
    page = '... "liveBroadcastDetails":{"isLiveNow":false,"startTimestamp":"2026-10-10T16:40:05+00:00","endTimestamp":"2026-10-10T18:33:06+00:00"} ...'
    assert stream_start_from_html(page) == iso_to_ms("2026-10-10T16:40:05Z")
    meta = '<meta itemprop="isLiveBroadcast" content="True"><meta itemprop="startDate" content="2026-10-10T16:40:05+00:00">'
    assert stream_start_from_html(meta) == iso_to_ms("2026-10-10T16:40:05+00:00")
    # Zwykły film ma startDate jako datę publikacji - bez transmisji nie bierzemy.
    assert stream_start_from_html('<meta itemprop="startDate" content="2026-10-10T16:40:05+00:00">') is None
    assert stream_start_from_api({"items": [{"liveStreamingDetails": {"actualStartTime": "2026-10-10T16:40:05Z"}}]}) == iso_to_ms("2026-10-10T16:40:05Z")
    assert stream_start_from_api({"items": []}) is None
    assert iso_to_ms("2026-10-10") is None
    assert youtube_watch_url("https://www.youtube.com/live/Sitswd4YP4k") == "https://www.youtube.com/watch?v=Sitswd4YP4k"


def test_synchronizacja_i_znaczniki_niosa_godzine():
    sync = clean_sync({"stream_start_ms": 1_791_650_405_000, "kickoff_wall_ms": "1791650700000", "second_half_wall_ms": 12})
    assert sync["stream_start_ms"] == 1_791_650_405_000
    assert sync["kickoff_wall_ms"] == 1_791_650_700_000
    assert sync["second_half_wall_ms"] is None
    markers = clean_markers(
        [
            {"id": "a", "label": "Kara", "kind": "penalty", "match_ms": 61000, "half": 1, "type": "penalty1", "wall_ms": 1_791_650_761_000, "wall_err_s": 12},
            {"id": "b", "label": "Własny", "kind": "manual", "video_s": 30, "wall_ms": 1_791_650_761_000, "type": "zly"},
        ]
    )
    assert markers[0]["wall_ms"] == 1_791_650_761_000 and markers[0]["wall_err_s"] == 12 and markers[0]["type"] == "penalty1"
    assert markers[1]["wall_ms"] is None and markers[1]["type"] is None


def test_wazny_znacznik_niesie_kategorie_i_komentarz():
    out = clean_markers(
        [
            {"id": "a", "label": "Kara", "kind": "penalty", "match_ms": 1000, "important": True, "category": "bledna", "comment": "  za późno — gwizdek "},
            {"id": "b", "label": "Bramka", "kind": "goal", "match_ms": 2000, "important": True, "category": "hack"},
            {"id": "c", "label": "Bramka", "kind": "goal", "match_ms": 3000, "important": "tak", "category": "trafna", "comment": "x"},
        ]
    )
    assert out[0]["important"] is True and out[0]["category"] == "bledna" and out[0]["comment"] == "za późno - gwizdek"
    assert out[1]["category"] == "inne"
    assert out[2]["important"] is False and out[2]["category"] is None and out[2]["comment"] is None
