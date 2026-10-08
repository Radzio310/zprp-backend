"""Odchudzona geometria tras w przeglądzie mapy odległości (08.10.2026)."""

import gzip
import json
import math
from pathlib import Path

from app.national_route_shape import (
    SLIM_MAX_POINTS,
    route_for_mode,
    route_mode,
    slim_route,
)


def _winding(n=141):
    # Katowice -> Opole z łagodnym zakolem, gęsto jak geometria OSRM.
    out = []
    for i in range(n):
        t = i / (n - 1)
        out.append([round(19.02 + (17.92 - 19.02) * t, 5), round(50.26 + (50.67 - 50.26) * t + 0.08 * math.sin(t * math.pi), 5)])
    return out


def test_slim_keeps_both_ends_exactly_and_drops_most_points():
    full = _winding()
    slim = slim_route(full)
    assert slim is not None
    assert 2 <= len(slim) < len(full) // 3
    # Na końcach stoją kropki miast - nie wolno ich przesunąć (poza zaokrągleniem).
    assert slim[0] == [round(full[0][0], 3), round(full[0][1], 3)]
    assert slim[-1] == [round(full[-1][0], 3), round(full[-1][1], 3)]


def test_slim_stays_close_to_the_original_shape():
    full = _winding()
    slim = slim_route(full)
    # Każdy punkt oryginału leży blisko uproszczonej łamanej (tolerancja + zaokrąglenie).
    def dist_to_poly(p):
        best = 1e9
        for a, b in zip(slim, slim[1:]):
            dx, dy = b[0] - a[0], b[1] - a[1]
            length = dx * dx + dy * dy or 1e-12
            t = max(0, min(1, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / length))
            best = min(best, math.hypot(p[0] - (a[0] + t * dx), p[1] - (a[1] + t * dy)))
        return best
    assert max(dist_to_poly(p) for p in full) < 0.02


def test_slim_caps_points_on_a_very_winding_route():
    zigzag = [[19 + i * 0.01, 50 + (0.05 if i % 2 else 0)] for i in range(300)]
    slim = slim_route(zigzag)
    assert slim is not None and len(slim) <= SLIM_MAX_POINTS


def test_slim_reads_json_text_and_rejects_garbage():
    # Kolumna JSON bywa oddana przez bazę jako napis.
    assert slim_route(json.dumps(_winding())) is not None
    assert slim_route(None) is None
    assert slim_route("nie json") is None
    assert slim_route([[19.0, 50.0]]) is None
    assert slim_route([["x", "y"], [19.0, 50.0]]) is None


def test_route_mode_defaults_to_full_for_older_apps():
    assert route_mode(None) == "full"
    assert route_mode("") == "full"
    assert route_mode("SLIM") == "slim"
    assert route_mode("none") == "none"
    assert route_mode("cokolwiek") == "full"
    full = _winding()
    assert route_for_mode(full, "full") is full
    assert route_for_mode(full, "none") is None
    assert len(route_for_mode(full, "slim")) < len(full)


def test_slim_payload_is_several_times_lighter():
    full = [_winding() for _ in range(50)]
    heavy = len(json.dumps(full))
    light = len(json.dumps([slim_route(r) for r in full]))
    assert light * 4 < heavy


def test_overview_wiring_uses_slim_mode_and_gzip():
    source = (Path(__file__).resolve().parents[1] / "app" / "national_distances.py").read_text(encoding="utf-8")
    overview = source.split("async def national_distances_overview", 1)[1].split("\n@router", 1)[0]
    assert "RS.route_mode(routes)" in overview
    assert "route_mode=mode" in overview
    assert "_json_response(request" in overview
    helper = source.split("def _json_response", 1)[1].split("\n@router", 1)[0]
    assert "gzip.compress" in helper and "Content-Encoding" in helper
    # Klient bez gzipa dostaje zwykły JSON.
    assert "accept-encoding" in helper
    assert gzip.decompress(gzip.compress(b"{}")) == b"{}"
