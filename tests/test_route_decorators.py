"""Straż: dekorator trasy musi stać nad obsługą trasy, nie nad funkcją pomocniczą.

Dwa razy wkradła się pomocnicza funkcja między `@router.get(...)` a właściwą
obsługę (strona meczu 23.10.2026, logowania 16.10.2026) - trasa odpowiadała
wtedy błędem 422 na każde wywołanie. Pomocnicze funkcje mają nazwy od `_`.
"""
import re
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
ROUTE = re.compile(r"@\w*router\.(get|post|put|patch|delete|websocket)\(")
DEF = re.compile(r"\s*(?:async\s+)?def\s+(\w+)\(")


def test_trasy_nie_wisza_nad_funkcjami_pomocniczymi():
    bad = []
    for path in APP.rglob("*.py"):
        lines = path.read_text(encoding="utf-8").split("\n")
        for i, line in enumerate(lines):
            if not ROUTE.match(line.strip()):
                continue
            j = i + 1
            while j < len(lines) and (lines[j].strip().startswith("@") or not lines[j].strip() or lines[j].strip().startswith(")")):
                j += 1
            m = DEF.match(lines[j]) if j < len(lines) else None
            if m and m.group(1).startswith("_"):
                bad.append(f"{path.relative_to(APP.parent)}:{i + 1} -> {m.group(1)}")
    assert not bad, "dekorator trasy nad funkcją pomocniczą: " + ", ".join(bad)


def test_strona_meczu_obsluguje_match_overview():
    text = (APP / "zprp_public" / "portal.py").read_text(encoding="utf-8")
    assert re.search(r'@router\.get\("/matches/\{match_id\}/overview"\)\s*\nasync def match_overview\(', text)
