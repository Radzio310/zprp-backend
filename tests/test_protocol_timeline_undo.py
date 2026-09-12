"""Cofnięta bramka w przebiegu meczu w protokole PDF.

Reguła: `goalRemoved` to nagrobek KONKRETNEJ bramki i zabiera ją z przebiegu w
całości - także wtedy, gdy była to bramka z rzutu karnego.

Do 12.09.2026 cofnięcie bramki z karnego nie ruszało przebiegu wcale
(`if penalty_flag: continue`). Skutek widać było dopiero na wydruku: licznik
karnych nad tabelą schodził do zera, a w przebiegu dalej stał wiersz „karny -
trafiony" z nieaktualnym wynikiem. Protokół mówił co innego niż tabela nad nim.
"""
from __future__ import annotations

import json

from app.results import _filter_protocol_events_for_timeline as filter_timeline


def goal(time_ms, team="host", player=11, kind="goal"):
    return {"type": kind, "team": team, "player": player, "time": time_ms, "half": 1}


def removed(time_ms, orig_time, *, team="host", player=11, penalty=False):
    return {
        "type": "goalRemoved",
        "team": team,
        "player": player,
        "time": time_ms,
        "half": 1,
        "extra": json.dumps({"origTime": orig_time, "penalty": penalty}),
    }


def types_of(events):
    return [e["type"] for e in events]


def test_cofnieta_zwykla_bramka_znika_z_przebiegu():
    out = filter_timeline([goal(60_000), removed(90_000, 60_000)])
    assert out == []


def test_cofnieta_bramka_z_karnego_zabiera_caly_rzut():
    """Sedno poprawki: karny znika, a nie zostaje z nieaktualnym wynikiem."""
    out = filter_timeline(
        [
            goal(60_000, kind="penaltyKickScored"),
            removed(90_000, 60_000, penalty=True),
        ]
    )
    assert out == []


def test_cofniecie_karnego_nie_rusza_zwyklej_bramki_tego_samego_zawodnika():
    """Nagrobek wskazuje bramkę czasem i rodzajem - nie „którąkolwiek jego"."""
    out = filter_timeline(
        [
            goal(60_000),  # zwykła bramka #11
            goal(120_000, kind="penaltyKickScored"),  # karny #11
            removed(150_000, 120_000, penalty=True),
        ]
    )
    assert types_of(out) == ["goal"]
    assert out[0]["time"] == 60_000


def test_pudlo_z_karnego_zostaje():
    """Cofamy bramkę, nie notatkę o nieudanym rzucie - to osobne zdarzenie."""
    out = filter_timeline(
        [
            goal(60_000, kind="penaltyKickMissed"),
            goal(120_000),
            removed(150_000, 120_000),
        ]
    )
    assert types_of(out) == ["penaltyKickMissed"]


def test_numer_zawodnika_jako_napis_i_jako_liczba_to_ten_sam_zawodnik():
    """Aplikacja bywa niekonsekwentna w typie numeru; dopasowanie nie może na tym polec."""
    out = filter_timeline(
        [
            goal(60_000, player=11),
            removed(90_000, 60_000, player="11"),
        ]
    )
    assert out == []


def test_osierocony_nagrobek_nie_zabiera_przypadkowej_bramki():
    """Bramki wskazanej przez nagrobek nie ma - nie wolno odjąć innej."""
    out = filter_timeline(
        [
            goal(60_000, player=7),
            removed(90_000, 30_000, player=11),
        ]
    )
    assert types_of(out) == ["goal"]
    assert out[0]["player"] == 7


def test_cofniecie_zabiera_ostatnia_pasujaca_bramke():
    """Dwie takie same bramki, jeden nagrobek - znika późniejsza."""
    out = filter_timeline(
        [
            goal(60_000),
            goal(120_000),
            removed(150_000, 120_000),
        ]
    )
    assert [e["time"] for e in out] == [60_000]


def test_nagrobek_sam_nigdy_nie_trafia_do_przebiegu():
    out = filter_timeline([removed(90_000, 60_000)])
    assert out == []
