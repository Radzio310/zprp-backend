"""Protokół meczu ręcznego dostaje nazwiska i osoby A-E ze składu meczu wspólnego (07.11.2026).

Zgłoszenie: skład ze zdjęcia wczytany na jednym telefonie, mecz rozpoczęty na innym
(starsza wersja) - w ProElu same numery. Serwer dopisuje braki przy każdym zapisie.
"""

import pytest

from app.proel_lineup_fill import fill_blob_from_lineup
from tests.mentor_panel_support import JUDGES, Env

A, B = JUDGES

LINEUP = {
    "home": {
        "name": "SPR Gliwice",
        "players": [{"number": 6, "name": "KOWALSKI Jan"}, {"number": 14, "name": "NOWAK Piotr"}, {"number": 31, "name": "ZIELIŃSKI Adam"}],
        "staff": [{"slot": "A", "name": "TRENER Anna", "function": "TRENER", "license": None}],
    },
    "away": {"name": "KS Opole", "players": [{"number": 9, "name": "NOVAK Luka"}], "staff": []},
}


def blob(**mc):
    base = {
        "hostTeamName": "SPR Gliwice",
        "guestTeamName": "KS Opole",
        "hostPlayers": [6, 14],
        "guestPlayers": [9],
        "hostPlayerCards": [{"number": 14, "fullName": "RĘCZNIE Wpisany"}],
        "guestPlayerCards": [],
        "hostCompanions": [{"id": "A", "fullName": "", "warned": True}],
        "guestCompanions": [],
    }
    base.update(mc)
    return {"matchConfig": base, "protocol": []}


def test_dopisuje_tylko_braki_po_numerze_i_literze():
    out, changed = fill_blob_from_lineup(blob(), LINEUP)
    mc = out["matchConfig"]
    assert changed is True
    names = {c["number"]: c["fullName"] for c in mc["hostPlayerCards"]}
    assert names == {14: "RĘCZNIE Wpisany", 6: "KOWALSKI Jan"}  # 31 nie gra - nie dokładamy
    assert mc["guestPlayerCards"] == [{"number": 9, "fullName": "NOVAK Luka"}]
    assert mc["hostCompanions"] == [{"id": "A", "fullName": "TRENER Anna", "warned": True, "function": "TRENER"}]


def test_drugi_przebieg_nic_nie_zmienia_i_strony_zamienione():
    once, _ = fill_blob_from_lineup(blob(), LINEUP)
    assert fill_blob_from_lineup(once, LINEUP)[1] is False
    swapped, changed = fill_blob_from_lineup(
        blob(hostTeamName="KS Opole", guestTeamName="SPR Gliwice", hostPlayers=[9], guestPlayers=[6], hostPlayerCards=[], hostCompanions=[]),
        LINEUP,
    )
    assert changed and swapped["matchConfig"]["hostPlayerCards"] == [{"number": 9, "fullName": "NOVAK Luka"}]


def test_zly_ksztalt_nie_wywraca():
    assert fill_blob_from_lineup(None, LINEUP) == (None, False)
    assert fill_blob_from_lineup({"x": 1}, LINEUP) == ({"x": 1}, False)
    assert fill_blob_from_lineup(blob(), None)[1] is False


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


def test_zapis_protokolu_meczu_recznego_bierze_sklad_meczu_wspolnego(env):
    from app.proel_lineup_fill import fill_shared_lineup
    from app.proel_match_key import shared_key_of, stem_of_row

    async def go():
        created = await env.shared.create_match(
            env.shared.CreateBody(home_name="SPR Gliwice", away_name="KS Opole", match_at="2026-11-07T16:00:00", code="EHF/1",
                                  hall="Hala", my_role="sedzia1", crew=[env.shared.CrewIn(judge_id=B, role="sedzia2")]),
            await env.actor(A),
        )
        mid = created["match"]["id"]
        await env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=created["rev"], lineup=LINEUP), await env.actor(A))
        row = await env.db.fetch_one(env.T["shared_matches"].select().where(env.T["shared_matches"].c.id == mid))
        key = shared_key_of(stem_of_row(dict(row)), "EHF/1")
        filled = await fill_shared_lineup(key, blob())
        foreign = await fill_shared_lineup("M-ZZZZZZZZ/EHF/1", blob())
        official = await fill_shared_lineup("EHF/1", blob())
        return key, filled, foreign, official

    key, filled, foreign, official = env.run(go)
    assert key.startswith("M-")
    assert {c["number"]: c["fullName"] for c in filled["matchConfig"]["hostPlayerCards"]}[6] == "KOWALSKI Jan"
    assert foreign == blob() and official == blob()
