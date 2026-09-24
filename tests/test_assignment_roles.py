"""
Role sędziów z listy ZPRP (25.09.2026): zapis z synchronizacji i odczyt spod
dwóch pisowni okręgu, plus kafelki kandydatów z ograniczeniem roli.
"""

from datetime import datetime, timezone

from app.assignment_auto import Context, MatchNeed, describe_candidates
from app.assignment_people import make_judge
from app.assignment_roles import (
    dump_roles,
    load_roles,
    pick_role_rows,
    roles_diff,
    zprp_roles_by_judge,
)

OFFICIALS = {
    "101": {"name": "WOJTYCZKA Grzegorz", "roles": ["stolikowy"], "roles_text": "Stolikowy"},
    "102": {"name": "NOWAK Jan", "roles": ["sedzia", "stolikowy"], "roles_text": "Sędzia\nStolikowy"},
    # Numer spoza okręgu, ale nazwisko jednoznaczne.
    "9999": {"name": "MAJKA Marek", "roles": ["Stolikowy"], "roles_text": "Stolikowy"},
    # Nazwisko pasuje do dwóch osób - nie zgadujemy.
    "8888": {"name": "KOWALSKI Adam", "roles": ["sedzia"]},
}
JUDGES = [
    ("101", "WOJTYCZKA Grzegorz"),
    ("102", "NOWAK Jan"),
    ("103", "Marek Majka"),
    ("104", "KOWALSKI Adam"),
    ("105", "Adam Kowalski"),
]


class TestZapisuRol:
    def test_dopasowanie_po_numerze_i_nazwisku(self):
        out = zprp_roles_by_judge(OFFICIALS, JUDGES)
        assert out["101"]["roles"] == ["stolikowy"]
        assert out["102"]["roles"] == ["sedzia", "stolikowy"]
        assert out["103"]["roles"] == ["stolikowy"]
        assert "104" not in out and "105" not in out

    def test_json_jako_tekst(self):
        assert dump_roles(["Stolikowy", "Sędzia"]) == '["sedzia", "stolikowy"]'
        assert load_roles('["stolikowy"]') == ["stolikowy"]
        assert load_roles(b'["sedzia"]') == ["sedzia"]
        assert load_roles("") == [] and load_roles("zepsute") == [] and load_roles(None) == []

    def test_dwie_pisownie_wygrywa_swiezszy_potem_kanoniczny(self):
        old = datetime(2026, 9, 1, tzinfo=timezone.utc)
        new = datetime(2026, 9, 25, tzinfo=timezone.utc)
        rows = [
            {"province": "ŚLĄSKIE", "judge_id": "1", "roles": '["sedzia"]', "updated_at": old},
            {"province": "SLASKIE", "judge_id": "1", "roles": '["stolikowy"]', "updated_at": new},
            {"province": "ŚLĄSKIE", "judge_id": "2", "roles": '["sedzia"]', "updated_at": new},
            {"province": "SLASKIE", "judge_id": "2", "roles": '["stolikowy"]', "updated_at": new},
        ]
        picked = pick_role_rows(rows, "SLASKIE")
        assert picked == {"1": ["stolikowy"], "2": ["stolikowy"]}

    def test_zapisujemy_tylko_zmiany(self):
        wanted = zprp_roles_by_judge(OFFICIALS, JUDGES)
        existing = {"101": ["stolikowy"], "102": ["sedzia"]}
        assert roles_diff(existing, wanted) == ["102", "103"]


class TestKafelkiKandydatow:
    def test_tylko_stolik_bez_boiska_z_powodem(self):
        table_only = make_judge("1", "WOJTYCZKA Grzegorz", city="Zabrze", roles=["stolikowy"])
        both = make_judge("2", "NOWAK Jan", city="Zabrze", roles=["sedzia"])
        people = {"1": table_only, "2": both}
        ctx = Context(
            judges=people,
            available=lambda judge_id, moment: True,
            paused=lambda judge_id, day: False,
            city_of=lambda judge_id, day: people[judge_id].city,
            km=lambda a, b: 10.0,
        )
        moment = datetime(2026, 10, 3, 12, 0)
        need = MatchNeed(
            match_id="1",
            code="S/JmM/1",
            moment=moment,
            day=moment.date(),
            host_city="Gliwice",
            field_needed=["pierwszy", "drugi"],
            table_needed=["sekretarz", "czas"],
        )
        views = {view.judge_id: view for view in describe_candidates(ctx, need, kind="field")}
        assert views["1"].fits == ["table"]
        assert views["1"].role_note == "tylko stolik (ZPRP)"
        assert "boisko: tylko stolik (ZPRP)" in views["1"].reason
        assert views["1"].score is None and views["2"].rank == 1
        assert views["2"].role_note == ""
        # Zakładka „Stolik" - tu pasuje i dostaje ocenę.
        table_views = {view.judge_id: view for view in describe_candidates(ctx, need, kind="table")}
        assert table_views["1"].score is not None
