"""
„4. sędzia" - drugi stolikowy u klubu, który stolikowego stawia sam.

Decyzja użytkownika z 18.09.2026: klub z deklaracją `table_by_club = 1` płaci
na meczu OKRĘGOWYM tylko za jednego stolikowego z okręgu. Potrójny ryczałt
(stolikowy klubu nie przyszedł, sędzia okręgu robił za trzech) zostaje w całości
na klubie. Ligi centralne i puchar wojewódzki są poza regułą.
"""

from datetime import date, datetime, timezone

from app import settlement_engine as E
from app import settlement_rates as R
from app.club_charges import (
    CHARGED,
    ClubSetting,
    TeamRef,
    build_charges,
    club_totals,
    keep_one_table,
    own_table_applies,
    RefereeShare,
)
from app.province_clubs_scrape import team_key

ZGODA = TeamRef(team_id="1", club_id="1126", name="KS Zgoda Ruda Śląska", category="Junior mł.")
VIRET = TeamRef(team_id="2", club_id="81", name="KS Viret CMC Zawiercie", category="Junior mł.")
TEAMS = (ZGODA, VIRET)
BY_KEY = {team_key(t.name): t for t in TEAMS}
BY_ID = {t.team_id: t for t in TEAMS}

SEZON = date(2026, 8, 1)
OWN = ClubSetting(table_by_club=1, table_since=SEZON)


def crew(judge, role, gross, travel, *, host="KS Viret CMC Zawiercie", day=date(2026, 10, 4),
         code="S/JmM/7", key="d:100", triple=False):
    return E.SettledMatch(
        match_key=key,
        judge_id=judge,
        match_at=datetime(day.year, day.month, day.day, 10, 0, tzinfo=timezone.utc),
        day=day,
        match_code=code,
        category="Junior mł.",
        level="district",
        role=role,
        origin="district",
        city="Zawiercie",
        home_city="Katowice",
        teams=f"{host} - Gość",
        distance_km=30.0,
        distance_source="table",
        km_rate=0.8,
        gross=gross,
        travel=travel,
        travel_shared=False,
        future=False,
        approved=True,
        triple_table=triple,
    )


def full_crew(**kw):
    """Junior: dwóch boiskowych i DWÓCH stolikowych z okręgu."""
    return [
        crew("11", R.ROLE_FIELD, 150, 40.0, **kw),
        crew("12", R.ROLE_FIELD, 150, 40.0, **kw),
        crew("21", R.ROLE_TABLE, 100, 24.0, **kw),
        crew("22", R.ROLE_TABLE, 100, 56.0, **kw),
    ]


def charge(rows, clubs, hosts=None):
    out = build_charges(rows, hosts=hosts or {}, teams_by_key=BY_KEY, teams_by_id=BY_ID,
                        clubs=clubs, key_of=team_key)
    assert len(out) == 1
    return out[0]


class TestRegulyWProzni:
    def test_bez_deklaracji_nic_sie_nie_zmienia(self):
        assert not own_table_applies(ClubSetting(), "S/JmM/7", date(2026, 10, 4))
        assert not own_table_applies(None, "S/JmM/7", date(2026, 10, 4))

    def test_mecz_okregowy_po_dacie_deklaracji(self):
        assert own_table_applies(OWN, "S/JmM/7", date(2026, 10, 4))
        assert own_table_applies(OWN, "S/JmM/7", SEZON)

    def test_przed_data_deklaracji_po_staremu(self):
        # Mecz już rozliczony z klubem nie może się przeliczyć wstecz.
        assert not own_table_applies(OWN, "S/JmM/7", date(2026, 7, 31))

    def test_bez_daty_od_zawsze(self):
        assert own_table_applies(ClubSetting(table_by_club=1), "S/JmM/7", date(2020, 1, 1))

    def test_stoliki_lig_centralnych_poza_regula(self):
        # II liga, I liga - obu stolikowych daje zawsze okręg.
        assert not own_table_applies(OWN, "IIM4/10", date(2026, 10, 4))
        assert not own_table_applies(OWN, "IMD/1", date(2026, 10, 4))

    def test_zostaje_tanszy_stolikowy(self):
        shares = [
            RefereeShare("21", "A", R.ROLE_TABLE, 100, 56.0),
            RefereeShare("22", "B", R.ROLE_TABLE, 100, 24.0),
            RefereeShare("11", "C", R.ROLE_FIELD, 150, 40.0),
        ]
        assert keep_one_table(shares) is True
        charged = {share.judge_id: share.charged for share in shares}
        assert charged == {"21": False, "22": True, "11": True}

    def test_jeden_stolikowy_nie_ma_czego_zdejmowac(self):
        shares = [RefereeShare("21", "A", R.ROLE_TABLE, 300, 24.0)]
        assert keep_one_table(shares) is False
        assert shares[0].charged is True


class TestObciazenia:
    def test_klub_z_nie_placi_za_jednego_stolikowego(self):
        row = charge(full_crew(), {"81": OWN})
        assert row.status == CHARGED
        assert row.own_table is True
        assert row.extra_table is True
        # Dwóch boiskowych (2 x 190) + tańszy stolikowy (124). Droższy (156) - okręg.
        assert row.amount == 380 + 124
        dropped = [share.judge_id for share in row.referees if not share.charged]
        assert dropped == ["22"]

    def test_klub_z_tak_placi_za_cala_obsade(self):
        row = charge(full_crew(), {"81": ClubSetting()})
        assert row.own_table is False
        assert row.extra_table is False
        assert row.amount == 380 + 124 + 156
        assert all(share.charged for share in row.referees)

    def test_potrojny_ryczalt_zostaje_na_klubie_w_calosci(self):
        # Stolikowy klubu nie przyszedł: jeden sędzia okręgu przy stoliku, x3.
        rows = [
            crew("11", R.ROLE_FIELD, 150, 40.0),
            crew("12", R.ROLE_FIELD, 150, 40.0),
            crew("21", R.ROLE_TABLE, 300, 24.0, triple=True),
        ]
        row = charge(rows, {"81": OWN})
        assert row.own_table is True
        assert row.extra_table is False
        assert row.amount == 380 + 324

    def test_jeden_stolikowy_bez_ostrzezenia(self):
        rows = [
            crew("11", R.ROLE_FIELD, 150, 40.0),
            crew("12", R.ROLE_FIELD, 150, 40.0),
            crew("21", R.ROLE_TABLE, 100, 24.0),
        ]
        row = charge(rows, {"81": OWN})
        assert row.own_table is True
        assert row.extra_table is False
        assert row.amount == 380 + 124

    def test_mecz_sprzed_deklaracji_liczy_sie_po_staremu(self):
        row = charge(full_crew(day=date(2026, 5, 10)), {"81": OWN})
        assert row.own_table is False
        assert row.amount == 380 + 124 + 156

    def test_stolik_na_lidze_centralnej_caly(self):
        rows = [
            crew("21", R.ROLE_TABLE, 70, 24.0, code="IMD/1"),
            crew("22", R.ROLE_TABLE, 70, 56.0, code="IMD/1"),
        ]
        row = charge(rows, {"81": OWN})
        assert row.own_table is False
        assert row.amount == 94 + 126

    def test_suma_klubu_liczy_tylko_obciazonych(self):
        row = charge(full_crew(), {"81": OWN})
        totals = club_totals([row])["81"]
        assert totals["charged"] == 504
        assert totals["gross"] == 400
        assert totals["travel"] == 104

    def test_deklaracja_innego_klubu_nie_przecieka(self):
        row = charge(full_crew(), {"1126": OWN})
        assert row.own_table is False
        assert row.amount == 660
