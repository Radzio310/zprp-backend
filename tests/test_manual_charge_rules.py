"""
Ręczne mecze z rachunkiem (SPARING): wycena, netto -> brutto, przejazdy,
zamiana na obsady silnika i wiersz obciążenia klubu.
"""

import io
import json
from datetime import date, datetime, timezone
from pathlib import Path

from app import club_charges as C
from app import manual_charge_rules as M
from app import settlement_engine as E
from app import settlement_rates as R

ROOT = Path(__file__).resolve().parent.parent
SEED = json.loads(io.open(ROOT / "app" / "data" / "central_rates_seed.json", encoding="utf-8").read())
CENTRAL = [
    {"id": 1, "valid_from": None, "valid_to": "2026-08-31", "enabled": True, "content": SEED["versions"][0]["content"]},
    {"id": 2, "valid_from": "2026-09-01", "valid_to": None, "enabled": True, "content": SEED["versions"][1]["content"]},
]
PROV_RAW = json.loads(
    io.open(ROOT.parent / "BAZA" / "assets" / "data" / "okregowe" / "slaskieCalcRates.json", encoding="utf-8").read()
)
PROV = [{"id": 10, "valid_from": "2026-09-01", "valid_to": None, "enabled": True, "content": PROV_RAW}]
NOW = datetime(2026, 12, 1, tzinfo=timezone.utc)


# --------------------------------------------------------------- netto/brutto

def test_gross_from_net_is_exact_inverse_everywhere():
    for gross in range(1, 1500):
        net = M.net_of(gross)
        back = M.gross_from_net(net)
        # Najmniejsze brutto o tym netto - netto zgadza się co do złotówki.
        assert M.net_of(back) == net
        assert back <= gross


def test_gross_from_net_below_and_above_threshold():
    # 117 zł brutto (poniżej progu): podatek 12% bez KUP -> 103 zł netto.
    assert M.net_of(117) == 103
    assert M.gross_from_net(103) == 117
    # Powyżej 200 zł: KUP 20% -> 250 brutto, koszty 50, podatek 24, netto 226.
    assert M.net_of(250) == 226
    assert M.gross_from_net(226) == 250


def test_gross_from_net_gap_at_threshold_rounds_up():
    # 200 brutto = 176 netto, 201 brutto = 182 netto: 177-181 nie istnieje.
    assert M.net_of(200) == 176 and M.net_of(201) == 182
    assert M.gross_from_net(179) == 201
    assert M.net_of(M.gross_from_net(179)) >= 179


def test_fee_gross_modes():
    assert M.fee_gross("117", M.MODE_GROSS) == 117
    assert M.fee_gross("103", M.MODE_NET) == 117
    assert M.fee_gross("0", M.MODE_NET) == 0
    assert M.fee_gross("abc", M.MODE_GROSS) == 0


# ---------------------------------------------------------------- podpowiedzi

def test_default_fee_sparing_uses_province_other_category():
    day = date(2026, 10, 7)  # środa
    field, source = M.default_fee("SPARING", M.FIELD, day, central_versions=CENTRAL, province_versions=PROV)
    table, _ = M.default_fee("", M.TABLE, day, central_versions=CENTRAL, province_versions=PROV)
    assert source == "province"
    assert field == 117 and table == 77


def test_default_fee_known_code_uses_its_category():
    day = date(2026, 10, 7)
    value, source = M.default_fee("S/IIIM/4", M.FIELD, day, central_versions=CENTRAL, province_versions=PROV)
    assert source == "code" and value == 131


def test_default_fee_without_tables_falls_back():
    value, source = M.default_fee("SPARING", M.FIELD, date(2026, 10, 7), central_versions=[], province_versions=[])
    assert (value, source) == (M.FALLBACK_FEES[M.FIELD], "fallback")


def test_km_rate_is_province_rate_for_sparing():
    assert M.km_rate("SPARING", "SLASKIE", date(2026, 10, 7), central_versions=CENTRAL, province_versions=PROV) == 0.7


# -------------------------------------------------------------------- wycena

def _crew():
    return [
        {"judge_id": "11", "name": "Jan KOWALSKI", "role": "table", "home_city": "Bytom", "km_one_way": 20, "km_source": "table"},
        {"judge_id": "12", "name": "Anna NOWAK", "role": "field", "home_city": "Gliwice", "km_one_way": 12.5, "km_source": "google"},
        {"judge_id": "13", "name": "Piotr ZIELIŃSKI", "role": "field", "home_city": "Zabrze", "km_one_way": 0, "km_source": "same-city"},
    ]


def test_price_officials_fee_by_role_and_travel_round_trip():
    priced = M.price_officials(_crew(), field_fee=117, table_fee=77, rate=0.7, travel_enabled=True)
    assert [p["role"] for p in priced] == ["field", "field", "table"]
    by_id = {p["judge_id"]: p for p in priced}
    assert by_id["12"]["fee_gross"] == 117 and by_id["12"]["travel"] == 17.5  # 12,5 x 2 x 0,70
    assert by_id["11"]["fee_gross"] == 77 and by_id["11"]["travel"] == 28.0
    assert by_id["13"]["travel"] == 0
    totals = M.totals_of(priced)
    assert totals["gross"] == 117 * 2 + 77
    assert totals["travel"] == 45.5
    assert totals["total"] == 356.5


def test_travel_switch_off_zeroes_travel():
    priced = M.price_officials(_crew(), field_fee=117, table_fee=77, rate=0.7, travel_enabled=False)
    assert M.totals_of(priced)["travel"] == 0
    assert M.totals_of(priced)["total"] == 311


def test_problems_explain_every_gap():
    out = M.problems(day=None, city="", officials=[], field_fee=0, table_fee=0, travel_enabled=True)
    assert "Wybierz dzień meczu." in out
    assert "Podaj miasto meczu." in out
    assert "Dodaj co najmniej jednego sędziego." in out

    crew = M.price_officials(
        [{"judge_id": "1", "name": "A", "role": "field"}, {"judge_id": "1", "name": "A", "role": "field"}],
        field_fee=0, table_fee=77, rate=0.7, travel_enabled=True,
    )
    out = M.problems(day=date(2026, 10, 1), city="Bytom", officials=crew, field_fee=0, table_fee=77, travel_enabled=True)
    assert any("dwa razy" in item for item in out)
    assert any("ryczałt boiskowego" in item for item in out)
    assert any(item.startswith("Brak kilometrów") for item in out)
    # Bez zwrotu za dojazd kilometry nie są potrzebne.
    out = M.problems(day=date(2026, 10, 1), city="Bytom", officials=crew[:1], field_fee=117, table_fee=77, travel_enabled=False)
    assert out == []


# ------------------------------------------------- obsady silnika i obciążenie

def _record(**extra):
    priced = M.price_officials(_crew(), field_fee=117, table_fee=77, rate=0.7, travel_enabled=True)
    base = {
        "id": 7,
        "province": "SLASKIE",
        "club_id": "K1",
        "day": date(2026, 10, 31),
        "match_time": "23:30",
        "code": "SPARING",
        "city": "Zabrze",
        "travel_enabled": True,
        "officials": json.dumps(priced),
        "totals": json.dumps({**M.totals_of(priced), "km_rate": 0.7}),
    }
    base.update(extra)
    return base


def test_assignments_keep_polish_day_and_fixed_amounts():
    items = M.assignments_of(_record(), club_name="SPR Pogoń - Zabrze")
    assert len(items) == 3
    first = items[0]
    assert first.match_key == "manual:7" and first.origin == "manual"
    # 23:30 czasu polskiego 31.10 to już 1.11 w UTC - liczy się dzień POLSKI.
    assert first.match_at.date() == date(2026, 10, 31)
    # Bez „ - ": most klubów nie rozpozna gospodarza i nie przeniesie meczu.
    assert " - " not in first.teams
    assert C.host_from_teams(first.teams) == ""


def test_engine_pays_fixed_amounts_and_taxes_the_month_sum():
    items = M.assignments_of(_record())
    entries = E.settle_judges(
        items, province="SLASKIE", central_versions=CENTRAL, province_versions=PROV, now=NOW,
        date_from=date(2026, 10, 1), date_to=date(2026, 10, 31),
    )
    by_id = {e.judge_id: e for e in entries}
    assert by_id["12"].gross == 117 and by_id["12"].travel == 17.5
    assert by_id["12"].net == R.settle_period(117)["net"]
    assert by_id["11"].gross == 77 and by_id["11"].travel == 28.0
    match = by_id["12"].matches[0]
    assert match.km_rate == 0.7 and match.distance_km == 12.5
    # Lista przejazdów: km x 2 x stawka zgadza się z kwotą.
    rows = {r.judge_id: r for r in E.travel_rows(entries)}
    assert rows["12"].total_km == 25 and rows["12"].amount == 17.5
    assert "13" not in rows  # 0 km - bez wiersza na liście przejazdów


def test_engine_never_drops_manual_as_zprp_or_tournament():
    # Numer wyglądający na Superligę albo dzieci nie może zdjąć ręcznego meczu.
    for code in ("SPM/1", "S/DzM/1"):
        items = M.assignments_of(_record(code=code))
        entries = E.settle_judges(
            items, province="SLASKIE", central_versions=CENTRAL, province_versions=PROV, now=NOW,
            date_from=date(2026, 10, 1), date_to=date(2026, 10, 31),
        )
        assert sum(e.gross for e in entries) == 311
        assert round(sum(e.travel for e in entries), 2) == 45.5


def test_charge_rows_sum_what_the_engine_paid():
    record = _record()
    entries = E.settle_judges(
        M.assignments_of(record), province="SLASKIE", central_versions=CENTRAL, province_versions=PROV, now=NOW,
    )
    settled = [m for e in entries for m in e.matches]
    rows = M.charge_rows([record], settled, judge_names={"12": "Anna NOWAK"}, club_names={"K1": "Klub"})
    assert len(rows) == 1
    row = rows[0]
    assert row.club_id == "K1" and row.status == C.CHARGED and row.manual_id == 7
    assert row.gross == 311 and row.travel == 45.5 and row.amount == 356.5
    assert C.club_totals(rows)["K1"]["charged"] == 356.5


def test_future_manual_match_follows_the_future_switch():
    record = _record(day=date(2027, 1, 10))
    items = M.assignments_of(record)
    kept = E.settle_judges(items, province="SLASKIE", central_versions=CENTRAL, province_versions=PROV, now=NOW)
    assert kept == []
    kept = E.settle_judges(
        items, province="SLASKIE", central_versions=CENTRAL, province_versions=PROV, now=NOW, include_future=True
    )
    assert len(kept) == 3


def test_record_json_and_season():
    out = M.record_json(_record())
    assert out["match_key"] == "manual:7" and out["code"] == "SPARING"
    assert len(out["officials"]) == 3 and out["totals"]["km_rate"] == 0.7
    assert M.club_season(date(2026, 8, 31)) == "2025/2026"
    assert M.club_season(date(2026, 9, 1)) == "2026/2027"


# ------------------------------------------------ stawka na sędziego (25.09)

def test_official_fee_own_amount_in_gross_and_net():
    own_gross = M.official_fee({"fee_amount": 150.5, "fee_mode": "brutto"}, role_gross=117)
    assert own_gross["fee_custom"] is True and own_gross["fee_gross"] == 150.5
    assert own_gross["fee_mode"] == M.MODE_GROSS
    assert own_gross["fee_net"] == M.net_of(150.5)
    # Netto 103 zł = 117 zł brutto; to TA SAMA kwota co stawka roli - bez znacznika.
    own_net = M.official_fee({"fee_amount": "103", "fee_mode": "netto"}, role_gross=117)
    assert own_net["fee_gross"] == 117 and own_net["fee_custom"] is False
    # Netto z groszami zostaje z groszami (podatek w pełnych złotych).
    cents = M.official_fee({"fee_amount": 103.4, "fee_mode": "net"}, role_gross=117)
    assert cents["fee_gross"] == 117.4 and cents["fee_net"] == 103.4


def test_official_fee_without_own_amount_follows_the_role():
    out = M.official_fee({}, role_gross=77, record_mode="net")
    assert out == {"fee_amount": None, "fee_mode": "net", "fee_custom": False, "fee_gross": 77, "fee_net": M.net_of(77)}


def test_mixed_crew_own_and_default_fees():
    crew = _crew()
    crew[1]["fee_amount"], crew[1]["fee_mode"] = 200, "gross"   # Anna - własne brutto
    crew[0]["fee_amount"], crew[0]["fee_mode"] = 90, "net"      # Jan - własne netto
    priced = M.price_officials(crew, field_fee=117, table_fee=77, rate=0.7, travel_enabled=True)
    by_id = {p["judge_id"]: p for p in priced}
    assert by_id["12"]["fee_gross"] == 200 and by_id["12"]["fee_custom"]
    assert by_id["11"]["fee_gross"] == M.gross_from_net(90) and by_id["11"]["fee_custom"]
    assert by_id["13"]["fee_gross"] == 117 and not by_id["13"]["fee_custom"]
    totals = M.totals_of(priced)
    assert totals["custom"] == 2
    assert totals["gross"] == 200 + M.gross_from_net(90) + 117
    assert totals["net"] == round(M.net_of(200) + 90 + M.net_of(117), 2)
    assert totals["total"] == round(totals["gross"] + totals["travel"], 2)


def test_changing_role_default_moves_only_rows_that_follow_it():
    crew = _crew()
    crew[1]["fee_amount"] = 160  # Anna ma swoje
    for field_fee in (117, 140):
        by_id = {p["judge_id"]: p for p in M.price_officials(crew, field_fee=field_fee, table_fee=77, rate=0.7, travel_enabled=True)}
        assert by_id["12"]["fee_gross"] == 160
        assert by_id["13"]["fee_gross"] == field_fee


def test_old_records_without_per_judge_fields_price_as_before():
    old = [{k: v for k, v in item.items()} for item in _crew()]
    priced = M.price_officials(old, field_fee=117, table_fee=77, rate=0.7, travel_enabled=True)
    assert [p["fee_gross"] for p in priced] == [117, 117, 77]
    assert all(p["travel_on"] is True and p["fee_amount"] is None for p in priced)
    assert M.totals_of(priced)["total"] == 356.5
    # Stary zapis w bazie (bez nowych pól) daje te same obsady silnika.
    legacy = [
        {k: v for k, v in item.items() if k not in ("fee_amount", "fee_mode", "fee_custom", "fee_net", "travel_on")}
        for item in priced
    ]
    items = M.assignments_of(_record(officials=json.dumps(legacy)))
    assert sorted(a.fixed_gross for a in items) == [77, 117, 117]
    assert round(sum(a.fixed_travel for a in items), 2) == 45.5


def test_per_judge_travel_switch():
    crew = _crew()
    crew[0]["travel_on"] = False           # Jan bez zwrotu
    crew[1]["km_one_way"] = None           # Anna bez km - ale ma zwrot, więc brak
    crew[1]["travel_on"] = True
    priced = M.price_officials(crew, field_fee=117, table_fee=77, rate=0.7, travel_enabled=True)
    by_id = {p["judge_id"]: p for p in priced}
    assert by_id["11"]["travel"] == 0 and by_id["11"]["travel_on"] is False
    out = M.problems(day=date(2026, 10, 1), city="Zabrze", officials=priced, field_fee=117, table_fee=77, travel_enabled=True)
    missing = [item for item in out if item.startswith("Brak kilometrów")]
    assert missing and "Anna NOWAK" in missing[0] and "Jan KOWALSKI" not in missing[0]
    # Sędzia bez zwrotu nie trafia na listę przejazdów.
    crew[1]["km_one_way"] = 12.5
    priced = M.price_officials(crew, field_fee=117, table_fee=77, rate=0.7, travel_enabled=True)
    items = {a.judge_id: a for a in M.assignments_of(_record(officials=json.dumps(priced)))}
    assert items["11"].fixed_travel == 0 and items["11"].distance_km is None
    assert items["12"].fixed_travel == 17.5


def test_problems_for_own_fees():
    crew = _crew()
    crew[0]["fee_amount"] = 0
    crew[1]["fee_amount"] = 50000
    priced = M.price_officials(crew, field_fee=117, table_fee=77, rate=0.7, travel_enabled=True)
    out = M.problems(day=date(2026, 10, 1), city="Zabrze", officials=priced, field_fee=117, table_fee=77, travel_enabled=True)
    assert any("Jan KOWALSKI musi być większy od zera" in item for item in out)
    assert any("Anna NOWAK (50 000,00 zł brutto) wygląda na pomyłkę" in item for item in out)
    # Wszyscy boiskowi mają swoje stawki - pusta stawka roli nie blokuje.
    crew = _crew()
    for item in crew:
        item["fee_amount"] = 120
    priced = M.price_officials(crew, field_fee=0, table_fee=0, rate=0.7, travel_enabled=True)
    out = M.problems(day=date(2026, 10, 1), city="Zabrze", officials=priced, field_fee=0, table_fee=0, travel_enabled=True)
    assert out == []


def test_engine_pays_two_field_judges_of_one_match_differently():
    crew = _crew()
    crew[1]["fee_amount"], crew[1]["fee_mode"] = 150.5, "gross"   # Anna
    crew[2]["fee_amount"], crew[2]["fee_mode"] = 103, "net"       # Piotr: 117 brutto
    priced = M.price_officials(crew, field_fee=130, table_fee=77, rate=0.7, travel_enabled=True)
    record = _record(officials=json.dumps(priced), totals=json.dumps({**M.totals_of(priced), "km_rate": 0.7}))
    entries = E.settle_judges(
        M.assignments_of(record), province="SLASKIE", central_versions=CENTRAL, province_versions=PROV, now=NOW,
        date_from=date(2026, 10, 1), date_to=date(2026, 10, 31),
    )
    by_id = {e.judge_id: e for e in entries}
    assert by_id["12"].gross == 150.5 and by_id["13"].gross == 117
    assert by_id["12"].gross != by_id["13"].gross
    assert by_id["12"].net == R.settle_period(150.5)["net"]
    # Klub płaci sumę brutto KAŻDEGO sędziego + przejazdy.
    settled = [m for e in entries for m in e.matches]
    row = M.charge_rows([record], settled)[0]
    assert row.gross == round(150.5 + 117 + 77, 2)
    assert row.amount == round(row.gross + 45.5, 2)
    assert sorted(share.gross for share in row.referees) == [77, 117, 150.5]


def test_modes_accept_polish_words():
    assert M.normalize_mode("brutto") == M.MODE_GROSS
    assert M.normalize_mode("NETTO") == M.MODE_NET
    assert M.normalize_mode("", None) is None
    assert M.fee_gross("103", "netto") == 117
