"""
Wyjazd zbiorczy zwyklych meczow (25.11.2026): ten sam sedzia + dzien + miejscowosc
+ platnik = jeden dojazd; reczna decyzja wygrywa; mecze sprzed 01.11 bez zmian;
turnieje dzieci zostaja po staremu.
"""

import dataclasses
from datetime import datetime, timezone

from app import settlement_engine as E
from app import settlement_rates as R
from tests.test_settlement_engine import CENTRAL_VERSIONS, PROV_VERSIONS, at, make

LATER = datetime(2026, 12, 1, 12, 0, tzinfo=timezone.utc)


def run(assignments, **kwargs):
    [entry] = E.settle_judges(
        assignments,
        province="ŚLĄSKIE",
        central_versions=CENTRAL_VERSIONS,
        province_versions=PROV_VERSIONS,
        now=LATER,
        names={"5124": "KOWALSKI Jan"},
        **kwargs,
    )
    return {m.match_key: m for m in entry.matches}, entry


def two(payer_a="OKREG", payer_b="OKREG", day="2026-11-07", mode_a=None, mode_b=None, city_b="Zabrze"):
    a = dataclasses.replace(
        make("a", "S/JMM/7", R.ROLE_FIELD, at(f"{day}T09:00")), payer=payer_a, trip_mode=mode_a
    )
    b = dataclasses.replace(
        make("b", "S/JMM/8", R.ROLE_FIELD, at(f"{day}T14:00"), city=city_b), payer=payer_b, trip_mode=mode_b
    )
    return [a, b]


def test_ten_sam_platnik_jeden_dojazd_przy_najwczesniejszym():
    got, entry = run(two())
    assert got["a"].travel == 28 and not got["a"].travel_shared
    assert got["b"].travel == 0 and got["b"].travel_shared
    assert got["a"].trip_candidate and got["b"].trip_candidate
    assert got["a"].trip_group == got["b"].trip_group and got["a"].trip_group
    assert (got["a"].trip_result, got["b"].trip_result) == ("own", "shared")
    assert got["a"].trip_reason == got["b"].trip_reason == "same-payer"
    assert entry.travel == 28
    assert len(E.travel_rows([entry])) == 1


def test_rozni_platnicy_dojazdy_osobno():
    got, entry = run(two(payer_b="1234"))
    assert got["a"].travel == 28 and got["b"].travel == 28
    assert not got["a"].travel_shared and not got["b"].travel_shared
    assert got["b"].trip_candidate and got["b"].trip_reason == "different-payers"
    assert entry.travel == 56


def test_nieznany_platnik_nie_skleja():
    got, _ = run(two(payer_a=None, payer_b=None))
    assert got["a"].travel == got["b"].travel == 28
    assert got["a"].trip_reason == "unknown-payer"


def test_reczne_razem_zeruje_dojazd_tej_obsady_nawet_gdy_platnicy_rozni():
    got, _ = run(two(payer_b="1234", mode_b="together"))
    assert got["a"].travel == 28
    assert got["b"].travel == 0 and got["b"].travel_shared
    assert got["b"].trip_mode == "together" and got["b"].trip_reason == "manual-together"


def test_reczne_razem_na_najwczesniejszym_dojazd_przechodzi_na_nastepny():
    got, entry = run(two(mode_a="together"))
    assert got["a"].travel == 0 and got["b"].travel == 28
    assert entry.travel == 28


def test_reczne_osobno_wygrywa_z_automatem():
    got, entry = run(two(mode_b="separate"))
    assert got["a"].travel == 28 and got["b"].travel == 28
    assert got["b"].trip_mode == "separate" and got["b"].trip_reason == "manual-separate"
    assert got["b"].trip_result == "own"
    assert entry.travel == 56


def test_powrot_do_automatu_to_brak_decyzji():
    got, _ = run(two(mode_b="separate"))
    assert got["b"].travel == 28
    got, _ = run(two(mode_b=None))
    assert got["b"].travel == 0 and got["b"].trip_mode == "auto"


def test_mecz_sprzed_pierwszego_listopada_bez_zmian():
    got, entry = run(two(day="2026-10-31", mode_b="together"))
    assert got["a"].travel == got["b"].travel == 28
    assert not got["b"].trip_candidate and got["b"].trip_mode == "together"
    assert entry.travel == 56


def test_inna_miejscowosc_to_osobny_dojazd():
    got, _ = run(two(city_b="Bytom"))
    assert got["a"].travel == got["b"].travel == 28
    assert not got["a"].trip_candidate


def test_cala_doba_bez_bufora_czasowego():
    items = two()
    items[1] = dataclasses.replace(items[1], match_at=at("2026-11-07T20:30"))
    got, _ = run(items)
    assert got["b"].travel_shared


def test_przyszly_mecz_nie_odbiera_dojazdu():
    items = two()
    # Najwczesniejszy mecz jeszcze sie nie odbyl - dojazd placi ten, ktory wszedl do rachunku.
    items[0] = dataclasses.replace(items[0], match_at=at("2026-12-20T09:00"))
    got, _ = run(items)
    assert list(got) == ["b"] and got["b"].travel == 28


def test_stara_regula_na_zadanie():
    got, _ = run(two(), share_trips=False)
    assert got["a"].travel == got["b"].travel == 28


def test_turniej_dzieci_i_zwykly_mecz_tego_samego_dnia():
    kids = [
        dataclasses.replace(
            make(f"d{i}", f"S/DZM/{i}", R.ROLE_FIELD, at(f"2026-11-07T{8 + i:02d}:00"), hall="Hala"),
            payer="OKREG",
        )
        for i in range(3)
    ]
    regular = two()
    got, entry = run([*kids, *regular])
    # turniej: jeden dojazd jak dotad, nikt z turnieju nie dostaje znacznikow nowej reguly
    assert sum(1 for k in ("d0", "d1", "d2") if got[k].travel) == 1
    assert not any(got[k].trip_candidate for k in ("d0", "d1", "d2"))
    assert got["d1"].tournament_key and got["d1"].travel_shared
    # zwykle mecze: jeden wspolny dojazd miedzy soba, osobny od turnieju
    assert got["a"].travel == 28 and got["b"].travel_shared
    assert entry.travel == round(sum(m.travel for m in got.values()), 2)
    assert len(E.travel_rows([entry])) == 2


def test_reczny_mecz_z_gotowa_kwota_nie_bierze_udzialu():
    items = two()
    fixed = dataclasses.replace(
        make("f", "SPARING", R.ROLE_FIELD, at("2026-11-07T11:00")),
        origin="manual", fixed_gross=100.0, fixed_travel=40.0, payer="OKREG",
    )
    got, _ = run([*items, fixed])
    assert got["f"].travel == 40 and not got["f"].travel_shared
    assert got["a"].travel == 28 and got["b"].travel_shared


def test_skrypt_audytu_wykrywa_dwa_dojazdy_i_rozroznia_platnikow():
    from scripts.settlement_trip_audit import build_situations

    items = two(day="2026-10-10")
    got, _ = run(items)
    rows = build_situations(
        list(got.values()),
        {"a": "10", "b": "10"},
        {},
        lambda p: str(p),
        lambda j: f"Jan ({j})",
    )
    assert len(rows) == 1
    assert rows[0]["kind"] == "ten sam płatnik" and rows[0]["excess"] == 28
    rows = build_situations(list(got.values()), {"a": "10", "b": "11"}, {}, str, str)
    assert rows[0]["kind"] == "różni płatnicy" and rows[0]["saving_new_rule"] == 0
    rows = build_situations(list(got.values()), {"a": "10", "b": "11"}, {"11": "10"}, str, str)
    assert rows[0]["kind"] == "ten sam płatnik"


def test_gospodarz_bez_nazwy_nie_jest_wspolnym_platnikiem():
    # Zrodlo, nie import: `settlement_club_scope` ciagnie `app.db` (polaczenie
    # z baza przy imporcie). Dwa mecze z nieznanym gospodarzem nie moga dostac
    # jednego platnika „host:?" - to sklejalo dojazdy nieznanych platnikow.
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[1] / "app" / "settlement_club_scope.py").read_text(
        encoding="utf-8"
    )
    assert 'payer_of.setdefault(row.match_key, row.club_id or f"host:{row.host_name}")' in source
    assert "if row.club_id or row.host_name:" in source


def test_razem_na_jedynym_meczu_dnia_zachowuje_dojazd():
    [a, _] = two(mode_a="together")
    got, entry = run([a])
    assert got["a"].travel == 28 and not got["a"].travel_shared
    assert (got["a"].trip_mode, got["a"].trip_result, got["a"].trip_reason) == (
        "together", "own", "manual-together-alone")
    assert entry.travel == 28


def test_wszystkie_mecze_w_razem_dojazd_przy_najwczesniejszym():
    got, entry = run(two(mode_a="together", mode_b="together"))
    assert got["a"].travel == 28 and got["a"].trip_reason == "manual-together-alone"
    assert got["b"].travel == 0 and got["b"].travel_shared and got["b"].trip_reason == "manual-together"
    assert entry.travel == 28


def test_razem_gdy_drugi_mecz_poza_zakresem_dat():
    got, _ = run(two(mode_b="together"), date_to=datetime(2026, 11, 7).date())
    assert got["b"].travel == 0  # a jest w zakresie i ma dojazd
    items = two(mode_a="together")
    got, _ = run(items, date_from=datetime(2026, 11, 7).date(), date_to=datetime(2026, 11, 7).date())
    assert got["a"].travel == 0 and got["b"].travel == 28
    items[1] = dataclasses.replace(items[1], match_at=at("2026-11-08T14:00"))
    got, _ = run(items, date_to=datetime(2026, 11, 7).date())
    assert got["a"].travel == 28 and got["a"].trip_reason == "manual-together-alone"
