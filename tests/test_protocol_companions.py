"""Kary osób towarzyszących w wydruku protokołu.

Mecz 208136: BRYZIK dostał 2' i dyskwalifikację, DAJERLING dyskwalifikację
z raportem, WRZEŚNIEWSKI upomnienie. Na baza.zprp.pl wszystkie trzy kary są
zaznaczone, a w wygenerowanym PDF rubryki U / 2' / D były puste - bo paczka
przyszła z konfiguracją bez flag ławki, a generator nie miał objazdu przez
przebieg meczu.
"""
from __future__ import annotations

from app.results import (
    _build_event_counters,
    _companion_events_penalties,
    _companion_penalty_strings,
)


def _ms(mm: int, ss: int) -> int:
    return (mm * 60 + ss) * 1000


#: Ławka tak, jak zapisuje ją autozapis aplikacji: nazwiska są, kar nie ma.
HOST_BENCH_NO_FLAGS = [
    {"id": "A", "fullName": "BRYZIK Jacek", "function": "TRENER A", "penaltyTimes": []},
    {"id": "B", "fullName": "WRZEŚNIEWSKI Stefan", "penaltyTimes": []},
    {"id": "C", "fullName": "DAJERLING Piotr", "penaltyTimes": []},
]

PROTOCOL_208136 = [
    {"time": _ms(3, 20), "half": 1, "type": "warning", "team": "host", "player": "B"},
    {"time": _ms(12, 34), "half": 1, "type": "penalty1", "team": "host", "player": "A"},
    {"time": _ms(45, 10), "half": 2, "type": "disqualification", "team": "host", "player": "A"},
    {"time": _ms(52, 41), "half": 2, "type": "disqualificationBlue", "team": "host", "player": "C"},
    {"time": _ms(21, 5), "half": 1, "type": "warning", "team": "guest", "player": "A"},
    # Zdarzenia zawodnika z numerem - ławki nie dotyczą.
    {"time": _ms(30, 4), "half": 1, "type": "goal", "team": "host", "player": 1},
    {"time": _ms(37, 26), "half": 2, "type": "penalty1", "team": "host", "player": 1},
]

DATA_208136 = {
    "matchConfig": {"hostCompanions": HOST_BENCH_NO_FLAGS},
    "protocol": PROTOCOL_208136,
}


# ───────────────────────── odczyt z przebiegu ─────────────────────────


def test_przebieg_oddaje_wszystkie_rodzaje_kary():
    ev = _companion_events_penalties(DATA_208136)["host"]
    assert ev["A"]["p2"] == ["12:34"]
    assert ev["A"]["disq"] == "45:10"
    assert ev["B"]["warn"] == "04:00"
    assert ev["C"]["disq"] == "52:41"


def test_upomnienie_zaokragla_sie_do_minuty():
    # Protokół nie ma rubryki na sekundy upomnienia; aplikacja liczy tak samo.
    ev = _companion_events_penalties(
        {"protocol": [{"type": "warning", "team": "host", "player": "A", "time": _ms(3, 20)}]}
    )
    assert ev["host"]["A"]["warn"] == "04:00"


def test_zawodnicy_i_druga_druzyna_nie_wchodza_na_lawke():
    ev = _companion_events_penalties(DATA_208136)
    assert set(ev["host"]) == {"A", "B", "C"}
    assert set(ev["guest"]) == {"A"}
    assert ev["guest"]["A"]["disq"] == ""


def test_smieci_w_przebiegu_nie_wywracaja_odczytu():
    ev = _companion_events_penalties(
        {"protocol": ["nie-obiekt", {"type": "warning", "team": "x", "player": "A"}, None]}
    )
    assert ev == {"host": {}, "guest": {}}
    assert _companion_events_penalties({}) == {"host": {}, "guest": {}}


# ───────────────────────── napisy do rubryk ─────────────────────────


def test_konfiguracja_bez_flag_drukuje_kary_z_przebiegu():
    ev = _companion_events_penalties(DATA_208136)["host"]
    out = _companion_penalty_strings(HOST_BENCH_NO_FLAGS, ev)

    assert out["A"]["p2"] == "2' - 12:34"
    assert out["A"]["disq"] == "D - 45:10"
    assert out["B"]["warn"] == "U - 04:00"
    assert out["C"]["disq"] == "D - 52:41"


def test_bez_przebiegu_zostaje_stare_zachowanie():
    # Zapisy sprzed poprawki mają w konfiguracji komplet flag - i mają się
    # drukować dokładnie tak jak dotąd.
    comp = [{"id": "A", "warned": True, "warningTime": "04:00", "penaltyTimes": ["12:34"], "red": True, "redTime": "45:10"}]
    out = _companion_penalty_strings(comp)
    assert out["A"] == {"warn": "U - 04:00", "p2": "2' - 12:34", "disq": "D - 45:10"}


def test_konfiguracja_ma_pierwszenstwo_dla_czasu():
    # Suma, nie podmiana: flaga z przebiegu dokłada to, czego nie ma, ale nie
    # przestawia czasu, który sędzia poprawił ręcznie.
    comp = [{"id": "A", "red": True, "redTime": "40:00"}]
    out = _companion_penalty_strings(comp, {"A": {"warn": "", "p2": [], "disq": "45:10"}})
    assert out["A"]["disq"] == "D - 40:00"


def test_niebieska_kartka_w_konfiguracji_tez_wypelnia_rubryke_D():
    comp = [{"id": "D", "redBlue": True, "redBlueTime": "52:41"}]
    out = _companion_penalty_strings(comp)
    assert out["D"]["disq"] == "D - 52:41"


def test_ukarany_spoza_skladu_nie_znika_z_wydruku():
    out = _companion_penalty_strings([], {"E": {"warn": "", "p2": ["10:00"], "disq": ""}})
    assert out["E"]["p2"] == "2' - 10:00"


def test_czysta_lawka_zostaje_pusta():
    ev = _companion_events_penalties({"protocol": []})["host"]
    out = _companion_penalty_strings(HOST_BENCH_NO_FLAGS, ev)
    assert all(row == {"warn": "", "p2": "", "disq": ""} for row in out.values())


# ───────────────────────── ptaszki na formularzu ─────────────────────────


def test_niebieska_kartka_liczy_sie_jako_dyskwalifikacja():
    # Ta sama reguła co przy oficjalnym API: `red` albo `redBlue` to rubryka D.
    counters = _build_event_counters(DATA_208136)
    assert counters["host"]["C"]["disq"] == 1
    assert counters["host"]["A"]["disq"] == 1
