# Reguly „bomb" - zgloszen, ze sedziego nie bylo na meczu.
#
# Te funkcje decyduja o wpisie przy CUDZYM nazwisku, z ktorego okreg czyta
# ranking. Najwazniejsze testy w tym pliku to `test_zglasza_tylko_obsada...`
# (kto tam nie byl, ten nie zglasza) i `test_uniewaznione_nie_licza_sie...`
# (decyzja komisji ma zdejmowac wpis z rankingu, a nie tylko go przekreslac).

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.match_bombs_rules import (
    COMMISSION_BADGE,
    CREW_SLOTS,
    REPORT_WINDOW_DAYS,
    author_is_visible,
    bomb_sentence,
    counts_to_stats,
    crew_from_payload,
    crew_from_state,
    find_in_crew,
    is_blank_name,
    may_report,
    may_void,
    may_withdraw,
    month_label,
    rank_bombs,
    report_window_end,
    same_person,
    season_label,
    season_of,
    slot_label,
)

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)
MATCH_AT = datetime(2026, 9, 1, 18, 0, tzinfo=timezone.utc)

STATE = {
    "NrSedzia_pierwszy": "5124",
    "NrSedzia_pierwszy_nazwisko": "WITKOWICZ Radosław",
    "NrSedzia_drugi": "8123",
    "NrSedzia_drugi_nazwisko": "WITKOWICZ Krzysztof",
    "NrSedzia_sekretarz": "0",
    "NrSedzia_sekretarz_nazwisko": "",
    "NrSedzia_czas_nazwisko": "--- ---",
    "NrSedzia_delegat": "777",
    "NrSedzia_delegat_nazwisko": "NOWAK Jan",
}


def bomb(**over):
    base = {
        "id": 1,
        "status": "active",
        "author_judge_id": "5124",
        "author_name": "WITKOWICZ Radosław",
        "subject_judge_id": "8123",
        "subject_name": "WITKOWICZ Krzysztof",
        "subject_slot": "sedzia2",
        "match_code": "IIM4/1",
    }
    base.update(over)
    return base


# ─────────────────────────── obsada ───────────────────────────


def test_puste_gniazdo_nie_jest_czlowiekiem():
    """Bez tego dalo by sie zglosic bombe na kreske."""
    assert is_blank_name("--- ---")
    assert is_blank_name("0")
    assert is_blank_name("")
    assert is_blank_name("   ")
    assert is_blank_name(None)
    assert not is_blank_name("NOWAK Jan")


def test_obsada_z_migawki_pomija_puste_role():
    crew = crew_from_state(STATE)
    slots = [c["slot"] for c in crew]
    assert slots == ["sedzia1", "sedzia2", "delegat"]
    assert crew[0]["judgeId"] == "5124"
    assert crew[2]["name"] == "NOWAK Jan"


def test_obsada_z_aplikacji_przyjmuje_tylko_znane_role():
    crew = crew_from_payload(
        [
            {"slot": "sedzia1", "name": "NOWAK Jan", "judgeId": "1"},
            {"slot": "kibic", "name": "KTOS Ktosiowy"},
            {"slot": "czas", "name": "--- ---"},
            {"slot": "delegat2", "name": "KOWALSKI Piotr"},
        ]
    )
    assert [c["slot"] for c in crew] == ["sedzia1", "delegat2"]


def test_numer_rozstrzyga_przed_nazwiskiem():
    """W okregu jest dwoch WITKOWICZOW - nazwisko samo nie wystarcza."""
    crew = crew_from_state(STATE)
    hit = find_in_crew(crew, judge_id="8123")
    assert hit is not None and hit["slot"] == "sedzia2"


def test_nazwisko_dziala_gdy_numeru_brak_i_znosi_kolejnosc_czlonow():
    crew = crew_from_state(STATE)
    hit = find_in_crew(crew, full_name="Radosław WITKOWICZ")
    assert hit is not None and hit["slot"] == "sedzia1"


def test_kogos_spoza_obsady_nie_ma_w_obsadzie():
    crew = crew_from_state(STATE)
    assert find_in_crew(crew, judge_id="9999", full_name="OBCY Nikt") is None
    # Samo nazwisko to za malo, gdy w obsadzie sa dwie osoby o tym nazwisku.
    assert find_in_crew(crew, full_name="WITKOWICZ") is None


def test_gniazdo_zaweza_gdy_ta_sama_osoba_stoi_dwa_razy():
    state = {
        "NrSedzia_sekretarz": "42",
        "NrSedzia_sekretarz_nazwisko": "NOWAK Jan",
        "NrSedzia_czas": "42",
        "NrSedzia_czas_nazwisko": "NOWAK Jan",
    }
    crew = crew_from_state(state)
    hit = find_in_crew(crew, judge_id="42", slot="czas")
    assert hit is not None and hit["slot"] == "czas"


def test_kazde_gniazdo_obsady_ma_podpis():
    for slot in CREW_SLOTS:
        assert slot_label(slot)
    assert slot_label("kibic") == "kibic"


def test_ta_sama_osoba_mimo_odwroconych_czlonow():
    assert same_person("WITKOWICZ Krzysztof", "Krzysztof WITKOWICZ")
    assert not same_person("WITKOWICZ Krzysztof", "WITKOWICZ Radosław")
    assert not same_person("", "NOWAK Jan")


# ─────────────────────────── okno czasu ───────────────────────────


def test_przed_pierwszym_gwizdkiem_nie_ma_czego_zglaszac():
    refusal = may_report(MATCH_AT, MATCH_AT - timedelta(hours=2))
    assert refusal and "jeszcze się nie zaczął" in refusal


def test_w_oknie_wolno():
    assert may_report(MATCH_AT, NOW) is None
    assert may_report(MATCH_AT, MATCH_AT + timedelta(minutes=1)) is None


def test_po_oknie_zostaje_komisja():
    late = MATCH_AT + timedelta(days=REPORT_WINDOW_DAYS, hours=1)
    refusal = may_report(MATCH_AT, late)
    assert refusal and "komisja" in refusal
    # Komisja dopisuje sprawe takze pozniej - to ona prowadzi rejestr.
    assert may_report(MATCH_AT, late, is_commission=True) is None


def test_mecz_bez_daty_nie_odcina_obsady():
    """Brak `data_fakt` to luka w bazie zwiazku, nie powod do blokady."""
    assert may_report(None, NOW) is None
    assert report_window_end(None) is None


def test_okno_konczy_sie_dokladnie_po_dwoch_tygodniach():
    assert report_window_end(MATCH_AT) == MATCH_AT + timedelta(days=14)


# ─────────────────────────── cofanie i uniewaznianie ───────────────────────────


def test_cofa_tylko_autor_i_tylko_czynne():
    assert may_withdraw(bomb(), "5124")
    assert not may_withdraw(bomb(), "8123")
    assert not may_withdraw(bomb(status="voided"), "5124")
    assert not may_withdraw(bomb(status="withdrawn"), "5124")


def test_komisja_uniewaznia_zamiast_cofac():
    assert may_void(True, bomb())
    assert not may_void(False, bomb())
    # Uniewaznic mozna raz - drugi raz nie ma czego.
    assert not may_void(True, bomb(status="voided"))


def test_uniewaznione_nie_licza_sie_do_rankingu():
    """Decyzja komisji ma ZDEJMOWAC wpis z rankingu, nie tylko go przekreslac."""
    assert counts_to_stats("active")
    assert not counts_to_stats("voided")
    assert not counts_to_stats("withdrawn")


# ─────────────────────────── widocznosc autora ───────────────────────────


def test_autora_widzi_komisja_zglaszajacy_i_zgloszony():
    assert author_is_visible(bomb(), "999", is_commission=True)
    assert author_is_visible(bomb(), "5124")
    assert author_is_visible(bomb(), "8123")


def test_reszta_obsady_widzi_sam_fakt():
    assert not author_is_visible(bomb(), "777")
    assert not author_is_visible(bomb(), "")


# ─────────────────────────── sezon i miesiac ───────────────────────────


@pytest.mark.parametrize(
    "stamp,expected",
    [
        (datetime(2026, 9, 1, tzinfo=timezone.utc), 2026),
        (datetime(2026, 8, 31, tzinfo=timezone.utc), 2025),
        (datetime(2027, 6, 30, tzinfo=timezone.utc), 2026),
    ],
)
def test_sezon_zaczyna_sie_pierwszego_wrzesnia(stamp, expected):
    assert season_of(stamp) == expected


def test_mecz_bez_daty_nie_trafia_do_zadnego_sezonu():
    """Zgadywanie przestawiloby wpis w czyims rankingu."""
    assert season_of(None) is None
    assert season_of("2026-09-01") is None


def test_etykieta_sezonu_jak_w_aplikacji():
    assert season_label(2026) == "2026/27"
    assert season_label(2029) == "2029/30"
    assert season_label("nie-rok") == ""


def test_miesiac_po_polsku():
    assert month_label("2026-09") == "wrzesień 2026"
    assert month_label("2026-13") == "2026-13"
    assert month_label("") == ""


# ─────────────────────────── ranking ───────────────────────────


def test_ranking_liczy_miejsca_ex_aequo():
    """Ta sama regula, co w tabelach rozgrywek: 1, 2, 2, 4."""
    ranked = rank_bombs(
        [
            {"judgeId": "1", "name": "NOWAK Jan", "count": 1},
            {"judgeId": "2", "name": "KOWALSKI Piotr", "count": 3},
            {"judgeId": "3", "name": "ABACKI Adam", "count": 2},
            {"judgeId": "4", "name": "BABACKI Bartek", "count": 2},
        ]
    )
    assert [(r["name"], r["place"]) for r in ranked] == [
        ("KOWALSKI Piotr", 1),
        ("ABACKI Adam", 2),
        ("BABACKI Bartek", 2),
        ("NOWAK Jan", 4),
    ]


def test_pusty_ranking_zostaje_pusty():
    assert rank_bombs([]) == []


# ─────────────────────────── zdanie ───────────────────────────


def test_zdanie_nie_zdradza_autora_dopoki_nie_wolno():
    text = bomb_sentence(bomb())
    assert text == "WITKOWICZ Krzysztof (sędzia 2) - zgłoszona nieobecność na meczu IIM4/1."
    assert "Radosław" not in text
    z_autorem = bomb_sentence(bomb(), with_author=True)
    assert "Zgłosił: WITKOWICZ Radosław." in z_autorem


def test_zdanie_sklada_sie_takze_bez_numeru_meczu():
    text = bomb_sentence(bomb(match_code=""))
    assert text.endswith("na meczu.")
    assert ".." not in text


def test_odznaka_komisji_ma_jedno_zrodlo():
    assert COMMISSION_BADGE == "Komisja sędziowska"
