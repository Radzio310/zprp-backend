"""Guard przed nadpisaniem cudzego protokołu i projekcja listy meczów.

Dlaczego to ma testy, skoro to trzy krótkie funkcje: bo od nich zależy, czy
zapis meczu wejdzie w wiersz SWOJEGO meczu, czy w wiersz meczu sprzed roku
o tym samym numerze. Numer meczu ("OSK/12") jest kluczem głównym tabeli
i jest unikalny w rozgrywkach, ale NIE między sezonami - a błąd w tę stronę
kasuje protokół, którego nikt już nie odtworzy z telefonu.

Druga funkcja pilnuje granicy, na której lista meczów przestaje wozić na
telefon nazwiska, licencje i przebieg wszystkich meczów w systemie.
"""
from __future__ import annotations

from app.proel_match_key import match_head, match_id_conflict, zprp_id_of


# ───────────────────────── zprp_id_of ─────────────────────────


def test_bierze_numeryczny_identyfikator_z_konfiguracji():
    assert zprp_id_of({"matchConfig": {"matchId": "208135"}}) == "208135"


def test_liczba_zamiast_tekstu_tez_przechodzi():
    assert zprp_id_of({"matchConfig": {"matchId": 208135}}) == "208135"


def test_syntetyczny_identyfikator_meczu_recznego_jest_pomijany():
    # Mecze zakładane ręcznie mają `Date.now()-…`; uznanie tego za identyfikator
    # ZPRP zablokowałoby prowadzenie zwykłego meczu bez rozgrywek.
    assert zprp_id_of({"matchConfig": {"matchId": "1755870000000-ab12"}}) == ""


def test_brak_konfiguracji_nie_wywraca_odczytu():
    assert zprp_id_of(None) == ""
    assert zprp_id_of({}) == ""
    assert zprp_id_of({"matchConfig": {}}) == ""
    assert zprp_id_of("nie-obiekt") == ""


# ───────────────────────── match_id_conflict ─────────────────────────


def test_inny_mecz_pod_tym_samym_numerem_to_konflikt():
    assert match_id_conflict("208135", "209001") is True


def test_ten_sam_mecz_przechodzi():
    assert match_id_conflict("208135", "208135") is False


def test_nieznany_identyfikator_po_ktorejkolwiek_stronie_nie_blokuje():
    # Mecz ręczny i zapis sprzed tej kolumny MUSZĄ przechodzić - inaczej guard
    # zabiłby prowadzenie meczu, który nigdy nie miał odpowiednika w ZPRP.
    assert match_id_conflict("", "209001") is False
    assert match_id_conflict("208135", "") is False
    assert match_id_conflict("", "") is False


# ───────────────────────── match_head ─────────────────────────


FULL_BLOB = {
    "date": "2026-08-14T18:30:00.000Z",
    "scoreHost": 29,
    "scoreGuest": 27,
    "protocol": [{"type": "goal", "player": 7}],
    "hostPlayerStats": [{"number": 7, "name": "KOWALSKI Jan"}],
    "matchConfig": {
        "matchNumber": "OSK/12",
        "matchId": "208135",
        "hostTeamName": "Gospodarze SA",
        "guestTeamName": "Goście SA",
        "isTest": False,
        "hostPlayers": ["7", "9", "11"],
        "hostPlayerCards": [{"number": 7, "license": "12345"}],
        "referee1": "NOWAK Adam",
    },
}


def test_naglowek_niesie_to_co_rysuje_wiersz_listy():
    head = match_head(FULL_BLOB)
    assert head["matchConfig"]["matchNumber"] == "OSK/12"
    assert head["matchConfig"]["hostTeamName"] == "Gospodarze SA"
    assert head["matchConfig"]["matchId"] == "208135"
    assert head["scoreHost"] == 29
    assert head["date"].startswith("2026-08-14")


def test_naglowek_nie_niesie_danych_osobowych_ani_przebiegu():
    head = match_head(FULL_BLOB)
    assert "hostPlayers" not in head["matchConfig"]
    assert "hostPlayerCards" not in head["matchConfig"]
    assert "referee1" not in head["matchConfig"]
    assert "protocol" not in head
    assert "hostPlayerStats" not in head


def test_naglowek_znosi_smieci_zamiast_bloba():
    assert match_head(None) == {"matchConfig": {}}
    assert match_head("nie-obiekt") == {"matchConfig": {}}
    assert match_head({}) == {"matchConfig": {}}
