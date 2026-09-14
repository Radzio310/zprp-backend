"""Reguły potwierdzania klauzuli RODO.

Sedno: potwierdzenie ma WERSJĘ. Gdy treść klauzuli się zmienia, wszyscy czytają
ją ponownie - ale ktoś, kto czytał poprzednią, ma zobaczyć „zmieniliśmy treść",
a nie ten sam komunikat, co zupełnie nowy użytkownik.
"""

import pytest

from app.privacy_consent_rules import (
    CURRENT_CLAUSE_VERSION,
    accepted_version,
    is_fresh_install,
    needs_consent,
    normalize_source,
    normalize_subject_id,
    normalize_subject_type,
    normalize_version,
)


class TestPotrzebaZgody:
    def test_brak_wpisu_to_potrzeba(self):
        assert needs_consent(None) is True
        assert needs_consent(0) is True

    def test_starsza_wersja_to_potrzeba(self):
        assert needs_consent(1, current=2) is True

    def test_biezaca_wersja_wystarcza(self):
        assert needs_consent(2, current=2) is False

    def test_nowsza_wersja_tez_wystarcza(self):
        """Telefon z nowszą aplikacją niż serwer nie jest niczyim zaniedbaniem."""
        assert needs_consent(3, current=2) is False


class TestPierwszyRaz:
    def test_zero_to_pierwszy_raz(self):
        assert is_fresh_install(None) is True
        assert is_fresh_install(0) is True

    def test_starsza_wersja_to_NIE_pierwszy_raz(self):
        """Od tego zależy, czy komunikat brzmi jak błąd, czy jak nowość."""
        assert is_fresh_install(1) is False


class TestNajwyzszaWersja:
    def test_bierze_maksimum_a_nie_ostatni(self):
        rows = [{"version": 2}, {"version": 1}]
        assert accepted_version(rows) == 2

    def test_pusta_lista_to_zero(self):
        assert accepted_version([]) == 0
        assert accepted_version(None) == 0

    def test_smiec_nie_podnosi_wersji(self):
        assert accepted_version([{"version": "ala"}, {"version": None}]) == 0


class TestNormalizacja:
    def test_rodzaj_podmiotu_bez_zgadywania(self):
        assert normalize_subject_type("PROEL") == "proel"
        assert normalize_subject_type(" zprp ") == "zprp"
        with pytest.raises(ValueError):
            normalize_subject_type("beach")
        with pytest.raises(ValueError):
            normalize_subject_type("")

    def test_pusty_identyfikator_to_blad(self):
        assert normalize_subject_id(" 12345 ") == "12345"
        assert normalize_subject_id(7) == "7"
        with pytest.raises(ValueError):
            normalize_subject_id("   ")

    def test_nieznane_zrodlo_to_logowanie(self):
        assert normalize_source("signup") == "signup"
        assert normalize_source("in_app") == "in_app"
        assert normalize_source("skadinad") == "login"
        assert normalize_source(None) == "login"

    def test_wersja_ujemna_i_smieciowa_to_zero(self):
        assert normalize_version(-3) == 0
        assert normalize_version("dwa") == 0
        assert normalize_version("2") == 2


class TestZgodnoscZAplikacja:
    def test_wersja_klauzuli_ta_sama_co_w_aplikacji(self):
        """Telefon i serwer muszą liczyć tę samą wersję tej samej zgody.

        Rozjazd znaczyłby, że serwer uważa zgodę za aktualną, a telefon pyta
        o nią w kółko (albo odwrotnie - nikt nigdy nie przeczyta nowej treści).
        """
        from pathlib import Path
        import re

        leaf = (
            Path(__file__).resolve().parents[2]
            / "BAZA"
            / "utils"
            / "privacyConsent.ts"
        )
        if not leaf.exists():
            pytest.skip("Repozytorium aplikacji nie stoi obok backendu.")

        text = leaf.read_text(encoding="utf-8")
        found = re.search(r"PRIVACY_CLAUSE_VERSION\s*=\s*(\d+)", text)
        assert found, "Aplikacja nie deklaruje PRIVACY_CLAUSE_VERSION."
        assert int(found.group(1)) == CURRENT_CLAUSE_VERSION
