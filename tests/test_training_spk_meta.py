# Nagłówek meczu wzorcowego czytany z protokołu.
#
# Powód istnienia tego pliku: na karcie w panelu pojawiło się
# „do przerwy {'host': 10, 'guest': 14}". Wynik do przerwy leży w protokole
# jako SŁOWNIK, a był rozbijany po myślniku jak tekst - rozbicie dawało jeden
# człon, czyli cały zapis Pythona, i tak trafiał na ekran.

import pytest

from app.training_spk_meta import half_scores, meta_from_blob


class TestWynikDoPrzerwy:
    def test_slownik_z_protokolu_aplikacji(self):
        assert half_scores({"halfScore": {"host": 10, "guest": 14}}) == ("10", "14")

    def test_zero_zostaje_zerem(self):
        # „0" jest fałszywe w Pythonie - naiwne `or ""` zamieniłoby wynik
        # bezbramkowej połowy w pusty.
        assert half_scores({"halfScore": {"host": 0, "guest": 0}}) == ("0", "0")

    @pytest.mark.parametrize("txt", ["10-14", "10:14", "10 - 14", "10–14"])
    def test_starsze_zapisy_tekstowe(self, txt):
        assert half_scores({"halfScore": txt}) == ("10", "14")

    def test_brak_wyniku(self):
        assert half_scores({}) == ("", "")
        assert half_scores({"halfScore": None}) == ("", "")

    def test_pojedyncza_liczba_to_nie_wynik(self):
        # Nie wiadomo, czyja jest - lepiej nie pokazać nic.
        assert half_scores({"halfScore": "13"}) == ("", "")


class TestNaglowekMeczu:
    def _blob(self, **over):
        blob = {
            "date": "2026-08-29T15:40:20.675Z",
            "scoreHost": 26,
            "scoreGuest": 26,
            "halfScore": {"host": 10, "guest": 14},
            "matchConfig": {
                "matchNumber": "SPK/1",
                "matchId": "208133",
                "hostTeamName": "KGHM MKS Zagłębie Lubin",
                "guestTeamName": "PGE MKS El-Volt Lublin",
            },
        }
        blob.update(over)
        return blob

    def test_komplet_z_prawdziwego_meczu(self):
        m = meta_from_blob(self._blob())
        assert (m["finalHost"], m["finalGuest"]) == ("26", "26")
        assert (m["halfHost"], m["halfGuest"]) == ("10", "14")
        assert m["zprpMatchId"] == "208133"
        assert m["hostTeamName"] == "KGHM MKS Zagłębie Lubin"

    def test_numer_meczu_ma_wartosc_domyslna(self):
        m = meta_from_blob({"matchConfig": {}})
        assert m["matchNumber"] == "SPK/1"

    def test_brak_konfiguracji_nie_wywraca(self):
        m = meta_from_blob({})
        assert m["matchNumber"] == "SPK/1"
        assert m["hostTeamName"] == ""
        assert m["halfHost"] == ""

    def test_konfiguracja_innego_typu_jest_ignorowana(self):
        # Zapis z pola tekstowego zamiast obiektu nie ma prawa wysypać importu.
        m = meta_from_blob({"matchConfig": "SPK/1"})
        assert m["hostTeamName"] == ""

    def test_data_z_konfiguracji_gdy_protokol_jej_nie_ma(self):
        m = meta_from_blob({"matchConfig": {"dateTime": "2026-08-29 15:00"}})
        assert m["date"] == "2026-08-29 15:00"

    def test_slowo_none_nie_trafia_na_ekran(self):
        # `str(None)` dawało napis „None" w miejscu nazwy drużyny.
        m = meta_from_blob({"matchConfig": {"hostTeamName": None}, "scoreHost": None})
        assert m["hostTeamName"] == ""
        assert m["finalHost"] == ""


class TestMedyk:
    """Opieka medyczna: publiczne API ZPRP jej nie zna, protokół tak."""

    def _with_medic(self, **medic):
        return {"matchConfig": {"extras": {"medic": medic}}}

    def test_komplet_z_protokolu(self):
        from app.training_spk_meta import medic_from_blob

        out = medic_from_blob(
            self._with_medic(
                fullName="KOWALSKA Anna",
                role="ratownik medyczny",
                number="PWZ 12345",
            )
        )
        assert out == {
            "fullName": "KOWALSKA Anna",
            "role": "ratownik medyczny",
            "number": "PWZ 12345",
        }

    def test_podpis_nigdy_nie_wychodzi(self):
        from app.training_spk_meta import medic_from_blob

        out = medic_from_blob(
            self._with_medic(fullName="KOWALSKA Anna", signature="bazgroł")
        )
        assert "signature" not in out

    def test_rola_schodzi_do_malych_liter(self):
        # Aplikacja trzyma role małymi (`utils/medicRoles.ts`) i tylko takie
        # trafiają w listę wyboru - „Lekarz Medycyny" wypadłby poza nią.
        from app.training_spk_meta import medic_from_blob

        out = medic_from_blob(self._with_medic(role="Lekarz Medycyny"))
        assert out["role"] == "lekarz medycyny"

    def test_puste_pola_nie_trafiaja_do_wyniku(self):
        from app.training_spk_meta import medic_from_blob

        assert medic_from_blob(self._with_medic(fullName="", role="  ")) == {}

    def test_brak_medyka_to_pusty_slownik_a_nie_blad(self):
        from app.training_spk_meta import medic_from_blob

        assert medic_from_blob({}) == {}
        assert medic_from_blob({"matchConfig": {"extras": {}}}) == {}
        assert medic_from_blob({"matchConfig": {"extras": {"medic": "nie obiekt"}}}) == {}

    def test_naglowek_meczu_niesie_medyka(self):
        m = meta_from_blob(
            {"matchConfig": {"extras": {"medic": {"fullName": "NOWAK Jan"}}}}
        )
        assert m["medic"] == {"fullName": "NOWAK Jan"}
