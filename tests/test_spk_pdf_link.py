# Podpisany adres materiału szkoleniowego.
#
# Ten token jest CAŁYM uprawnieniem do trasy - inaczej niż token sesji
# podniesionej, który jest tylko dodatkiem do tożsamości. Stąd inny zestaw
# pytań: czy wygasły naprawdę odmawia, czy podpis da się podmienić i czy token
# wystawiony do czegoś innego nie otwiera tej trasy.

import time

import pytest

from app import proel_elevation, spk_pdf_link
from app.spk_pdf_link import (
    TOKEN_AUDIENCE,
    create_pdf_token,
    token_expires_at,
    verify_pdf_token,
)


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("PROEL_AUTH_SECRET", "sekret-do-testow")
    monkeypatch.delenv("SPK_PDF_LINK_TTL_SECONDS", raising=False)


class TestWystawianie:
    def test_swiezy_token_przechodzi(self):
        payload = verify_pdf_token(create_pdf_token("625"))
        assert payload is not None
        assert payload["aud"] == TOKEN_AUDIENCE

    def test_zapisuje_kto_poprosil(self):
        payload = verify_pdf_token(create_pdf_token("proel:41"))
        assert payload["by"] == "proel:41"

    def test_bez_podpisujacego_tez_dziala(self):
        # `by` jest zapisem audytowym, nie warunkiem.
        assert verify_pdf_token(create_pdf_token("")) is not None

    def test_domyslne_zycie_to_dziesiec_minut(self):
        exp = token_expires_at(create_pdf_token("625"))
        assert 9 * 60 <= exp - int(time.time()) <= 10 * 60

    def test_dlugosc_zycia_da_sie_ustawic_zmienna(self, monkeypatch):
        monkeypatch.setenv("SPK_PDF_LINK_TTL_SECONDS", "60")
        exp = token_expires_at(create_pdf_token("625"))
        assert exp - int(time.time()) <= 60


class TestOdmowa:
    def test_wygasly_to_odmowa_a_nie_zejscie_nizej(self):
        assert verify_pdf_token(create_pdf_token("625", ttl_seconds=-5)) is None

    def test_pusty_i_bezsensowny(self):
        assert verify_pdf_token("") is None
        assert verify_pdf_token("bez-kropki") is None
        assert verify_pdf_token("a.b") is None

    def test_podmieniony_podpis(self):
        token = create_pdf_token("625")
        head, _, _sig = token.partition(".")
        assert verify_pdf_token(head + ".podrobiony") is None

    def test_podmieniona_tresc_przy_starym_podpisie(self):
        token = create_pdf_token("625")
        _head, _, sig = token.partition(".")
        assert verify_pdf_token("aGVq." + sig) is None

    def test_inny_sekret_nie_otwiera(self, monkeypatch):
        token = create_pdf_token("625")
        monkeypatch.setenv("PROEL_AUTH_SECRET", "zupelnie-inny")
        assert verify_pdf_token(token) is None


class TestRozdzielnoscTokenow:
    def test_token_sesji_podniesionej_nie_otwiera_materialu(self):
        # Oba podpisy schodzą tym samym sekretem - rozdziela je wyłącznie
        # publiczność, i to jest tu jedyna linia obrony.
        elev = proel_elevation.create_elevation_token("625", admin=True)
        assert verify_pdf_token(elev) is None

    def test_token_materialu_nie_podnosi_sesji(self):
        assert proel_elevation.verify_elevation_token(create_pdf_token("625")) is None

    def test_publicznosci_sa_rozne(self):
        assert spk_pdf_link.TOKEN_AUDIENCE != proel_elevation.TOKEN_AUDIENCE


class TestRodzajDokumentu:
    """Adres prezentacji jest do pokazania sali; raport niesie nazwiska.

    Jeden token nie ma prawa otwierać obu - rozstrzyga `doc` w payloadzie,
    a stare tokeny bez `doc` znaczą prezentację, bo tylko ją wtedy
    podpisywaliśmy.
    """

    def test_domyslnie_prezentacja(self):
        from app.spk_pdf_link import create_pdf_token, verify_pdf_token

        payload = verify_pdf_token(create_pdf_token("1234"))
        assert payload["doc"] == "slides"
        assert "prov" not in payload

    def test_raport_niesie_doc_i_okreg(self):
        from app.spk_pdf_link import create_pdf_token, verify_pdf_token

        token = create_pdf_token("1234", doc="report", province="LUBELSKIE")
        payload = verify_pdf_token(token)
        assert payload["doc"] == "report"
        assert payload["prov"] == "LUBELSKIE"

    def test_raport_ogolnopolski_bez_okregu(self):
        from app.spk_pdf_link import create_pdf_token, verify_pdf_token

        payload = verify_pdf_token(create_pdf_token("1234", doc="report"))
        assert payload["doc"] == "report"
        assert "prov" not in payload
