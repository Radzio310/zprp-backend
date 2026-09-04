# Nazwisko z listy okregu kontra podpis opcji w formularzu ZPRP.
#
# Z produkcji (2026-09-04): zatwierdzenie wymiany na gieldzie padalo z kodem
# NAME_NOT_IN_OPTIONS dla "Krzysztof WITKOWICZ", choc sedzia stal wsrod 811
# opcji gniazda - jako "WITKOWICZ Krzysztof". Formularz podpisuje NAZWISKO Imie,
# lista sedziow okregu bywa prowadzona Imie NAZWISKO, a rygiel porownywal
# napisy doslownie. Te testy pilnuja, zeby kolejnosc czlonow nie blokowala
# zapisu, a wieloznacznosc nadal go wstrzymywala.

import pytest

from tests.test_zprp_assignment_apply import SELECTS, apply, form_html, http  # noqa: F401


OPTIONS = {
    name: [("1", "NOWAK Jan"), ("7", "WITKOWICZ Krzysztof"), ("3", "MAZUR Adam")]
    for name in SELECTS
}


@pytest.mark.asyncio
async def test_reversed_name_order_still_finds_the_option(http):
    before = form_html({"NrSedzia_pierwszy": "1"}, OPTIONS)
    after = form_html({"NrSedzia_pierwszy": "7"}, OPTIONS)
    fake = http(before, after)

    out = await apply(
        {"NrSedzia_pierwszy": ("", "Krzysztof WITKOWICZ")},
        require_name_match=True,
    )

    assert out["success"] is True, out
    assert fake.submitted["NrSedzia_pierwszy"] == "7"


@pytest.mark.asyncio
async def test_verification_accepts_the_zprp_spelling(http):
    # Po zapisie ZPRP oddaje "WITKOWICZ Krzysztof" - to ten sam czlowiek, wiec
    # weryfikacja nie ma prawa uznac udanego zapisu za nieudany.
    before = form_html({"NrSedzia_drugi": "1"}, OPTIONS)
    after = form_html({"NrSedzia_drugi": "7"}, OPTIONS)
    http(before, after)

    out = await apply({"NrSedzia_drugi": ("7", "Krzysztof WITKOWICZ")})

    assert out["success"] is True, out
    assert out["verified_slots"]["sedzia2"]["name"] == "WITKOWICZ Krzysztof"


@pytest.mark.asyncio
async def test_exact_spelling_wins_over_a_looser_match(http):
    options = {
        name: [("1", "NOWAK Jan"), ("2", "NOWAK Jan Pawel")] for name in SELECTS
    }
    before = form_html({"NrSedzia_pierwszy": ""}, options)
    after = form_html({"NrSedzia_pierwszy": "1"}, options)
    fake = http(before, after)

    out = await apply({"NrSedzia_pierwszy": ("", "NOWAK Jan")}, require_name_match=True)

    assert out["success"] is True, out
    assert fake.submitted["NrSedzia_pierwszy"] == "1"


@pytest.mark.asyncio
async def test_ambiguous_name_is_refused_not_guessed(http):
    options = {
        name: [("1", "NOWAK Jan Pawel"), ("2", "NOWAK Jan Piotr")] for name in SELECTS
    }
    fake = http(form_html({"NrSedzia_pierwszy": ""}, options))

    out = await apply({"NrSedzia_pierwszy": ("", "Jan Nowak")}, require_name_match=True)

    assert out["success"] is False
    assert out["code"] == "NAME_AMBIGUOUS"
    assert "NOWAK Jan Pawel" in out["error"]
    # Nie doszlo do wysylki - w bazie zwiazku nic sie nie zmienilo.
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_stranger_is_still_refused(http):
    fake = http(form_html({"NrSedzia_pierwszy": "1"}, OPTIONS))

    out = await apply({"NrSedzia_pierwszy": ("", "Ktos SPOZA LISTY")}, require_name_match=True)

    assert out["success"] is False
    assert out["code"] == "NAME_NOT_IN_OPTIONS"
    assert len(fake.calls) == 1
