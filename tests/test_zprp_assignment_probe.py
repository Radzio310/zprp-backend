"""Sonda uprawnień - czy konto okręgu może obsadzać ten mecz.

Sędzia widzi w aplikacji wszystkie swoje mecze, ale okręg obsadza tylko część
z nich. Superligę, ligi centralne i turnieje młodzieżowe obsadza związek i
konto wojewódzkie nie ma tam czego kliknąć. Bez tego sprawdzenia sędzia
wystawiłby taki mecz na giełdę, ktoś by się zgłosił, obsadowy by zatwierdził -
i dopiero wtedy okazałoby się, że zapisu nie ma jak wykonać.

Testy pilnują trzech odpowiedzi, które ZPRP oddaje na to samo zapytanie, i
tego, żeby dwie z nich NIE wyglądały tak samo:

* pełny formularz z listą sędziów - mecz nasz,
* strona bez pól wyboru - mecz nie nasz,
* pola wyboru bez opcji - mecz nasz, ale zmiany nie ma jak zapisać.

Warstwa HTTP jest podmieniona. Sprawdzamy własne czytanie odpowiedzi, nie ZPRP.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from app.zprp import assignments as A

TRADEABLE = ("NrSedzia_pierwszy", "NrSedzia_drugi", "NrSedzia_sekretarz", "NrSedzia_czas")
ALL_SELECTS = TRADEABLE + ("NrSedzia_delegat", "NrSedzia_delegat2")


def full_form(selected: Dict[str, str] | None = None, options: int = 3) -> str:
    """Formularz obsady tak, jak widzi go konto z uprawnieniami."""
    selected = selected or {}
    names = ["NOWAK Jan", "KOWALSKI Piotr", "MAZUR Adam", "ŁACNY Bartłomiej"]
    parts = ['<html><body><input type="hidden" name="IdZawody" value="208136">']
    for field in ALL_SELECTS:
        parts.append(f'<select name="{field}">')
        parts.append('<option value="">--- ---</option>')
        for i in range(options):
            value = str(i + 1)
            mark = " selected" if selected.get(field) == value else ""
            parts.append(f'<option value="{value}"{mark}>{names[i % len(names)]}</option>')
        parts.append("</select>")
    parts.append("</body></html>")
    return "".join(parts)


def no_form() -> str:
    """Odpowiedź dla meczu spoza zasięgu konta - żadnych pól wyboru."""
    return (
        "<html><body><h3>Zawody</h3>"
        "<p>Brak uprawnień do edycji obsady tych zawodów.</p>"
        '<a href="index.php?a=terminarz">Powrót</a>'
        "</body></html>"
    )


def empty_selects() -> str:
    """Pola są, ale filtr ZPRP nie zwrócił ani jednego sędziego."""
    return full_form(options=0)


class FakeHttp:
    """Podstawka pod `fetch_with_correct_encoding` - oddaje zadaną stronę."""

    def __init__(self, page: str):
        self.page = page
        self.calls: List[Dict[str, Any]] = []

    async def __call__(self, client, path, method="GET", data=None, cookies=None, **kw):
        self.calls.append({"path": path, "data": dict(data or {})})
        return None, self.page


@pytest.fixture
def http(monkeypatch):
    def install(page: str) -> FakeHttp:
        fake = FakeHttp(page)
        monkeypatch.setattr(A, "fetch_with_correct_encoding", fake)
        return fake

    return install


async def probe(**kw):
    return await A.probe_assignment_rights(None, {}, "208136", **kw)


@pytest.mark.asyncio
async def test_full_form_means_the_district_assigns_this_match(http):
    http(full_form())
    out = await probe()

    assert out["assignable"] is True
    assert out["reason"] == "OK"
    # Zgoda nie potrzebuje uzasadnienia - komunikat zostaje pusty.
    assert out["message"] == ""


@pytest.mark.asyncio
async def test_page_without_selects_is_a_refusal(http):
    http(no_form())
    out = await probe()

    assert out["assignable"] is False
    assert out["reason"] == "NO_FORM"


@pytest.mark.asyncio
async def test_refusal_explains_itself_to_the_referee(http):
    # Zasada „zero cichych blokad": odmowa musi się wytłumaczyć, bo sędzia
    # inaczej zobaczy wyszarzony przycisk bez powodu i zadzwoni do obsadowego.
    http(no_form())
    out = await probe()

    assert "obsad" in out["message"].lower()
    assert len(out["message"]) > 30


@pytest.mark.asyncio
async def test_empty_lists_are_not_the_same_answer_as_no_form(http):
    """Dwie odmowy, dwa różne powody - i to jest cała wartość tego testu.

    `_parse_select_options` oddaje pustą listę zarówno wtedy, gdy pola nie ma,
    jak i wtedy, gdy jest puste. Gdyby sonda opierała się tylko na niej, okręg
    dostawałby komunikat „to nie Wasz mecz" przy meczu, który jest jego.
    """
    http(empty_selects())
    out = await probe()

    assert out["assignable"] is False
    assert out["reason"] == "NO_OPTIONS"
    assert out["reason"] != "NO_FORM"


@pytest.mark.asyncio
async def test_probe_reads_the_same_form_the_save_uses(http):
    fake = http(full_form())
    await probe()

    assert len(fake.calls) == 1
    assert fake.calls[0]["path"] == "/zawody_UstawSedziow.php"
    assert fake.calls[0]["data"]["IdZawody"] == "208136"
    assert fake.calls[0]["data"]["akcja"] == "UstawSedziow"
    # Sonda tylko PYTA. Pole zapisu nie ma prawa tu pojechać.
    assert "akcja_edycja" not in fake.calls[0]["data"]


@pytest.mark.asyncio
async def test_probe_reports_who_sits_in_the_slot(http):
    http(full_form({"NrSedzia_pierwszy": "2"}))
    out = await probe(slot="sedzia1")

    assert out["holder"] == "KOWALSKI Piotr"


@pytest.mark.asyncio
async def test_holder_is_empty_when_no_slot_was_named(http):
    http(full_form({"NrSedzia_pierwszy": "2"}))
    out = await probe()

    assert out["holder"] == ""


@pytest.mark.asyncio
async def test_delegate_slot_alone_does_not_open_the_market(http):
    """Sam delegat to za mało.

    Gdyby ZPRP wyrenderowało wyłącznie pole delegata, giełda nie ma czym
    handlować - delegaci są spoza wymiany.
    """
    html = (
        '<html><body><select name="NrSedzia_delegat">'
        '<option value="1">NOWAK Jan</option></select></body></html>'
    )
    http(html)
    out = await probe()

    assert out["assignable"] is False
    assert out["reason"] == "NO_FORM"


@pytest.mark.asyncio
async def test_a_single_tradeable_select_is_enough(http):
    html = (
        '<html><body><select name="NrSedzia_czas">'
        '<option value="">--- ---</option>'
        '<option value="4">MAZUR Adam</option></select></body></html>'
    )
    http(html)
    out = await probe()

    assert out["assignable"] is True
    assert out["option_count"] == 1
