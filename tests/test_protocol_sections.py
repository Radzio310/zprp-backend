"""Stara droga zapisu protokołu potrafi teraz wypełnić TYLKO wybrane bloki.

Po co: statystyki zawodników mają własny endpoint w oficjalnym API ZPRP, więc
logowanie się na stronę i przechodzenie przez kilkadziesiąt pól formularza jest
potrzebne wyłącznie do tego, czego API nie obsługuje - osób towarzyszących
i uwag sędziów. Bez zawężenia zakresu ta droga nadpisywałaby zaraz po API te
same statystyki jeszcze raz, tyle że kruchym scrapem.

Testy pilnują, żeby zawężenie faktycznie ODCINAŁO wysyłkę, a nie tylko
pomijało logi - i żeby brak parametru dalej znaczył „wszystko", bo tak działa
dotychczasowa ścieżka z modala wyniku skróconego.
"""
from __future__ import annotations

import pytest
from bs4 import BeautifulSoup

import app.results as r

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


def _tag(html: str):
    return BeautifulSoup(html, "html.parser").find()


@pytest.fixture
def wired(monkeypatch):
    """Podmienia zbieranie pól i zapisy - zostaje sama logika zakresu."""
    calls = {"players": [], "companions": [], "comment": []}

    monkeypatch.setattr(
        r,
        "_collect_players_inputs",
        lambda soup, *, host_name, guest_name: {
            ("host", "7", "goals"): {
                "inp": _tag('<input type="text" name="bramki7" value="0">'),
                "args4": ("a", "b", "c", "d"),
            }
        },
    )
    monkeypatch.setattr(
        r,
        "_collect_companion_inputs",
        lambda soup, *, host_name, guest_name: {
            ("host", "A", "warn"): {
                "inp": _tag('<input type="checkbox" name="ku1" value="1">'),
                "args8": ("a", "b", "c", "d", "e", "f", "g", "h"),
            }
        },
    )
    monkeypatch.setattr(
        r,
        "_collect_comment_input",
        lambda soup: {
            "inp": _tag("<textarea name='uwagi'></textarea>"),
            "args4": ("a", "b", "c", "d"),
        },
    )

    async def save2(client, args4, *, value_str, checked):
        calls["players"].append(value_str)
        return True, "ok"

    async def save3(client, args4, *, value_str, checked):
        calls["comment"].append(value_str)
        return True, "ok"

    async def save4(client, args8, *, value_str, checked):
        calls["companions"].append(checked)
        return True, "ok"

    monkeypatch.setattr(r, "_save_via_zapisz2", save2)
    monkeypatch.setattr(r, "_save_via_zapisz3", save3)
    monkeypatch.setattr(r, "_save_via_zapisz4", save4)
    return calls


STATS = {
    "host": {
        "7": {
            "goals": 5,
            "entered": True,
            "warn": False,
            "p2": 0,
            "disq": False,
            "pk_total": 0,
            "pk_goals": 0,
            "so_total": 0,
            "so_goals": 0,
        },
        "A": {"warn": True, "p2": 0, "disq": False},
    },
    "guest": {},
}


async def _apply(sections):
    return await r._apply_protocol_updates_4blocks(
        None,
        BeautifulSoup("<html></html>", "html.parser"),
        STATS,
        host_name="KS Test 1",
        guest_name="KS Test 2",
        referee_comment="Uwaga sędziów.",
        sections=sections,
    )


async def test_brak_zakresu_wypelnia_wszystko(wired):
    await _apply(None)

    assert wired["players"], "zawodnicy mieli pójść"
    assert wired["companions"], "osoby towarzyszące miały pójść"
    assert wired["comment"], "uwagi miały pójść"


async def test_sam_zakres_uzupelniajacy_pomija_zawodnikow(wired):
    await _apply({"companions", "comment"})

    assert wired["players"] == [], "zawodnicy już poszli przez API - nie ruszamy ich"
    assert wired["companions"]
    assert wired["comment"] == ["Uwaga sędziów."]


async def test_sami_zawodnicy(wired):
    await _apply({"players"})

    assert wired["players"]
    assert wired["companions"] == []
    assert wired["comment"] == []


async def test_wylaczone_uwagi_nie_trafiaja_na_liste_brakow(wired):
    """Pominięty blok to nie jest brak - nie ma o czym meldować."""
    out = await _apply({"companions"})

    assert wired["comment"] == []
    assert all(m.get("section") != "comment" for m in out.get("missing") or [])
