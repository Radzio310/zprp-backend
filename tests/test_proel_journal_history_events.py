"""Zdarzenia dziennika, które POWSTAŁY RAZEM Z HISTORIĄ WERSJI.

Dziennik meczu odpowiada na pytanie „co się tu działo". Historia wersji dodała
do niego sześć chwil, których wcześniej nikt nie widział, a które tłumaczą
dziury i niespodzianki w osi czasu:

* powrót do meczu z zapisu lokalnego - stąd wersja godzinę po ciszy,
* przyjęcie wersji z serwera - stąd urwane zapisy z jednego telefonu,
* ćwiczenie na tym samym meczu - stąd drugi zapis obok prawdziwego,
* odmowa zatwierdzenia - mecz, którego nikt nie próbował zatwierdzić, wyglądał
  jak mecz, w którym próbowały trzy osoby,
* dosyłka historii z telefonu - mecz prowadzony bez zasięgu,
* limit migawek na dobę - JEDYNE wytłumaczenie dziury w historii.

KAŻDE z nich musi mieć etykietę I zdanie. Zdarzenie bez zdania pokazuje się
w panelu jako sam nagłówek bez podtytułu - czyli dokładnie ten szyfr, z którym
ten dziennik miał skończyć.
"""
from __future__ import annotations

import pytest

from app.proel_journal import EVENT_LABELS, _CLIENT_REPORTABLE, event_summary

NEW_EVENTS = [
    "match.resumed_local",
    "match.version_adopted",
    "match.training_run",
    "match.approve_refused",
    "match.snapshots_backfilled",
    "match.snapshot_limit",
]


@pytest.mark.parametrize("event", NEW_EVENTS)
def test_kazde_nowe_zdarzenie_ma_etykiete(event):
    assert EVENT_LABELS.get(event), event


@pytest.mark.parametrize("event", NEW_EVENTS)
def test_kazde_nowe_zdarzenie_ma_zdanie_takze_bez_szczegolow(event):
    """Stary wiersz nie ma `details` - podtytuł i tak ma coś powiedzieć."""
    assert event_summary(event, None).strip(), event
    assert event_summary(event, {}).strip(), event


def test_powrot_do_meczu_mowi_przy_jakim_stanie():
    text = event_summary(
        "match.resumed_local",
        {"scoreHost": 3, "scoreGuest": 2, "protocolLen": 14},
    )
    assert "3:2" in text
    assert "14 wpisów" in text


def test_doslylka_mowi_ile_wersji_i_ze_bylo_bez_zasiegu():
    one = event_summary("match.snapshots_backfilled", {"accepted": 1})
    many = event_summary("match.snapshots_backfilled", {"accepted": 22, "skipped": 5})
    # Odmiana liczebnika: „1 wersję", ale „22 wersje".
    assert "1 wersję" in one
    assert "22 wersje" in many
    assert "5 pominięto" in many
    assert "bez zasięgu" in one


def test_limit_mowi_ze_zapisy_ida_dalej():
    """Najważniejsze zdanie z całej szóstki: mecz NIE jest zablokowany."""
    text = event_summary("match.snapshot_limit", {"limit": 600})
    assert "600" in text
    assert "normalnie" in text


def test_odmowa_zatwierdzenia_mowi_kto_moze():
    text = event_summary("match.approve_refused", {"who": "Jan Kowalski"})
    assert "Jan Kowalski" in text
    # Ta sama obsada, co w komunikacie 403 i w welonie akcji pomeczowych.
    assert "delegat" in text and "boiskowi" in text


def test_cwiczenie_mowi_ktore_podejscie():
    assert "K3N8P2WQ" in event_summary("match.training_run", {"run": "K3N8P2WQ"})


def test_tylko_powrot_z_autozapisu_doszedl_do_zglaszalnych_przez_aplikacje():
    """Reszta MUSI powstawać przy operacji, którą opisuje.

    Gdyby telefon mógł zgłosić „zatwierdzono protokół", wpis w dzienniku
    przestałby być dowodem czegokolwiek.
    """
    assert _CLIENT_REPORTABLE == {
        "zprp.send_failed",
        "zprp.send_queued",
        "match.resumed_local",
    }
