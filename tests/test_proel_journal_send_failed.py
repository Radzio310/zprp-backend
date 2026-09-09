"""Nieudana wysyłka do ZPRP w dzienniku meczu.

Dziennik odpowiadał tylko na pytanie „kiedy dane doszły". Mecz, którego wysyłka
się nie udała, wyglądał w nim identycznie jak mecz, którego nikt nie próbował
wysłać - a to są dwie zupełnie różne sytuacje i inaczej się je naprawia.

Te zdarzenia są jedynymi, które wolno zgłosić APLIKACJI: dzieją się wyłącznie
między telefonem a serwerem związku, więc serwer BAZY nie ma jak się o nich
dowiedzieć sam.
"""
from __future__ import annotations

import pytest

from app.proel_journal import (
    _CLIENT_REPORTABLE,
    EVENT_LABELS,
    event_summary,
    send_attempt_sentence,
)


def test_nowe_zdarzenia_maja_etykiety():
    assert EVENT_LABELS["zprp.send_failed"] == "Nieudana próba wysyłki do ZPRP"
    assert EVENT_LABELS["zprp.send_queued"] == "Wysyłka odłożona do dosyłki"


def test_aplikacja_moze_zglosic_wylacznie_nieudane_wysylki():
    # Wpis „zatwierdzono protokół" musi znaczyć, że protokół NAPRAWDĘ został
    # zatwierdzony - a nie że ktoś tak powiedział.
    assert _CLIENT_REPORTABLE == {"zprp.send_failed", "zprp.send_queued"}
    for forbidden in (
        "match.approved",
        "match.deleted",
        "zprp.full_data_sent",
        "protocol.pdf_generated",
    ):
        assert forbidden not in _CLIENT_REPORTABLE


def test_zdanie_niesie_numer_proby_i_bilans():
    out = send_attempt_sentence(
        "zprp.send_failed",
        {"what": "full", "attempt": 2, "of": 3, "sent": 12, "left": 4},
    )
    assert "Nie udało się wysłać pełnych danych meczu" in out
    assert "próba 2 z 3" in out
    assert "zapisano 12" in out
    assert "bez zapisu 4" in out


def test_doslowna_odpowiedz_zwiazku_jest_w_zdaniu():
    # Bez cytatu z ZPRP każda odmowa wygląda tak samo - i tak właśnie wyglądała.
    out = send_attempt_sentence(
        "zprp.send_failed",
        {
            "what": "players",
            "attempt": 1,
            "upstream": "Nie znaleziono takiego zawodnika w kadrze tego meczu.",
        },
    )
    assert "Nie znaleziono takiego zawodnika w kadrze tego meczu." in out
    assert "statystyk zawodników" in out


def test_gdy_zwiazek_nic_nie_powiedzial_zostaje_nasz_powod():
    out = send_attempt_sentence(
        "zprp.send_failed",
        {"what": "summary", "reason": "Brak połączenia z siecią."},
    )
    assert "wyniku skróconego" in out
    assert "Brak połączenia z siecią." in out


def test_odlozenie_do_dosylki_ma_wlasne_zdanie():
    out = send_attempt_sentence("zprp.send_queued", {"what": "full", "left": 3})
    assert out.startswith("Wysyłka pełnych danych meczu odłożona do dosyłki")


def test_event_summary_kieruje_nowe_zdarzenia_do_tego_zdania():
    details = {"what": "officials", "attempt": 3, "of": 3}
    assert event_summary("zprp.send_failed", details) == send_attempt_sentence(
        "zprp.send_failed", details
    )


def test_nieznany_blok_nie_wywraca_zdania():
    out = send_attempt_sentence("zprp.send_failed", {"what": "cokolwiek"})
    assert "danych meczu" in out


@pytest.mark.parametrize("details", [None, {}])
def test_puste_szczegoly_nie_wywracaja_zdania(details):
    assert send_attempt_sentence("zprp.send_failed", details)
