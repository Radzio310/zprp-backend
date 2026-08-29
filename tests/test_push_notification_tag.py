"""Znacznik powiadomienia - dlaczego trzy zmiany dają trzy powiadomienia.

Zmiana daty meczu, dopisanie adresu hali i edycja wyniku skróconego idą JEDNYM
przebiegiem monitora, w odstępie sekund. Bez własnego `tag` Android potrafi
podmienić jedno powiadomienie drugim - sędzia widzi wtedy ostatnie i nie ma
pojęcia, że termin się przesunął.

Te testy pilnują dwóch rzeczy naraz, bo obie da się zepsuć jedną pomyłką:
różne zdarzenia MUSZĄ mieć różne znaczniki, a to samo zdarzenie wysłane
powtórnie MUSI mieć ten sam - inaczej ponowienie mnożyłoby kopie.
"""
from __future__ import annotations

from app.push.fcm import notification_tag


def event(key: str) -> dict:
    return {
        "kind": "province_match_change",
        "event_type": "match_data_changed",
        "match_id": "208136",
        "matchNumber": "OSM/12",
        "event_key": key,
    }


def test_different_events_never_share_a_tag():
    # Trzy zmiany w tym samym meczu, jeden przebieg monitora.
    date_change = notification_tag(event("aaa111"), "Zmiana terminu", "Zmieniono datę")
    hall_change = notification_tag(event("bbb222"), "Zmiana danych", "Zmieniono adres hali")
    score_edit = notification_tag(event("ccc333"), "Zmiana danych", "Edytowano wynik")

    assert len({date_change, hall_change, score_edit}) == 3


def test_the_same_event_keeps_its_tag():
    # Ponowienie po nieudanej wysyłce ma ZASTĄPIĆ, a nie dołożyć.
    first = notification_tag(event("aaa111"), "Zmiana terminu", "Zmieniono datę")
    retry = notification_tag(event("aaa111"), "Zmiana terminu", "Zmieniono datę")

    assert first == retry


def test_tag_survives_a_payload_without_event_key():
    # Giełda meczów nie niesie `event_key` - znacznik powstaje z treści.
    a = notification_tag({"kind": "match_market", "offerId": "7"}, "Mecz do wzięcia", "x")
    b = notification_tag({"kind": "match_market", "offerId": "8"}, "Mecz do wzięcia", "x")

    assert a != b
    assert a and b


def test_two_offers_with_identical_text_still_differ():
    # Treść bywa identyczna dla dwóch różnych ofert - rozstrzyga numer.
    a = notification_tag({"kind": "match_market", "offerId": "7"}, "T", "B")
    b = notification_tag({"kind": "match_market", "offerId": "9"}, "T", "B")
    assert a != b


def test_tag_is_short_enough_for_android():
    # Android ucina długie znaczniki w powiadomieniach - trzymamy je krótkie.
    long_key = "f" * 200
    assert len(notification_tag(event(long_key), "T", "B")) <= 40


def test_empty_payload_does_not_crash():
    assert notification_tag(None, "T", "B")
    assert notification_tag({}, "T", "B")
