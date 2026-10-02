"""Znacznik powiadomienia i grupowanie żywego wątku.

Jedna rewizja meczu jest już jednym zdarzeniem, a wszystkie kolejne rewizje
tego samego meczu dzielą stabilny ``notificationThread``. Android zastępuje
więc stary kafel nowszym, podczas gdy niezależne zdarzenia bez wątku nadal
mają różne znaczniki. Ponowienie tej samej dostawy również nie tworzy kopii.
"""
from __future__ import annotations

from app.push.fcm import fcm_message_payload, notification_tag


def event(key: str) -> dict:
    return {
        "kind": "province_match_change",
        "event_type": "match_data_changed",
        "match_id": "208136",
        "matchNumber": "OSM/12",
        "event_key": key,
    }


def test_different_events_never_share_a_tag():
    # Niezależne zdarzenia bez jawnego wątku pozostają rozdzielone.
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


def test_live_thread_replaces_older_state_even_when_text_changes():
    first = notification_tag(
        {"kind": "match_market", "notificationThread": "offer-7"},
        "Mecz do wzięcia",
        "Czeka na chętnych",
    )
    updated = notification_tag(
        {"kind": "match_market", "notificationThread": "offer-7"},
        "3 zgłoszenia",
        "Anna, Jan i Piotr",
    )
    other = notification_tag(
        {"kind": "match_market", "notificationThread": "offer-8"},
        "3 zgłoszenia",
        "Anna, Jan i Piotr",
    )
    assert first == updated
    assert first != other


def test_match_thread_replaces_an_older_revision_of_the_same_match():
    first = event("aaa111") | {"notificationThread": "province-match:slaskie:208136"}
    updated = event("bbb222") | {"notificationThread": "province-match:slaskie:208136"}
    other = event("ccc333") | {"notificationThread": "province-match:slaskie:208137"}

    assert notification_tag(first, "Termin", "12:00") == notification_tag(
        updated, "Hala", "Nowy adres"
    )
    assert notification_tag(first, "Termin", "12:00") != notification_tag(
        other, "Termin", "12:00"
    )


def test_silent_update_uses_the_quiet_channel_without_sound():
    payload = fcm_message_payload(
        "secret-token",
        "2 zgłoszenia",
        "Anna i Jan",
        {
            "notificationThread": "offer-7",
            "notificationSilent": "true",
        },
    )["message"]
    android = payload["android"]["notification"]
    aps = payload["apns"]["payload"]["aps"]
    assert android["channel_id"] == "market_updates_silent"
    assert "sound" not in android
    assert "sound" not in aps
    assert payload["apns"]["headers"]["apns-collapse-id"] == android["tag"]


def test_fresh_claim_still_alerts_normally():
    payload = fcm_message_payload(
        "secret-token",
        "Nowe zgłoszenie",
        "Anna",
        {"notificationThread": "offer-7"},
    )["message"]
    assert payload["android"]["notification"]["channel_id"] == "default"
    assert payload["android"]["notification"]["sound"] == "default"
    assert payload["apns"]["payload"]["aps"]["sound"] == "default"
