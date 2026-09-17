"""Tablica Komisji Okręgowej (`app/board_rules.py`) - dostęp, skład, przeciąganie, kosz."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import board_rules as B


# ---------------------------------------------------------------------------
# Dostęp (decyzja z 16.09.2026: tylko komisja własnego okręgu)
# ---------------------------------------------------------------------------


def test_sedzia_bez_odznaki_nie_widzi_tablicy():
    access = B.resolve_access(is_org=False, is_judge=True, has_badge=False)
    assert not access["can_read"] and not access["can_write"]
    assert access["reason"] == B.NO_ACCESS_JUDGE


def test_sedzia_z_odznaka_albo_dopisany_recznie_widzi_i_pisze():
    for access in (
        B.resolve_access(is_org=False, is_judge=True, has_badge=True),
        B.resolve_access(is_org=False, is_judge=True, manual_member=True),
    ):
        assert access["can_read"] and access["can_write"] and access["role"] == "member"


def test_konto_okregu_z_innego_wojewodztwa_nie_wchodzi():
    access = B.resolve_access(is_org=True, is_judge=False, vip_same_province=False, vip_permissions_raw={"assignments": True})
    assert not access["can_read"] and access["reason"] == B.NO_ACCESS_VIP_PROVINCE


def test_konto_okregu_potrzebuje_uprawnienia_tablicy():
    denied = B.resolve_access(is_org=True, is_judge=False, vip_same_province=True, vip_permissions_raw={"district_unavailability": True})
    assert not denied["can_read"] and denied["reason"] == B.NO_ACCESS_VIP_PERMISSION
    # Jawne `district_board: false` wygrywa z `assignments`.
    assert not B.vip_sees_board({"assignments": True, "district_board": False})
    assert B.vip_sees_board('{"assignments": true}')
    assert B.vip_sees_board({"admin": True})
    allowed = B.resolve_access(is_org=True, is_judge=False, vip_same_province=True, vip_permissions_raw={"district_board": True})
    assert allowed["can_write"] and allowed["role"] == "vip"


def test_admin_widzi_kazda_tablice():
    access = B.resolve_access(is_org=False, is_judge=True, is_admin=True)
    assert access["can_read"] and access["role"] == "admin"


def test_konto_nierozpoznane():
    access = B.resolve_access(is_org=False, is_judge=False)
    assert not access["can_read"] and access["reason"] == B.NO_ACCESS_ACCOUNT


def test_odznaka_komisji_w_kazdym_ksztalcie():
    assert B.has_committee_badge({"Komisja Sędziowska": True})
    assert B.has_committee_badge('["komisja"]')
    assert not B.has_committee_badge({"Komisja Sędziowska": False, "Obsadowy": True})


def test_tozsamosc_tylko_z_tokenu():
    judge = B.actor_from_payload({"sub": "x", "judge_id": "123", "account_type": "judge"}, judge_name="Anna Nowak")
    assert judge == B.Actor(key="judge:123", name="Anna Nowak", judge_id="123", is_org=False)
    org = B.actor_from_payload({"sub": "slask", "account_type": "org", "display_name": "Jan KOWALSKI | Śląski ZPR"})
    assert org.key == "org:slask" and org.name == "Jan KOWALSKI" and org.is_org
    assert B.actor_from_payload({"sub": "ktos", "account_type": "unknown"}) is None


# ---------------------------------------------------------------------------
# Skład komisji z odznak
# ---------------------------------------------------------------------------


def test_sklad_z_odznak_dopisuje_brakujacych_i_oznacza_bylych():
    badge = [{"judge_id": "1", "full_name": "Anna"}, {"judge_id": "2", "full_name": "Bartek"}, {"judge_id": "2", "full_name": "Bartek"}]
    rows = [
        {"id": 10, "judge_id": "1", "source": "badge", "active": False},  # odznaka wróciła
        {"id": 11, "judge_id": "3", "source": "badge", "active": True},  # odznakę zdjęto
        {"id": 12, "judge_id": "4", "source": "manual", "active": True},  # dopisany ręcznie
        {"id": 13, "judge_id": None, "source": "manual", "active": True},  # spoza sędziów
    ]
    plan = B.plan_member_sync(badge, rows)
    assert plan.inserts == [{"judge_id": "2", "name": "Bartek"}]
    assert plan.activate == [10]
    assert plan.deactivate == [11]


def test_sedzia_dopisany_recznie_nie_dostaje_drugiego_wiersza_z_odznaki():
    plan = B.plan_member_sync([{"judge_id": "4", "full_name": "Celina"}], [{"id": 12, "judge_id": "4", "source": "manual", "active": True}])
    assert plan.inserts == [] and plan.activate == [] and plan.deactivate == []


def test_podwojny_wiersz_sedziego_znika_przy_odczycie():
    rows = [{"id": 7, "judge_id": "1"}, {"id": 3, "judge_id": "1"}, {"id": 9, "judge_id": None}, {"id": 8, "judge_id": None}]
    assert [row["id"] for row in B.dedupe_members(rows)] == [3, 8, 9]


# ---------------------------------------------------------------------------
# Przeciąganie zadań
# ---------------------------------------------------------------------------


def _tasks():
    return [
        {"id": 1, "status": "todo", "order_index": 0},
        {"id": 2, "status": "todo", "order_index": 0},  # stary remis
        {"id": 3, "status": "todo", "order_index": 2},
        {"id": 4, "status": "in_progress", "order_index": 0},
        {"id": 5, "status": "in_progress", "order_index": 1},
    ]


def _apply(tasks, changes):
    by_id = {task["id"]: dict(task) for task in tasks}
    for task_id, status, index in changes:
        by_id[task_id].update(status=status, order_index=index)
    columns = {}
    for task in sorted(by_id.values(), key=lambda t: (t["order_index"], t["id"])):
        columns.setdefault(task["status"], []).append(task["id"])
    return columns


def test_przeniesienie_do_innej_kolumny_w_srodek():
    tasks = _tasks()
    columns = _apply(tasks, B.plan_task_move(tasks, 2, "in_progress", 1))
    assert columns["in_progress"] == [4, 2, 5]
    assert columns["todo"] == [1, 3]


def test_kolejnosc_w_tej_samej_kolumnie_i_indeks_poza_zakresem():
    tasks = _tasks()
    assert _apply(tasks, B.plan_task_move(tasks, 1, "todo", 99))["todo"] == [2, 3, 1]
    assert _apply(tasks, B.plan_task_move(tasks, 3, "todo", -5))["todo"] == [3, 1, 2]


def test_przeniesienie_zapisuje_tylko_zmiany():
    tasks = [{"id": 1, "status": "done", "order_index": 0}, {"id": 2, "status": "done", "order_index": 1}]
    assert B.plan_task_move(tasks, 2, "done", 1) == [(2, "done", 1)]


def test_przeniesienie_blednego_statusu_i_nieznanego_zadania():
    with pytest.raises(ValueError):
        B.plan_task_move(_tasks(), 1, "archiwum", 0)
    with pytest.raises(KeyError):
        B.plan_task_move(_tasks(), 99, "todo", 0)


# ---------------------------------------------------------------------------
# Kosz i walidacja
# ---------------------------------------------------------------------------


def test_kosz_trzyma_30_dni():
    now = datetime(2026, 9, 16, 12, tzinfo=timezone.utc)
    assert B.restorable(now - timedelta(days=29, hours=23), now)
    assert not B.restorable(now - timedelta(days=30, minutes=1), now)
    assert not B.restorable(None, now)
    assert B.days_left(now - timedelta(days=1), now) == 29


def test_walidacja_mowi_po_polsku():
    assert B.clean_date("2026-09-16") == "2026-09-16"
    with pytest.raises(B.Invalid, match="nie istnieje"):
        B.clean_date("2026-02-30")
    with pytest.raises(B.Invalid, match="później"):
        B.clean_time_range("18:00", "17:30")
    assert B.clean_color("#e7b68f") == "#E7B68F"
    assert B.clean_url("zprp.pl/regulamin") == "https://zprp.pl/regulamin"
    with pytest.raises(B.Invalid):
        B.clean_title("  ", required=True)
    assert B.clean_checklist([{"text": " A "}, {"text": ""}, "x"]) == [{"id": "c1", "text": "A", "done": False}]


def test_zalacznik_typ_z_naglowka_albo_rozszerzenia_i_sygnatura():
    assert B.attachment_mime("protokol.PDF", "") == "application/pdf"
    assert B.attachment_mime("x.exe", "application/octet-stream") is None
    assert B.sniff_matches("application/pdf", b"%PDF-1.7")
    assert not B.sniff_matches("image/png", b"%PDF-1.7")
    assert B.sniff_matches("image/webp", b"RIFF\x00\x00\x00\x00WEBPVP8 ")


def test_nazwa_zalacznika_bezpieczna():
    assert B.safe_filename("../../etc/pass\"wd", "application/pdf") == "passwd.pdf"
    assert B.safe_filename("", "image/png") == "zalacznik.png"
    assert B.safe_filename("zdjęcie.jpeg", "image/jpeg") == "zdjęcie.jpeg"
    assert B.ascii_filename("Łódź protokół.pdf") == "Lodz protokol.pdf"


def test_filtr_historii_rodzaj_albo_czynnosc_i_autor():
    komentarz_do_zadania = {"action": "commented", "target_type": "task", "actor_key": "judge:7"}
    do_kosza = {"action": "deleted", "target_type": "member", "actor_key": "org:slaskie"}
    z_odznaki = {"action": "joined", "target_type": "member", "actor_key": None}

    zadania = B.activity_filter("tasks")
    assert B.activity_matches(komentarz_do_zadania, zadania)
    assert not B.activity_matches(do_kosza, zadania)
    assert B.activity_matches(komentarz_do_zadania, B.activity_filter("talk"))
    assert B.activity_matches(do_kosza, B.activity_filter("trash"))
    assert B.activity_matches(do_kosza, B.activity_filter("members"))

    assert B.activity_matches(z_odznaki, B.activity_filter(None, "system"))
    assert not B.activity_matches(do_kosza, B.activity_filter("", "system"))
    assert B.activity_matches(komentarz_do_zadania, B.activity_filter("", "judge:7"))
    assert not B.activity_matches(z_odznaki, B.activity_filter("", "judge:7"))
    assert all(B.activity_matches(item, B.activity_filter()) for item in (komentarz_do_zadania, do_kosza, z_odznaki))

    with pytest.raises(B.Invalid):
        B.activity_filter("rankingi")
