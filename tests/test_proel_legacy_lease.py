"""Leasing-widmo: kto prowadzi mecz, gdy prowadzi go stara aplikacja.

Twarda blokada prowadzenia opiera się na leasingu, a leasingu żąda tylko
zaktualizowana aplikacja. Bez tego mechanizmu mecz prowadzony ze starego
telefonu wyglądałby dla nowej aplikacji na nieprowadzony przez nikogo — czyli
dokładnie w tej sytuacji, w której dwa stoliki zaczynają pisać jeden protokół,
nowa aplikacja weszłaby bez ostrzeżenia.

Czysta logika, bez bazy — wzorem `test_proel_fields.py`.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.proel_lease import LEGACY_LEASE_TTL_SECONDS, legacy_lease_values


def now():
    return datetime.now(timezone.utc)


def state(**kw):
    base = {
        "lease_install": None,
        "lease_judge_id": None,
        "lease_name": None,
        "lease_kind": None,
        "lease_epoch": 0,
        "lease_until": None,
    }
    base.update(kw)
    return base


def test_bez_leasingu_stary_klient_obejmuje_widmo():
    out = legacy_lease_values(state(), "ins_stary")
    assert out is not None
    assert out["lease_kind"] == "legacy"
    assert out["lease_install"] == "ins_stary"
    assert out["lease_epoch"] == 1


def test_widmo_zyje_dluzej_niz_zwykly_leasing():
    # Stara aplikacja pisze co 60 s i nie ma czym bić serca — 90 s TTL
    # oddawałoby mecz po dwóch przegapionych zapisach.
    out = legacy_lease_values(state(), "ins_stary")
    ttl = (out["lease_until"] - now()).total_seconds()
    assert LEGACY_LEASE_TTL_SECONDS - 5 < ttl <= LEGACY_LEASE_TTL_SECONDS


def test_nie_podbieramy_zywego_leasingu_aplikacji():
    """To jest sedno: świadome prowadzenie wygrywa ze starym zapisem."""
    held = state(
        lease_install="ins_nowy",
        lease_kind="app",
        lease_epoch=7,
        lease_until=now() + timedelta(seconds=60),
    )
    assert legacy_lease_values(held, "ins_stary") is None


def test_wygasly_leasing_aplikacji_mozna_przejac():
    stale = state(
        lease_install="ins_nowy",
        lease_kind="app",
        lease_epoch=7,
        lease_until=now() - timedelta(seconds=1),
    )
    out = legacy_lease_values(stale, "ins_stary")
    assert out is not None
    assert out["lease_install"] == "ins_stary"
    assert out["lease_epoch"] == 8  # bicie serca starego posiadacza dostanie 412


def test_wlasne_widmo_tylko_przedluzamy_bez_ruszania_epoki():
    mine = state(
        lease_install="ins_stary",
        lease_kind="legacy",
        lease_epoch=3,
        lease_until=now() + timedelta(seconds=30),
    )
    out = legacy_lease_values(mine, "ins_stary")
    assert out is not None
    assert "lease_epoch" not in out
    assert out["lease_until"] > mine["lease_until"]


def test_drugi_stary_klient_nie_przejmuje_zywego_widma():
    """Dwa stare telefony na jednym meczu to i tak dwa protokoły — ale
    przynajmniej nowa aplikacja zobaczy spójnego posiadacza, a nie migotanie."""
    held = state(
        lease_install="ins_stary_a",
        lease_kind="legacy",
        lease_epoch=2,
        lease_until=now() + timedelta(seconds=30),
    )
    assert legacy_lease_values(held, "ins_stary_b") is None


def test_stary_klient_bez_installation_id_tez_obejmuje_widmo():
    """Naprawdę stare wersje nie wysyłają żadnej tożsamości.

    Pusty identyfikator jest tu w porządku: `is_you` po stronie `/state`
    wymaga NIEPUSTEGO identyfikatora aktora, więc nowa aplikacja nigdy nie
    uzna takiego widma za własne i pokaże twardą blokadę.
    """
    out = legacy_lease_values(state(), "")
    assert out is not None
    assert out["lease_install"] == ""
    assert out["lease_kind"] == "legacy"
