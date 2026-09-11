"""Zapis szkoleniowy jako oficjalny: kiedy wolno, co zmienia się w blobie.

Ta reguła TWORZY oficjalny protokół. Błąd w stronę "za łatwo" zakłada drugi
protokół meczu, który już ma swój, albo wpycha ćwiczenie z kursu do wyników.
Błąd w stronę "za trudno" zostawia prawdziwy mecz pod kluczem, którego nie
widzi lista stolików.
"""
from __future__ import annotations

import copy

import pytest

from app.proel_bulk_delete_rules import lock_message
from app.proel_promote_rules import (
    MAX_BULK,
    PromotionFacts,
    exercise_kind,
    normalize_keys,
    official_blob,
    official_blob_is_clean,
    official_key_for,
    promote_lock_message,
    promoted_detail,
    promotion_verdict,
)
from app.proel_training_key import blob_is_training, key_conflicts_with_blob

KEY = "T-JYFBZ7S2/SK/8"

BLOB = {
    "scoreHost": 30,
    "scoreGuest": 28,
    "protocol": [{"type": "goal", "player": 7}],
    "matchConfig": {
        "matchNumber": "SK/8",
        "matchId": "206650",
        "hostTeamName": "Gospodarze",
        "guestTeamName": "Goście",
        "origin": "training",
        "proelKey": KEY,
        "referee1": "NOWAK Adam",
    },
}


def _facts(**over) -> PromotionFacts:
    base = dict(key=KEY, training_exists=True, config=copy.deepcopy(BLOB["matchConfig"]))
    base.update(over)
    return PromotionFacts(**base)


# ───────────────────────── klucze ─────────────────────────


def test_klucz_oficjalny_to_numer_wielkimi_literami():
    assert official_key_for(KEY) == "SK/8"
    assert official_key_for("t-jyfbz7s2/sk/8") == "SK/8"
    assert official_key_for(" T-ABCDEF12/ osk/12 ") == "OSK/12"


def test_klucze_normalizuje_ta_sama_regula_co_usuwanie():
    assert normalize_keys([KEY, "", KEY, None]) == [KEY]
    assert 50 <= MAX_BULK <= 500


# ───────────────────────── blob ─────────────────────────


def test_kopia_zmienia_tylko_pochodzenie_i_klucz():
    out = official_blob(BLOB, KEY, "2026-09-11T10:00:00+00:00", "Admin Jan")
    cfg = out["matchConfig"]
    assert cfg["origin"] == "account"
    assert "proelKey" not in cfg
    assert cfg["promotedFromTraining"] == {
        "key": KEY,
        "at": "2026-09-11T10:00:00+00:00",
        "by": "Admin Jan",
    }
    changed = {k for k in set(cfg) | set(BLOB["matchConfig"]) if cfg.get(k) != BLOB["matchConfig"].get(k)}
    assert changed == {"origin", "proelKey", "promotedFromTraining"}
    assert {k: v for k, v in out.items() if k != "matchConfig"} == {
        k: v for k, v in BLOB.items() if k != "matchConfig"
    }


def test_kopia_nie_rusza_bloba_szkoleniowego():
    before = copy.deepcopy(BLOB)
    out = official_blob(BLOB, KEY, "t", "a")
    out["protocol"].append({"type": "x"})
    assert BLOB == before


def test_kopia_przechodzi_przez_straznika_jak_zwykly_mecz():
    out = official_blob(BLOB, KEY, "t", "a")
    assert key_conflicts_with_blob("SK/8", out) is False
    assert blob_is_training(out) is False
    assert official_blob_is_clean("SK/8", out) is True
    # a szkoleniowy pod czystym numerem jest dokładnie tą kolizją
    assert official_blob_is_clean("SK/8", BLOB) is False


def test_kopia_bez_konfiguracji_dostaje_ja():
    out = official_blob({"scoreHost": 1}, KEY, "t", "a")
    assert out["matchConfig"]["origin"] == "account"


def test_blob_nie_obiekt_to_blad():
    with pytest.raises(ValueError):
        official_blob("napis", KEY, "t", "a")


def test_rodzaj_cwiczenia():
    assert exercise_kind({"isTest": True}) == "test"
    assert exercise_kind({"matchConfig": {"training": {"eventId": "ev"}}}) == "course"
    assert exercise_kind({"training": {"eventId": " "}}) == ""
    assert exercise_kind(None) == ""


# ───────────────────────── werdykt ─────────────────────────


def test_czysty_zapis_wolno_przeniesc():
    assert promotion_verdict(_facts()) is None


def test_klucz_nieszkoleniowy():
    out = promotion_verdict(_facts(key="SK/8"))
    assert out["reason"] == "not_training"
    assert "T-" in out["message"]


def test_brakujacy_zapis_to_nie_odmowa():
    assert promotion_verdict(_facts(training_exists=False))["reason"] == "missing"


def test_juz_przeniesiony_mowi_dokad():
    out = promotion_verdict(_facts(promoted_to="SK/8"))
    assert out["reason"] == "already_promoted"
    assert "SK/8" in out["message"]


@pytest.mark.parametrize(
    "extra,word",
    [({"isTest": True}, "testowy"), ({"training": {"eventId": "ev-1"}}, "kursokonferencji")],
)
def test_cwiczenia_i_testy_nigdy_nie_sa_oficjalne(extra, word):
    cfg = {**BLOB["matchConfig"], **extra}
    out = promotion_verdict(_facts(config=cfg))
    assert out["reason"] == "exercise"
    assert word in out["message"]


def test_prowadzony_zapis_szkoleniowy():
    out = promotion_verdict(_facts(training_lease_active=True, training_lease_holder="KOWALSKI"))
    assert out["reason"] == "in_use"
    assert "KOWALSKI" in out["message"]


def test_protokol_innego_numeru():
    cfg = {**BLOB["matchConfig"], "matchNumber": "SK/9"}
    out = promotion_verdict(_facts(config=cfg))
    assert out["reason"] == "number_mismatch"


def test_numer_rozni_sie_tylko_wielkoscia_liter():
    cfg = {**BLOB["matchConfig"], "matchNumber": " sk/8 "}
    assert promotion_verdict(_facts(config=cfg)) is None


def test_oficjalny_zapis_juz_jest_i_mowi_jaki():
    out = promotion_verdict(_facts(official_status="approved"))
    assert out["reason"] == "official_exists"
    assert "zatwierdzony" in out["message"]
    assert "SK/8" in out["message"]


def test_ten_sam_mecz_pod_innym_kluczem():
    out = promotion_verdict(_facts(zprp_twin_key="SK/08"))
    assert out["reason"] == "official_exists"
    assert "SK/08" in out["message"]
    assert "206650" in out["message"]


def test_oficjalny_prowadzony():
    out = promotion_verdict(_facts(official_lease_active=True, official_lease_holder="NOWAK"))
    assert out["reason"] == "official_in_use"
    assert "NOWAK" in out["message"]


def test_oficjalny_wiersz_stanu_innego_meczu():
    out = promotion_verdict(_facts(official_zprp_id="999999"))
    assert out["reason"] == "id_conflict"


def test_oficjalny_wiersz_stanu_tego_samego_meczu_przechodzi():
    assert promotion_verdict(_facts(official_zprp_id="206650")) is None
    # wiersz bez tożsamości - przyjmie tożsamość kopii
    assert promotion_verdict(_facts(official_zprp_id=None, official_local_key=None)) is None


def test_oficjalny_z_danymi_wspolpracy_trzeba_scalic_recznie():
    out = promotion_verdict(_facts(official_overlay_nonempty=True))
    assert out["reason"] == "overlay_nonempty"
    assert "ręcznie" in out["message"]


def test_kolejnosc_pytan():
    # przeniesiony ćwiczeniem: najpierw "już przeniesiony"
    cfg = {**BLOB["matchConfig"], "isTest": True}
    assert promotion_verdict(_facts(promoted_to="SK/8", config=cfg))["reason"] == "already_promoted"
    # ćwiczenie pod zajętym numerem: najpierw "ćwiczenie"
    assert promotion_verdict(_facts(config=cfg, official_status="finished"))["reason"] == "exercise"
    # zajęty numer i prowadzony oficjalny: najpierw "zajęty"
    assert (
        promotion_verdict(_facts(official_status="finished", official_lease_active=True))["reason"]
        == "official_exists"
    )


def test_kazda_odmowa_tlumaczy_sie_sama():
    cases = [
        _facts(key="SK/8"),
        _facts(promoted_to="SK/8"),
        _facts(config={**BLOB["matchConfig"], "isTest": True}),
        _facts(training_lease_active=True),
        _facts(config={**BLOB["matchConfig"], "matchNumber": "SK/9"}),
        _facts(official_status="in_progress"),
        _facts(zprp_twin_key="X/1"),
        _facts(official_lease_active=True),
        _facts(official_zprp_id="1"),
        _facts(official_overlay_nonempty=True),
    ]
    for facts in cases:
        out = promotion_verdict(facts)
        assert out and out["message"].strip().endswith(".")
        assert "—" not in out["message"] and "–" not in out["message"]


# ───────────────────────── odpowiedzi ─────────────────────────


def test_odmowa_zapisu_pod_przeniesiony_klucz():
    out = promoted_detail("SK/8", 1, 14)
    assert out["code"] == "MATCH_PROMOTED"
    assert "SK/8" in out["message"]
    assert out["official_key"] == "SK/8"
    assert out["official_doc_rev"] == 1
    assert out["promoted_from_rev"] == 14
    assert promoted_detail("SK/8", None, None)["official_doc_rev"] is None


def test_blokada_pin_mowi_o_przenoszeniu_a_usuwanie_bez_zmian():
    assert "nic nie zostało przeniesione" in promote_lock_message(600)
    assert "Przenoszenie wróci za 10 min" in promote_lock_message(600)
    assert lock_message(600) == (
        "Za dużo błędnych PIN-ów. Usuwanie wróci za 10 min - nic nie zostało usunięte."
    )
