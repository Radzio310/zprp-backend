# -*- coding: utf-8 -*-
"""Klucz meczu szkoleniowego: rozpoznanie i zgodność z blobem.

Reguła decyduje o tym, czy ćwiczenie zapisze się obok prawdziwego protokołu,
czy na nim. Testujemy liść, bo `app.proel` do importu wymaga Postgresa.
"""
from app.proel_training_key import (
    TRAINING_KEY_LIKE,
    TRAINING_KEY_PREFIX,
    blob_is_training,
    blob_knows_provenance,
    is_training_key,
    key_conflicts_with_blob,
    match_number_from_key,
    training_run_from_key,
)


def _blob(**config):
    return {"matchConfig": {"matchNumber": "SPM/1", **config}}


class TestRozpoznanieKlucza:
    def test_klucz_szkoleniowy(self):
        assert is_training_key("T-K3N8P2WQ/SPM/1")
        assert is_training_key("t-k3n8p2wq/spm/1")

    def test_prawdziwe_numery_nie_sa_szkoleniowe(self):
        for number in ("SPM/1", "MP/JM/12", "T/12", "OSK/123", "", None):
            assert not is_training_key(number), number

    def test_numer_i_podejscie_z_klucza(self):
        assert match_number_from_key("T-K3N8P2WQ/MP/JM/12") == "MP/JM/12"
        assert match_number_from_key("SPM/1") == "SPM/1"
        assert training_run_from_key("T-K3N8P2WQ/SPM/1") == "K3N8P2WQ"
        assert training_run_from_key("SPM/1") == ""

    def test_wzorzec_sql_pasuje_do_przedrostka(self):
        assert TRAINING_KEY_LIKE.startswith(TRAINING_KEY_PREFIX)


class TestPochodzenieZBloba:
    def test_trzy_rownowazne_powody(self):
        assert blob_is_training(_blob(origin="training"))
        assert blob_is_training(_blob(isTest=True))
        assert blob_is_training(_blob(training={"eventId": "kk2026"}))

    def test_oficjalne_pochodzenia(self):
        for origin in ("account", "token", "manual"):
            assert not blob_is_training(_blob(origin=origin)), origin

    def test_blob_bez_konfiguracji_nie_wywraca_sie(self):
        assert not blob_is_training(None)
        assert not blob_is_training({})
        assert not blob_is_training("nie-slownik")
        assert not blob_is_training({"matchConfig": None})

    def test_stary_blob_nie_wie_o_pochodzeniu(self):
        assert not blob_knows_provenance(_blob())
        assert blob_knows_provenance(_blob(origin="account"))
        # Znacznik ćwiczenia jedzie w konfiguracji od dawna - to jest wiedza.
        assert blob_knows_provenance(_blob(isTest=True))


class TestZgodnoscKlucza:
    def test_szkoleniowy_pod_czystym_numerem_to_konflikt(self):
        assert key_conflicts_with_blob("SPM/1", _blob(origin="training"))
        assert key_conflicts_with_blob("SPM/1", _blob(isTest=True))

    def test_szkoleniowy_pod_swoim_kluczem_przechodzi(self):
        assert not key_conflicts_with_blob(
            "T-K3N8P2WQ/SPM/1", _blob(origin="training")
        )

    def test_oficjalny_pod_kluczem_szkoleniowym_to_konflikt(self):
        assert key_conflicts_with_blob("T-K3N8P2WQ/SPM/1", _blob(origin="account"))

    def test_oficjalny_pod_numerem_przechodzi(self):
        for origin in ("account", "token", "manual"):
            assert not key_conflicts_with_blob("SPM/1", _blob(origin=origin)), origin

    def test_stary_klient_przechodzi_zawsze(self):
        assert not key_conflicts_with_blob("SPM/1", _blob())
        assert not key_conflicts_with_blob("T-K3N8P2WQ/SPM/1", _blob())


def test_zero_dlugich_myslnikow_w_module():
    import app.proel_training_key as mod

    source = open(mod.__file__, encoding="utf-8").read()
    assert chr(0x2013) not in source
    assert chr(0x2014) not in source
