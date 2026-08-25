"""
Kody resetu hasła ProEl - ważność i tolerancja dla starszego maila.

Co tu poszło źle w praktyce: sędzia poprosił o kod, dostał go, wpisał - i
usłyszał „Kod wygasł". Powód nie miał nic wspólnego z czasem. Oba etapy resetu
brały wyłącznie NAJNOWSZY nieużyty kod, a `/request` unieważniał przy okazji
wszystkie poprzednie. Dwa maile pod rząd (albo ponowne otwarcie ekranu)
wystarczały, żeby kod sprzed minuty przestał działać.

Weryfikacja e-maila w Beachu rozwiązała to dawno - akceptuje każdy aktywny kod
i daje staremu okno karencji. Te testy pilnują, że reset robi to samo, oraz że
sam termin ważności jest liczony osobno i dłużej.

Bez bazy: sprawdzamy funkcję czasu wprost, a kształt obu etapów przez odczyt
źródła. Pełne scenariusze DB wymagają Postgresa (patrz test_email_verification).
"""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from app.proel_users.password_reset_email import (
    _DEFAULT_RESET_TTL_MINUTES,
    _reset_ttl_minutes,
)

CFG = SimpleNamespace(ttl_minutes=15)

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "app"
    / "proel_users"
    / "password_reset_email.py"
).read_text(encoding="utf-8")


def _function_code(name: str) -> str:
    """Ciało funkcji bez docstringu - żeby test nie łapał własnych komentarzy."""
    tree = ast.parse(SOURCE)
    fn = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name
    )
    body = [
        node
        for node in fn.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    return "\n".join(ast.unparse(node) for node in body)


# ─────────────────────────── termin ważności ───────────────────────────

def test_domyslnie_dwie_godziny(monkeypatch):
    monkeypatch.delenv("PROEL_PASSWORD_RESET_TTL_MINUTES", raising=False)
    assert _reset_ttl_minutes(CFG) == _DEFAULT_RESET_TTL_MINUTES == 120


def test_dluzej_niz_kod_weryfikacji_emaila(monkeypatch):
    """Po kod resetu idzie się do skrzynki - kwadrans na tę drogę to za mało."""
    monkeypatch.delenv("PROEL_PASSWORD_RESET_TTL_MINUTES", raising=False)
    assert _reset_ttl_minutes(CFG) > CFG.ttl_minutes


def test_da_sie_ustawic_zmienna_srodowiskowa(monkeypatch):
    monkeypatch.setenv("PROEL_PASSWORD_RESET_TTL_MINUTES", "45")
    assert _reset_ttl_minutes(CFG) == 45


def test_nigdy_krocej_niz_weryfikacja_emaila(monkeypatch):
    """Podłóg jest twardy: literówka w konfiguracji nie skróci kodu do minuty."""
    monkeypatch.setenv("PROEL_PASSWORD_RESET_TTL_MINUTES", "1")
    assert _reset_ttl_minutes(SimpleNamespace(ttl_minutes=15)) == 15


def test_smiec_w_zmiennej_nie_wywraca(monkeypatch):
    monkeypatch.setenv("PROEL_PASSWORD_RESET_TTL_MINUTES", "godzina")
    assert _reset_ttl_minutes(CFG) == _DEFAULT_RESET_TTL_MINUTES


# ─────────────────────── kształt obu etapów ───────────────────────

def test_oba_etapy_biora_kazdy_zywy_kod():
    for name in ("verify_reset_code", "confirm_reset"):
        code = _function_code(name)
        assert "_live_reset_codes" in code, name
        # `limit(1)` na najnowszym kodzie było CAŁYM błędem - nie może wrócić.
        assert "limit(1)" not in code, name


def test_brak_zywego_kodu_rozroznia_wygasl_od_zuzyty():
    for name in ("verify_reset_code", "confirm_reset"):
        assert "_no_live_code_error" in _function_code(name), name


def test_nowy_kod_nie_zabija_od_razu_poprzedniego():
    code = _function_code("request_reset")
    assert "SUPERSEDE_GRACE_SECONDS" in code
    assert "last_sent_at" in code


def test_wiadomosc_i_odpowiedz_nioso_ten_sam_termin():
    code = _function_code("request_reset")
    assert "ttl_minutes = _reset_ttl_minutes(cfg)" in code
    assert "cfg.ttl_seconds" not in code
