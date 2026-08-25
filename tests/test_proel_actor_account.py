"""Tożsamość aktora ProEl: konto ProEl i gość bez numeru sędziego.

CO SIĘ ZEPSUŁO. `proel_actor` uznawał za tożsamość WYŁĄCZNIE numer sędziego z
baza.zprp.pl. Kto wszedł do ProEla kontem ProEl, ten nie miał takiego numeru w
ogóle - aplikacja wysyłała pusty `X-Judge-Id` i dostawała 401 na każdej trasie
z `Depends(proel_actor)`: liście meczów, stanie, leasingu, patchu. Widoczne było
tylko jedno: zakładka „Baza ProEl" świeciła pustką i namawiała do odświeżenia.

Dlaczego bez bazy: ścieżka konta kończy się na jednym odczycie, który tu
podmieniamy, a ścieżka zastępcza celowo NIE dotyka rejestru urządzeń. Reszta
`proel_actor` to czysta decyzja o tym, kim jest wołający - i taka ma zostać.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app import proel_auth
from app.proel_auth import (
    DEVICE_PREFIX,
    PROEL_ACCOUNT_PREFIX,
    is_synthetic_judge_id,
    proel_actor,
)
from app.proel_users.tokens import create_access_token

ACCOUNT = {"id": 7, "full_name": "KOWALSKI Jan", "is_active": True}


@pytest.fixture
def account(monkeypatch):
    """Konto ProEl #7 w bazie - bez bazy."""
    seen: dict = {}

    async def _load(user_id: int):
        seen["user_id"] = user_id
        return dict(ACCOUNT)

    monkeypatch.setattr(proel_auth, "_load_proel_account", _load)
    return seen


def bearer(user_id: int = 7) -> str:
    return f"Bearer {create_access_token(user_id)}"


# ─────────────────────── identyfikator zastępczy ───────────────────────

def test_rozpoznajemy_identyfikatory_zastepcze():
    assert is_synthetic_judge_id(f"{PROEL_ACCOUNT_PREFIX}7")
    assert is_synthetic_judge_id(f"{DEVICE_PREFIX}abc-123")
    assert is_synthetic_judge_id("  proel:7  ")


def test_numer_sedziego_nie_jest_zastepczy():
    for value in ("12345", "", None, "proel", "instalacja", "0"):
        assert not is_synthetic_judge_id(value), value


# ─────────────────────── konto ProEl jako aktor ───────────────────────

@pytest.mark.asyncio
async def test_konto_proel_wchodzi_bez_numeru_sedziego(account):
    actor = await proel_actor(
        x_judge_id=None,
        x_installation_id="telefon-1",
        x_actor_name=None,
        authorization=bearer(7),
    )
    assert actor.judge_id == f"{PROEL_ACCOUNT_PREFIX}7"
    assert actor.installation_id == "telefon-1"
    assert actor.verified is True
    assert account["user_id"] == 7


@pytest.mark.asyncio
async def test_nazwisko_z_konta_gdy_naglowka_brak(account):
    """Bez nazwiska nie ma dopasowania roli w meczu - a konto je zna."""
    actor = await proel_actor(
        x_judge_id=None,
        x_installation_id="telefon-1",
        x_actor_name=None,
        authorization=bearer(7),
    )
    assert actor.name == "KOWALSKI Jan"


@pytest.mark.asyncio
async def test_numer_sedziego_z_konta_NIE_staje_sie_tozsamoscia(monkeypatch):
    """Numer wpisany przy zakładaniu konta jest niesprawdzony - nie daje praw."""
    async def _load(_uid: int):
        return {"id": 7, "full_name": "KOWALSKI Jan", "is_active": True, "judge_id": "12345"}

    monkeypatch.setattr(proel_auth, "_load_proel_account", _load)
    actor = await proel_actor(
        x_judge_id=None,
        x_installation_id="telefon-1",
        x_actor_name=None,
        authorization=bearer(7),
    )
    assert actor.judge_id == f"{PROEL_ACCOUNT_PREFIX}7"


@pytest.mark.asyncio
async def test_zablokowane_konto_mowi_wprost_ze_jest_zablokowane(monkeypatch):
    async def _load(_uid: int):
        return {"id": 7, "full_name": "KOWALSKI Jan", "is_active": False}

    monkeypatch.setattr(proel_auth, "_load_proel_account", _load)
    with pytest.raises(HTTPException) as e:
        await proel_actor(
            x_judge_id=None,
            x_installation_id="telefon-1",
            x_actor_name=None,
            authorization=bearer(7),
        )
    assert e.value.status_code == 403
    assert e.value.detail["code"] == "ACCOUNT_BLOCKED"


@pytest.mark.asyncio
async def test_skasowane_konto_to_nie_tozsamosc(monkeypatch):
    async def _load(_uid: int):
        return None

    monkeypatch.setattr(proel_auth, "_load_proel_account", _load)
    with pytest.raises(HTTPException) as e:
        await proel_actor(
            x_judge_id=None,
            x_installation_id="telefon-1",
            x_actor_name=None,
            authorization=bearer(7),
        )
    assert e.value.status_code == 401
    assert e.value.detail["code"] == "ACTOR_REQUIRED"


@pytest.mark.asyncio
async def test_zly_token_nie_wywraca_tylko_nic_nie_wnosi(monkeypatch):
    """Podrobiony token ma być przezroczysty, a nie zamieniać się w 500."""
    async def _load(_uid: int):
        raise AssertionError("do odczytu konta nie powinno dojść")

    monkeypatch.setattr(proel_auth, "_load_proel_account", _load)
    with pytest.raises(HTTPException) as e:
        await proel_actor(
            x_judge_id=None,
            x_installation_id="telefon-1",
            x_actor_name=None,
            authorization="Bearer nie.jest.tokenem",
        )
    assert e.value.status_code == 401
    assert e.value.detail["code"] == "ACTOR_REQUIRED"


# ─────────────────── pierwszeństwo numeru sędziego ───────────────────

@pytest.mark.asyncio
async def test_prawdziwy_numer_sedziego_wygrywa_z_tokenem(monkeypatch):
    """Sędzia z konta BAZA nie może stracić roli przez token konta ProEl."""
    async def _load(_uid: int):
        raise AssertionError("token nie powinien być w ogóle pytany")

    monkeypatch.setattr(proel_auth, "_load_proel_account", _load)

    # Numer prawdziwy -> normalna ścieżka; rejestr urządzeń może być
    # niedostępny (tak jest w tym środowisku) i to nie ma prawa nic zmienić.
    actor = await proel_actor(
        x_judge_id="12345",
        x_installation_id="telefon-1",
        x_actor_name="KOWALSKI Jan",
        authorization=bearer(7),
    )
    assert actor.judge_id == "12345"


# ─────────────────── samo urządzenie (profil lokalny) ───────────────────

@pytest.mark.asyncio
async def test_samo_urzadzenie_wchodzi_jako_niezweryfikowane():
    actor = await proel_actor(
        x_judge_id=f"{DEVICE_PREFIX}abc-123",
        x_installation_id="abc-123",
        x_actor_name="NOWAK Anna",
        authorization=None,
    )
    assert actor.judge_id == f"{DEVICE_PREFIX}abc-123"
    assert actor.verified is False
    assert actor.name == "NOWAK Anna"


@pytest.mark.asyncio
async def test_bez_niczego_dalej_401():
    with pytest.raises(HTTPException) as e:
        await proel_actor(
            x_judge_id=None,
            x_installation_id=None,
            x_actor_name=None,
            authorization=None,
        )
    assert e.value.status_code == 401
    assert e.value.detail["code"] == "ACTOR_REQUIRED"
