"""Sesja podniesiona: token zamiast rejestru urządzeń.

CO SIĘ ZEPSUŁO. Sędzia boiskowy kończył protokół na telefonie stolikowego.
Uprawnienie przyznawał `/match/official-role` (logowanie do baza.zprp.pl), więc
aplikacja odblokowywała przyciski - ale każdy zapis leciał przez `proel_actor`,
a ten porównywał `X-Installation-Id` z rejestrem `push_tokens`. Instalacja
należała do stolikowego, numer sędziego był czyjś inny, więc odpowiedzią było
401 `ACTOR_MISMATCH`. Ekran mówił „możesz", serwer odpowiadał „to nie ty".

Bez bazy: token jest czystym HMAC-iem, a ścieżka podniesiona w `proel_actor`
świadomie NIE dotyka rejestru urządzeń - i to jest właśnie to, co sprawdzamy.
"""
from __future__ import annotations

import time

import pytest

from app.proel_elevation import (
    TOKEN_AUDIENCE,
    create_elevation_token,
    token_expires_at,
    verify_elevation_token,
)
from app.proel_auth import can_approve, proel_actor
from app.proel_users.tokens import create_access_token


# ─────────────────────────── sam token ───────────────────────────

def test_token_wraca_z_numerem_i_znacznikiem_admina():
    payload = verify_elevation_token(
        create_elevation_token("12345", admin=True, match_id="99887")
    )
    assert payload is not None
    assert payload["jid"] == "12345"
    assert payload["adm"] is True
    assert payload["mid"] == "99887"
    assert payload["aud"] == TOKEN_AUDIENCE


def test_podrobiony_podpis_nie_przechodzi():
    token = create_elevation_token("12345")
    payload_b64, sig = token.split(".", 1)
    assert verify_elevation_token(f"{payload_b64}.{sig[:-2]}xx") is None


def test_wygasly_token_nie_przechodzi():
    assert verify_elevation_token(create_elevation_token("12345", ttl_seconds=-1)) is None


def test_token_konta_proel_nie_jest_tokenem_podniesienia():
    """Oba podpisy schodzą tym samym sekretem - rozdziela je WYŁĄCZNIE `aud`.

    Bez tego testu wystarczyłoby literówkowe zrównanie publiczności, żeby token
    konta ProEl (ważny 30 dni) otwierał sesję podniesioną na cudzym telefonie.
    """
    assert verify_elevation_token(create_access_token(7)) is None


def test_smieci_nie_wywracaja_weryfikacji():
    for value in ("", None, "bezkropki", "a.b", "...", "  "):
        assert verify_elevation_token(value) is None


def test_czas_wygasniecia_da_sie_pokazac_bez_weryfikacji():
    now = int(time.time())
    exp = token_expires_at(create_elevation_token("12345", ttl_seconds=600))
    assert now + 590 <= exp <= now + 610


# ────────────────────── token w `proel_actor` ──────────────────────

@pytest.mark.asyncio
async def test_token_omija_rejestr_urzadzen(monkeypatch):
    """Cudza instalacja przestaje być powodem odmowy - o to w tym całym chodzi."""

    def _boom(*_a, **_k):  # pragma: no cover - wywołanie jest tu błędem
        raise AssertionError("ścieżka podniesiona nie ma prawa pytać o bazę")

    monkeypatch.setattr("app.proel_auth.select", _boom)

    actor = await proel_actor(
        x_judge_id="12345",
        x_installation_id="telefon-stolikowego",
        x_actor_name="KOWALSKI Jan",
        x_elevation=create_elevation_token("12345", match_id="99887"),
        authorization=None,
    )
    assert actor.judge_id == "12345"
    assert actor.verified is True
    assert actor.elevated is True
    assert actor.as_by()["elevated"] is True


@pytest.mark.asyncio
async def test_token_dziala_bez_naglowka_z_numerem():
    """Numer bierzemy z podpisu, nie z nagłówka - nagłówek może go nie nieść."""
    actor = await proel_actor(
        x_judge_id=None,
        x_installation_id="telefon-stolikowego",
        x_actor_name=None,
        x_elevation=create_elevation_token("12345"),
        authorization=None,
    )
    assert actor.judge_id == "12345"
    assert actor.elevated is True


@pytest.mark.asyncio
async def test_rozjazd_naglowka_z_tokenem_wraca_na_zwykla_sciezke(monkeypatch):
    """Token na numer 12345, nagłówek na 999 - to nie jest ta sama czynność.

    Aplikacja, która podmieniła jedno bez drugiego, zapisałaby czynność na
    kogoś innego, niż mówi podpis. Wtedy token przestaje być dowodem i sprawę
    rozstrzyga zwykła reguła, razem z rejestrem urządzeń.
    """
    seen: dict = {}

    class _FakeDb:
        async def fetch_one(self, *_a, **_k):
            seen["pytano"] = True
            return None

    monkeypatch.setitem(
        __import__("sys").modules,
        "app.db",
        type("M", (), {"database": _FakeDb(), "push_tokens": object()})(),
    )

    actor = await proel_actor(
        x_judge_id="999",
        x_installation_id="telefon-stolikowego",
        x_actor_name=None,
        x_elevation=create_elevation_token("12345"),
        authorization=None,
    )
    assert actor.judge_id == "999"
    assert actor.elevated is False


@pytest.mark.asyncio
async def test_zwykly_aktor_nie_dostaje_znacznika_podniesienia(monkeypatch):
    """`as_by()` bez sesji podniesionej ma zostać dokładnie taki, jak był."""

    class _FakeDb:
        async def fetch_one(self, *_a, **_k):
            return None

    monkeypatch.setitem(
        __import__("sys").modules,
        "app.db",
        type("M", (), {"database": _FakeDb(), "push_tokens": object()})(),
    )

    actor = await proel_actor(
        x_judge_id="12345",
        x_installation_id="wlasny-telefon",
        x_actor_name=None,
        x_elevation=None,
        authorization=None,
    )
    assert actor.elevated is False
    assert "elevated" not in actor.as_by()


# ─────────────── podniesienie a zatwierdzenie protokołu ───────────────
#
# To była druga połowa tej samej dziury. Sędzia boiskowy odblokowywał na cudzym
# telefonie wszystkie akcje pomeczowe i odbijał się od tej jednej, ostatniej -
# bo o autora zmiany statusu serwer pyta osobno (`_require_approver`).


@pytest.mark.asyncio
async def test_sedzia_z_obsady_zatwierdza_z_cudzego_telefonu():
    actor = await proel_actor(
        x_judge_id="12345",
        x_installation_id="telefon-stolikowego",
        x_actor_name=None,
        x_elevation=create_elevation_token("12345", match_id="99887"),
        authorization=None,
    )
    officials = {
        "referee1": {"name": "KOWALSKI Jan", "judgeId": "12345"},
        "referee2": {"name": "NOWAK Piotr", "judgeId": "54321"},
        "secretary": {"name": "WISNIEWSKI Adam", "judgeId": "77777"},
    }
    assert can_approve(actor, officials) is True


@pytest.mark.asyncio
async def test_podniesienie_nie_nadaje_roli_w_cudzym_meczu():
    """Token dowodzi TOŻSAMOŚCI, nie uprawnienia - o rolę pyta się dalej obsady."""
    actor = await proel_actor(
        x_judge_id="99999",
        x_installation_id="telefon-stolikowego",
        x_actor_name=None,
        x_elevation=create_elevation_token("99999"),
        authorization=None,
    )
    officials = {
        "referee1": {"name": "KOWALSKI Jan", "judgeId": "12345"},
        "referee2": {"name": "NOWAK Piotr", "judgeId": "54321"},
    }
    assert can_approve(actor, officials) is False
