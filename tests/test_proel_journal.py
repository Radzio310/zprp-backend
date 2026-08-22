"""Dziennik zdarzeń meczu - to, co da się sprawdzić bez bazy.

Trzy rzeczy, na których stoi ten moduł i które łatwo zepsuć po cichu:

  • **Miękki odczyt aktora.** Twarda zależność zwraca 401 przy braku
    nagłówków, a stara wersja aplikacji ich nie wysyła. Gdyby `soft_actor`
    kiedykolwiek zaczął rzucać, dziennik wywróciłby zapis meczu ze starszego
    telefonu - czyli funkcja pomocnicza zabiłaby funkcję główną.
  • **Etykiety zdarzeń w JEDNYM miejscu.** Panel bierze nazwę z odpowiedzi
    serwera i sam trzyma wyłącznie ikonę. W panelu Beacha te same nazwy żyją
    w dwóch plikach i dawno się rozjechały.
  • **Kształt wiersza.** Ekran czyta `label`, `actor.name` i `created_at`;
    zmiana nazwy pola po cichu zamienia oś czasu w listę pustych węzłów.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.proel_journal import EVENT_LABELS, _row_out, client_ip, soft_actor

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


# ───────────────────────── soft_actor ─────────────────────────


async def test_brak_naglowkow_daje_none_zamiast_401():
    assert await soft_actor(None, None, None) is None
    assert await soft_actor("", "", "") is None


async def test_sam_numer_sedziego_wystarczy_do_atrybucji():
    actor = await soft_actor("12345", None, "KOWALSKI Jan")
    assert actor is not None
    assert actor.judge_id == "12345"
    assert actor.name == "KOWALSKI Jan"
    # Bez pary (instalacja + sędzia) nie ma czego weryfikować.
    assert actor.verified is False


async def test_sama_instalacja_tez_jest_sladem():
    actor = await soft_actor(None, "install-abc", None)
    assert actor is not None
    assert actor.installation_id == "install-abc"
    assert actor.verified is False


async def test_nazwisko_z_polskimi_znakami_wraca_poprawnie():
    # Nagłówki HTTP są latin-1; aplikacja wysyła UTF-8, więc „Radosław"
    # dociera jako „RadosÅ‚aw" i musi zostać przewinięty z powrotem.
    on_the_wire = "Radosław".encode("utf-8").decode("latin-1")
    actor = await soft_actor("1", None, on_the_wire)
    assert actor is not None
    assert actor.name == "Radosław"


# ───────────────────────── etykiety ─────────────────────────


#: Zdarzenia, które backend faktycznie zapisuje. Lista pilnuje, żeby nikt nie
#: dołożył zdarzenia bez nazwy - w panelu wyszłoby wtedy surowe „match.foo".
EMITTED = [
    "match.created",
    "match.live_started",
    "table.taken_over",
    "match.finished",
    "match.approved",
    "match.unapproved",
    "match.deleted",
    "match.restored",
    "match.id_conflict",
    "field.changed",
]


@pytest.mark.parametrize("event", EMITTED)
def test_kazde_zapisywane_zdarzenie_ma_etykiete(event):
    assert EVENT_LABELS.get(event), f"brak etykiety dla {event}"


def test_etykiety_sa_po_polsku_i_bez_kropek_na_koncu():
    for label in EVENT_LABELS.values():
        assert label.strip() == label
        assert not label.endswith(".")


# ───────────────────────── kształt wiersza ─────────────────────────


def _row(**over):
    base = {
        "id": 41,
        "match_number": "OSK/12",
        "zprp_match_id": "208135",
        "event": "match.approved",
        "actor_judge_id": "12345",
        "actor_name": "KOWALSKI Jan",
        "actor_install": "install-abc",
        "actor_verified": True,
        "details_json": {"from": "finished", "to": "approved"},
        "app_version": "1.9.0",
        "client_ip": "10.0.0.1",
        "created_at": datetime(2026, 8, 22, 14, 51, tzinfo=timezone.utc),
    }
    base.update(over)
    return base


def test_wiersz_niesie_etykiete_aktora_i_czas():
    out = _row_out(_row())
    assert out["label"] == EVENT_LABELS["match.approved"]
    assert out["actor"]["name"] == "KOWALSKI Jan"
    assert out["actor"]["verified"] is True
    assert out["created_at"].startswith("2026-08-22T14:51")
    assert out["details"] == {"from": "finished", "to": "approved"}


def test_nieznane_zdarzenie_pokazuje_wlasna_nazwe_zamiast_pustki():
    out = _row_out(_row(event="match.something_new"))
    assert out["label"] == "match.something_new"


def test_brak_aktora_nie_wywraca_wiersza():
    out = _row_out(
        _row(actor_judge_id=None, actor_name=None, actor_install=None, actor_verified=False)
    )
    assert out["actor"]["name"] is None
    assert out["actor"]["verified"] is False


def test_brak_daty_nie_wywraca_wiersza():
    assert _row_out(_row(created_at=None))["created_at"] is None


# ───────────────────────── client_ip ─────────────────────────


def test_adres_zza_proxy_bierzemy_z_pierwszego_wpisu():
    assert client_ip(None, "203.0.113.7, 10.0.0.1") == "203.0.113.7"


def test_brak_zrodla_daje_pusty_tekst():
    assert client_ip(None, None) == ""
