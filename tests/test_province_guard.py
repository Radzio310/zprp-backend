"""Bramka zapisów okręgowych: okres przejściowy, konta org i odmowa z powodem.

Moduł `app.province_guard` czyta bazę dopiero w środku funkcji, więc da się go
sprawdzić bez Postgresa - podmieniamy odczyt list na gotowe odpowiedzi.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app import province_guard


@pytest.fixture(autouse=True)
def lists(monkeypatch):
    """Master Dolnego Śląska to 7, administrator aplikacji to 999.

    Listy są PER WOJEWÓDZTWO, bo cała reguła stoi na tej różnicy - fałszywka
    zwracająca wszędzie to samo przepuściłaby przenosiny wpisu do cudzego
    okręgu i test niczego by nie pilnował.
    """
    state = {
        "masters": {"DOLNOSLASKIE": ["7"], "SLASKIE": []},
        "admins": ["999"],
        "calls": [],
    }

    async def fake(kind, province):
        state["calls"].append((kind, province))
        key = province_guard.normalize_province(province)
        return list(state["masters"].get(key, [])), list(state["admins"])

    monkeypatch.setattr(province_guard, "_read_access_lists", fake)
    monkeypatch.delenv(province_guard.STRICT_ENV, raising=False)
    return state


def token(judge_id="7", account_type="judge"):
    return {"sub": "login", "judge_id": judge_id, "account_type": account_type}


async def test_master_okregu_przechodzi():
    await province_guard.ensure_announcement_write(
        token(), province="DOLNOŚLĄSKIE", action="Dodanie ogłoszenia"
    )


async def test_obcy_dostaje_403_z_powodem_i_wyjsciem():
    with pytest.raises(HTTPException) as err:
        await province_guard.ensure_announcement_write(
            token("8"), province="DOLNOŚLĄSKIE", action="Dodanie ogłoszenia"
        )
    assert err.value.status_code == 403
    # Odmowa musi się tłumaczyć: co, gdzie i co z tym zrobić.
    assert "News Mastera" in err.value.detail
    assert "DOLNOSLASKIE" in err.value.detail
    assert "administratora" in err.value.detail


async def test_administrator_przechodzi():
    await province_guard.ensure_announcement_write(
        token("999"), province="MAZOWIECKIE", action="Usunięcie ogłoszenia"
    )


async def test_konto_organizacji_nie_przechodzi():
    # Konto klubu nie ma numeru sędziego, więc nie może być Masterem - i w
    # aplikacji też nie widzi tych przycisków.
    with pytest.raises(HTTPException) as err:
        await province_guard.ensure_announcement_write(
            token("", "org"), province="ŚLĄSKIE", action="Dodanie ogłoszenia"
        )
    assert err.value.status_code == 403


async def test_bez_tokenu_okres_przejsciowy_przepuszcza(caplog):
    # Stare wersje aplikacji nie dokładały nagłówka - do czasu ich wygaśnięcia
    # przepuszczamy, ale zostawiamy ślad w logu.
    with caplog.at_level("WARNING"):
        await province_guard.ensure_announcement_write(
            None, province="ŚLĄSKIE", action="Dodanie ogłoszenia"
        )
    assert any("province_guard" in r.message for r in caplog.records)


async def test_bez_tokenu_po_zamknieciu_furtki_odmowa(monkeypatch):
    monkeypatch.setenv(province_guard.STRICT_ENV, "1")
    with pytest.raises(HTTPException) as err:
        await province_guard.ensure_announcement_write(
            None, province="ŚLĄSKIE", action="Dodanie ogłoszenia"
        )
    assert err.value.status_code == 401
    assert "Zaloguj" in err.value.detail


async def test_przenosiny_ogloszenia_pytaja_o_oba_okregi(lists):
    # Master Dolnego Śląska nie wrzuci wpisu na Śląsk.
    with pytest.raises(HTTPException):
        await province_guard.ensure_announcement_write(
            token(),
            province="DOLNOŚLĄSKIE",
            action="Edycja ogłoszenia",
            extra_province="ŚLĄSKIE",
        )
    assert lists["calls"] == [
        ("news", "DOLNOŚLĄSKIE"),
        ("news", "ŚLĄSKIE"),
    ]


async def test_ten_sam_okreg_nie_jest_przenosinami(lists):
    await province_guard.ensure_announcement_write(
        token(),
        province="DOLNOŚLĄSKIE",
        action="Edycja ogłoszenia",
        extra_province="Dolnoslaskie",
    )
    assert len(lists["calls"]) == 1


async def test_po_swoich_niedyspozycjach_pisze_kazdy_zalogowany():
    await province_guard.ensure_offtimes_write(
        token("55"),
        province="DOLNOŚLĄSKIE",
        target_judge_id="55",
        action="Zapis niedyspozycji",
    )


async def test_po_cudzych_niedyspozycjach_tylko_calendar_master(lists):
    with pytest.raises(HTTPException) as err:
        await province_guard.ensure_offtimes_write(
            token("55"),
            province="DOLNOŚLĄSKIE",
            target_judge_id="66",
            action="Zapis niedyspozycji",
        )
    assert err.value.status_code == 403
    assert "Calendar Mastera" in err.value.detail
    # Pytanie poszło o listę kalendarzową, nie o ogłoszeniową.
    assert lists["calls"] == [("calendar", "DOLNOŚLĄSKIE")]


async def test_numer_z_tresci_zadania_nic_nie_znaczy():
    # Tożsamość bierzemy wyłącznie z tokenu - inaczej wystarczyłoby wpisać
    # cudzy numer w formularzu.
    assert province_guard.actor_judge_id({"judge_id": "7"}) == "7"
    assert province_guard.actor_judge_id({}) == ""
    assert province_guard.actor_judge_id(None) == ""


async def test_nieznany_rodzaj_uprawnienia_to_blad_programisty():
    with pytest.raises(ValueError):
        await province_guard.ensure_province_write(
            token(), province="ŚLĄSKIE", kind="wymyslony"
        )
