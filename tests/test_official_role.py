"""Testy rozpoznawania roli sędziego w meczu - czysta logika, bez sieci.

Ta funkcja stoi między stolikowym a akcjami pomeczowymi, więc pomyłka kosztuje
albo zablokowanego sędziego, albo dostęp dla kogoś spoza obsady.
"""
from __future__ import annotations

from app.official_role import (
    AUTHORIZED_ROLES,
    _name_for,
    _roles_for,
    _authorized_crew,
    is_authorized,
)


MATCH = {
    "NrSedzia_pierwszy": "1001",
    "NrSedzia_pierwszy_nazwisko": "KOWALSKI Jan",
    "NrSedzia_drugi": "1002",
    "NrSedzia_drugi_nazwisko": "NOWAK Piotr",
    "NrSedzia_sekretarz": "2001",
    "NrSedzia_sekretarz_nazwisko": "WIŚNIEWSKA Anna",
    "NrSedzia_czas": "2002",
    "NrSedzia_czas_nazwisko": "ZIELIŃSKI Adam",
    "NrSedzia_delegat": "3001",
    "NrSedzia_delegat_nazwisko": "LEWANDOWSKI Marek",
    "NrSedzia_delegat2": "",
    "NrSedzia_delegat2_nazwisko": "",
}


def test_field_referee_is_authorized():
    roles = _roles_for(MATCH, "1001")
    assert roles == ["referee1"]
    assert any(r in AUTHORIZED_ROLES for r in roles)
    assert _name_for(MATCH, roles) == "KOWALSKI Jan"


def test_second_referee_is_authorized():
    assert _roles_for(MATCH, "1002") == ["referee2"]


def test_delegate_is_authorized():
    roles = _roles_for(MATCH, "3001")
    assert roles == ["delegate"]
    assert any(r in AUTHORIZED_ROLES for r in roles)


def test_table_official_is_recognised_but_not_authorized():
    """Stolikowy MA rolę - i właśnie dlatego umiemy mu to powiedzieć wprost.

    Odmowa „to konto jest sekretarzem tego meczu" jest czymś innym niż
    „tego konta nie ma w obsadzie" i sędzia przy stoliku musi widzieć różnicę.
    """
    roles = _roles_for(MATCH, "2001")
    assert roles == ["secretary"]
    assert not any(r in AUTHORIZED_ROLES for r in roles)


def test_stranger_has_no_role():
    assert _roles_for(MATCH, "9999") == []


def test_empty_slot_never_matches_empty_judge_id():
    """Puste pole obsady nie może pasować do pustego numeru.

    Bez tego warunku konto bez numeru sędziego „wchodziło" w każdą nieobsadzoną
    rolę - w tym w delegata, którego na większości meczów nie ma.
    """
    assert _roles_for(MATCH, "") == []


def test_second_delegate_counts_as_delegate():
    match = dict(MATCH, NrSedzia_delegat="", NrSedzia_delegat_nazwisko="",
                 NrSedzia_delegat2="3002",
                 NrSedzia_delegat2_nazwisko="DĄBROWSKI Jan")
    roles = _roles_for(match, "3002")
    assert roles == ["delegate"]
    assert _name_for(match, roles) == "DĄBROWSKI Jan"


def test_same_person_in_two_roles_keeps_both():
    match = dict(MATCH, NrSedzia_czas="1001")
    assert _roles_for(match, "1001") == ["referee1", "timekeeper"]


# ─────────────────────── furtka administratora ───────────────────────
#
# Administrator aplikacji odblokowuje akcje pomeczowe niezależnie od obsady.
# Reguła jest krótka, więc łatwo ją przy okazji odwrócić - stąd te cztery
# przypadki: obie drogi osobno, obie naraz i brak obu.


def test_admin_spoza_obsady_ma_dostep():
    """Sedzia spoza obsady, ale administrator - akcje otwarte.

    To jest cala tresc furtki: numer 9999 nie prowadzi tego meczu i nigdy nie
    dostanie roli, a mimo to ma dokonczyc protokol.
    """
    roles = _roles_for(MATCH, "9999")
    assert roles == []
    assert is_authorized(roles, admin=True)


def test_stolikowy_bedacy_adminem_ma_dostep():
    """Sekretarz meczu, ktory jest administratorem.

    Rola z obsady nie wystarcza (`secretary` nie jest w AUTHORIZED_ROLES), wiec
    o dostepie decyduje wylacznie druga droga. Gdyby ktos kiedys zamienil `or`
    na `and`, ten test zapali sie pierwszy.
    """
    roles = _roles_for(MATCH, "2001")
    assert roles == ["secretary"]
    assert not is_authorized(roles, admin=False)
    assert is_authorized(roles, admin=True)


def test_sedzia_boiskowy_nie_potrzebuje_admina():
    """Obsada dziala dalej sama z siebie - furtka niczego nie przejela."""
    assert is_authorized(_roles_for(MATCH, "1001"), admin=False)


def test_obcy_bez_admina_nie_wchodzi():
    """Brak obsady i brak admina to jedyny wynik odmowny."""
    assert not is_authorized(_roles_for(MATCH, "9999"), admin=False)


# ───────────── obsada do zapisu w ZPRP (tylko dla admina) ─────────────


def test_crew_zawiera_wylacznie_role_uprawnione():
    """Sekretarz i czasomierzysta NIE moga otworzyc sesji zapisu.

    Gdyby weszli na te liste, administrator probowalby ich numerami i dostawal
    odmowy - a przy okazji lista mowilaby nieprawde o tym, kto ma prawo pisac.
    """
    crew = _authorized_crew(MATCH)
    assert [c["role"] for c in crew] == ["referee1", "referee2", "delegate"]
    assert [c["judgeId"] for c in crew] == ["1001", "1002", "3001"]


def test_crew_niesie_nazwiska_do_pokazania():
    crew = _authorized_crew(MATCH)
    assert crew[0]["fullName"] == "KOWALSKI Jan"
    assert crew[2]["fullName"] == "LEWANDOWSKI Marek"


def test_crew_pomija_puste_gniazda():
    """Pusty slot delegata nie moze wyprodukowac wpisu z pustym numerem."""
    match = dict(MATCH, NrSedzia_delegat="", NrSedzia_delegat_nazwisko="")
    crew = _authorized_crew(match)
    assert all(c["judgeId"] for c in crew)
    assert [c["role"] for c in crew] == ["referee1", "referee2"]


def test_crew_bez_duplikatow():
    """Ten sam czlowiek w dwoch gniazdach daje JEDEN wpis.

    Inaczej administrator probowalby tym samym numerem dwa razy, a przy odmowie
    czekalby dwa razy dluzej na ten sam wynik.
    """
    match = dict(MATCH, NrSedzia_delegat2="3001", NrSedzia_delegat2_nazwisko="LEWANDOWSKI Marek")
    ids = [c["judgeId"] for c in _authorized_crew(match)]
    assert len(ids) == len(set(ids))


def test_drugi_delegat_wchodzi_na_liste():
    match = dict(MATCH, NrSedzia_delegat2="3002", NrSedzia_delegat2_nazwisko="DĄBROWSKI Jan")
    ids = [c["judgeId"] for c in _authorized_crew(match)]
    assert "3002" in ids
