"""Oś czasu zamieniona na polecenia - jedno źródło dla slajdów, paska i PDF.

Gdyby każde z tych trzech miejsc składało zdania samo, ta sama akcja brzmiałaby
w każdym inaczej - a sędzia porównuje rzutnik z telefonem.
"""
from __future__ import annotations

from app.training_spk_slides import (
    SAME_ACTION_MS,
    action_text,
    format_clock,
    slides_from_timeline,
    slides_header,
)


def ev(t, kind="goal", team="host", player=16, half=1, **extra):
    out = {"time": t, "type": kind, "team": team, "player": player, "half": half}
    out.update(extra)
    return out


def test_zegar_liczony_od_poczatku_meczu():
    assert format_clock(0) == "00:00"
    assert format_clock(65_000) == "01:05"
    assert format_clock(1_800_000) == "30:00"
    assert format_clock(None) == "00:00"


def test_zdania_o_bramkach():
    assert action_text(ev(0)) == "Bramka gospodarzy nr 16"
    assert action_text(ev(0, team="guest", player=7)) == "Bramka gości nr 7"
    assert action_text(ev(0, kind="goalRemoved")) == "Anulowana bramka gospodarzy nr 16"


def test_zdania_o_karach():
    assert action_text(ev(0, kind="penalty1", team="guest", player=7)) == (
        "Kara 2 minut dla gości nr 7"
    )
    assert "(druga)" in action_text(ev(0, kind="penalty2"))
    assert "(trzecia)" in action_text(ev(0, kind="penalty3"))
    assert action_text(ev(0, kind="warning")) == "Upomnienie dla gospodarzy nr 16"


def test_zdania_o_rzutach_karnych_i_dyskwalifikacji():
    assert action_text(ev(0, kind="penaltyKickScored")) == (
        "Rzut karny wykorzystany, gospodarzy nr 16"
    )
    assert action_text(ev(0, kind="penaltyKickMissed")).startswith(
        "Rzut karny niewykorzystany"
    )
    assert action_text(ev(0, kind="disqualification")).startswith("Dyskwalifikacja,")
    assert "raportem" in action_text(ev(0, kind="disqualificationBlue"))


def test_czas_dla_druzyny_uzywa_mianownika():
    assert action_text(ev(0, kind="teamTime", player=None)) == (
        "Czas dla drużyny: gospodarze"
    )
    assert "(T2)" in action_text(ev(0, kind="teamTime", player=None, extra="T2"))


def test_osoby_z_lawki_nie_maja_numeru():
    """Protokół zapisuje je jako „Tr" i „Os" - „nr Tr" nikt nie wypowiada."""
    assert action_text(ev(0, kind="warning", player="Tr")) == (
        "Upomnienie dla gospodarzy trener"
    )
    assert "osoba towarzysząca" in action_text(ev(0, kind="warning", player="Os"))


def test_nieznany_rodzaj_nie_daje_zdania():
    assert action_text(ev(0, kind="cosNowego")) == ""


# ───────────────────────── slajdy ─────────────────────────

def test_slajdy_ida_w_kolejnosci_meczu():
    out = slides_from_timeline([ev(30_000), ev(10_000, player=3)])
    assert [s["clock"] for s in out] == ["00:10", "00:30"]
    assert [s["n"] for s in out] == [1, 2]


def test_zdarzenia_rownoczesne_trafiaja_na_jeden_slajd():
    """Bramka i kara w jednej akcji to jeden slajd - przykład z wymagania."""
    out = slides_from_timeline(
        [ev(600_000, player=16), ev(600_000, kind="penalty1", team="guest", player=7)]
    )
    assert len(out) == 1
    assert out[0]["text"] == "Bramka gospodarzy nr 16 i kara 2 minut dla gości nr 7"


def test_okno_rownoczesnosci_jest_waskie():
    out = slides_from_timeline([ev(0), ev(SAME_ACTION_MS + 1, player=3)])
    assert len(out) == 2


def test_numeracja_bez_dziur_po_scaleniu():
    out = slides_from_timeline(
        [ev(0), ev(0, kind="penalty1"), ev(60_000), ev(120_000)]
    )
    assert [s["n"] for s in out] == [1, 2, 3]


def test_zdarzenia_z_serii_karnych_ida_na_koniec():
    out = slides_from_timeline(
        [ev(3_600_000, kind="penalty1", shootout=True), ev(10_000)]
    )
    assert out[0]["shootout"] is False
    assert out[-1]["shootout"] is True


def test_seria_nie_sklei_sie_z_gra_mimo_tego_samego_czasu():
    out = slides_from_timeline(
        [ev(3_600_000), ev(3_600_000, kind="penalty1", shootout=True)]
    )
    assert len(out) == 2


def test_nieznane_zdarzenie_nie_tworzy_pustego_slajdu():
    out = slides_from_timeline([ev(0, kind="cosNowego"), ev(1_000_000)])
    assert len(out) == 1


def test_pusta_os_czasu_daje_pusta_liste():
    assert slides_from_timeline(None) == []
    assert slides_from_timeline([]) == []


def test_naglowek_materialu():
    head = slides_header(
        {
            "matchNumber": "SPK/1",
            "hostTeamName": "Zagłębie",
            "guestTeamName": "MKS",
            "finalHost": "30",
            "finalGuest": "24",
            "halfHost": "15",
            "halfGuest": "12",
        }
    )
    assert head["teams"] == "Zagłębie - MKS"
    assert head["result"] == "30:24"
    assert head["halfResult"] == "15:12"
