"""Reguly migawek meczu - `app/snapshot_rules.py`.

Migawka powstaje z KAZDEGO przyjetego pelnego zapisu, wiec te reguly decyduja
o dwoch rzeczach naraz: czy panel bedzie mial do czego wrocic i czy baza nie
spuchnie. Testy pilnuja obu stron.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.snapshot_rules import (
    MAX_PER_MATCH_PER_DAY,
    MAX_SNAPSHOT_BYTES,
    MILESTONE_RETENTION_DAYS,
    MIN_INTERVAL_SECONDS,
    RETENTION_DAYS,
    expires_at,
    is_stripped,
    may_store,
    merge_signatures_forward,
    milestone_of,
    pack,
    snapshot_hash,
    strip_heavy,
    too_big,
    unpack,
)

NOW = datetime(2026, 9, 14, 18, 0, tzinfo=timezone.utc)
SIG = "data:image/png;base64," + "A" * 20000


def blob(**over):
    base = {
        "matchConfig": {
            "matchNumber": "LCK/6",
            "extras": {
                "hostTeamSignature": SIG,
                "guestTeamSignature": "",
                "officials": {"referee1": {"fullName": "KOWALSKI Jan", "signature": SIG}},
                "medic": {"signature": SIG},
                "notesText": "Uwagi",
            },
            "hostCompanions": [{"id": "A", "fullName": "T Jan", "signature": SIG}],
        },
        "protocol": [{"id": f"ev{i}", "type": "goal"} for i in range(70)],
        "scoreHost": 32,
    }
    base.update(over)
    return base


# ───────────────────────── odchudzanie ─────────────────────────


def test_podpisy_wypadaja_z_migawki():
    lean, stats = strip_heavy(blob())
    assert stats["stripped"] == 4  # dwie druzyny? nie - host, sedzia, medyk, towarzyszacy
    assert is_stripped(lean["matchConfig"]["extras"]["hostTeamSignature"])
    assert is_stripped(lean["matchConfig"]["extras"]["officials"]["referee1"]["signature"])
    assert is_stripped(lean["matchConfig"]["extras"]["medic"]["signature"])
    assert is_stripped(lean["matchConfig"]["hostCompanions"][0]["signature"])


def test_odchudzanie_nie_rusza_oryginalu():
    """Ta sama tresc jedzie zaraz do zapisu meczu - nie wolno jej tknac."""
    original = blob()
    strip_heavy(original)
    assert original["matchConfig"]["extras"]["hostTeamSignature"] == SIG


def test_slad_niesie_rozmiar_i_odcisk():
    lean, _ = strip_heavy(blob())
    mark = lean["matchConfig"]["extras"]["hostTeamSignature"]
    assert "podpis" in mark and "KB" in mark


def test_slad_zmienia_sie_razem_z_podpisem():
    """Panel ma umiec powiedziec „ten podpis sie ZMIENIL" bez trzymania tresci."""
    a, _ = strip_heavy(blob())
    other = blob()
    other["matchConfig"]["extras"]["hostTeamSignature"] = SIG.replace("A", "B")
    b, _ = strip_heavy(other)
    assert (
        a["matchConfig"]["extras"]["hostTeamSignature"]
        != b["matchConfig"]["extras"]["hostTeamSignature"]
    )


def test_puste_i_krotkie_pola_zostaja_nietkniete():
    lean, _ = strip_heavy(blob())
    assert lean["matchConfig"]["extras"]["guestTeamSignature"] == ""
    assert lean["matchConfig"]["extras"]["notesText"] == "Uwagi"
    assert len(lean["protocol"]) == 70


def test_wklejony_obrazek_tez_wypada():
    """Ten sam mechanizm broni przed migawka ze zdjeciem w polu tekstowym."""
    lean, stats = strip_heavy({"extras": {"notesText": "data:image/jpeg;base64," + "Z" * 9000}})
    assert stats["stripped"] == 1
    assert is_stripped(lean["extras"]["notesText"])


def test_odchudzanie_scina_rozmiar_o_rzad_wielkosci():
    full = len(json.dumps(blob(), ensure_ascii=False).encode())
    lean, _ = strip_heavy(blob())
    thin = len(json.dumps(lean, ensure_ascii=False).encode())
    assert thin * 10 < full


# ───────────────────────── podpisy przy przywracaniu ─────────────────────────


def test_przywracanie_NIE_USUWA_podpisu():
    """Twarda regula: sedzia nie traci podpisu przez cofniecie meczu."""
    lean, _ = strip_heavy(blob())
    restored = json.loads(json.dumps(lean))
    merged = merge_signatures_forward(restored, blob())
    assert merged["matchConfig"]["extras"]["hostTeamSignature"] == SIG
    assert merged["matchConfig"]["extras"]["officials"]["referee1"]["signature"] == SIG
    assert merged["matchConfig"]["hostCompanions"][0]["signature"] == SIG


def test_wlasny_podpis_przywracanej_wersji_wygrywa():
    """Gdy stara wersja MA podpis, zostaje jej wlasny - nie podmieniamy."""
    old = blob()
    old["matchConfig"]["extras"]["hostTeamSignature"] = "STARY"
    merged = merge_signatures_forward(old, blob())
    assert merged["matchConfig"]["extras"]["hostTeamSignature"] == "STARY"


def test_istniejacy_pojemnik_przyjmuje_podpis_ktorego_nie_mial():
    """Stara wersja sprzed zlozenia podpisu ma go dostac - o to chodzi."""
    thin = {"matchConfig": {"extras": {}}}
    merged = merge_signatures_forward(thin, blob())
    assert merged["matchConfig"]["extras"]["hostTeamSignature"] == SIG


def test_brakujacego_pojemnika_NIE_dotwarzamy():
    """Nie wymyslamy struktury, ktorej w przywracanej wersji nie bylo.

    Podpis sedziego nie ma gdzie wejsc, gdy w tamtej wersji nie bylo jeszcze
    sekcji obsady - i lepiej go pominac niz zbudowac wpis z niczego.
    """
    thin = {"matchConfig": {}}
    merged = merge_signatures_forward(thin, blob())
    assert merged == {"matchConfig": {}}


def test_scalanie_znosi_dziwne_ksztalty():
    assert merge_signatures_forward(None, blob()) is None
    assert merge_signatures_forward("tekst", blob()) == "tekst"
    assert merge_signatures_forward({"a": 1}, None) == {"a": 1}


# ───────────────────────── pakowanie i odcisk ─────────────────────────


def test_spakowana_migawka_wraca_bez_zmian():
    lean, _ = strip_heavy(blob())
    assert unpack(pack(lean)) == lean


def test_kompresja_naprawde_oszczedza():
    lean, _ = strip_heavy(blob())
    raw = len(json.dumps(lean, ensure_ascii=False).encode())
    assert len(pack(lean)) * 3 < raw


def test_brak_tresci_to_None_a_nie_wyjatek():
    assert unpack(None) is None
    assert unpack(b"") is None
    assert unpack(b"to nie jest zlib") is None


def test_odcisk_nie_zalezy_od_KOLEJNOSCI_kluczy():
    """Sterownik i klient potrafia oddac te same pola w innej kolejnosci -
    bez tego kazdy zapis wygladalby na nowa wersje."""
    assert snapshot_hash({"a": 1, "b": 2}) == snapshot_hash({"b": 2, "a": 1})


def test_odcisk_lapie_prawdziwa_zmiane():
    lean, _ = strip_heavy(blob())
    other, _ = strip_heavy(blob(scoreHost=33))
    assert snapshot_hash(lean) != snapshot_hash(other)


def test_za_duza_tresc_jest_rozpoznawana():
    assert too_big(blob()) is False
    assert too_big({"x": "y" * (MAX_SNAPSHOT_BYTES + 10)}) is True


# ───────────────────────── kamienie milowe ─────────────────────────


def test_pierwsza_migawka_meczu_to_start():
    assert milestone_of(prev=None, phase="pre", status=None, first_half=True) == "start"


def test_pierwszy_gwizdek_druga_polowa_i_koniec():
    pre = {"phase": "pre", "status": "in_progress", "first_half": True}
    assert milestone_of(prev=pre, phase="live", status="in_progress", first_half=True) == "live"
    live = {"phase": "live", "status": "in_progress", "first_half": True}
    assert milestone_of(prev=live, phase="live", status="in_progress", first_half=False) == "halftime"
    assert milestone_of(prev=live, phase="post", status="finished", first_half=False) == "end"


def test_zatwierdzenie_i_jego_cofniecie():
    post = {"phase": "post", "status": "finished", "first_half": False}
    assert milestone_of(prev=post, phase="locked", status="approved", first_half=False) == "approve"
    locked = {"phase": "locked", "status": "approved", "first_half": False}
    assert milestone_of(prev=locked, phase="post", status="finished", first_half=False) == "unapprove"


def test_zwykly_takt_nie_jest_kamieniem_milowym():
    """Dziesiata migawka drugiej polowy nie jest przerwa."""
    live = {"phase": "live", "status": "in_progress", "first_half": False}
    assert milestone_of(prev=live, phase="live", status="in_progress", first_half=False) is None


def test_kamien_milowy_zyje_dluzej():
    assert expires_at(NOW, None) == NOW + timedelta(days=RETENTION_DAYS)
    assert expires_at(NOW, "approve") == NOW + timedelta(days=MILESTONE_RETENTION_DAYS)


# ───────────────────────── zapory przed zalaniem bazy ─────────────────────────


def test_normalny_takt_przechodzi():
    ok, why = may_store(now=NOW, last_at=NOW - timedelta(seconds=60), today_count=10, milestone=None)
    assert ok and why == ""


def test_klient_w_petli_nie_zaleje_bazy():
    ok, why = may_store(
        now=NOW, last_at=NOW - timedelta(seconds=MIN_INTERVAL_SECONDS - 1),
        today_count=10, milestone=None,
    )
    assert not ok and why == "za_czesto"


def test_limit_dobowy_zatrzymuje_zwykle_migawki():
    ok, why = may_store(now=NOW, last_at=None, today_count=MAX_PER_MATCH_PER_DAY, milestone=None)
    assert not ok and why == "limit"


def test_ale_kamien_milowy_przechodzi_ZAWSZE():
    """Po limicie zbieramy wylacznie chwile wazne - i one nie moga wypasc."""
    ok, why = may_store(
        now=NOW, last_at=NOW, today_count=MAX_PER_MATCH_PER_DAY * 10, milestone="approve"
    )
    assert ok and why == ""


def test_pierwsza_migawka_meczu_nie_ma_z_czym_porownac_odstepu():
    ok, _ = may_store(now=NOW, last_at=None, today_count=0, milestone=None)
    assert ok


def test_znacznik_bez_strefy_nie_wywraca_porownania():
    """Sterowniki oddaja czas raz ze strefa, raz bez - to nie moze decydowac."""
    naive = (NOW - timedelta(seconds=5)).replace(tzinfo=None)
    ok, why = may_store(now=NOW, last_at=naive, today_count=1, milestone=None)
    assert not ok and why == "za_czesto"
