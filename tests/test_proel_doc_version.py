"""Wersja treści meczu: kiedy zapis jest przeterminowany, a kiedy tylko spóźniony.

Dwa błędy, oba kosztowne:

* fałszywy konflikt - telefon, któremu zginęła odpowiedź na własny zapis,
  dostaje arkusz "na serwerze jest nowsza wersja" i sędzia wybiera między
  dwiema kopiami własnej pracy;
* przeoczony konflikt - zapis z telefonu, który nie widział cudzej treści,
  przechodzi i niszczy ją po cichu.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.proel_doc_version import (
    CLIENT_REASONS,
    MAX_HISTORY_BYTES,
    REASON_OVERWRITTEN,
    REASON_REJECTED_LOCAL,
    STALE_MESSAGE,
    conflict_event_key,
    is_stale_write,
    iso,
    parse_base_rev,
    parse_overwrite,
    payload_bytes,
    should_archive_on_overwrite,
    should_bump,
    stale_detail,
    writer_view,
)


# ───────────────────────── nagłówki ─────────────────────────


@pytest.mark.parametrize("raw", [None, "", "  ", "abc", "1.5", "-1", True, False])
def test_brak_albo_smieci_w_naglowku_to_stara_aplikacja(raw):
    assert parse_base_rev(raw) is None


@pytest.mark.parametrize("raw,expected", [("0", 0), (" 7 ", 7), (12, 12), ("0012", 12)])
def test_poprawna_wersja_z_naglowka(raw, expected):
    assert parse_base_rev(raw) == expected


def test_nadpisanie_tylko_przy_jawnym_conflict():
    assert parse_overwrite("conflict") is True
    assert parse_overwrite(" Conflict ") is True
    assert parse_overwrite(None) is False
    assert parse_overwrite("") is False
    assert parse_overwrite("yes") is False


# ───────────────────────── is_stale_write ─────────────────────────


def test_stara_aplikacja_bez_naglowka_pisze_jak_dotad():
    assert is_stale_write(None, 9, "inny-telefon", "moj-telefon") is False


def test_wiersz_nigdy_niewersjonowany_nie_ma_z_czym_porownac():
    assert is_stale_write(3, 0, None, "moj-telefon") is False


def test_ta_sama_wersja_przechodzi():
    assert is_stale_write(5, 5, "inny-telefon", "moj-telefon") is False


def test_nowsza_wersja_z_tego_samego_urzadzenia_to_zgubiona_odpowiedz():
    assert is_stale_write(5, 6, "moj-telefon", "moj-telefon") is False


def test_nowsza_wersja_z_innego_urzadzenia_to_konflikt():
    assert is_stale_write(5, 6, "inny-telefon", "moj-telefon") is True


def test_nieznany_autor_nowszej_wersji_to_konflikt():
    """Wersja zapisana przez starego klienta bez identyfikatora instalacji."""
    assert is_stale_write(5, 6, None, "moj-telefon") is True
    assert is_stale_write(5, 6, "", "moj-telefon") is True


def test_puste_urzadzenie_po_obu_stronach_to_nie_ten_sam_autor():
    assert is_stale_write(5, 6, "", "") is True
    assert is_stale_write(5, 6, None, None) is True


def test_swiezy_mecz_nie_nadpisuje_protokolu_sprzed_wersjonowania():
    """Wersja 0 = telefon zaczął od zera. Porzucony mecz na drugim telefonie
    (wiersz bez wersji i bez autora) nie może zniknąć pod pustym meczem."""
    assert is_stale_write(0, 0, None, "moj-telefon") is True
    assert is_stale_write(0, 0, "", "moj-telefon") is True


def test_swiezy_mecz_na_wlasnym_zapisie_przechodzi():
    """Wysłałem POST, odpowiedź zginęła, telefon pisze dalej z wersją 0."""
    assert is_stale_write(0, 0, "moj-telefon", "moj-telefon") is False
    assert is_stale_write(0, 4, "moj-telefon", "moj-telefon") is False


def test_swiezy_mecz_na_cudzym_wersjonowanym_zapisie_to_konflikt():
    assert is_stale_write(0, 4, "inny-telefon", "moj-telefon") is True


def test_swiezy_mecz_bez_protokolu_na_serwerze_nie_ma_konfliktu():
    assert is_stale_write(0, 0, None, "moj-telefon", doc_exists=False) is False


def test_swiadomy_wybor_na_wierszu_niewersjonowanym_przechodzi():
    """Arkusz konfliktu pokazał wersję 0 - wybór własnej musi dać się zapisać."""
    assert is_stale_write(0, 0, None, "moj-telefon", overwrite=True) is False
    # ale nie wtedy, gdy serwer zdążył pójść dalej
    assert is_stale_write(0, 3, "inny-telefon", "moj-telefon", overwrite=True) is True


def test_wersja_z_przyszlosci_od_innego_urzadzenia_tez_jest_konfliktem():
    """Wiersz przywrócony z archiwum zaczyna liczyć od nowa - telefon z wyższą
    wersją nie widział tego, co leży tam teraz."""
    assert is_stale_write(9, 2, "inny-telefon", "moj-telefon") is True


# ───────────────────────── podbijanie wersji ─────────────────────────


def test_zatwierdzenie_i_cofniecie_nie_podbijaja_wersji():
    assert should_bump(approval_transition=True, content_changed=True) is False
    assert should_bump(approval_transition=True, content_changed=False) is False


def test_zmiana_tresci_podbija_a_identyczny_zapis_nie():
    assert should_bump(approval_transition=False, content_changed=True) is True
    assert should_bump(approval_transition=False, content_changed=False) is False


# ───────────────────────── historia przy nadpisaniu ─────────────────────────


def test_swiadome_nadpisanie_cudzej_wersji_odklada_ja_do_historii():
    assert should_archive_on_overwrite(True, "inny-telefon", "moj-telefon") is True
    assert should_archive_on_overwrite(True, None, "moj-telefon") is True


def test_nadpisanie_wlasnej_wersji_nie_robi_duplikatu():
    assert should_archive_on_overwrite(True, "moj-telefon", "moj-telefon") is False


def test_bez_naglowka_nic_nie_trafia_do_historii():
    assert should_archive_on_overwrite(False, "inny-telefon", "moj-telefon") is False


def test_telefon_moze_zglosic_tylko_swoja_przegrana_wersje():
    assert REASON_REJECTED_LOCAL in CLIENT_REASONS
    assert REASON_OVERWRITTEN not in CLIENT_REASONS


# ───────────────────────── kształty odpowiedzi ─────────────────────────


def test_odmowa_niesie_wersje_autora_i_czas_w_detail():
    at = datetime(2026, 9, 11, 18, 30, tzinfo=timezone.utc)
    out = stale_detail(7, "  KOWALSKI Jan ", at)
    assert out == {
        "code": "DOC_STALE",
        "message": STALE_MESSAGE,
        "doc_rev": 7,
        "writer_name": "KOWALSKI Jan",
        "written_at": "2026-09-11T18:30:00+00:00",
        "writer_install_is_you": False,
    }


def test_odmowa_bez_autora_nie_wywraca_sie():
    out = stale_detail(3, None, None)
    assert out["writer_name"] is None
    assert out["written_at"] is None


def test_autor_nie_zdradza_cudzej_instalacji():
    view = writer_view("inny-telefon", "12345", "NOWAK Adam", "moj-telefon")
    assert view == {"install_is_you": False, "judge_id": "12345", "name": "NOWAK Adam"}
    assert "inny-telefon" not in str(view)


def test_autor_to_ja():
    view = writer_view("moj-telefon", "", "", "moj-telefon")
    assert view == {"install_is_you": True, "judge_id": None, "name": None}


def test_nic_nie_wiadomo_o_autorze():
    assert writer_view(None, None, None, "moj-telefon") is None


def test_klucz_dziennika_gasi_ponowienia_z_tego_samego_urzadzenia():
    a = conflict_event_key("SK/8", 6, "moj-telefon")
    assert a == conflict_event_key(" SK/8 ", 6, "moj-telefon")
    assert a != conflict_event_key("SK/8", 7, "moj-telefon")
    assert a != conflict_event_key("SK/8", 6, "inny-telefon")
    assert conflict_event_key("SK/8", 6, None).endswith(":-")


def test_iso():
    assert iso(None) is None
    assert iso("") is None
    assert iso("2026-09-11T10:00:00Z") == "2026-09-11T10:00:00Z"


def test_json_z_bazy_jako_napis_wraca_obiektem():
    from app.proel_doc_version import json_value

    assert json_value('{"a": 1}') == {"a": 1}
    assert json_value(b'[1, 2]') == [1, 2]
    assert json_value({"a": 1}) == {"a": 1}
    assert json_value(None) is None
    assert json_value("nie-json") == "nie-json"


def test_rozmiar_bloba_do_limitu_historii():
    assert payload_bytes({"a": "ż"}) == len('{"a": "ż"}'.encode("utf-8"))
    assert payload_bytes({"x": "a" * 10}) < MAX_HISTORY_BYTES
    assert MAX_HISTORY_BYTES >= 1024 * 1024


def test_komunikat_mowi_co_sie_stalo_i_co_zrobic():
    assert "nie został przyjęty" in STALE_MESSAGE
    assert "wybierz wersję" in STALE_MESSAGE


def test_bez_dlugich_myslnikow_w_nowych_modulach():
    root = Path(__file__).resolve().parents[1] / "app"
    for name in ("proel_doc_version.py", "proel_promote_rules.py"):
        text = (root / name).read_text(encoding="utf-8")
        assert "—" not in text and "–" not in text, name
