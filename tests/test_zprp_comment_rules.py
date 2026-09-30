"""Ramka dodatkowego raportu w uwagach ZPRP - reguły serwera (LCK/17, 29.09.2026).

Dwie rzeczy do upilnowania:
  • limit drogi awaryjnej tnie verte PRZED ramką, nigdy ramkę (była na końcu
    i ginęła pierwsza),
  • samodzielny dopisek raportu to osobne zdarzenie dziennika, które nie
    składa się w „przerwaną wysyłkę pełnych danych".
"""

from datetime import datetime, timedelta, timezone

from app.proel_journal import (
    EVENT_LABELS,
    _effective_event,
    collapse_full_data_run,
    event_summary,
)
from app.proel_post_marks import REFRESHED_TASKS, SERVER_MARKED_TASKS
from app.zprp_comment_rules import (
    EVENT_COMMENT,
    EVENT_EXTRA_REPORT_COMMENT,
    EVENT_EXTRA_REPORT_VERIFIED,
    EXTRA_REPORT_FOOTER,
    EXTRA_REPORT_HEADER,
    comment_journal_event,
    extract_extra_block,
    fit_comment_limit,
    has_extra_block,
    preserve_extra_block,
    strip_extra_blocks,
)

BLOCK = "\n".join([EXTRA_REPORT_HEADER, "1. Czerwona kartka nr 7.", EXTRA_REPORT_FOOTER])


# ───────────────────────── limit drogi awaryjnej ─────────────────────────


def test_krotki_tekst_bez_zmian():
    text = f"Verte\n\n{BLOCK}"
    assert fit_comment_limit(text) == (text, False)


def test_limit_tnie_verte_przed_ramka_i_zglasza_przyciecie():
    text = "x" * 3000 + "\n\n" + BLOCK
    out, cut = fit_comment_limit(text, limit=500)
    assert cut is True
    assert len(out) <= 500
    assert out.endswith(BLOCK)
    assert extract_extra_block(out) == BLOCK


def test_limit_bez_ramki_tnie_od_konca():
    out, cut = fit_comment_limit("a" * 30, limit=10)
    assert (out, cut) == ("a" * 10, True)


def test_ramka_dluzsza_od_limitu_jest_przycieta_i_zgloszona():
    big = "\n".join([EXTRA_REPORT_HEADER, "1. " + "y" * 600, EXTRA_REPORT_FOOTER])
    out, cut = fit_comment_limit("Verte\n\n" + big, limit=100)
    assert cut is True
    assert out.startswith(EXTRA_REPORT_HEADER)
    assert len(out) <= 100


# ───────────────────────── ramka nie znika ─────────────────────────


def test_tekst_bez_ramki_nie_zdejmuje_ramki_z_pola():
    assert preserve_extra_block(f"Stare\n\n{BLOCK}", "Nowe verte") == f"Nowe verte\n\n{BLOCK}"


def test_tekst_z_ramka_idzie_doslownie():
    other = BLOCK.replace("7", "9")
    assert preserve_extra_block(f"V\n\n{BLOCK}", f"V\n\n{other}") == f"V\n\n{other}"


def test_bez_ramki_w_polu_nic_nie_dokleja():
    assert preserve_extra_block("Stare", "Nowe") == "Nowe"
    assert preserve_extra_block("", "") == ""


def test_zdejmowanie_ramek():
    assert strip_extra_blocks(f"V\n\n{BLOCK}\n\n{BLOCK}") == "V"
    assert has_extra_block(f"V\r\n\r\n{BLOCK}") is True
    assert has_extra_block("V") is False


# ───────────────────────── dziennik ─────────────────────────


def test_samodzielny_dopisek_ma_wlasne_zdarzenie():
    event, details = comment_journal_event("extra-report", f"V\n\n{BLOCK}")
    assert event == EVENT_EXTRA_REPORT_COMMENT
    assert details == {"hasExtraBlock": True, "length": len(f"V\n\n{BLOCK}")}


def test_starszy_klient_i_pelne_dane_zostaja_przy_comment_sent():
    assert comment_journal_event(None, "V")[0] == EVENT_COMMENT
    assert comment_journal_event("full", "V")[0] == EVENT_COMMENT
    assert comment_journal_event(None, "V")[1]["hasExtraBlock"] is False


def test_nowe_zdarzenia_maja_etykiety_i_zdania():
    for ev in (EVENT_EXTRA_REPORT_COMMENT, EVENT_EXTRA_REPORT_VERIFIED):
        assert ev in EVENT_LABELS
    assert "Z ramką" in event_summary(EVENT_EXTRA_REPORT_COMMENT, {"hasExtraBlock": True, "length": 120})
    assert "Bez ramki" in event_summary(EVENT_COMMENT, {"hasExtraBlock": False, "length": 5})
    assert "uratowana" in event_summary(EVENT_EXTRA_REPORT_VERIFIED, {"preserved": True})


def test_dopisek_raportu_nie_jest_przerwana_wysylka_pelnych_danych():
    t0 = datetime(2026, 9, 29, 18, 0, tzinfo=timezone.utc)
    row = {
        "id": 1,
        "match_number": "LCK/17",
        "zprp_match_id": "210000",
        "event": EVENT_EXTRA_REPORT_COMMENT,
        "created_at": t0,
        "details_json": {"hasExtraBlock": True, "length": 300},
    }
    out = collapse_full_data_run([row], now=t0 + timedelta(hours=2))
    assert len(out) == 1
    assert out[0]["event"] == EVENT_EXTRA_REPORT_COMMENT
    assert not out[0]["details_json"].get("stalled")
    assert _effective_event(EVENT_EXTRA_REPORT_COMMENT, out[0]["details_json"]) == EVENT_EXTRA_REPORT_COMMENT


def test_uwagi_z_pelnych_danych_dalej_skladaja_sie_w_serie():
    t0 = datetime(2026, 9, 29, 18, 0, tzinfo=timezone.utc)
    row = {
        "id": 1,
        "match_number": "LCK/17",
        "zprp_match_id": "210000",
        "event": EVENT_COMMENT,
        "created_at": t0,
        "details_json": {},
    }
    out = collapse_full_data_run([row], now=t0 + timedelta(hours=2))
    assert out[0]["details_json"].get("stalled") is True


def test_znacznik_raportu_odswiezany_przez_serwer():
    assert "extraReportInZprp" in SERVER_MARKED_TASKS
    assert "extraReportInZprp" in REFRESHED_TASKS
    assert "fullDataSent" not in REFRESHED_TASKS
