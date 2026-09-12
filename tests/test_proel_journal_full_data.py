"""Dziennik meczu: seria „Zapisz pełne dane meczu" jako jeden wiersz.

Decyzja z 12.09.2026: wysyłka pełnych danych zgłasza się DWA razy - początkiem
(żądania przepuszczane przez nasz serwer) i końcem (`/proel/zprp/full-data-done`
po potwierdzonym sukcesie). Dziennik czeka na obie połowy i dopiero wtedy
decyduje, co pokazać. Te testy pilnują właśnie tego czekania, bo bez niego
administrator nie odróżni „wysłali i doszło" od „próbowali i się urwało".
"""

from datetime import datetime, timedelta, timezone

from app.proel_journal import (
    _row_out,
    collapse_full_data_run,
    event_summary,
)

T0 = datetime(2026, 9, 11, 18, 46, tzinfo=timezone.utc)


def _row(id_, *, event, at, match="206737", details=None):
    return {
        "id": id_,
        "match_number": "LCM/5",
        "zprp_match_id": match,
        "event": event,
        "actor_judge_id": "5635",
        "actor_name": "SKORUPA Jakub",
        "actor_install": "ins_j3i4t73pmu",
        "actor_verified": True,
        "details_json": dict(details or {}),
        "app_version": "2.0.3",
        "client_ip": "10.0.0.1",
        "created_at": at,
    }


def _run_rows(end=True):
    """Typowa seria, od najnowszego wiersza - tak czyta ją dziennik."""
    rows = []
    if end:
        rows.append(
            _row(
                40,
                event="zprp.full_data_sent",
                at=T0,
                details={"via": "official", "attempts": 1},
            )
        )
    rows += [
        _row(39, event="zprp.comment_sent", at=T0 - timedelta(seconds=8)),
        _row(38, event="zprp.officials_sent", at=T0 - timedelta(seconds=30)),
        _row(37, event="zprp.players_sent", at=T0 - timedelta(seconds=95)),
    ]
    return rows


def test_udana_seria_to_jeden_wiersz_o_koncu():
    out = collapse_full_data_run(_run_rows(), now=T0 + timedelta(minutes=1))
    assert [r["event"] for r in out] == ["zprp.full_data_sent"]
    details = out[0]["details_json"]
    # Trzy części wsiąkły w wiersz końca, a godzina mówi, od kiedy trwało.
    assert details["merged"] == 4
    assert details["since"].startswith("2026-09-11T18:44:25")


def test_brak_konca_zostawia_poczatek_jako_przerwane():
    out = collapse_full_data_run(
        _run_rows(end=False), now=T0 + timedelta(hours=2)
    )
    assert len(out) == 1
    row = out[0]
    # Zostaje NAJSTARSZY wiersz serii - to on jest jej początkiem.
    assert row["id"] == 37
    assert _row_out(row)["event"] == "zprp.full_data_stalled"
    assert "3 zapisów doszło" in _row_out(row)["summary"]


def test_swieza_seria_bez_konca_to_jeszcze_nie_awaria():
    out = collapse_full_data_run(
        _run_rows(end=False), now=T0 + timedelta(seconds=30)
    )
    assert _row_out(out[0])["event"] == "zprp.full_data_running"


def test_koniec_starszy_od_czesci_nie_przygarnia_ich():
    """Koniec POPRZEDNIEJ wysyłki nie może domknąć następnej.

    Sędzia poprawia skład i wysyła drugi raz; gdyby pary szukać bez względu na
    kolejność w czasie, druga seria wyglądałaby na zakończoną tym, co zamknęło
    pierwszą - i przerwana wysyłka zniknęłaby z dziennika.
    """
    rows = [
        _row(42, event="zprp.players_sent", at=T0 + timedelta(minutes=40)),
        _row(41, event="zprp.full_data_sent", at=T0),
        _row(37, event="zprp.players_sent", at=T0 - timedelta(seconds=95)),
    ]
    out = collapse_full_data_run(rows, now=T0 + timedelta(hours=3))
    assert [_row_out(r)["event"] for r in out] == [
        "zprp.full_data_stalled",
        "zprp.full_data_sent",
    ]


def test_serie_dwoch_meczow_nie_mieszaja_sie():
    rows = [
        _row(51, event="zprp.full_data_sent", at=T0, match="206737"),
        _row(50, event="zprp.players_sent", at=T0 - timedelta(seconds=20), match="999"),
        _row(49, event="zprp.players_sent", at=T0 - timedelta(seconds=40), match="206737"),
    ]
    out = collapse_full_data_run(rows, now=T0 + timedelta(hours=2))
    events = [_row_out(r)["event"] for r in out]
    # Mecz 206737 domknięty, mecz 999 zostaje z własnym, przerwanym początkiem.
    assert events == ["zprp.full_data_sent", "zprp.full_data_stalled"]


def test_zdanie_przerwanej_serii_mowi_o_ryzyku():
    sentence = event_summary("zprp.full_data_stalled", {"merged": 1})
    assert sentence.startswith("Wysyłka nie zgłosiła końca - jeden zapis doszedł")
    assert "bazie ZPRP" in sentence
