"""Dziennik meczu: scalanie zmian pól, podpisy, raport dodatkowy.

Zgłoszenie z 12.09.2026: panel przy meczu LCM/5 pokazywał trzydzieści wierszy
„Zmieniono: osoba towarzysząca B gości - licencja" i ani jednej wysyłki. Te
testy pilnują obu stron tej sprawy: żeby ściana wpisów zeszła do jednego
wiersza, a czynności (podpis, raport) miały własne zdania.
"""

from datetime import datetime, timedelta, timezone

from app.proel_journal import (
    EVENT_LABELS,
    _effective_event,
    _row_out,
    collapse_duplicate_sends,
    describe_field,
    event_summary,
    merge_field_changes,
    signature_events_from_ops,
)

T0 = datetime(2026, 9, 11, 18, 46, tzinfo=timezone.utc)


def _row(id_: int, *, event="field.changed", paths=None, at=T0, judge="5635", **over):
    base = {
        "id": id_,
        "match_number": "LCM/5",
        "zprp_match_id": "206737",
        "event": event,
        "actor_judge_id": judge,
        "actor_name": "SKORUPA Jakub",
        "actor_install": "ins_j3i4t73pmu",
        "actor_verified": True,
        "details_json": {"paths": list(paths or []), "rev": id_},
        "app_version": "2.0.3",
        "client_ip": "10.0.0.1",
        "created_at": at,
    }
    base.update(over)
    return base


# ───────────────────────── scalanie zmian pól ─────────────────────────


def test_kolejne_poprawki_jednej_osoby_to_jeden_wiersz():
    rows = [
        _row(30, paths=["companion.guest.B.license"], at=T0),
        _row(29, paths=["companion.guest.B.function"], at=T0 - timedelta(seconds=20)),
        _row(28, paths=["companion.guest.B.fullName"], at=T0 - timedelta(seconds=40)),
    ]
    out = merge_field_changes(rows)
    assert len(out) == 1
    details = out[0]["details_json"]
    assert details["merged"] == 3
    assert len(details["paths"]) == 3
    # Wiersz zostaje pod NAJNOWSZYM id - kursor stronicowania idzie po id.
    assert out[0]["id"] == 30
    assert details["since"].startswith("2026-09-11T18:45:20")


def test_zdanie_scalonego_wiersza_mowi_ile_pol():
    rows = [
        _row(30, paths=["companion.guest.B.license"]),
        _row(29, paths=["companion.guest.B.function"], at=T0 - timedelta(seconds=20)),
    ]
    out = _row_out(merge_field_changes(rows)[0])
    assert out["summary"].startswith("Zmieniono 2 pola: ")
    assert out["merged"] == 2
    assert "osoba towarzysząca B gości - licencja" in out["summary"]


def test_prace_dwoch_osob_zostaja_osobno():
    rows = [
        _row(30, paths=["post.notesText"], judge="5635"),
        _row(29, paths=["post.spectatorsCount"], judge="5124", at=T0 - timedelta(seconds=5)),
    ]
    assert len(merge_field_changes(rows)) == 2


def test_poprawka_po_godzinie_to_osobne_wejscie():
    rows = [
        _row(30, paths=["post.notesText"]),
        _row(29, paths=["post.spectatorsCount"], at=T0 - timedelta(hours=1)),
    ]
    assert len(merge_field_changes(rows)) == 2


def test_wysylka_i_podpis_nie_wpadaja_do_worka_ze_zmianami():
    rows = [
        _row(31, paths=["post.shortResultSent"]),
        _row(30, paths=["companion.guest.B.license"], at=T0 - timedelta(seconds=10)),
        _row(29, paths=["sig.team.host"], at=T0 - timedelta(seconds=20)),
        _row(28, paths=["companion.guest.B.function"], at=T0 - timedelta(seconds=30)),
    ]
    out = [_row_out(r) for r in merge_field_changes(rows)]
    assert [r["event"] for r in out] == [
        "zprp.summary_sent",
        "field.changed",
        "match.signed",
        "field.changed",
    ]


# ─────────────────── ta sama wysyłka z dwóch stron ───────────────────


def test_slad_serwera_i_znacznik_telefonu_to_jedna_wysylka():
    rows = [
        # Znacznik z telefonu (nowszy, niesie okoliczności).
        _row(41, paths=["post.shortResultSent"], details_json={"paths": ["post.shortResultSent"], "via": "official"}),
        # Ślad serwera z chwili wysyłki.
        _row(
            40,
            event="zprp.summary_sent",
            at=T0 - timedelta(seconds=3),
            details_json={"src": "server", "fields": 12},
        ),
    ]
    out = collapse_duplicate_sends(rows)
    assert len(out) == 1
    assert out[0]["id"] == 41
    assert out[0]["details_json"]["merged"] == 2


def test_powtorna_wysylka_po_czasie_zostaje_osobnym_wierszem():
    rows = [
        _row(41, event="zprp.summary_sent", details_json={"src": "server"}),
        _row(
            40,
            event="zprp.summary_sent",
            at=T0 - timedelta(hours=2),
            details_json={"src": "server"},
        ),
    ]
    assert len(collapse_duplicate_sends(rows)) == 2


# ───────────────────────────── podpisy ─────────────────────────────


def test_same_podpisy_daja_zdarzenie_podpisu():
    out = signature_events_from_ops(
        [("official.referee1.signature", "data:image/png;base64,AAA"), ("sig.team.host", "x")]
    )
    assert out[0][0] == "match.signed"
    assert [s["who"] for s in out[0][1]["signatures"]] == ["sędzia 1", "drużyna gospodarzy"]


def test_w_szczegolach_nie_ma_samego_podpisu():
    _, details = signature_events_from_ops(
        [("official.referee2.signature", "data:image/png;base64,DLUGI_OBRAZEK")]
    )[0]
    assert "DLUGI_OBRAZEK" not in str(details)


def test_wyczyszczony_podpis_to_inne_zdarzenie():
    out = signature_events_from_ops([("medic.signature", "")])
    assert out[0][0] == "match.signature_removed"
    assert event_summary("match.signature_removed", out[0][1]) == "Usunięto podpis: medyk"


def test_patch_mieszany_zostaje_zwykla_zmiana_pol():
    assert signature_events_from_ops(
        [("sig.team.host", "x"), ("post.notesText", "cokolwiek")]
    ) == []


def test_stary_wpis_o_podpisie_nie_zgaduje_czy_doszedl():
    details = {"paths": ["official.secretary.signature"]}
    assert _effective_event("field.changed", details) == "match.signed"
    assert event_summary("match.signed", details) == "Podpis: sekretarz"


def test_podpis_medyka_ma_nazwe_a_nie_sciezke():
    assert describe_field("medic.signature") == "medyk - podpis"
    assert describe_field("medic.fullName") == "medyk - nazwisko"


# ──────────────────────── raport dodatkowy ────────────────────────


def test_zlozenie_raportu_mowi_czyj_i_ile_opisow():
    assert EVENT_LABELS["report.submitted"] == "Złożenie raportu dodatkowego"
    assert (
        event_summary("report.submitted", {"kind": "referee", "entries": 3})
        == "Złożono raport sędziów (3 opisy)"
    )
    assert (
        event_summary("report.submitted", {"kind": "delegate", "entries": 1})
        == "Złożono raport delegata (1 opis)"
    )
