"""Testy rejestru pól ProEl — czysta logika, bez bazy.

Najważniejszy test w tym pliku to `test_projection_survives_full_blob_overwrite`:
odtwarza sytuację, w której sędzia potwierdza badania na swoim telefonie, a
telefon prowadzącego mecz wysyła w tym czasie swój pełny snapshot. Bez
reprojekcji potwierdzenie znikało w ciągu minuty.
"""
from __future__ import annotations

import pytest

from app.proel_fields import (
    EXAM_RANK,
    PathRejected,
    UnknownPath,
    live_signal,
    normalize_name,
    parse_path,
    project,
)


def entry(value, **kw):
    """Wpis overlaya w kształcie, jaki zapisuje `/proel/patch`."""
    e = {"v": value, "rev": 1, "at": "2026-08-14T10:00:00Z", "by": {}, "src": "patch"}
    e.update(kw)
    return e


def blob_with_cards(host=None, guest=None):
    return {
        "matchConfig": {
            "matchNumber": "OSK/12",
            "hostPlayerCards": host if host is not None else [],
            "guestPlayerCards": guest if guest is not None else [],
        }
    }


# ─────────────────────────── ścieżki ───────────────────────────


def test_parse_path_exam():
    spec, params = parse_path("exam.host.#7")
    assert spec.name == "exam"
    assert params == {"team": "host", "num": "7"}


def test_parse_path_official():
    spec, params = parse_path("official.delegate.signature")
    assert spec.name == "official"
    assert params == {"role": "delegate", "leaf": "signature"}


@pytest.mark.parametrize(
    "bad",
    [
        "exam.host.7",  # brak #
        "exam.both.#7",  # nieznana drużyna
        "matchConfig.hostPlayers",  # goły JSON-pointer
        "official.kapitan.signature",  # nieznana rola
        "",
    ],
)
def test_unknown_paths_are_rejected(bad):
    with pytest.raises(UnknownPath):
        parse_path(bad)


# ─────────────────────────── krata badań ───────────────────────────


def test_exam_rank_matches_client_order():
    # Musi się zgadzać z BAZA/utils/playerExam.ts
    assert EXAM_RANK["none"] < EXAM_RANK["manual"] < EXAM_RANK["wzpr"] < EXAM_RANK["zprp"]


def test_exam_merge_is_idempotent_and_commutative():
    spec, _ = parse_path("exam.host.#7")
    manual = {"mark": "manual", "name": "kowalski jan"}
    # idempotencja: to samo dwa razy
    assert spec.merge(entry(manual), manual, False) == manual
    # przemienność: „potwierdź" wygrywa niezależnie od kolejności
    none_v = {"mark": "none", "name": "kowalski jan"}
    assert spec.merge(entry(none_v), manual, False) == manual
    with pytest.raises(PathRejected):
        spec.merge(entry(manual), none_v, False)


def test_exam_downgrade_requires_force():
    spec, _ = parse_path("exam.host.#7")
    manual = {"mark": "manual", "name": "kowalski jan"}
    none_v = {"mark": "none", "name": "kowalski jan"}
    assert spec.merge(entry(manual), none_v, True) == none_v


def test_exam_rejects_unknown_mark():
    spec, _ = parse_path("exam.host.#7")
    with pytest.raises(PathRejected):
        spec.merge(None, {"mark": "byle_co"}, False)


# ─────────────────────────── projekcja ───────────────────────────


def test_projection_writes_mark_onto_card():
    blob = blob_with_cards(host=[{"number": 7, "fullName": "KOWALSKI Jan"}])
    project(
        {"exam.host.#7": entry({"mark": "manual", "name": "KOWALSKI Jan"})},
        blob,
    )
    assert blob["matchConfig"]["hostPlayerCards"][0]["exam"] == "manual"


def test_api_mark_always_beats_manual():
    """ZPRP/WZPR z API wygrywa — ręcznie da się tylko uzupełnić brak."""
    blob = blob_with_cards(
        host=[{"number": 7, "fullName": "KOWALSKI Jan", "exam": "zprp"}]
    )
    project({"exam.host.#7": entry({"mark": "manual", "name": "KOWALSKI Jan"})}, blob)
    assert blob["matchConfig"]["hostPlayerCards"][0]["exam"] == "zprp"


def test_unconfirm_removes_mark_from_card():
    blob = blob_with_cards(
        host=[{"number": 7, "fullName": "KOWALSKI Jan", "exam": "manual"}]
    )
    project({"exam.host.#7": entry({"mark": "none", "name": "KOWALSKI Jan"})}, blob)
    assert "exam" not in blob["matchConfig"]["hostPlayerCards"][0]


def test_match_by_name_survives_number_change():
    """Numer zmieniony tuż przed meczem nie może gubić potwierdzenia."""
    blob = blob_with_cards(host=[{"number": 21, "fullName": "KOWALSKI Jan"}])
    project({"exam.host.#7": entry({"mark": "manual", "name": "KOWALSKI Jan"})}, blob)
    assert blob["matchConfig"]["hostPlayerCards"][0]["exam"] == "manual"


def test_match_by_number_when_name_missing():
    blob = blob_with_cards(host=[{"number": 7}])
    project({"exam.host.#7": entry({"mark": "manual", "name": ""})}, blob)
    assert blob["matchConfig"]["hostPlayerCards"][0]["exam"] == "manual"


def test_projection_never_invents_a_card():
    blob = blob_with_cards(host=[])
    project({"exam.host.#7": entry({"mark": "manual", "name": "KOWALSKI Jan"})}, blob)
    assert blob["matchConfig"]["hostPlayerCards"] == []


def test_projection_is_idempotent():
    blob = blob_with_cards(host=[{"number": 7, "fullName": "KOWALSKI Jan"}])
    overlay = {"exam.host.#7": entry({"mark": "manual", "name": "KOWALSKI Jan"})}
    project(overlay, blob)
    once = [dict(c) for c in blob["matchConfig"]["hostPlayerCards"]]
    project(overlay, blob)
    assert blob["matchConfig"]["hostPlayerCards"] == once


def test_superseded_entries_are_not_projected():
    blob = blob_with_cards(host=[{"number": 7, "fullName": "KOWALSKI Jan"}])
    project(
        {
            "exam.host.#7": entry(
                {"mark": "manual", "name": "KOWALSKI Jan"},
                superseded_at="2026-08-14T11:00:00Z",
            )
        },
        blob,
    )
    assert "exam" not in blob["matchConfig"]["hostPlayerCards"][0]


def test_unknown_overlay_path_does_not_break_projection():
    """Wpis z nowszego serwera nie może wywrócić projekcji starszemu."""
    blob = blob_with_cards(host=[{"number": 7, "fullName": "KOWALSKI Jan"}])
    project(
        {
            "cos.czego.nie.znam": entry("x"),
            "exam.host.#7": entry({"mark": "manual", "name": "KOWALSKI Jan"}),
        },
        blob,
    )
    assert blob["matchConfig"]["hostPlayerCards"][0]["exam"] == "manual"


def test_projection_survives_full_blob_overwrite():
    """TO JEST TEST R3.

    Telefon prowadzącego wysyła świeży, kompletny blob zbudowany z własnego
    stanu — bez żadnej wiedzy o badaniach. Po reprojekcji potwierdzenie
    sędziego nadal tam jest.
    """
    overlay = {"exam.host.#7": entry({"mark": "manual", "name": "KOWALSKI Jan"})}
    incoming_from_match_screen = blob_with_cards(
        host=[{"number": 7, "fullName": "KOWALSKI Jan"}]
    )
    incoming_from_match_screen["scoreHost"] = 12
    project(overlay, incoming_from_match_screen)
    assert incoming_from_match_screen["matchConfig"]["hostPlayerCards"][0]["exam"] == "manual"


# ─────────────────────────── podpisy ───────────────────────────


def test_signature_is_write_once():
    spec, _ = parse_path("sig.team.host")
    assert spec.merge(None, "/static/a.png", False) == "/static/a.png"
    # ten sam URL ponownie (ponowienie z outboxa) — przechodzi
    assert spec.merge(entry("/static/a.png"), "/static/a.png", False) == "/static/a.png"
    with pytest.raises(PathRejected) as ei:
        spec.merge(entry("/static/a.png"), "/static/b.png", False)
    assert ei.value.code == "SIGNATURE_EXISTS"
    # delegat z force może podmienić
    assert spec.merge(entry("/static/a.png"), "/static/b.png", True) == "/static/b.png"


def test_official_signature_projection():
    blob = {"matchConfig": {}}
    project({"official.delegate.signature": entry("/static/d.png")}, blob)
    assert (
        blob["matchConfig"]["extras"]["officials"]["delegate"]["signature"]
        == "/static/d.png"
    )


def test_post_field_projection():
    blob = {"matchConfig": {}}
    project({"post.spectatorsCount": entry(350)}, blob)
    assert blob["matchConfig"]["extras"]["spectatorsCount"] == 350


# ─────────────────────────── fazy ───────────────────────────


def test_exam_is_writable_in_every_phase():
    spec, _ = parse_path("exam.host.#7")
    assert set(spec.phases) == {"pre", "live", "post"}


def test_post_fields_are_post_only():
    spec, _ = parse_path("post.spectatorsCount")
    assert spec.phases == ("post",)


def test_notes_are_writable_before_and_after():
    spec, _ = parse_path("post.notesText")
    assert set(spec.phases) == {"pre", "post"}


# ─────────────────────────── live_signal ───────────────────────────


@pytest.mark.parametrize(
    "blob,expected",
    [
        ({}, False),
        ({"matchConfig": {}}, False),
        ({"isGameRunning": True}, True),
        ({"isFirstHalf": False}, True),
        ({"penaltyShootoutActive": True}, True),
        ({"mainTime": 1}, True),
        ({"mainTime": 0}, False),
        ({"scoreHost": 1, "scoreGuest": 0}, True),
        ({"scoreHost": 0, "scoreGuest": 0}, False),
        ({"protocol": [{"t": 1}]}, True),
        ({"protocol": []}, False),
        ({"goalHistory": [{"t": 1}]}, True),
        ({"isFirstHalf": True, "scoreHost": 0}, False),
        (None, False),
    ],
)
def test_live_signal(blob, expected):
    assert live_signal(blob) is expected


# ─────────────────────────── normalizacja ───────────────────────────


def test_normalize_name_strips_diacritics_and_case():
    assert normalize_name("KOWALSKI Jan") == "kowalski jan"
    assert normalize_name("  ŻÓŁĆ   Ćwikła ") == "zołc cwikła"
    assert normalize_name(None) == ""


def test_normalize_name_matches_the_typescript_port_exactly():
    """Kontrakt międzyjęzykowy z `BAZA/utils/matchRole.ts:normalizeName`.

    Obie strony robią NFKD + usunięcie znaków łączących (U+0300–U+036F), więc
    obie zostawiają „ł" NIETKNIĘTE — U+0142 to osobny znak, nie „l" + kreska,
    i NFKD go nie rozkłada. To NIE jest przeoczenie: dopasowanie zawodnika
    działa tylko wtedy, gdy klient i serwer normalizują identycznie.
    Gdyby kiedyś dokładać tu mapowanie ł→l, trzeba je dodać PO OBU stronach
    naraz, inaczej potwierdzenia badań przestaną trafiać w karty.
    """
    assert normalize_name("Żółć") == "zołc"
    assert normalize_name("Ćwikła") == "cwikła"
    assert normalize_name("Łukasz") == "łukasz"
    # spacje zwijane, wielkość liter bez znaczenia
    assert normalize_name("  NOWAK   Piotr  ") == "nowak piotr"
