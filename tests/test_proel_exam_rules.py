"""Badania w ProElu: reguły bez bazy i bez sieci (`app/proel_fields.py`).

Dwa zgłoszenia z SK/5 (GAKIDOVA, nr 77), które te testy zamieniają w reguły:

* ręczne potwierdzenie z ekranu konfiguracji jedzie tylko w kartach bloba i
  nie zostawiało śladu - teraz wchodzi do overlaya, ale wyłącznie w górę i z
  cofnięciem tylko z tego samego urządzenia,
* baza związku potwierdziła badania po fakcie, a ręczny ptaszek został -
  teraz awansuje, ale tylko wtedy, gdy API mówi „OK" o TYM zawodniku.
"""
from __future__ import annotations

from app.proel_fields import (
    EXAM_SRC_BLOB,
    adopt_blob_exams,
    blob_exam_cards,
    exam_entry,
    exam_mark_from_roster,
    exam_path,
    has_manual_exams,
    manual_exam_candidates,
    project,
    PHASE_PRE,
    exam_mark_meets,
    exam_recheck_from_blob,
    phase_of,
    promotions_for,
    roster_marks,
)
from app.proel_journal import event_summary
from app.protocol_category import exam_requirement_for_code


def blob(host=None, guest=None):
    return {
        "matchConfig": {
            "matchNumber": "SK/5",
            "hostPlayerCards": host if host is not None else [],
            "guestPlayerCards": guest if guest is not None else [],
        }
    }


def entry(mark, name="", src="patch", install="tel-1", **kw):
    e = exam_entry(mark, name, rev=1, at="2026-09-05T12:50:00Z", by={"install": install}, src=src)
    e.update(kw)
    return e


GAKIDOVA = {"number": 77, "fullName": "GAKIDOVA Ivana", "exam": "manual"}


# ───────────────────────── co mówi API ─────────────────────────


def test_roster_record_maps_to_the_same_marks_as_the_app():
    assert exam_mark_from_roster({"badania_ZPRP": "OK", "badania_WZPR": "OK"}) == "zprp"
    assert exam_mark_from_roster({"badania_ZPRP": "", "badania_WZPR": "OK"}) == "wzpr"
    assert exam_mark_from_roster({"badania_ZPRP": "", "badania_WZPR": ""}) == "none"
    # Ta sama biała lista, co w `playerExam.ts` - gdyby ZPRP zmieniło token.
    assert exam_mark_from_roster({"badania_ZPRP": "tak"}) == "zprp"
    assert exam_mark_from_roster(None) == "none"


def test_roster_marks_keep_the_nominal_sides():
    payload = {
        "gosp": {"107443": {"NrKoszulki": "77", "nazwisko": "GAKIDOVA", "imie": "Ivana", "badania_ZPRP": "OK"}},
        "gosc": [{"NrKoszulki": "3", "nazwisko": "NOWAK", "imie": "Anna", "badania_WZPR": "OK"}],
    }
    marks = roster_marks(payload)
    assert marks["host"] == [{"number": 77, "name": "GAKIDOVA Ivana", "mark": "zprp"}]
    assert marks["guest"] == [{"number": 3, "name": "NOWAK Anna", "mark": "wzpr"}]
    assert roster_marks(None) == {"host": [], "guest": []}


# ───────────────────────── karty bloba ─────────────────────────


def test_blob_cards_carry_path_team_and_mark():
    cards = blob_exam_cards(blob(host=[GAKIDOVA, {"number": 5, "fullName": "X Y", "exam": "zprp"}, {"fullName": "bez numeru", "exam": "manual"}]))
    assert cards == [
        {"path": "exam.host.#77", "team": "host", "number": 77, "name": "GAKIDOVA Ivana", "mark": "manual"},
        {"path": "exam.host.#5", "team": "host", "number": 5, "name": "X Y", "mark": "zprp"},
    ]
    assert has_manual_exams(blob(host=[GAKIDOVA]))
    assert not has_manual_exams(blob(host=[{"number": 5, "exam": "zprp"}]))
    assert not has_manual_exams("nie blob")


# ───────────────────────── wchłanianie z bloba ─────────────────────────


def test_manual_card_enters_the_overlay_with_the_writers_signature():
    out, confirmed, withdrawn = adopt_blob_exams(
        {}, blob(host=[GAKIDOVA]), rev=4, at="T", by={"install": "tel-1", "name": "KORNEK Mikołaj"}, install="tel-1"
    )
    assert confirmed == [{"team": "host", "number": 77, "name": "GAKIDOVA Ivana"}]
    assert withdrawn == []
    got = out["exam.host.#77"]
    assert got["v"] == {"mark": "manual", "name": "GAKIDOVA Ivana"}
    assert got["src"] == EXAM_SRC_BLOB
    assert got["by"]["name"] == "KORNEK Mikołaj"
    assert got["rev"] == 4


def test_overlay_that_already_knows_is_left_alone():
    overlay = {"exam.host.#77": entry("manual", "GAKIDOVA Ivana")}
    out, confirmed, _ = adopt_blob_exams(overlay, blob(host=[GAKIDOVA]), rev=2, at="T", by={}, install="tel-1")
    assert confirmed == []
    assert out["exam.host.#77"] is overlay["exam.host.#77"]
    # Wyższy stopień z API tym bardziej zostaje.
    overlay = {"exam.host.#77": entry("zprp", "GAKIDOVA Ivana", src="zprp")}
    out, confirmed, _ = adopt_blob_exams(overlay, blob(host=[GAKIDOVA]), rev=2, at="T", by={}, install="tel-1")
    assert confirmed == [] and out["exam.host.#77"]["v"]["mark"] == "zprp"


def test_api_marks_on_cards_are_not_adopted():
    out, confirmed, _ = adopt_blob_exams({}, blob(host=[{"number": 5, "fullName": "X Y", "exam": "zprp"}]), rev=1, at="T", by={}, install="tel-1")
    assert out == {} and confirmed == []


def test_withdrawal_only_by_the_device_that_confirmed_and_only_from_blob_entries():
    card_without = {"number": 77, "fullName": "GAKIDOVA Ivana"}
    mine = {"exam.host.#77": entry("manual", "GAKIDOVA Ivana", src=EXAM_SRC_BLOB, install="tel-1")}
    # To samo urządzenie cofa.
    out, _, withdrawn = adopt_blob_exams(mine, blob(host=[card_without]), rev=3, at="T", by={}, install="tel-1")
    assert withdrawn == [{"team": "host", "number": 77, "name": "GAKIDOVA Ivana"}]
    assert out["exam.host.#77"]["v"]["mark"] == "none"
    # Drugi telefon, który o potwierdzeniu nie wie, nie ma prawa go skasować.
    out, _, withdrawn = adopt_blob_exams(mine, blob(host=[card_without]), rev=3, at="T", by={}, install="tel-2")
    assert withdrawn == [] and out["exam.host.#77"]["v"]["mark"] == "manual"
    # Potwierdzenie z arkusza (`patch`) cofa się tylko w arkuszu, z `force`.
    sheet = {"exam.host.#77": entry("manual", "GAKIDOVA Ivana", src="patch", install="tel-1")}
    out, _, withdrawn = adopt_blob_exams(sheet, blob(host=[card_without]), rev=3, at="T", by={}, install="tel-1")
    assert withdrawn == [] and out["exam.host.#77"]["v"]["mark"] == "manual"


def test_adoption_is_a_copy_and_is_idempotent():
    overlay = {}
    out1, c1, _ = adopt_blob_exams(overlay, blob(host=[GAKIDOVA]), rev=1, at="T", by={}, install="tel-1")
    assert overlay == {}
    out2, c2, _ = adopt_blob_exams(out1, blob(host=[GAKIDOVA]), rev=2, at="T", by={}, install="tel-1")
    assert c1 and not c2
    assert out2 == out1


# ───────────────────────── kandydaci i awans ─────────────────────────


def test_candidates_come_from_overlay_and_cards_without_duplicates():
    overlay = {"exam.host.#77": entry("manual", "GAKIDOVA Ivana")}
    cands = manual_exam_candidates(overlay, blob(host=[GAKIDOVA, {"number": 9, "fullName": "INNA Osoba", "exam": "manual"}]))
    assert [c["path"] for c in cands] == ["exam.host.#77", "exam.host.#9"]
    # Overlay, który już ma stopień z API, nie pyta o nic.
    overlay = {"exam.host.#77": entry("zprp", "GAKIDOVA Ivana", src="zprp")}
    assert manual_exam_candidates(overlay, blob(host=[GAKIDOVA])) == []
    assert manual_exam_candidates({}, blob(host=[{"number": 5, "exam": "zprp"}])) == []


def test_promotion_only_where_the_union_says_ok():
    cands = manual_exam_candidates({}, blob(host=[GAKIDOVA, {"number": 9, "fullName": "INNA Osoba", "exam": "manual"}]))
    marks = {
        "host": [
            {"number": 77, "name": "GAKIDOVA Ivana", "mark": "zprp"},
            {"number": 9, "name": "INNA Osoba", "mark": "none"},
        ],
        "guest": [],
    }
    got = promotions_for(cands, marks)
    assert got == [{"path": "exam.host.#77", "team": "host", "number": 77, "name": "GAKIDOVA Ivana", "mark": "zprp"}]


def test_promotion_matches_by_name_when_the_number_changed():
    cands = manual_exam_candidates({}, blob(host=[{"number": 21, "fullName": "GAKIDOVA Ivana", "exam": "manual"}]))
    marks = {"host": [{"number": 77, "name": "Gakidova Ivana", "mark": "wzpr"}], "guest": []}
    got = promotions_for(cands, marks)
    assert got[0]["mark"] == "wzpr" and got[0]["path"] == "exam.host.#21"


def test_promotion_never_crosses_sides():
    cands = manual_exam_candidates({}, blob(guest=[{"number": 77, "fullName": "GAKIDOVA Ivana", "exam": "manual"}]))
    marks = {"host": [{"number": 77, "name": "GAKIDOVA Ivana", "mark": "zprp"}], "guest": []}
    assert promotions_for(cands, marks) == []


def test_promoted_entry_reaches_the_card_through_projection():
    """Krata: `zprp` z overlaya nadpisuje `manual` na karcie - i nic więcej."""
    b = blob(host=[dict(GAKIDOVA)])
    project({exam_path("host", 77): entry("zprp", "GAKIDOVA Ivana", src="zprp")}, b)
    assert b["matchConfig"]["hostPlayerCards"][0]["exam"] == "zprp"


def test_promotion_by_number_needs_the_same_person():
    """Sprawdzone na SK/5: numer 5 w rosterze to inna zawodniczka niz na karcie."""
    cands = manual_exam_candidates({}, blob(host=[{"number": 5, "fullName": "NIKT Taki", "exam": "manual"}]))
    marks = {"host": [{"number": 5, "name": "PRAWDZIWA Zawodniczka", "mark": "zprp"}], "guest": []}
    assert promotions_for(cands, marks) == []
    # Odwrocona kolejnosc czlonow to wciaz ta sama osoba.
    cands = manual_exam_candidates({}, blob(host=[{"number": 5, "fullName": "Ivana GAKIDOVA", "exam": "manual"}]))
    marks = {"host": [{"number": 5, "name": "GAKIDOVA Ivana", "mark": "zprp"}], "guest": []}
    assert promotions_for(cands, marks)[0]["mark"] == "zprp"
    # Karta bez nazwiska: numer wystarcza, bo nie ma czego porownac.
    cands = manual_exam_candidates({}, blob(host=[{"number": 5, "exam": "manual"}]))
    assert promotions_for(cands, marks)[0]["path"] == "exam.host.#5"


# ---------------------------------------------------------------------------
# Prog badan w rozgrywce (decyzja z 2026-09-08)
# ---------------------------------------------------------------------------


def test_which_competitions_need_zprp_exams():
    for number in ("SK/5", "OSM/12", "LSM/3", "LC/7", "LCK/7", "IM/4",
                   "PP/2", "PPK/2", "SPM/1", "S/PPK/2"):
        assert exam_requirement_for_code(number) == "zprp", number
    # II i III liga, mlodziez, Mistrzostwa Polski i mecz nierozpoznany
    # zostaja przy WZPR. „IIM4/1" to pulapka czytania numeru przez
    # `includes`: zawiera „IM", a I liga wymaga badan ZPRP.
    for number in ("IIM4/1", "IIIK/2", "JM/8", "MlK/9", "MP/3", "MPK/4", ""):
        assert exam_requirement_for_code(number) == "any", number


def test_which_marks_meet_the_threshold():
    for mark in ("zprp", "manual"):
        assert exam_mark_meets(mark, "zprp")
        assert exam_mark_meets(mark)
    assert exam_mark_meets("wzpr")
    assert not exam_mark_meets("wzpr", "zprp")
    assert not exam_mark_meets("none", "zprp")
    assert not exam_mark_meets(None)


def test_manual_is_not_promoted_to_wzpr_in_central_competitions():
    """Awans w kracie, ale odebranie prawa gry - wiec nie zachodzi."""
    cands = manual_exam_candidates(
        {}, blob(host=[{"number": 77, "fullName": "GAKIDOVA Ivana", "exam": "manual"}])
    )
    marks = {"host": [{"number": 77, "name": "GAKIDOVA Ivana", "mark": "wzpr"}], "guest": []}
    assert promotions_for(cands, marks, "zprp") == []
    # Bez progu (II liga, mlodziez) awans dziala jak dotad.
    assert promotions_for(cands, marks)[0]["mark"] == "wzpr"
    # ZPRP awansuje w kazdej rozgrywce.
    marks["host"][0]["mark"] = "zprp"
    assert promotions_for(cands, marks, "zprp")[0]["mark"] == "zprp"


def test_phase_of_says_when_the_match_started():
    assert phase_of(None, None) == PHASE_PRE
    assert phase_of({"live_started_at": None}, "in_progress") == PHASE_PRE
    assert phase_of({"live_started_at": "2026-09-08T18:00:00"}, "in_progress") != PHASE_PRE
    assert phase_of({}, "finished") != PHASE_PRE
    assert phase_of({}, "approved") != PHASE_PRE


# ---------------------------------------------------------------------------
# Slad po sprawdzeniu badan w bazie zwiazku (decyzja z 2026-09-08)
# ---------------------------------------------------------------------------


def recheck_blob(check):
    b = blob()
    b["matchConfig"]["examCheck"] = check
    return b


def test_recheck_from_blob_reads_the_negative_answer():
    got = exam_recheck_from_blob(
        recheck_blob(
            {
                "at": "2026-09-08T18:32:07.000Z",
                "missing": [
                    {"team": "host", "number": 77, "name": "GAKIDOVA Ivana", "mark": "wzpr"},
                    {"team": "guest", "number": 3, "name": "NOWAK Anna", "mark": "none"},
                ],
            }
        )
    )
    assert got["at"].startswith("2026-09-08T18:32")
    assert [p["mark"] for p in got["players"]] == ["wzpr", "none"]
    assert got["players"][0]["team"] == "host"


def test_recheck_from_blob_is_quiet_when_there_is_nothing_to_say():
    # Komplet badan i stara aplikacja wygladaja tu tak samo: bez wpisu.
    assert exam_recheck_from_blob(blob()) is None
    assert exam_recheck_from_blob(recheck_blob({"at": "", "missing": []})) is None
    assert exam_recheck_from_blob(recheck_blob({"at": "2026-09-08T18:32:07Z"})) is None
    assert exam_recheck_from_blob(None) is None


def test_recheck_from_blob_drops_junk():
    got = exam_recheck_from_blob(
        recheck_blob(
            {
                "at": "2026-09-08T18:32:07Z",
                "missing": [
                    "nie obiekt",
                    {"team": "obcy", "number": 1},
                    {"team": "host", "number": 9, "mark": "cokolwiek"},
                ],
            }
        )
    )
    assert got["players"] == [
        {"team": "host", "number": 9, "name": "", "mark": "none"}
    ]


def test_recheck_sentence_names_the_hour():
    text = event_summary(
        "exam.rechecked",
        {
            "at": "2026-09-08T18:32:07Z",
            "players": [{"team": "host", "number": 77, "name": "GAKIDOVA Ivana"}],
        },
    )
    assert "18:32" in text
    assert "nr 77" in text
    assert "nadal bez badan" in text.replace("ń", "n")
