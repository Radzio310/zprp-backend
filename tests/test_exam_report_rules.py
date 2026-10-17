"""Egzamin - wyniki komisji: agregaty bez bazy (ranking ex aequo, okręgi, przepisy, naruszenia, unieważnienie)."""

import pytest

from app import exam_report_rules as R
from app.exam_rules import ExamError


def att(jid, pct, *, no=1, status="submitted", passed=None, prov="ŚLĄSKIE", name=None, integrity=None,
        start="2026-11-02T10:00:00+00:00", end="2026-11-02T10:10:00+00:00"):
    return {"attempt_id": f"{jid}-{no}", "judge_id": jid, "judge_name": name or f"Sędzia {jid}", "province": prov,
            "attempt_no": no, "status": status, "percent": pct, "passed": pct is not None and pct >= 60 if passed is None else passed,
            "started_at": start, "finished_at": end if status != "in_progress" else None,
            "integrity": integrity or {"score": 100, "level": "ok", "breakdown": []}}


def test_miejsca_ex_aequo_1_2_2_4():
    assert R.place_ex_aequo([90, 80, 80, 70]) == [1, 2, 2, 4]
    assert R.place_ex_aequo([66.666, 66.667, 50]) == [1, 1, 3]
    assert R.place_ex_aequo([100, None]) == [1, None]


def test_ranking_bierze_najlepsze_podejscie_osoby_i_liczy_podejscia():
    rows = R.ranking([att("1", 50, no=1), att("1", 80, no=2), att("2", 80), att("3", 40), att("4", None, status="in_progress")])
    assert [(r["judge_id"], r["place"]) for r in rows] == [("1", 1), ("2", 1), ("3", 3)]
    assert rows[0]["attempts_used"] == 2 and rows[0]["attempt_no"] == 2


def test_podsumowanie_frekwencja_mediana_czas_i_histogram():
    s = R.summary([att("1", 100), att("2", 55), att("3", 75), att("4", None, status="in_progress")], 2, 60)
    assert s["people"] == 4 and s["invited"] == 6 and s["finished_people"] == 3 and s["in_progress"] == 1
    assert s["passed"] == 2 and s["pass_rate"] == pytest.approx(0.6667, abs=1e-4)
    assert s["median_percent"] == 75 and s["avg_duration_s"] == 600
    assert s["histogram_10pct"][9] == 1 and s["histogram_10pct"][5] == 1 and s["histogram_10pct"][7] == 1


def test_najslabszy_przepis_wazony_bez_unieważnionych():
    qs = [{"qid": "a", "number": "8.1", "rule": 8, "total": 10, "correct_rate": 0.2, "voided": None},
          {"qid": "b", "number": "8.2", "rule": 8, "total": 30, "correct_rate": 0.6, "voided": None},
          {"qid": "c", "number": "1.1", "rule": 1, "total": 10, "correct_rate": 0.9, "voided": None},
          {"qid": "d", "number": "1.2", "rule": 1, "total": 10, "correct_rate": 0.0, "voided": "drop"}]
    rules = R.weakest_rules(qs, limit=0)
    assert rules[0]["rule"] == 8 and rules[0]["correct_rate"] == 0.5 and rules[0]["worst"]["number"] == "8.1"
    assert rules[1]["rule"] == 1 and rules[1]["questions"] == 1
    assert rules[0]["label"].startswith("Przepis 8")


def test_mapa_naruszen_liczy_osoby_i_zdarzenia():
    bad = {"score": 40, "level": "suspicious", "breakdown": [
        {"kind": "app_background", "flag": None, "label": "Wyjścia z aplikacji", "count": 3, "penalty": 12},
        {"kind": "time_flag", "flag": "too_fast", "label": "Szybko", "count": 2, "penalty": 6}]}
    mid = {"score": 70, "level": "warning", "breakdown": [
        {"kind": "app_background", "flag": None, "label": "Wyjścia z aplikacji", "count": 1, "penalty": 4}]}
    v = R.violation_map([att("1", 50, integrity=bad), att("2", 70, integrity=mid), att("3", 90)])
    assert v["levels"] == {"ok": 1, "warning": 1, "suspicious": 1} and not v["clean"]
    first = v["kinds"][0]
    assert first["kind"] == "app_background" and first["people"] == 2 and first["events"] == 4


def test_porownanie_okregow_z_frekwencja_i_remisem():
    attempts = [att("1", 80, prov="ŚLĄSKIE"), att("2", 40, prov="ŚLĄSKIE"), att("3", 80, prov="OPOLSKIE"), att("4", 40, prov="OPOLSKIE")]
    missing = [{"judge_id": "9", "name": "X", "province": "OPOLSKIE"}, {"judge_id": "8", "name": "Y", "province": "LUBUSKIE"}]
    rows = {r["province"]: r for r in R.province_comparison(attempts, missing)}
    assert rows["OPOLSKIE"]["invited"] == 3 and rows["OPOLSKIE"]["attendance_rate"] == pytest.approx(0.6667, abs=1e-4)
    assert rows["ŚLĄSKIE"]["place"] == rows["OPOLSKIE"]["place"] == 1
    assert rows["LUBUSKIE"]["attended"] == 0 and rows["LUBUSKIE"]["place"] is None


def test_podglad_unieważnienia_drop_i_credit():
    def score(points_bad, passed):
        qs = [{"qid": "q1", "points": 1.0, "max": 1.0}, {"qid": "q2", "points": 1.0, "max": 1.0},
              {"qid": "bad", "points": points_bad, "max": 1.0}]
        pct = round(sum(q["points"] for q in qs) / 3 * 100, 2)
        return {"questions": qs, "percent": pct, "passed": passed}

    scores = [score(0.0, False), score(1.0, True)]
    out = R.void_preview(scores, "bad", 75)
    assert out["drop"]["newly_passed"] == 1 and out["drop"]["newly_failed"] == 0
    assert out["credit"]["newly_passed"] == 1 and out["credit"]["avg_after"] == 100.0
    assert out["finished"] == 2 and out["drop"]["affected"] == 2


def test_opcje_eksportu_z_powodem_odmowy():
    ok = R.clean_export_options({"format": "html", "sections": ["cards", "summary", "provinces", "cards"]}, national=False)
    # Kolejność to kolejność komisji (przeciąganie), powtórzenia i okręgi przy egzaminie okręgowym odpadają.
    assert ok["sections"] == ["cards", "summary"] and ok["seal"] is True and ok["range"] == "best"
    assert ok["anonymize"] is True and ok["layout"] == {"orientation": "portrait", "density": "comfortable", "cover": False}
    assert ok["people"]["sort"] == "place" and ok["questions"]["voided"] == "include"
    for bad in ({"format": "docx"}, {"range": "x"}, {"theme": "neon"}, {"sections": ["nope"]}, {"sections": []},
                {"layout": {"orientation": "ukos"}}, {"layout": {"density": "x"}}, {"layout": "pion"},
                {"people": {"min_percent": 80, "max_percent": 20}}, {"people": {"min_percent": 120}},
                {"people": {"sort": "losowo"}}, {"people": {"flags": "x"}}, {"people": {"provinces": "ŚLĄSKIE"}},
                {"questions": {"rules": ["osiem"]}}, {"questions": {"weakest": 0}}, {"questions": {"difficulty": "x"}},
                {"questions": {"voided": "x"}}):
        with pytest.raises(ExamError) as err:
            R.clean_export_options(bad, national=True)
        assert err.value.code == "BAD_EXPORT" and err.value.message


def test_zakres_listy_i_anonimizacja_bez_zdradzania_miejsca():
    attempts = [att("1", 90, name="Zofia Zając"), att("2", 50, name="Adam Abacki"), att("3", 50, name="Ewa Ek")]
    failed = R.select_rows(attempts, "failed")
    assert [r["place"] for r in failed] == [1, 1]
    rows = R.select_rows(attempts, "best")
    missing = [{"judge_id": "7", "name": "Bartek Bąk", "province": "ŚLĄSKIE"}]
    R.anonymize(rows, missing)
    names = {r["judge_id"]: r["judge_name"] for r in rows}
    assert names["2"] == "Zdający 001" and missing[0]["name"] == "Zdający 002" and names["1"] == "Zdający 004"
    assert R.export_filename("Egzamin sezonowy 2026/27 - Śląsk", "pdf", __import__("datetime").datetime(2026, 11, 2)) \
        == "wyniki-egzamin-sezonowy-2026-27-slask-2026-11-02.pdf"


def test_nowe_motywy_i_uklad_przechodza():
    out = R.clean_export_options({"theme": "ink", "layout": {"orientation": "landscape", "density": "compact", "cover": True},
                                  "people": {"flags": "only", "min_percent": 40, "max_percent": 80, "provinces": ["ŚLĄSKIE"], "sort": "name"},
                                  "questions": {"rules": [8, "16"], "difficulty": "hard", "weakest": 10, "voided": "exclude"}},
                                 national=True)
    assert out["theme"] == "ink" and out["layout"]["cover"] is True and out["layout"]["orientation"] == "landscape"
    assert out["people"]["provinces"] == ["ŚLĄSKIE"] and out["questions"]["rules"] == [8, 16]
    assert R.clean_export_options({"theme": "zprp"}, national=False)["theme"] == "zprp"


def _flag(score=40):
    return {"score": score, "level": "suspicious" if score < 50 else "warning", "breakdown": []}


def test_filtr_zdajacych_rzetelnosc_przedzial_okreg_i_miejsce_w_okregu():
    rows = R.select_rows([att("1", 90, prov="ŚLĄSKIE"), att("2", 80, prov="OPOLSKIE"), att("3", 80, prov="ŚLĄSKIE"),
                          att("4", 55, prov="ŚLĄSKIE", integrity=_flag()), att("5", 30, prov="OPOLSKIE")], "best")
    assert [r["place"] for r in rows] == [1, 2, 2, 4, 5]
    only = R.apply_people(rows, {"flags": "only"})
    assert [r["judge_id"] for r in only] == ["4"] and only[0]["place"] == 4  # miejsce z zakresu zostaje
    clean = R.apply_people(rows, {"flags": "none", "min_percent": 50, "max_percent": 85})
    assert [r["judge_id"] for r in clean] == ["2", "3"]
    sl = R.apply_people(rows, {"provinces": ["slaskie"]})
    # Zawężenie do okręgu = miejsce w okręgu.
    assert [(r["judge_id"], r["place"]) for r in sl] == [("1", 1), ("3", 2), ("4", 3)]
    asc = R.apply_people(rows, {"sort": "percent_asc"})
    assert [r["judge_id"] for r in asc][:2] == ["5", "4"]
    by_int = R.apply_people(rows, {"sort": "integrity"})
    assert by_int[0]["judge_id"] == "4"
    by_name = R.apply_people(rows, {"sort": "name"})
    assert [r["judge_name"] for r in by_name] == sorted(r["judge_name"] for r in rows)
    missing = R.filter_missing([{"judge_id": "9", "name": "Zenon", "province": "OPOLSKIE"},
                                {"judge_id": "8", "name": "Adam", "province": "ŚLĄSKIE"}], {"provinces": ["ŚLĄSKIE"]})
    assert [m["judge_id"] for m in missing] == ["8"]


def test_filtr_pytan_przepisy_trudnosc_najslabsze_uniewaznione():
    qs = [{"qid": "a", "number": "8.2", "rule": 8, "total": 10, "correct_rate": 0.2, "voided": None},
          {"qid": "b", "number": "8.1", "rule": 8, "total": 10, "correct_rate": 0.6, "voided": None},
          {"qid": "c", "number": "1.1", "rule": 1, "total": 10, "correct_rate": 0.9, "voided": None},
          {"qid": "d", "number": "1.2", "rule": 1, "total": 10, "correct_rate": 0.1, "voided": "drop"},
          {"qid": "e", "number": "16.1", "rule": 16, "total": 0, "correct_rate": None, "voided": None}]
    allq = R.filter_questions(qs, None)
    assert [q["number"] for q in allq["grid"]] == ["1.1", "1.2", "8.1", "8.2", "16.1"] and allq["note"] == ""
    assert [q["qid"] for q in allq["table"]] == ["a", "b", "c"]
    r8 = R.filter_questions(qs, {"rules": [8]})
    assert [q["qid"] for q in r8["grid"]] == ["b", "a"] and "przepisy 8" in r8["note"]
    hard = R.filter_questions(qs, {"difficulty": "hard"})
    assert [q["qid"] for q in hard["grid"]] == ["a"]  # unieważnione i bez odpowiedzi nie mają trudności
    weak = R.filter_questions(qs, {"weakest": 2})
    assert {q["qid"] for q in weak["grid"]} == {"a", "b"} and "2 najsłabszych" in weak["note"]
    only_void = R.filter_questions(qs, {"voided": "only"})
    assert [q["qid"] for q in only_void["grid"]] == ["d"]
    assert "d" not in {q["qid"] for q in R.filter_questions(qs, {"voided": "exclude"})["grid"]}


def test_opis_kogo_obejmuje_plik():
    opts = R.clean_export_options({"range": "failed", "people": {"flags": "only", "min_percent": 40.5, "max_percent": 70,
                                                                  "provinces": ["OPOLSKIE"], "sort": "name"}}, national=True)
    text = R.describe_people(opts, 3)
    assert "tylko niezaliczone" in text and "z uwagami" in text and "40,5-70%" in text and "OPOLSKIE" in text
    assert "nazwisko" in text and text.endswith("(3 os.)")
