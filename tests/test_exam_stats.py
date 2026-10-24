"""Statystyki łączne teczki i karta sędziego: grupy, ex aequo, pary, uprawnienia, zgodność z raportem."""

from datetime import datetime, timedelta, timezone

import pytest

from app import exam_report_service as RS
from app import exam_rules as X
from app import exam_service as S
from app import exam_stats_rules as SR
from app import exam_stats_service as SS
from test_exam_service import (  # noqa: F401 - fixture `st` i pomocnicze
    ADMIN, CLOSE, COMMISSION, CORRECT, DELEGATE, OPEN, OTHER_COMMISSION, PLAIN, ROSTER, TEACH, answer_all, make, st,
)

LETTERS = {"1": ["SL", "MP"], "3": ["II", "III"], "4": ["II"], "5": []}
PAIRS = {"3": "4", "4": "3", "1": "5", "5": "1", "2": "9"}  # 2->9 jednostronna = nie para


def wrong(qid):
    return ["b"] if CORRECT[qid] == "a" else ["a"]


def two_right(qid):
    return [CORRECT[qid]] if qid != "q1-3" else wrong(qid)


def ss_of(st):
    async def roster(provinces):
        people = {}
        for prov, rows in ROSTER.items():
            if S.display(prov) not in provinces and prov not in provinces:
                continue
            for j in rows:
                people[j["judge_id"]] = {"name": j["full_name"], "province": S.display(prov), "badges": list(j["badges"]),
                                         "letters": LETTERS.get(j["judge_id"], [])}
        return {"people": people, "pairs": dict(PAIRS)}

    return SS.StatsStore(st=st, roster=roster)


async def write(st, w, exam_id, now, choose=None):
    state = await S.start_attempt(st, w, exam_id, {}, now=now)
    await answer_all(st, w, state["attempt"]["id"], now, choose=choose, state=state)
    return state["attempt"]["id"]


async def scenario(st):
    """Egzamin A: Anna 100, Jan 100 (ex aequo), Ola 0. Egzamin B (2 dni później): Jan 66,67, Ola 100."""
    first, _ = await make(st)
    later = (OPEN + timedelta(days=2)).isoformat()
    second, _ = await make(st, window_start=later, max_attempts=2)
    t = OPEN + timedelta(minutes=5)
    await write(st, ADMIN, first["id"], t)
    await write(st, PLAIN, first["id"], t)
    await write(st, DELEGATE, first["id"], t, choose=wrong)
    t2 = OPEN + timedelta(days=2, minutes=5)
    await write(st, PLAIN, second["id"], t2, choose=two_right)
    await write(st, DELEGATE, second["id"], t2)
    return first, second


AFTER = CLOSE + timedelta(days=1)


async def test_przeglad_zgodny_z_raportem_komisji(st):
    first, second = await scenario(st)
    out = await SS.stats_overview(ss_of(st), COMMISSION, "ŚLĄSKIE", {}, now=AFTER)
    assert out["scope"] == "province" and [e["id"] for e in out["exams"]] == [first["id"], second["id"]]
    for row in out["exams"]:
        rep = (await RS.build_report(st, COMMISSION, row["id"], now=AFTER))["summary"]
        for key in ("people", "invited", "passed", "pass_rate", "avg_percent", "median_percent", "avg_duration_s", "median_duration_s"):
            assert row[key] == rep[key], key
    a = out["exams"][0]
    assert a["people"] == 3 and a["invited"] == 5 and a["missing"] == 2 and a["pass_rate"] == round(2 / 3, 4)
    assert out["totals"]["exams"] == 2 and out["totals"]["people"] == 3 and out["totals"]["finished"] == 5
    assert out["durations"]["count"] == 5 and out["durations"]["median_s"] == 60.0


async def test_trend_w_kubelkach_i_okres(st):
    first, second = await scenario(st)
    ss = ss_of(st)
    by_exam = await SS.stats_overview(ss, COMMISSION, "ŚLĄSKIE", {"bucket": "exam"}, now=AFTER)
    assert [t["exams"] for t in by_exam["trend"]] == [[first["id"]], [second["id"]]]
    month = await SS.stats_overview(ss, COMMISSION, "ŚLĄSKIE", {"bucket": "month"}, now=AFTER)
    assert len(month["trend"]) == 1 and month["trend"][0]["label"] == "lis 2026" and month["trend"][0]["finished"] == 5
    only_late = await SS.stats_overview(ss, COMMISSION, "ŚLĄSKIE", {"from": (OPEN + timedelta(days=1)).isoformat()}, now=AFTER)
    assert [e["id"] for e in only_late["exams"]] == [second["id"]]
    picked = await SS.stats_overview(ss, COMMISSION, "ŚLĄSKIE", {"exams": first["id"]}, now=AFTER)
    assert [e["id"] for e in picked["exams"]] == [first["id"]]
    assert len(picked["catalog"]) == 2  # wybór egzaminów widzi całą teczkę


async def test_grupy_odznaki_szczebel_i_pary(st):
    await scenario(st)
    out = await SS.stats_overview(ss_of(st), COMMISSION, "ŚLĄSKIE", {}, now=AFTER)
    badge = {g["key"]: g for g in out["groups"]["badge"]}
    assert badge["Delegaci"]["avg_percent"] == 50.0 and badge["Delegaci"]["members"] == 1
    assert badge[SR.NO_BADGE]["members"] == 3  # Anna, Jan, Piotr (Piotr nic nie pisał, ale był zaproszony)
    level = {g["key"]: g for g in out["groups"]["level"]}
    assert level["SL"]["avg_percent"] == 100.0 and level["II"]["finished"] == 4
    assert "province" not in out["groups"]
    pairs = {g["key"]: g for g in out["groups"]["pair"]}
    assert set(pairs) == {"3|4", "1|5"}  # jednostronny wpis 2->9 odpada
    jan_ola = pairs["3|4"]
    # Jan: (100 + 66,67) / 2 = 83,33; Ola: (0 + 100) / 2 = 50 -> para 66,67
    assert abs(jan_ola["avg_percent"] - 66.67) < 0.01
    assert jan_ola["complete"] is True and {p["judge_id"] for p in jan_ola["persons"]} == {"3", "4"}
    anna_piotr = pairs["1|5"]
    assert anna_piotr["complete"] is False and anna_piotr["avg_percent"] == 100.0
    assert [g["key"] for g in out["groups"]["pair"]] == ["1|5", "3|4"] and out["groups"]["pair"][0]["place"] == 1


async def test_najslabsze_przepisy_i_kraj_z_okregami(st):
    await scenario(st)
    out = await SS.stats_overview(ss_of(st), COMMISSION, "ŚLĄSKIE", {}, now=AFTER)
    rules = out["weak_rules"]["rules"]
    assert rules and rules[0]["rule"] == 1 and rules[0]["answers"] == 15
    assert rules[0]["correct_rate"] == round((3 + 3 + 0 + 2 + 3) / 15, 4)
    nat, _ = await S.create_exam(st, ADMIN, {"name": "Krajowy", "scope": "national", "config": {
        "scope": {"manual_ids": ["q1-1", "q1-2", "q1-3"]}, "question_count": 3, "window_start": OPEN.isoformat(),
        "window_end": CLOSE.isoformat(), "pass_percent": 60}}, now=OPEN - timedelta(hours=1))
    await write(st, PLAIN, nat["id"], OPEN + timedelta(minutes=1))
    opole = S.Who(judge_id="9", name="Opole Zwykły", province="OPOLSKIE", is_admin=False, badges={})
    await write(st, opole, nat["id"], OPEN + timedelta(minutes=1), choose=wrong)
    country = await SS.stats_overview(ss_of(st), ADMIN, None, {"metric": "pass_rate"}, now=AFTER)
    assert country["scope"] == "national" and [e["id"] for e in country["exams"]] == [nat["id"]]
    prov = {g["key"]: g for g in country["groups"]["province"]}
    assert prov["ŚLĄSKIE"]["pass_rate"] == 1.0 and prov["OPOLSKIE"]["pass_rate"] == 0.0
    assert prov["ŚLĄSKIE"]["place"] == 1 and prov["OPOLSKIE"]["place"] == 2
    every = await SS.stats_overview(ss_of(st), ADMIN, None, {"source": "all"}, now=AFTER)
    assert len(every["exams"]) == 3


async def test_uprawnienia_jak_teczka(st):
    await scenario(st)
    ss = ss_of(st)
    for denied, prov in ((PLAIN, "ŚLĄSKIE"), (DELEGATE, "ŚLĄSKIE"), (OTHER_COMMISSION, "ŚLĄSKIE")):
        with pytest.raises(X.ExamError) as err:
            await SS.stats_overview(ss, denied, prov, {}, now=AFTER)
        assert err.value.status == 403 and err.value.message
    with pytest.raises(X.ExamError) as err:
        await SS.judges_list(ss, PLAIN, None, {}, now=AFTER)  # bez okręgu = własny okręg, ale bez prawa
    assert err.value.status == 403
    assert (await SS.judges_list(ss, TEACH, "ŚLĄSKIE", {}, now=AFTER))["scope"] == "province"
    assert (await SS.stats_overview(ss, COMMISSION, None, {}, now=AFTER))["province"] == "ŚLĄSKIE"
    with pytest.raises(X.ExamError) as err:
        await SS.judge_card(ss, OTHER_COMMISSION, "3", "ŚLĄSKIE", {}, now=AFTER)
    assert err.value.status == 403
    with pytest.raises(X.ExamError) as err:
        await SS.stats_overview(ss, COMMISSION, "ŚLĄSKIE", {"metric": "nie-ma"}, now=AFTER)
    assert err.value.code == "BAD_FILTER" and "miary" in err.value.message


async def test_lista_sedziow_ex_aequo_trend_i_nieobecni(st):
    first, second = await scenario(st)
    out = await SS.judges_list(ss_of(st), COMMISSION, "ŚLĄSKIE", {}, now=AFTER)
    rows = {r["judge_id"]: r for r in out["judges"]}
    assert set(rows) == {"1", "2", "3", "4", "5"}
    assert rows["1"]["avg_percent"] == 100.0 and rows["1"]["place"] == 1 and rows["1"]["missing"] == 1
    assert rows["3"]["spark"] == [100.0, 66.67] and rows["3"]["delta"] == -33.33 and rows["3"]["level"] == "II"
    assert rows["4"]["delta"] == 100.0 and rows["4"]["partner_name"] == "Jan Zwykły"
    assert rows["5"]["exams"] == 0 and rows["5"]["missing"] == 2 and rows["5"]["place"] is None
    assert "Delegaci" in out["badges"]
    places = [r["place"] for r in out["judges"]]
    assert places[:3] == [1, 2, 3]


async def test_karta_sedziego_historia_i_uniewaznienia(st):
    first, second = await scenario(st)
    ss = ss_of(st)
    again = await S.start_attempt(st, PLAIN, second["id"], {}, now=OPEN + timedelta(days=2, minutes=30))
    await S.void_question(st, COMMISSION, first["id"], "q1-3", "credit", now=AFTER)
    card = await SS.judge_card(ss, COMMISSION, "3", "ŚLĄSKIE", {}, now=AFTER)
    assert card["judge"]["name"] == "Jan Zwykły" and card["judge"]["partner_id"] == "4"
    assert [s["exam_id"] for s in card["series"]] == [first["id"], second["id"]]
    assert card["series"][0]["scope_avg"] is not None and card["series"][1]["percent"] == 66.67
    hist = card["history"]
    assert len(hist) == 3 and hist[0]["attempt_id"] == again["attempt"]["id"] and hist[0]["status"] != "submitted"
    voided = [h for h in hist if h["exam_id"] == first["id"]][0]
    assert voided["voided"] == [{"qid": "q1-3", "number": voided["voided"][0]["number"], "mode": "credit"}]
    assert voided["integrity"]["level"] == "ok" and voided["best"] is True
    assert card["weak_rules"][0]["rule"] == 1 and card["weak_rules"][0]["scope_rate"] is not None
    with pytest.raises(X.ExamError) as err:
        await SS.judge_card(ss, COMMISSION, "777", "ŚLĄSKIE", {}, now=AFTER)
    assert err.value.status == 404 and err.value.code == "STATS_JUDGE_UNKNOWN"


async def test_pusta_teczka(st):
    out = await SS.stats_overview(ss_of(st), COMMISSION, "ŚLĄSKIE", {}, now=AFTER)
    assert out["exams"] == [] and out["trend"] == [] and out["totals"]["finished"] == 0
    assert out["durations"]["bins"] == [] and out["weak_rules"]["rules"] == []
    judges = await SS.judges_list(ss_of(st), COMMISSION, "ŚLĄSKIE", {}, now=AFTER)
    assert len(judges["judges"]) == 5 and all(j["place"] is None for j in judges["judges"])


# --- reguły bez bazy -------------------------------------------------------


def test_miejsca_ex_aequo_i_czas_krotszy_wyzej():
    rows = [{"label": "A", "avg_percent": 80.0, "avg_duration_s": 300}, {"label": "B", "avg_percent": 80.004, "avg_duration_s": 200},
            {"label": "C", "avg_percent": 70.0, "avg_duration_s": 200}, {"label": "D", "avg_percent": None, "avg_duration_s": None}]
    by_pct = SR.place_by([dict(r) for r in rows], "avg_percent")
    assert [(r["label"], r["place"], r["shared"]) for r in by_pct] == [("B", 1, True), ("A", 1, True), ("C", 3, False), ("D", None, False)]
    by_time = SR.place_by([dict(r) for r in rows], "avg_duration_s")
    assert [(r["label"], r["place"]) for r in by_time] == [("B", 1), ("C", 1), ("A", 3), ("D", None)]


def test_szczebel_sezon_i_rozklad_czasu():
    assert SR.level_of(["MP", "II", "III"]) == "II" and SR.level_of(["Mł"]) == "ML" and SR.level_of([]) == "none"
    assert SR.level_of(["lc", "I"]) == "LC"
    assert SR.season_of(datetime(2026, 8, 1, tzinfo=timezone.utc)) == "2026/27"
    assert SR.season_of(datetime(2027, 7, 31, tzinfo=timezone.utc)) == "2026/27"
    h = SR.duration_histogram([30, 60, 61, 900])
    assert h["width_s"] == 120 and sum(b["count"] for b in h["bins"]) == 4 and len(h["bins"]) <= SR.MAX_DURATION_BINS
    assert SR.duration_histogram([])["bins"] == []
    assert SR.clean_pairs({"1": "2", "2": "1", "3": "4"}) == {"1": "2", "2": "1"}
    with pytest.raises(X.ExamError):
        SR.clean_filters({"from": "2026-12-01", "to": "2026-01-01"})
    with pytest.raises(X.ExamError):
        SR.clean_filters({"bucket": "rok"})


def test_trasy_zarejestrowane_i_bez_bazy_na_gorze():
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    assert "app.include_router(exam_stats_router)" in (root / "main.py").read_text(encoding="utf-8")
    for name in ("exam_stats.py", "exam_stats_service.py", "exam_stats_rules.py"):
        tree = ast.parse((root / "app" / name).read_text(encoding="utf-8"))
        top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        assert not any(getattr(n, "module", "") == "app.db" for n in top), name
    src = (root / "app" / "exam_stats.py").read_text(encoding="utf-8")
    assert src.count("Depends(_who)") == 5


async def test_kartoteka_sedziego_i_komisji(st):
    from app import exam_record as RC

    first, second = await scenario(st)
    ss = ss_of(st)
    mine = await RC.my_record(ss, PLAIN, now=AFTER)
    assert mine["viewer"] == "self" and mine["judge"]["name"] == "Jan Zwykły"
    t = mine["totals"]
    assert t["tests"] == 2 and t["attempts"] == 2 and t["best_percent"] == 100.0 and t["best_exam_id"] == first["id"]
    assert t["avg_percent"] == round((100.0 + 66.67) / 2, 2) and t["best_duration_s"] is not None
    assert [f["exam_id"] for f in mine["form"]] == [first["id"], second["id"]]
    assert mine["exams"][0]["exam_id"] == second["id"] and mine["exams"][0]["attempts"][0]["review_available"] is True
    row = mine["exams"][0]["attempts"][0]
    assert row["right"] == 2 and row["wrong"] == 1 and row["violations"] == 0
    board = await RC.judge_record(ss, COMMISSION, "3", "ŚLĄSKIE", now=AFTER)
    assert board["viewer"] == "committee" and board["totals"] == t
    with pytest.raises(X.ExamError):
        await RC.judge_record(ss, PLAIN, "3", "ŚLĄSKIE", now=AFTER)
    # Wynik w koszu znika z kartoteki obu widzów.
    from app import exam_trash as T

    await T.delete_result(st, COMMISSION, second["id"], "3", now=AFTER)
    after = await RC.my_record(ss, PLAIN, now=AFTER)
    assert [e["exam_id"] for e in after["exams"]] == [first["id"]]
    assert (await RC.judge_record(ss, COMMISSION, "3", "ŚLĄSKIE", now=AFTER))["totals"]["tests"] == 1


async def test_kartoteka_ukrywa_wynik_wg_polityki(st):
    from app import exam_record as RC

    exam, _ = await make(st, result_release="after_close")
    await write(st, PLAIN, exam["id"], OPEN + timedelta(minutes=5))
    mine = await RC.my_record(ss_of(st), PLAIN, now=OPEN + timedelta(hours=1))
    row = mine["exams"][0]["attempts"][0]
    assert row["visible"] is False and row["percent"] is None and row["right"] is None
    assert row["review_available"] is False and "razem z wynikiem" in row["review_reason"]
    assert mine["totals"]["tests"] == 1 and mine["totals"]["avg_percent"] is None and mine["weak_rules"] == []
