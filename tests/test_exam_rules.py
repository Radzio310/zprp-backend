"""Egzamin z przepisów - reguły bez bazy: uprawnienia, ocena, czas, polityka wyniku, rzetelność."""

from datetime import datetime, timedelta, timezone

import copy

import pytest

from app import exam_rules as X

UTC = timezone.utc
T0 = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)

Q_SINGLE = {"qid": "q1", "number": "1.1", "rule": 1, "kind": "wiedza", "multi": False, "topics": ["boisko"],
            "text": "Ile metrów ma boisko do gry w piłkę ręczną wzdłuż?",
            "answers": [{"key": "a", "text": "40", "correct": True}, {"key": "b", "text": "42", "correct": False},
                        {"key": "c", "text": "38", "correct": False}]}
Q_MULTI = {"qid": "q2", "number": "6.24", "rule": 6, "kind": "scenariusz", "multi": True, "topics": [],
           "text": "Co orzeka sędzia?",
           "answers": [{"key": "a", "text": "wolny", "correct": False}, {"key": "b", "text": "karny", "correct": True},
                       {"key": "c", "text": "kara", "correct": True}, {"key": "d", "text": "nic", "correct": False}]}
BANK = {"q1": Q_SINGLE, "q2": Q_MULTI}


def cfg(**over):
    raw = {"window_start": T0.isoformat(), "window_end": (T0 + timedelta(days=3)).isoformat(), "question_count": 2}
    raw.update(over)
    return X.clean_config(raw)


def attempt(config, now=T0):
    paper = [{"qid": "q1", "keys": ["a", "b", "c"]}, {"qid": "q2", "keys": ["a", "b", "c", "d"]}]
    return {"id": "A1", "judge_id": "7", "status": "in_progress", "started_at": now,
            "deadline_at": X.attempt_deadline(config, now), "current_index": 0, "paper": paper, "dirty": False}


# --- uprawnienia -----------------------------------------------------------


def perm(**kw):
    base = dict(scope="province", province="ŚLĄSKIE", is_admin=False, own_province="SLASKIE", badges={}, is_teach_master=False)
    base.update(kw)
    return X.manage_refusal(**base)


def test_krajowy_tylko_admin():
    assert perm(scope="national", province=None, is_admin=True) is None
    reason = perm(scope="national", province=None, badges={"Komisja sędziowska": True}, is_teach_master=True)
    assert "ogólnopolskie" in reason and "administrator" in reason


def test_okregowy_admin_komisja_i_teach_master():
    assert perm(is_admin=True) is None
    assert perm(badges={"Komisja sędziowska": True}) is None
    assert perm(is_teach_master=True) is None


def test_komisja_cudzego_okregu_i_zwykly_sedzia_dostaja_zdanie():
    other = perm(badges={"Komisja sędziowska": True}, own_province="OPOLSKIE")
    assert other and "ŚLĄSKIE" in other and "Teach Master" in other
    plain = perm()
    assert plain and "O nadanie uprawnień poproś administratora" in plain
    with pytest.raises(X.ExamError) as err:
        X.require_manage(scope="province", province="ŚLĄSKIE", is_admin=False, own_province="SLASKIE", badges={}, is_teach_master=False)
    assert err.value.status == 403 and err.value.code == "EXAM_FORBIDDEN"


# --- konfiguracja ----------------------------------------------------------


def test_szablony_i_domyslna_punktacja():
    for key in X.TEMPLATES:
        c = X.clean_config({"window_start": T0.isoformat(), "window_end": (T0 + timedelta(days=5)).isoformat()}, template=key)
        assert c["multi_scoring"] == "all_or_nothing"
    assert [X.TEMPLATES[k]["label"] for k in X.TEMPLATES] == ["Egzamin 25", "Egzamin 30", "Egzamin 15"]
    short = X.clean_config({"window_start": T0.isoformat(), "window_end": (T0 + timedelta(days=5)).isoformat()}, template="exam15")
    assert short["question_count"] == 15 and short["result_release"] == "after_close"


@pytest.mark.parametrize("raw, fragment", [
    ({"window_end": None}, "Podaj okno"),
    ({"allow_back": True, "time_per_question_s": 30}, "Cofanie"),
    ({"retake": "only_failed", "result_release": "after_close"}, "wyniku od razu"),
    ({"pass_percent": 120}, "0-100"),
    ({"set_mode": "x"}, "zestaw"),
    ({"question_count": 0}, "liczba pytań"),
])
def test_bledna_konfiguracja_ma_polskie_zdanie(raw, fragment):
    base = {"window_start": T0.isoformat(), "window_end": (T0 + timedelta(days=3)).isoformat()}
    base.update(raw)
    with pytest.raises(X.ExamError) as err:
        X.clean_config(base)
    assert fragment in err.value.message


def test_pula_zestaw_wspolny_i_za_mala_pula():
    bank = [Q_SINGLE, Q_MULTI]
    assert X.resolve_pool({"rules": [6]}, bank) == ["q2"]
    assert X.resolve_pool({"manual_ids": ["q1"]}, bank) == ["q1"]
    with pytest.raises(X.ExamError):
        X.resolve_pool({"manual_ids": ["nie-ma"]}, bank)
    with pytest.raises(X.ExamError) as err:
        X.pick_set(["q1"], 2, "shared", "seed")
    assert err.value.code == "POOL_TOO_SMALL"


def test_zestaw_wspolny_jest_ten_sam_a_losowany_rozny_i_powtarzalny():
    pool = [f"q{i}" for i in range(1, 31)]
    bank = {q: {**Q_SINGLE, "qid": q, "number": f"1.{i}"} for i, q in enumerate(pool, 1)}
    c = cfg(question_count=5, set_mode="shared", shuffle_answers=True)
    shared = X.pick_set(pool, 5, "shared", "exam1")
    p1 = X.build_paper(c, shared, bank, exam_id="e", judge_id="1", attempt_no=1)
    p2 = X.build_paper(c, shared, bank, exam_id="e", judge_id="2", attempt_no=1)
    assert [i["qid"] for i in p1] == [i["qid"] for i in p2]
    d = cfg(question_count=5, set_mode="drawn")
    d1 = X.build_paper(d, pool, bank, exam_id="e", judge_id="1", attempt_no=1)
    d2 = X.build_paper(d, pool, bank, exam_id="e", judge_id="2", attempt_no=1)
    assert [i["qid"] for i in d1] != [i["qid"] for i in d2]
    assert d1 == X.build_paper(d, pool, bank, exam_id="e", judge_id="1", attempt_no=1)


# --- brak kluczy -----------------------------------------------------------


def test_pytanie_dla_telefonu_nie_ma_kluczy_ani_ciekawostki():
    pub = X.public_question({**Q_MULTI, "curiosity": "sekret"}, ["c", "a", "b", "d"])
    assert [a["key"] for a in pub["answers"]] == ["c", "a", "b", "d"]
    flat = repr(pub)
    assert "correct" not in flat and "sekret" not in flat and "curiosity" not in flat


# --- ocena -----------------------------------------------------------------


def test_ocena_wszystko_albo_nic_i_czesciowa():
    assert X.score_question(Q_MULTI, ["b", "c"], "all_or_nothing") == 1.0
    assert X.score_question(Q_MULTI, ["b"], "all_or_nothing") == 0.0
    assert X.score_question(Q_MULTI, ["b", "c", "a"], "all_or_nothing") == 0.0
    assert X.score_question(Q_MULTI, ["b"], "partial") == 0.5
    assert X.score_question(Q_MULTI, ["b", "c", "a"], "partial") == 0.5
    assert X.score_question(Q_MULTI, ["a", "d"], "partial") == 0.0
    assert X.score_question(Q_SINGLE, ["a"], "partial") == 1.0
    assert X.score_question(Q_SINGLE, [], "partial") == 0.0


def test_wynik_progu_i_unieważnienie():
    c = cfg(pass_percent=75)
    paper = attempt(c)["paper"]
    answers = {"q1": {"selected": ["a"]}, "q2": {"selected": ["b"]}}
    score = X.score_attempt(c, paper, answers, BANK, {})
    assert score["points"] == 1.0 and score["max"] == 2.0 and score["percent"] == 50.0 and not score["passed"]
    dropped = X.score_attempt(c, paper, answers, BANK, {"q2": "drop"})
    assert dropped["max"] == 1.0 and dropped["percent"] == 100.0 and dropped["passed"]
    credited = X.score_attempt(c, paper, answers, BANK, {"q2": "credit"})
    assert credited["points"] == 2.0 and credited["passed"]
    part = X.score_attempt(cfg(multi_scoring="partial"), paper, answers, BANK, {})
    assert part["points"] == 1.5


# --- kolejność, cofanie, czas serwerowy -----------------------------------


def serve(c, a, answers, now):
    return X.serve_question(c, a, answers, now, None)


def test_nastepne_pytanie_dopiero_po_odpowiedzi_i_brak_cofania():
    c = cfg()
    a, answers = attempt(c), {}
    assert serve(c, a, answers, T0) == 0
    early = X.apply_answers(c, a, answers, [{"qid": "q2", "selected": ["b"]}], BANK, T0 + timedelta(seconds=5))
    assert early[0]["code"] == "EXAM_ORDER"
    ok = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["a"]}], BANK, T0 + timedelta(seconds=10))
    assert ok[0]["status"] == "accepted" and a["current_index"] == 1
    with pytest.raises(X.ExamError) as err:
        X.serve_question(c, a, answers, T0 + timedelta(seconds=11), 0)
    assert err.value.code == "EXAM_NO_BACK"
    again = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["b"]}], BANK, T0 + timedelta(seconds=12))
    assert again[0]["code"] == "EXAM_ALREADY_ANSWERED"
    same = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["a"]}], BANK, T0 + timedelta(seconds=13))
    assert same[0]["status"] == "duplicate"


def test_cofanie_pozwala_poprawic_ale_nie_wyprzedzac():
    c = cfg(allow_back=True)
    a, answers = attempt(c), {}
    serve(c, a, answers, T0)
    X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["a"]}], BANK, T0 + timedelta(seconds=10))
    assert serve(c, a, answers, T0 + timedelta(seconds=11)) == 1
    assert X.serve_question(c, a, answers, T0 + timedelta(seconds=12), 0) == 0
    fix = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["b"]}], BANK, T0 + timedelta(seconds=20))
    assert fix[0]["status"] == "accepted" and answers["q1"]["selected"] == ["b"] and answers["q1"]["changes"] == 1
    assert a["status"] == "in_progress"  # z cofaniem arkusz oddaje się jawnie
    X.apply_answers(c, a, answers, [{"qid": "q2", "selected": ["b", "c"]}], BANK, T0 + timedelta(seconds=30))
    assert X.finish_refusal(c, a) is None


def test_czas_na_pytanie_liczy_serwer_i_pytanie_przepada():
    c = cfg(time_per_question_s=30)
    a, answers = attempt(c), {}
    serve(c, a, answers, T0)
    late = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["a"]}], BANK, T0 + timedelta(seconds=45))
    assert late[0]["code"] == "EXAM_QUESTION_TIME_UP"
    assert answers["q1"]["timed_out"] and answers["q1"]["selected"] == [] and a["current_index"] == 1
    assert X.score_attempt(c, a["paper"], answers, BANK, {})["points"] == 0
    # w tolerancji sieci (3 s) odpowiedź jeszcze się liczy
    c2 = cfg(time_per_question_s=30)
    a2, ans2 = attempt(c2), {}
    serve(c2, a2, ans2, T0)
    fine = X.apply_answers(c2, a2, ans2, [{"qid": "q1", "selected": ["a"]}], BANK, T0 + timedelta(seconds=32))
    assert fine[0]["status"] == "accepted"


def test_czas_calosci_i_koniec_okna_domykaja_podejscie():
    c = cfg(time_total_min=10)
    a, answers = attempt(c), {}
    serve(c, a, answers, T0)
    assert a["deadline_at"] == T0 + timedelta(minutes=10)
    X.settle(c, a, answers, T0 + timedelta(minutes=11))
    assert a["status"] == "expired" and a["finish_reason"] == "time_up"
    late = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["a"]}], BANK, T0 + timedelta(minutes=12))
    assert late[0]["code"] == "EXAM_FINISHED"
    # termin podejścia nigdy nie wychodzi poza okno
    c2 = cfg(time_total_min=480)
    assert X.attempt_deadline(c2, T0 + timedelta(days=3) - timedelta(minutes=20)) == T0 + timedelta(days=3)


def test_bufor_ze_stemplem_klienta_z_tolerancja_i_flagami():
    c = cfg(time_per_question_s=30, anti={"speed_flags": True})
    a, answers = attempt(c), {}
    serve(c, a, answers, T0)
    now = T0 + timedelta(seconds=300)
    # telefon odpowiedział po 20 s, ale paczka dotarła po 5 minutach; jego zegar spieszy o godzinę
    client_now = (now.timestamp() + 3600) * 1000
    stamp = (T0.timestamp() + 20 + 3600) * 1000
    res = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["a"], "client_ts_ms": stamp}], BANK, now, client_now,
                          buffered=True)
    assert res[0]["status"] == "accepted" and "buffered_late" in res[0]["flags"]
    assert answers["q1"]["answered_at"] == T0 + timedelta(seconds=20)
    # stempel z przyszłości ignorujemy i oznaczamy
    future = X.estimate_answer_time({"client_ts_ms": client_now + 60_000}, client_now, now)
    assert future[0] == now and future[1] == ["future_stamp"]


def test_zbyt_szybka_odpowiedz_dostaje_flage_ale_jest_przyjeta():
    c = cfg(anti={"speed_flags": True})
    a, answers = attempt(c), {}
    serve(c, a, answers, T0)
    res = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["a"]}], BANK, T0 + timedelta(milliseconds=300))
    assert res[0]["status"] == "accepted" and "too_fast" in res[0]["flags"]


def test_walidacja_odpowiedzi_ma_zdania():
    c = cfg()
    a, answers = attempt(c), {}
    serve(c, a, answers, T0)
    now = T0 + timedelta(seconds=10)
    codes = {r["qid"]: r["code"] for r in X.apply_answers(c, a, answers, [
        {"qid": "nie-ma", "selected": ["a"]}, {"qid": "q1", "selected": []},
        {"qid": "q1", "selected": ["z"]}, {"qid": "q1", "selected": ["a", "b"]}], BANK, now)}
    assert codes["nie-ma"] == "EXAM_UNKNOWN_QUESTION"
    res = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": []}], BANK, now)
    assert res[0]["code"] == "EXAM_EMPTY_ANSWER" and res[0]["message"]


def test_wyjscie_z_aplikacji_wg_polityki():
    for policy, status, index in (("log", "in_progress", 0), ("warn", "in_progress", 0), ("void_question", "in_progress", 1), ("end", "submitted", 0)):
        c = cfg(anti={"leave_app": policy})
        a, answers = attempt(c), {}
        serve(c, a, answers, T0)
        out = X.apply_leave_policy(c, a, answers, T0 + timedelta(seconds=9))
        assert a["status"] == status and a["current_index"] == index, policy
        assert out["policy"] == policy
    assert answers  # end: pytanie zostaje bez odpowiedzi
    c = cfg(anti={"leave_app": "void_question"})
    a, answers = attempt(c), {}
    serve(c, a, answers, T0)
    X.apply_leave_policy(c, a, answers, T0 + timedelta(seconds=9))
    assert answers["q1"]["timed_out"] and "lost_on_leave" in answers["q1"]["flags"]


# --- polityka wyniku i przeglądu ------------------------------------------


def test_wynik_od_razu_albo_po_zamknieciu_okna():
    done = {"status": "submitted", "score": {"points": 1, "max": 2, "percent": 50, "passed": False, "pass_percent": 75}}
    inside = T0 + timedelta(days=1)
    after = T0 + timedelta(days=4)
    now_cfg = cfg(result_release="immediate")
    assert X.result_view(now_cfg, done, inside)["visible"] is True
    late_cfg = cfg(result_release="after_close")
    hidden = X.result_view(late_cfg, done, inside)
    assert hidden["visible"] is False and hidden["available_at"] == late_cfg["window_end"] and hidden["reason"]
    assert X.result_view(late_cfg, done, after)["percent"] == 50
    assert X.result_view(now_cfg, {"status": "in_progress"}, inside)["visible"] is False


def test_przeglad_zawsze_po_zamknieciu_okna_nawet_przy_wyniku_od_razu():
    c = cfg(result_release="immediate")
    assert "zamknięciu okna" in X.review_refusal(c, "submitted", T0 + timedelta(days=1))
    assert X.review_refusal(c, "submitted", T0 + timedelta(days=4)) is None
    assert X.review_refusal(c, "in_progress", T0 + timedelta(days=4))
    paper = attempt(c)["paper"]
    score = X.score_attempt(c, paper, {"q1": {"selected": ["a"]}}, BANK, {})
    review = X.review_view(c, paper, {"q1": {"selected": ["a"]}}, {"q1": Q_SINGLE, "q2": {**Q_MULTI, "curiosity": "ciekawostka"}}, score)
    assert review[0]["correct_keys"] == ["a"] and review[1]["curiosity"] == "ciekawostka"


# --- rzetelność ------------------------------------------------------------


def test_wskaznik_rzetelnosci_z_rozpisaniem_i_limitami():
    clean = X.integrity_report([])
    assert clean["score"] == 100 and clean["level"] == "ok" and clean["breakdown"] == []
    events = [{"kind": "app_background", "detail": {"seconds": 40}}] * 2 + [
        {"kind": "screenshot", "detail": {}}, {"kind": "time_flag", "detail": {"flag": "too_fast"}}] + \
        [{"kind": "device_change", "detail": {}}]
    rep = X.integrity_report(events)
    kinds = {(b["kind"], b["flag"]): b for b in rep["breakdown"]}
    assert kinds[("app_background", None)]["penalty"] == 16 and kinds[("app_background", None)]["count"] == 2
    assert rep["score"] == 100 - 16 - 10 - 3 - 25 and rep["level"] == "suspicious"
    many = X.integrity_report([{"kind": "screenshot", "detail": {}}] * 20)
    assert many["breakdown"][0]["penalty"] == 30  # górny limit grupy
    assert "dyskwalifikuje" in many["note"]
    floor = X.integrity_report([{"kind": k, "detail": {}} for k in ("device_change", "similarity", "similarity")] + [{"kind": "screenshot", "detail": {}}] * 5)
    assert 0 <= floor["score"] <= 100


def test_podobienstwo_par_wymaga_wspolnych_bledow_i_bliskich_czasow():
    def pack(aid, offset):
        return {"attempt_id": aid, "judge_id": aid, "answers": {
            f"q{i}": {"selected": ["c"], "correct": False, "answered_at": T0 + timedelta(seconds=10 * i + offset)} for i in range(4)}}
    pairs = X.similarity_pairs([pack("a", 0), pack("b", 5), pack("c", 400)])
    assert len(pairs) == 1 and set(pairs[0]["attempt_ids"]) == {"a", "b"}
    assert X.similarity_pairs([pack("a", 0), pack("c", 400)]) == []


def test_statystyki_pytan_surowe():
    rows = [{"qid": "q1", "selected": ["a"], "timed_out": False, "elapsed_ms": 4000},
            {"qid": "q1", "selected": ["b"], "timed_out": False, "elapsed_ms": 8000},
            {"qid": "q1", "selected": [], "timed_out": True, "elapsed_ms": None}]
    stats = X.question_stats(rows, BANK, {"q1": "drop"}, "all_or_nothing")[0]
    assert stats["total"] == 3 and stats["answered"] == 2 and stats["timed_out"] == 1
    assert stats["correct_rate"] == round(1 / 3, 4) and stats["avg_time_s"] == 6.0
    assert stats["distribution"] == {"a": 1, "b": 1, "c": 0} and stats["voided"] == "drop"


# --- kod sali --------------------------------------------------------------


def test_kod_sali_zmienia_sie_co_30_s_i_trzyma_poprzedni():
    now = datetime(2026, 11, 2, 10, 0, 10, tzinfo=UTC)
    code = X.room_code("sekret", "e1", now)["code"]
    assert X.room_code_ok("sekret", "e1", code, now + timedelta(seconds=5))
    assert X.room_code_ok("sekret", "e1", code, now + timedelta(seconds=30))  # poprzedni slot jeszcze działa
    assert not X.room_code_ok("sekret", "e1", code, now + timedelta(seconds=90))
    assert not X.room_code_ok("inny", "e1", code, now)


# --- przypomnienia ---------------------------------------------------------


def test_przypomnienia_najblizszy_prog_i_dedup():
    start, end = T0, T0 + timedelta(days=5)
    kw = dict(window_start=start, window_end=end, created_at=start - timedelta(days=1), thresholds_hours=[72, 24, 2], pending=["1", "2"])
    assert X.due_exam_reminders(now=start + timedelta(days=1), sent=set(), **kw) == []
    due = X.due_exam_reminders(now=end - timedelta(hours=70), sent=set(), **kw)
    assert due == [("before_72h", ["1", "2"])]
    dedup = X.due_exam_reminders(now=end - timedelta(hours=70), sent={("1", "before_72h")}, **kw)
    assert dedup == [("before_72h", ["2"])]
    # po przestoju: tylko najbliższy przekroczony próg, nie seria
    assert X.due_exam_reminders(now=end - timedelta(hours=1), sent=set(), **kw) == [("before_2h", ["1", "2"])]
    assert X.due_exam_reminders(now=end + timedelta(seconds=1), sent=set(), **kw) == []
    # próg sprzed otwarcia okna nie strzela świeżemu egzaminowi
    fresh = dict(kw, created_at=end - timedelta(hours=10))
    assert X.due_exam_reminders(now=end - timedelta(hours=9), sent=set(), **fresh) == []


def test_pola_wydarzenia_exam():
    c = cfg(mandatory=True, target={"include_badges": ["Delegaci"]})
    f = X.exam_event_fields("Egzamin sezonowy", "opis", c, "abc")
    assert f["event_type"] == "exam" and f["data_json"]["exam_id"] == "abc" and f["data_json"]["obligatory"] is True
    assert f["data_json"]["target"]["include_badges"] == ["Delegaci"]
    assert f["event_date"] == T0 and f["end_date"] == T0 + timedelta(days=3)


# --- progi rzetelności ustawiane przez komisję ------------------------------


def test_progi_domyslne_daja_te_same_wyniki_co_stale_stare():
    th = X.clean_integrity(None)
    assert th == X.DEFAULT_INTEGRITY
    events = [{"kind": "screenshot", "detail": {}}] * 20
    assert X.integrity_report(events)["score"] == X.integrity_report(events, th)["score"] == 70
    assert X.integrity_report([])["custom"] is False
    assert cfg()["anti"]["integrity"] == X.DEFAULT_INTEGRITY


def test_wlasne_progi_przeliczaja_wskaznik_i_sa_w_raporcie():
    custom = {"penalties": {"screenshot": 20}, "max_events": {"screenshot": 2}, "ok_min": 90, "warning_min": 60}
    rep = X.integrity_report([{"kind": "screenshot", "detail": {}}] * 5, custom)
    assert rep["breakdown"][0]["penalty"] == 40 and rep["score"] == 60 and rep["level"] == "warning"
    assert rep["custom"] is True and rep["thresholds"]["penalties"]["screenshot"] == 20
    assert rep["thresholds"]["penalties"]["app_background"] == 4  # braki z domyślnych
    long_abs = X.integrity_report([{"kind": "app_background", "detail": {"seconds": 12}}], {"long_absence_s": 10, "long_absence_extra": 6})
    assert long_abs["breakdown"][0]["penalty"] == 10


@pytest.mark.parametrize("bad", [
    {"penalties": {"screenshot": 51}}, {"penalties": {"nieznany": 1}}, {"max_events": {"screenshot": 0}},
    {"ok_min": 50, "warning_min": 50}, {"similarity_min_common": 1}, {"similarity_min_common": 2, "similarity_close_min": 3},
    {"similarity_close_s": 0}, {"long_absence_s": 4},
])
def test_progi_rzetelnosci_poza_zakresem_odrzucone(bad):
    with pytest.raises(X.ExamError) as err:
        cfg(anti={"integrity": bad})
    assert err.value.code == "BAD_CONFIG" and "Progi rzetelności" in err.value.message


def test_progi_podobienstwa_z_konfiguracji():
    def pack(aid, offset, n=4):
        return {"attempt_id": aid, "judge_id": aid, "answers": {
            f"q{i}": {"selected": ["c"], "correct": False, "answered_at": T0 + timedelta(seconds=10 * i + offset)} for i in range(n)}}
    packs = [pack("a", 0), pack("b", 20)]
    assert len(X.similarity_pairs(packs)) == 1
    assert X.similarity_pairs(packs, thresholds={"similarity_close_s": 10}) == []
    assert X.similarity_pairs(packs, thresholds={"similarity_min_common": 5}) == []
    assert len(X.similarity_pairs(packs, thresholds={"similarity_min_common": 4, "similarity_close_min": 4})) == 1


def test_progi_rzetelnosci_nie_sa_zablokowane_po_starcie():
    old = cfg()
    new = X.clean_config(X._merge(copy.deepcopy(old), {"anti": {"integrity": {"ok_min": 90}}}))
    assert X.locked_changes(old, new) == []
    changed = X.clean_config(X._merge(copy.deepcopy(old), {"anti": {"screenshots": True}}))
    assert X.locked_changes(old, changed) == ["anti"]


# --- podpowiedź „jedna poprawna" (24.10.2026) -------------------------------


def test_bez_podpowiedzi_pytanie_z_jedna_poprawna_przyjmuje_kilka_odpowiedzi_i_ocenia_zbior():
    c = cfg()
    assert c["single_hint_all"] is False and c["single_hint_ids"] == []
    view = X.exam_question(c, Q_SINGLE, ["c", "a", "b"])
    # Karta nie zdradza liczby poprawnych: wolno zaznaczyć kilka.
    assert view["multi"] is True and view["single_hint"] is False
    assert [x["key"] for x in view["answers"]] == ["c", "a", "b"]
    a, answers = attempt(c), {}
    serve(c, a, answers, T0)
    out = X.apply_answers(c, a, answers, [{"qid": "q1", "selected": ["a", "b"]}], BANK, T0 + timedelta(seconds=10))
    assert out[0]["status"] == "accepted"
    assert X.score_question(Q_SINGLE, ["a", "b"], "all_or_nothing") == 0.0
    assert X.score_question(Q_SINGLE, ["a", "b"], "partial") == 0.0
    assert X.score_question(Q_SINGLE, ["a"], "all_or_nothing") == 1.0


def test_podpowiedz_dla_pytania_i_dla_calego_egzaminu():
    picked = cfg(single_hint_ids=["q1", "q2"])
    assert X.exam_question(picked, Q_SINGLE)["single_hint"] is True
    assert X.exam_question(picked, Q_SINGLE)["multi"] is False
    # Pytanie z kilkoma poprawnymi nigdy nie dostaje podpowiedzi „jedna".
    assert X.exam_question(picked, Q_MULTI)["single_hint"] is False
    every = cfg(single_hint_all=True)
    assert X.single_hint(every, Q_SINGLE) and not X.single_hint(every, Q_MULTI)
    a, answers = attempt(picked), {}
    serve(picked, a, answers, T0)
    out = X.apply_answers(picked, a, answers, [{"qid": "q1", "selected": ["a", "b"]}], BANK, T0 + timedelta(seconds=10))
    assert out[0]["code"] == "EXAM_SINGLE_ONLY"


def test_stary_egzamin_bez_pol_podpowiedzi_nie_blokuje_edycji():
    old = cfg()
    old.pop("single_hint_all")
    old.pop("single_hint_ids")
    assert X.single_hint(old, Q_SINGLE) is False
    assert X.locked_changes(old, cfg()) == []
    assert "single_hint_all" in X.locked_changes(old, cfg(single_hint_all=True))
