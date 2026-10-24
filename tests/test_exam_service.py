"""Egzamin z przepisów - serwis na SQLite (bez Postgresa): bank, definicje, wydarzenia, sesja, sweep."""

import json
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from databases import Database
from sqlalchemy import JSON, Column, DateTime, Integer, MetaData, String, Table, Text, create_engine, select

from app import exam_rules as X
from app import exam_service as S
from app.exam_tables import define_tables

UTC = timezone.utc
T0 = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
OPEN = T0 + timedelta(hours=1)
CLOSE = T0 + timedelta(days=5)
SINGLES = ["q1-1", "q1-2", "q1-3"]  # klucze: a, b, c
CORRECT = {"q1-1": "a", "q1-2": "b", "q1-3": "c"}


def judge(jid, name, badges=None):
    return {"judge_id": jid, "full_name": name, "badges": badges or []}


ROSTER = {
    "ŚLĄSKIE": [judge("1", "Anna Admin"), judge("2", "Kasia Komisja", ["Komisja sędziowska"]), judge("3", "Jan Zwykły"),
                judge("4", "Ola Delegat", ["Delegaci"]), judge("5", "Piotr Cichy")],
    "OPOLSKIE": [judge("8", "Opole Komisja", ["Komisja sędziowska"]), judge("9", "Opole Zwykły")],
}


@pytest_asyncio.fixture
async def st(tmp_path):
    meta = MetaData()
    banks, bq, defs, attempts, answers, events, reminders = define_tables(meta)
    pe = Table("province_events", meta,
               Column("id", Integer, primary_key=True, autoincrement=True), Column("province", String),
               Column("event_date", DateTime(timezone=True)), Column("end_date", DateTime(timezone=True)),
               Column("name", String), Column("description", Text), Column("event_type", String),
               Column("data_json", JSON), Column("created_by", String), Column("created_by_name", String),
               Column("created_at", DateTime(timezone=True)), Column("updated_at", DateTime(timezone=True)),
               Column("deleted_at", DateTime(timezone=True)))
    path = tmp_path / "exam.db"
    create_engine(f"sqlite:///{path}").dispose()
    meta.create_all(create_engine(f"sqlite:///{path}"))
    db = Database(f"sqlite+aiosqlite:///{path}")
    await db.connect()
    pushes = []

    async def judges(province):
        return [dict(j) for j in ROSTER.get(province, [])]

    async def push(ids, title, body, data):
        pushes.append({"ids": list(ids), "title": title, "body": body, "data": data})

    store = S.Store(database=db, t=S.Tables(banks, bq, defs, attempts, answers, events, reminders, pe),
                    judges=judges, push=push, secret="sekret")
    store.pushes = pushes
    S._BANK_CACHE.clear()
    yield store
    await db.disconnect()


def who(jid, name, *, admin=False, badges=None, province="SLASKIE", teach=False):
    async def teach_check(_prov):
        return teach

    return S.Who(judge_id=jid, name=name, province=province, is_admin=admin, badges=badges or {}, teach_check=teach_check)


ADMIN = who("1", "Anna Admin", admin=True)
COMMISSION = who("2", "Kasia Komisja", badges={"Komisja sędziowska": True})
PLAIN = who("3", "Jan Zwykły")
DELEGATE = who("4", "Ola Delegat", badges={"Delegaci": True})
OTHER_COMMISSION = who("8", "Opole Komisja", badges={"Komisja sędziowska": True}, province="OPOLSKIE")
TEACH = who("5", "Piotr Cichy", teach=True)


def body(**cfg):
    config = {"scope": {"manual_ids": SINGLES}, "question_count": 3, "window_start": OPEN.isoformat(),
              "window_end": CLOSE.isoformat(), "shuffle_answers": True, "pass_percent": 60}
    config.update(cfg)
    return {"name": "Test z przepisów", "description": "Opis", "scope": "province", "province": "ŚLĄSKIE", "config": config}


async def make(st, **cfg):
    exam, published = await S.create_exam(st, COMMISSION, body(**cfg), now=T0)
    return exam, published


async def answer_all(st, w, attempt_id, now, choose=None, state=None):
    """Odpowiada po kolei na wszystkie pytania; choose(qid) -> klucze."""
    state = state or await S.attempt_state(st, w, attempt_id, None, None, now)
    results = []
    while state["question"]:
        q = state["question"]
        now += timedelta(seconds=20)
        keys = choose(q["qid"]) if choose else [CORRECT[q["qid"]]]
        out = await S.post_answers(st, w, attempt_id, {"answers": [{"qid": q["qid"], "selected": keys}]}, now)
        results.append(out["results"][0])
        state = out["state"]
    return state, results, now


# --- bank ------------------------------------------------------------------


async def test_bank_publiczny_bez_kluczy_i_z_wersja(st):
    out = await S.bank_public(st)
    assert out["count"] == 432 and out["version"]
    flat = json.dumps(out, ensure_ascii=False)
    assert '"correct"' not in flat and "curiosity" not in flat and "Ciekawostka" not in flat
    again = await S.bank_public(st, since=out["version"])
    assert again["unchanged"] is True and again["questions"] == []
    assert (await S.bank_public(st, rule=1))["count"] < 432


async def test_import_banku_idempotentny_i_ciekawostka_624(st):
    data = json.loads(S.SEED_PATH.read_text(encoding="utf-8"))
    first = await S.import_bank(st, data)
    second = await S.import_bank(st, data)
    assert first["created"] is True and second["created"] is False and first["version"] == second["version"]
    bank = await S.load_bank(st, first["version"])
    assert "Ciekawostka" in bank["q6-24"]["curiosity"] and "8:8i" in bank["q6-24"]["curiosity"]
    assert bank["q1-1"]["curiosity"] is None
    changed = dict(data, questions=data["questions"][:50])
    third = await S.import_bank(st, changed)
    assert third["created"] is True and third["version"] != first["version"]
    assert await S.ensure_bank(st) == third["version"]


# --- uprawnienia i wydarzenia ---------------------------------------------


async def test_tworzenie_uprawnienia_i_komunikaty(st):
    for denied in (PLAIN, DELEGATE, OTHER_COMMISSION):
        with pytest.raises(X.ExamError) as err:
            await S.create_exam(st, denied, body(), now=T0)
        assert err.value.status == 403 and "O nadanie uprawnień" in err.value.message
    for allowed in (ADMIN, COMMISSION, TEACH):
        exam, _ = await S.create_exam(st, allowed, body(), now=T0)
        assert exam["scope"] == "province"
    national = dict(body(), scope="national", province=None)
    with pytest.raises(X.ExamError) as err:
        await S.create_exam(st, COMMISSION, national, now=T0)
    assert "tylko administrator" in err.value.message
    exam, published = await S.create_exam(st, ADMIN, national, now=T0)
    assert exam["scope"] == "national" and len(published) == 16


async def test_egzamin_publikuje_wydarzenie_exam_i_aktualizuje_je(st):
    exam, published = await make(st)
    assert len(published) == 1 and published[0]["province"] == "ŚLĄSKIE"
    rows = [dict(r._mapping) for r in await st.database.fetch_all(select(st.t.province_events))]
    assert len(rows) == 1 and rows[0]["event_type"] == "exam" and rows[0]["data_json"]["exam_id"] == exam["id"]
    assert rows[0]["name"] == "Test z przepisów" and rows[0]["created_by"] == "2"
    new_end = (CLOSE + timedelta(days=2)).isoformat()
    updated, moved = await S.update_exam(st, COMMISSION, exam["id"], {"name": "Nowa nazwa", "config": {"window_end": new_end, "mandatory": True}}, now=T0)
    assert moved is True and updated["name"] == "Nowa nazwa"
    row = dict((await st.database.fetch_one(select(st.t.province_events)))._mapping)
    assert row["name"] == "Nowa nazwa" and row["data_json"]["obligatory"] is True
    assert S._dt(row["end_date"]) == CLOSE + timedelta(days=2)
    with pytest.raises(X.ExamError):
        await S.update_exam(st, PLAIN, exam["id"], {"name": "x"}, now=T0)
    await S.delete_exam(st, COMMISSION, exam["id"], now=T0)
    row = dict((await st.database.fetch_one(select(st.t.province_events)))._mapping)
    assert row["deleted_at"] is not None
    with pytest.raises(X.ExamError) as err:
        await S.get_exam(st, ADMIN, exam["id"], now=T0)
    assert err.value.status == 404


async def test_po_starcie_zdajacych_konfiguracja_jest_zablokowana_z_powodem(st):
    exam, _ = await make(st)
    await S.start_attempt(st, PLAIN, exam["id"], {}, now=OPEN + timedelta(minutes=1))
    with pytest.raises(X.ExamError) as err:
        await S.update_exam(st, COMMISSION, exam["id"], {"config": {"pass_percent": 10}}, now=OPEN)
    assert err.value.code == "EXAM_LOCKED" and "pass_percent" in err.value.message
    ok, _ = await S.update_exam(st, COMMISSION, exam["id"], {"config": {"reminders_hours": [3]}}, now=OPEN)
    assert ok["config"]["reminders_hours"] == [3]


async def test_adresaci_po_odznakach(st):
    exam, _ = await make(st, target={"include_badges": ["Delegaci"]})
    await S.start_attempt(st, DELEGATE, exam["id"], {}, now=OPEN + timedelta(minutes=1))
    with pytest.raises(X.ExamError) as err:
        await S.start_attempt(st, PLAIN, exam["id"], {}, now=OPEN + timedelta(minutes=1))
    assert err.value.code == "EXAM_NOT_INVITED"
    listed = await S.list_for_judge(st, PLAIN, now=OPEN)
    assert listed["exams"] == []
    assert len((await S.list_for_judge(st, DELEGATE, now=OPEN))["exams"]) == 1
    miss = await S.missing(st, COMMISSION, exam["id"])
    assert miss["count"] == 0
    exam2, _ = await make(st)
    miss2 = await S.missing(st, COMMISSION, exam2["id"])
    assert miss2["count"] == 5


# --- sesja -----------------------------------------------------------------


async def test_pytania_w_sesji_nie_maja_kluczy_i_leca_po_kolei(st):
    exam, _ = await make(st)
    t = OPEN + timedelta(minutes=5)
    with pytest.raises(X.ExamError) as err:
        await S.start_attempt(st, PLAIN, exam["id"], {}, now=T0)
    assert err.value.code == "EXAM_NOT_OPEN"
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    flat = json.dumps(state, ensure_ascii=False)
    assert '"correct' not in flat and state["attempt"]["total"] == 3
    aid = state["attempt"]["id"]
    first = state["question"]
    second_qid = [q for q in SINGLES if q != first["qid"]][0]
    early = await S.post_answers(st, PLAIN, aid, {"answers": [{"qid": second_qid, "selected": ["a"]}]}, t + timedelta(seconds=5))
    assert early["results"][0]["code"] in ("EXAM_ORDER",)
    again = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t + timedelta(seconds=30))
    assert again["resumed"] is True and again["attempt"]["id"] == aid
    final, results, end = await answer_all(st, PLAIN, aid, t)
    assert all(r["status"] == "accepted" for r in results)
    assert final["attempt"]["status"] == "submitted" and final["question"] is None


async def test_caly_arkusz_bez_kluczy_w_kolejnosci_podejscia_i_odpowiedzi_bez_sieci(st):
    exam, _ = await make(st, time_per_question_s=60)
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid = state["attempt"]["id"]
    paper = await S.attempt_paper(st, PLAIN, aid, None, now=t + timedelta(seconds=1))
    flat = json.dumps(paper, ensure_ascii=False)
    assert '"correct' not in flat and paper["total"] == 3
    assert [q["index"] for q in paper["questions"]] == [0, 1, 2]
    assert paper["questions"][0]["qid"] == state["question"]["qid"]
    assert [a["key"] for a in paper["questions"][0]["answers"]] == [a["key"] for a in state["question"]["answers"]]
    # Cały arkusz rozwiązany bez sieci (łańcuch advance) i wysłany jedną paczką po kwadransie.
    ms = lambda d: d.timestamp() * 1000  # noqa: E731
    items, at = [], t
    for i, q in enumerate(paper["questions"]):
        at += timedelta(seconds=20)
        items.append({"qid": q["qid"], "selected": [CORRECT[q["qid"]]], "client_ts_ms": ms(at), "advance": i < 2, "time_ms": 19000})
    late = t + timedelta(minutes=15)
    out = await S.post_answers(st, PLAIN, aid, {"answers": items, "buffered": True, "client_now_ms": ms(late)}, late)
    assert [r["status"] for r in out["results"]] == ["accepted"] * 3
    assert out["state"]["attempt"]["status"] == "submitted"
    with pytest.raises(X.ExamError) as err:
        await S.attempt_paper(st, PLAIN, aid, None, now=late)
    assert err.value.code == "EXAM_FINISHED"


async def test_ocena_tylko_na_serwerze_i_polityka_wyniku(st):
    exam, _ = await make(st, result_release="after_close")
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid = state["attempt"]["id"]
    final, _, end = await answer_all(st, PLAIN, aid, t, state=state)
    assert final["result"]["visible"] is False and "po zamknięciu okna" in final["result"]["reason"]
    res = await S.attempt_result(st, PLAIN, aid, now=end)
    assert res["result"]["visible"] is False and res["review_available"] is False
    with pytest.raises(X.ExamError) as err:
        await S.attempt_review(st, PLAIN, aid, now=end)
    assert err.value.code == "EXAM_REVIEW_LOCKED" and err.value.status == 403
    late = CLOSE + timedelta(minutes=1)
    res = await S.attempt_result(st, PLAIN, aid, now=late)
    assert res["result"]["percent"] == 100.0 and res["result"]["passed"] is True
    review = await S.attempt_review(st, PLAIN, aid, now=late)
    assert len(review["questions"]) == 3 and review["questions"][0]["correct_keys"]
    # cudze podejście nie istnieje
    with pytest.raises(X.ExamError):
        await S.attempt_review(st, DELEGATE, aid, now=late)


async def test_wynik_od_razu_ale_przeglad_dopiero_po_oknie(st):
    exam, _ = await make(st, result_release="immediate", answers_release="after_close")
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    final, _, end = await answer_all(st, PLAIN, state["attempt"]["id"], t, choose=lambda q: ["d"], state=state)
    assert final["result"]["visible"] is True and final["result"]["percent"] == 0.0 and final["result"]["passed"] is False
    with pytest.raises(X.ExamError) as err:
        await S.attempt_review(st, PLAIN, state["attempt"]["id"], now=end)
    assert err.value.code == "EXAM_REVIEW_LOCKED"


async def test_limit_podejsc_i_druga_szansa_tylko_dla_niezdanych(st):
    exam, _ = await make(st, result_release="immediate", max_attempts=2, retake="only_failed")
    t = OPEN + timedelta(minutes=5)
    s1 = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    await answer_all(st, PLAIN, s1["attempt"]["id"], t, state=s1)
    with pytest.raises(X.ExamError) as err:
        await S.start_attempt(st, PLAIN, exam["id"], {}, now=t + timedelta(hours=1))
    assert err.value.code == "EXAM_ALREADY_PASSED"
    s2 = await S.start_attempt(st, DELEGATE, exam["id"], {}, now=t)
    await answer_all(st, DELEGATE, s2["attempt"]["id"], t, choose=lambda q: ["d"], state=s2)
    s3 = await S.start_attempt(st, DELEGATE, exam["id"], {}, now=t + timedelta(hours=1))
    assert s3["attempt"]["attempt_no"] == 2
    await answer_all(st, DELEGATE, s3["attempt"]["id"], t + timedelta(hours=1), choose=lambda q: ["d"], state=s3)
    with pytest.raises(X.ExamError) as err:
        await S.start_attempt(st, DELEGATE, exam["id"], {}, now=t + timedelta(hours=2))
    assert err.value.code == "EXAM_NO_ATTEMPTS"


async def test_czas_serwerowy_pytanie_przepada_i_buforowana_odpowiedz_na_czas(st):
    exam, _ = await make(st, time_per_question_s=30)
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid, q = state["attempt"]["id"], state["question"]
    assert 0 < q["seconds_left"] <= 30
    # odpowiedź padła po 20 s, dotarła po 3 minutach (bufor): liczy się stempel, nie chwila dotarcia
    now = t + timedelta(minutes=3)
    client_now = now.timestamp() * 1000 + 5000
    stamp = (t.timestamp() + 20) * 1000 + 5000
    out = await S.post_answers(st, PLAIN, aid, {"client_now_ms": client_now, "buffered": True, "answers": [
        {"qid": q["qid"], "selected": [CORRECT[q["qid"]]], "client_ts_ms": stamp}]}, now)
    assert out["results"][0]["status"] == "accepted" and "buffered_late" in out["results"][0]["flags"]
    q2 = out["state"]["question"]
    # drugie pytanie: spóźnienie > 30 s, bez stempla
    late = await S.post_answers(st, PLAIN, aid, {"answers": [{"qid": q2["qid"], "selected": ["a"]}]}, now + timedelta(seconds=45))
    assert late["results"][0]["code"] == "EXAM_QUESTION_TIME_UP"
    assert late["state"]["attempt"]["current_index"] == 2
    events = await S.attempt_card(st, COMMISSION, exam["id"], aid)
    assert any(e["kind"] == "time_flag" and e["detail"]["flag"] == "buffered_late" for e in events["events"])


async def test_czas_calosci_domyka_podejscie_a_sweep_liczy_wynik(st):
    exam, _ = await make(st, time_total_min=10, result_release="immediate")
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid = state["attempt"]["id"]
    await S.post_answers(st, PLAIN, aid, {"answers": [{"qid": state["question"]["qid"], "selected": [CORRECT[state["question"]["qid"]]]}]}, t + timedelta(seconds=30))
    await S.sweep_exam_reminders(st, t + timedelta(minutes=30))
    row = dict((await st.database.fetch_one(select(st.t.attempts)))._mapping)
    assert row["status"] == "expired" and row["finish_reason"] == "time_up" and row["percent"] == pytest.approx(33.33, abs=0.01)


async def test_wyjscie_z_aplikacji_zapisuje_zdarzenie_i_stosuje_polityke(st):
    exam, _ = await make(st, anti={"leave_app": "void_question", "screenshots": False})
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid = state["attempt"]["id"]
    out = await S.post_events(st, PLAIN, aid, {"events": [
        {"kind": "app_background", "detail": {"seconds": 45}}, {"kind": "screenshot"}, {"kind": "hack"}]}, t + timedelta(seconds=10))
    assert out["recorded"] == 1 and len(out["ignored"]) == 2
    assert out["policy"]["action"] == "question_lost" and out["state"]["attempt"]["current_index"] == 1
    card = await S.attempt_card(st, COMMISSION, exam["id"], aid)
    assert card["integrity"]["score"] < 100 and card["integrity"]["breakdown"][0]["kind"] == "app_background"
    assert card["timeline"][0]["timed_out"] is True


async def test_jedno_urzadzenie_i_zgoda_komisji(st):
    exam, _ = await make(st, anti={"single_device": True})
    t = OPEN + timedelta(minutes=5)
    with pytest.raises(X.ExamError) as err:
        await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    assert err.value.code == "EXAM_DEVICE_REQUIRED"
    state = await S.start_attempt(st, PLAIN, exam["id"], {"device_id": "tel-A"}, now=t)
    aid = state["attempt"]["id"]
    with pytest.raises(X.ExamError) as err:
        await S.attempt_state(st, PLAIN, aid, None, "tel-B", t + timedelta(seconds=30))
    assert err.value.code == "EXAM_OTHER_DEVICE" and "zgody komisji" in err.value.message
    card = await S.attempt_card(st, COMMISSION, exam["id"], aid)
    assert [e["kind"] for e in card["events"]] == ["device_change"]
    await S.allow_device(st, COMMISSION, exam["id"], aid, "tel-B")
    ok = await S.attempt_state(st, PLAIN, aid, None, "tel-B", t + timedelta(seconds=40))
    assert ok["attempt"]["status"] == "in_progress"


async def test_kod_sali_wymagany_na_starcie(st):
    exam, _ = await make(st, anti={"room_code": True})
    t = OPEN + timedelta(minutes=5)
    with pytest.raises(X.ExamError) as err:
        await S.start_attempt(st, PLAIN, exam["id"], {"room_code": "000000"}, now=t)
    assert err.value.code == "EXAM_ROOM_CODE"
    code = (await S.room_code_for(st, COMMISSION, exam["id"], now=t))["code"]
    state = await S.start_attempt(st, PLAIN, exam["id"], {"room_code": code}, now=t)
    assert state["attempt"]["status"] == "in_progress"


# --- komisja ---------------------------------------------------------------


async def test_unieważnienie_pytania_przelicza_wyniki(st):
    exam, _ = await make(st, result_release="immediate", pass_percent=60)
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    bad = state["question"]["qid"]

    def choose(qid):
        return ["d"] if qid == bad else [CORRECT[qid]]

    final, _, end = await answer_all(st, PLAIN, state["attempt"]["id"], t, choose=choose, state=state)
    assert final["result"]["percent"] == pytest.approx(66.67, abs=0.01)
    out = await S.void_question(st, COMMISSION, exam["id"], bad, "drop")
    assert out["recomputed"] == 1 and out["voided"] == {bad: "drop"}
    res = await S.attempt_result(st, PLAIN, state["attempt"]["id"], now=end)
    assert res["result"]["percent"] == 100.0 and res["result"]["max"] == 2.0
    await S.void_question(st, COMMISSION, exam["id"], bad, "credit")
    assert (await S.attempt_result(st, PLAIN, state["attempt"]["id"], now=end))["result"]["max"] == 3.0
    await S.unvoid_question(st, COMMISSION, exam["id"], bad)
    assert (await S.attempt_result(st, PLAIN, state["attempt"]["id"], now=end))["result"]["percent"] == pytest.approx(66.67, abs=0.01)
    with pytest.raises(X.ExamError):
        await S.void_question(st, PLAIN, exam["id"], bad, "drop")
    with pytest.raises(X.ExamError) as err:
        await S.void_question(st, COMMISSION, exam["id"], "q9-9", "drop")
    assert err.value.code == "EXAM_UNKNOWN_QUESTION"


async def test_listy_dla_komisji_statystyki_i_nie_przystapili(st):
    exam, _ = await make(st, result_release="immediate")
    t = OPEN + timedelta(minutes=5)
    for w in (PLAIN, DELEGATE):
        state = await S.start_attempt(st, w, exam["id"], {}, now=t)
        await answer_all(st, w, state["attempt"]["id"], t, choose=(lambda q: ["a"]), state=state)
    lst = await S.attempts_list(st, COMMISSION, exam["id"])
    assert len(lst["attempts"]) == 2 and all(a["integrity"]["score"] == 100 for a in lst["attempts"])
    stats = await S.exam_stats(st, COMMISSION, exam["id"])
    assert stats["summary"]["finished"] == 2 and len(stats["questions"]) == 3
    by_q = {q["qid"]: q for q in stats["questions"]}
    assert by_q["q1-1"]["correct_rate"] == 1.0 and by_q["q1-2"]["correct_rate"] == 0.0
    missing = await S.missing(st, COMMISSION, exam["id"])
    assert {m["judge_id"] for m in missing["missing"]} == {"1", "2", "5"}
    for denied in (PLAIN, OTHER_COMMISSION):
        for call in (S.attempts_list, S.exam_stats, S.missing):
            with pytest.raises(X.ExamError) as err:
                await call(st, denied, exam["id"])
            assert err.value.status == 403 and err.value.message


async def test_podobienstwo_wymaga_wlaczenia(st):
    exam, _ = await make(st)
    with pytest.raises(X.ExamError) as err:
        await S.similarity_scan(st, COMMISSION, exam["id"])
    assert err.value.code == "EXAM_FEATURE_OFF"
    exam2, _ = await make(st, anti={"similarity": True}, result_release="immediate")
    assert (await S.similarity_scan(st, COMMISSION, exam2["id"]))["pairs"] == []


# --- sweep -----------------------------------------------------------------


async def test_sweep_przypomnien_z_dedupem_i_push_wynikow(st):
    exam, _ = await make(st, reminders_hours=[72, 24], results_push=True, target={"include_all": True})
    created = T0
    # za wcześnie na jakikolwiek próg
    assert await S.sweep_exam_reminders(st, OPEN + timedelta(hours=2)) == 0
    # 70 h przed końcem: próg 72 h przekroczony PO utworzeniu egzaminu? nie - próg wypadał przed otwarciem okna
    near = CLOSE - timedelta(hours=23)
    # jeden z zaproszonych przystąpił i nie dostanie przypomnienia
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=near - timedelta(hours=1))
    sent = await S.sweep_exam_reminders(st, near)
    assert sent == 4  # 5 sędziów śląskich bez Jana
    reminder = [p for p in st.pushes if p["data"]["notice"] == "exam_reminder"]
    assert len(reminder) == 1 and "3" not in reminder[0]["ids"] and reminder[0]["data"]["examId"] == exam["id"]
    assert reminder[0]["data"]["kind"] == "province_event" and reminder[0]["data"]["eventId"]
    # drugie przejście nie wysyła ponownie
    assert await S.sweep_exam_reminders(st, near + timedelta(minutes=10)) == 0
    # po zamknięciu okna: domknięcie podejścia i JEDEN push „wyniki dostępne"
    after = CLOSE + timedelta(minutes=10)
    pushed = await S.sweep_exam_reminders(st, after)
    results = [p for p in st.pushes if p["data"]["notice"] == "exam_results"]
    assert pushed == 1 and len(results) == 1 and results[0]["ids"] == ["3"]
    assert await S.sweep_exam_reminders(st, after + timedelta(minutes=10)) == 0
    assert len([p for p in st.pushes if p["data"]["notice"] == "exam_results"]) == 1
    row = dict((await st.database.fetch_one(select(st.t.attempts)))._mapping)
    assert row["status"] == "expired"


async def test_klucz_od_razu_po_oddaniu_i_przeglad_komisji(st):
    exam, _ = await make(st, result_release="immediate")
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid = state["attempt"]["id"]
    await S.post_events(st, PLAIN, aid, {"events": [{"kind": "app_background", "detail": {"seconds": 3}}]}, now=t)
    _final, _, end = await answer_all(st, PLAIN, aid, t, choose=lambda q: ["d"], state=state)
    mine = await S.attempt_review(st, PLAIN, aid, now=end)
    assert mine["violations"] == 1 and "events" not in mine and mine["exam"]["answers_release"] == "immediate"
    assert all("position" in q and "difficulty" in q for q in mine["questions"])
    listed = await S.list_for_judge(st, PLAIN, now=end)
    att = next(e for e in listed["exams"] if e["id"] == exam["id"])["my_attempts"][0]
    assert att["review_available"] is True and att["review_reason"] is None
    card = await S.attempt_card(st, COMMISSION, exam["id"], aid)
    assert all("client_time_ms" in row for row in card["timeline"])
    full = await S.committee_review(st, COMMISSION, exam["id"], aid)
    assert full["violations"] == 1 and full["events"][0]["kind"] == "app_background" and full["flags"] == []
    with pytest.raises(X.ExamError):
        await S.committee_review(st, PLAIN, exam["id"], aid)
