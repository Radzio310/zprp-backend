"""Wdrożenie okręgu (`docs/wdrozenie-okregu.md`): kod, limit prób, rotacja,
postęp, publikacja ryczałtów i sejf bez sekretów w zdarzeniach.

Górna połowa czyta reguły (czysty liść, zawsze). Dolna przechodzi przez
prawdziwe trasy na Postgresie - pomijana, gdy `DATABASE_URL` nie wskazuje
Postgresa (ta sama bariera co `conftest.requires_db`).
"""
from __future__ import annotations

import base64
import json
import os
import random

import pytest

from app import district_onboarding_rules as R

# ── Kod ─────────────────────────────────────────────────────────────────────


def test_code_uses_unambiguous_alphabet_and_formats_like_the_board():
    code = R.generate_code(random.Random(7))
    assert len(code) == 8
    assert all(ch in R.CODE_ALPHABET for ch in code)
    assert not set("01IO") & set(R.CODE_ALPHABET)
    assert R.format_code("WK7Q3MPX") == "WK7Q-3MPX"
    assert R.code_link("WK7Q3MPX").endswith("/okreg/start#WK7Q3MPX")


def test_code_typed_by_a_human_is_normalized_and_garbage_rejected():
    assert R.normalize_code(" wk7q-3mpx ") == "WK7Q3MPX"
    assert R.normalize_code("WK7Q 3MPX") == "WK7Q3MPX"
    assert R.normalize_code("WK7Q3MP") == ""  # za krótki
    assert R.normalize_code("WK7Q3MP0") == ""  # zero nie należy do alfabetu
    assert R.normalize_code(None) == ""


def test_code_hash_depends_on_pepper_and_never_equals_the_code():
    h1 = R.code_hash("WK7Q3MPX", "a")
    assert h1 != R.code_hash("WK7Q3MPX", "b")
    assert "WK7Q3MPX" not in h1 and len(h1) == 64


# ── Token ───────────────────────────────────────────────────────────────────


def test_token_roundtrip_carries_province_version_and_name():
    token = R.sign_token("s", province="POMORSKIE", code_version=3, name="Anna Nowak", now=1000)
    claims = R.verify_token("s", token, now=1001)
    assert claims and claims.province == "POMORSKIE" and claims.code_version == 3 and claims.name == "Anna Nowak"


def test_token_expires_after_12_hours_and_rejects_tampering():
    token = R.sign_token("s", province="POMORSKIE", code_version=1, name="Anna Nowak", now=0)
    assert R.verify_token("s", token, now=R.TOKEN_TTL_SECONDS - 1)
    assert R.verify_token("s", token, now=R.TOKEN_TTL_SECONDS) is None
    assert R.verify_token("inny", token, now=1) is None
    body, sig = token.split(".")
    forged = json.loads(base64.urlsafe_b64decode(body + "==")) | {"p": "SLASKIE"}
    forged_body = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    assert R.verify_token("s", f"{forged_body}.{sig}", now=1) is None
    assert R.verify_token("s", "", now=1) is None


def test_signature_needs_first_and_last_name():
    assert R.clean_name("Anna Nowak") == "Anna Nowak"
    assert R.clean_name("  Jan   Maria  Kowalski ") == "Jan Maria Kowalski"
    assert R.clean_name("Anna") == ""
    assert R.clean_name("a\u0000 b") == ""


# ── Limit prób ──────────────────────────────────────────────────────────────


def test_limit_five_attempts_per_minute():
    lim = R.EnterLimiter()
    for i in range(5):
        assert lim.retry_after("ip", now=100 + i) == 0
        lim.attempt("ip", ok=False, now=100 + i)
    assert lim.retry_after("ip", now=105) > 0
    assert lim.retry_after("inny", now=105) == 0
    assert lim.retry_after("ip", now=161) == 0  # minuta minęła


def test_twenty_failures_block_the_ip_for_an_hour():
    lim = R.EnterLimiter()
    t = 0.0
    for _ in range(20):
        lim.attempt("ip", ok=False, now=t)
        t += 61  # nigdy nie wpada w limit minutowy
    assert lim.is_blocked("ip", now=t)
    assert 3000 < lim.retry_after("ip", now=t) <= 3601
    assert lim.retry_after("ip", now=t + 3601) == 0
    assert "godzinę" in R.wait_message(3600)
    assert R.wait_message(30) == "Za dużo prób naraz. Spróbuj znów za 1 minutę."


def test_success_clears_failures():
    lim = R.EnterLimiter()
    for i in range(19):
        lim.attempt("ip", ok=False, now=i * 61)
    lim.attempt("ip", ok=True, now=19 * 61)
    lim.attempt("ip", ok=False, now=20 * 61)
    assert not lim.is_blocked("ip", now=20 * 61)


# ── Zakres, postęp, etap ────────────────────────────────────────────────────


def test_scope_follows_modules_and_core_is_always_there():
    assert R.scope_keys([]) == ["zprp_sync", "keeper", "commission"]
    assert R.scope_keys(["obsada", "rozliczenia"]) == [
        "zprp_sync", "zprp_assign", "rates", "distances", "keeper", "commission",
    ]
    assert "mentors" in R.scope_keys(["rozwoj"]) and "masters" in R.scope_keys(["egzaminy"])
    assert R.clean_modules(["egzaminy", "nic", "obsada", 5]) == ["obsada", "egzaminy"]


def test_progress_is_weighted_and_normalized_to_scope():
    items = {"zprp_sync": {"status": "active"}}
    # rdzeń: sync 20 + keeper 5 + commission 15 = 40
    assert R.compute_progress(items, []) == 50
    items["commission"] = {"status": "submitted"}
    assert R.compute_progress(items, []) == round(100 * (20 + 15 * 0.6) / 40)
    items["keeper"] = {"status": "rejected"}
    assert R.compute_progress(items, []) == round(100 * (20 + 9) / 40)
    full = {k: {"status": "active"} for k in R.KEY_ORDER}
    full["distances"] = {"status": "skipped"}
    assert R.compute_progress(full, list(R.MODULES)) == 100
    assert R.compute_progress({}, list(R.MODULES)) == 0


def test_stage_moves_waiting_in_progress_ready_live():
    done = {k: {"status": "active"} for k in R.scope_keys([])}
    assert R.compute_stage({}, [], entered=False, live=False) == "waiting"
    assert R.compute_stage({}, [], entered=True, live=False) == "in_progress"
    assert R.compute_stage(done, [], entered=True, live=False) == "ready"
    assert R.compute_stage(done, ["obsada"], entered=True, live=False) == "in_progress"
    assert R.compute_stage({}, [], entered=False, live=True) == "live"


def test_lit_modules_need_core_and_their_keys():
    items = {k: {"status": "active"} for k in R.scope_keys([])}
    assert R.lit_modules(items, ["statystyki", "obsada"]) == ["rdzen", "statystyki"]
    items["zprp_assign"] = {"status": "active"}
    assert R.lit_modules(items, ["statystyki", "obsada"]) == ["rdzen", "obsada", "statystyki"]
    assert R.lit_modules({}, ["obsada"]) == []
    items["distances"] = {"status": "skipped"}
    assert R.skipped_keys(items, ["rozliczenia"]) == ["distances"]


def test_only_optional_keys_can_be_skipped_and_say_what_goes_dark():
    skippable = {k.key for k in R.KEYS if k.skippable}
    assert skippable == {"distances", "masters", "mentors"}
    assert all(R.KEY_META[k].skip_effect for k in skippable)
    assert "Google" in R.KEY_META["distances"].skip_effect


# ── Szkice ──────────────────────────────────────────────────────────────────


def _rates_draft():
    return {
        "validFrom": "2026-12-01",
        "content": {
            "Sędzia boiskowy": {"Junior": "120,50", "III liga": 150, "Młodzik": ""},
            "Sędzia stolikowy": {"Junior": 60},
            "Delegat": {"III liga": {"miejscowy": 80, "zamiejscowy": 100}},
        },
    }


def test_rates_draft_matches_settlement_engine_shape():
    clean, errors = R.validate_rates_draft(_rates_draft())
    assert errors == []
    assert clean["content"]["Sędzia boiskowy"] == {"Junior": 120.5, "III liga": 150}
    from datetime import date

    from app.settlement_rates import provincial_gross

    day = date(2026, 12, 5)
    assert provincial_gross(clean["content"], 10, "Junior", "Sędzia boiskowy", day) == 120.5
    assert provincial_gross(clean["content"], 10, "III liga", "Delegat", day) == 100


def test_rates_draft_reports_what_is_missing():
    _clean, errors = R.validate_rates_draft({"content": {"Sędzia boiskowy": {"Junior": -5}}})
    assert any("datę" in e for e in errors)
    assert any("stolikowy" in e for e in errors)
    assert any("poza zakresem" in e for e in errors)


def test_distance_draft_needs_full_matrix():
    cities = ["Gdańsk", "Gdynia", "Sopot"]
    edges = [{"from": "Gdańsk", "to": "Gdynia", "distance_km": 25}, {"from": "Sopot", "to": "Gdańsk", "km": "12"}]
    _clean, errors = R.validate_distances_draft({"validFrom": "2026-12-01", "cities": cities, "edges": edges})
    assert errors == ["Brakuje 1 pary miast."]
    edges.append({"from": "Gdynia", "to": "Sopot", "distance_km": 14})
    clean, errors = R.validate_distances_draft({"validFrom": "2026-12-01", "cities": cities, "edges": edges})
    assert errors == []
    assert len(clean["edges"]) == 3 and clean["edges"][1] == {"from": "Gdańsk", "to": "Sopot", "distance_km": 12}


def test_people_need_names_rights_and_logins():
    people, errors = R.clean_people("commission", [
        {"first_name": "Anna", "last_name": "Nowak", "login": "anowak", "rights": ["admin", "inne"]},
        {"first_name": "Anna", "last_name": "Nowak", "login": "ANOWAK", "rights": ["admin"]},
    ])
    assert errors == [] and len(people) == 1 and people[0]["rights"] == ["admin"]
    _p, errors = R.clean_people("commission", [{"first_name": "Jan", "last_name": "Kos", "login": "jk", "rights": []}])
    assert errors and "prawo" in errors[0]
    _p, errors = R.clean_people("keeper", {"first_name": "Jan", "last_name": "Kos", "phone": "12", "email": "x"})
    assert len(errors) == 2


# ── Sejf i zdarzenia ────────────────────────────────────────────────────────


def test_vault_accepts_only_sealed_box_shapes():
    sealed = base64.b64encode(b"\x01" * 80).decode()
    assert R.check_ciphertext(sealed) == sealed
    assert R.check_ciphertext("tajnehaslo123") == ""  # jawne hasło nie przejdzie jako szyfrogram
    assert R.check_ciphertext(base64.b64encode(b"x" * 48).decode()) == ""
    assert R.check_public_key(base64.b64encode(b"k" * 32).decode())
    assert R.check_public_key(base64.b64encode(b"k" * 31).decode()) == ""
    assert R.railway_env_names("POMORSKIE", "zprp_assign") == (
        "ZPRP_ASSIGN_POMORSKIE_USERNAME", "ZPRP_ASSIGN_POMORSKIE_PASSWORD",
    )


def test_scrub_removes_secrets_at_every_level():
    clean = R.scrub({"login": "a", "password": "x", "nested": [{"ciphertext": "c", "ok": 1}], "Code": "W"})
    assert clean == {"login": "a", "nested": [{"ok": 1}]}


def test_public_items_never_carry_secret_material():
    items = {
        "zprp_sync": {"status": "submitted", "sealed": True, "login": "ks", "ciphertext": "c"},
        "rates": {"status": "in_review", "draft": {"a": 1}, "files": 2},
    }
    out = R.public_items(items)
    assert "login" not in out["zprp_sync"] and "ciphertext" not in out["zprp_sync"]
    assert out["zprp_sync"]["sealed"] is True
    assert out["rates"]["draft"] == {"a": 1} and "draft" not in out["zprp_sync"]
    assert R.public_items(items, for_admin=True)["zprp_sync"]["login"] == "ks"


# ── Powiadomienia ───────────────────────────────────────────────────────────


def test_batcher_sends_first_change_and_bundles_the_next_ten_minutes():
    b = R.NotifyBatcher()
    assert len(b.add("POMORSKIE", {"key": "rates", "action": "submitted"}, now=0)) == 1
    assert b.add("POMORSKIE", {"key": "keeper", "action": "submitted"}, now=60) == []
    assert b.add("POMORSKIE", {"key": "commission", "action": "submitted", "count": 2}, now=120) == []
    assert b.add("LODZKIE", {"key": "rates", "action": "submitted"}, now=120)  # inny okręg osobno
    assert b.flush("POMORSKIE", now=599) == []
    sent = b.flush("POMORSKIE", now=600)
    assert len(sent) == 2 and b.pending("POMORSKIE") == 0


def test_push_text_reads_like_the_spec():
    title, body = R.batch_text("POMORSKIE", [
        {"key": "rates", "action": "submitted", "via": "file"},
        {"key": "zprp_sync", "action": "submitted"},
        {"key": "commission", "action": "submitted", "count": 2},
    ])
    assert title == "Okręg pomorski: 3 nowe rzeczy"
    assert body == "Ryczałty (plik), konto odczytu, 2 osoby komisji"
    assert R.batch_text("LODZKIE", [{"key": "x"}] * 5)[0] == "Okręg łódzki: 5 nowych rzeczy"


def test_admin_alert_kind_is_registered_with_bare_title():
    from app.admin_alert_rules import alert_title, is_known_kind

    assert is_known_kind("district_onboarding")
    assert alert_title("district_onboarding", "Okręg pomorski: 1 nowa rzecz").endswith("Okręg pomorski: 1 nowa rzecz")
    assert "Wdrożenie okręgu -" not in alert_title("district_onboarding", "Okręg pomorski: 1 nowa rzecz")


def test_plural_forms():
    assert [R.plural(n, "okręg", "okręgi", "okręgów") for n in (1, 2, 5, 12, 22, 25)] == [
        "okręg", "okręgi", "okręgów", "okręgów", "okręgi", "okręgów",
    ]


# ── Trasy na Postgresie ─────────────────────────────────────────────────────

_PG = os.getenv("DATABASE_URL", "").startswith("postgres")
requires_pg = pytest.mark.skipif(not _PG, reason="Wymaga Postgresa. Ustaw DATABASE_URL=postgresql://…")

SEALED = base64.b64encode(bytes(range(96))).decode()
PROVINCE = "POMORSKIE"


@pytest.fixture
def api(monkeypatch):
    os.environ.setdefault("ONBOARDING_CODE_PEPPER", "pieprz-testowy")
    os.environ.setdefault("ONBOARDING_TOKEN_SECRET", "sekret-testowy")
    from contextlib import asynccontextmanager

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text

    from app import district_onboarding as D
    from app.access_control import require_app_admin
    from app.db import database

    engine = create_engine(os.environ["DATABASE_URL"])

    def clean():
        with engine.begin() as c:
            for table in ("district_onboarding_events", "district_onboarding_files", "sealed_secrets",
                          "onboarding_sealing_keys", "district_onboarding"):
                c.execute(text(f"DELETE FROM {table}"))
            c.execute(text("DELETE FROM okreg_rates WHERE province = 'POMORSKIE'"))
            c.execute(text("DELETE FROM active_provinces WHERE province = 'POMORSKIE'"))

    clean()
    sent: list = []
    monkeypatch.setattr(D, "_LIMITER", R.EnterLimiter())
    monkeypatch.setattr(D, "_notify", lambda province, change: sent.append((province, change)))

    @asynccontextmanager
    async def lifespan(_app):
        await database.connect()
        yield
        await database.disconnect()

    app = FastAPI(lifespan=lifespan)
    app.include_router(D.public_router)
    app.include_router(D.district_router)
    app.include_router(D.admin_router)
    app.dependency_overrides[require_app_admin] = lambda: {"judge_id": "1"}
    with TestClient(app) as client:
        client.sent = sent
        client.engine = engine
        yield client
    clean()


def _enter(api, code, name="Anna Nowak"):
    return api.post("/public/onboarding/enter", json={"code": code, "name": name})


@requires_pg
def test_code_enter_and_rotation_kills_old_tokens(api):
    issued = api.post(f"/admin/onboarding/{PROVINCE}/code").json()
    assert issued["display"] == R.format_code(issued["code"])
    assert api.post("/public/onboarding/enter", json={"code": issued["display"]}).json()["need_name"] is True
    res = _enter(api, issued["display"].lower())
    assert res.status_code == 200 and res.json()["label"] == "Okręg pomorski"
    token = res.json()["token"]
    state = api.get("/onboarding/state", headers={"X-Onboarding-Token": token}).json()
    assert state["stage"] == "in_progress" and state["events"][0]["by"] == "Anna Nowak"

    with api.engine.connect() as c:
        from sqlalchemy import text

        stored = c.execute(text("SELECT code_hash FROM district_onboarding")).scalar()
    assert stored and issued["code"] not in stored

    fresh = api.post(f"/admin/onboarding/{PROVINCE}/code").json()
    assert api.get("/onboarding/state", headers={"X-Onboarding-Token": token}).status_code == 401
    assert _enter(api, issued["code"]).status_code == 401
    assert _enter(api, fresh["code"]).status_code == 200


@requires_pg
def test_bad_code_is_generic_and_limited(api):
    first = _enter(api, "ZZZZZZZZ")
    assert first.status_code == 401 and first.json()["detail"]["message"] == R.BAD_CODE
    for _ in range(4):
        assert _enter(api, "ZZZZZZZZ").status_code == 401
    limited = _enter(api, "ZZZZZZZZ")
    assert limited.status_code == 429 and limited.json()["detail"]["retry_after"] > 0


@requires_pg
def test_progress_and_approve_publishes_okreg_rates_version(api):
    code = api.post(f"/admin/onboarding/{PROVINCE}/code").json()["code"]
    h = {"X-Onboarding-Token": _enter(api, code).json()["token"]}
    state = api.put("/onboarding/modules", json={"modules": ["rozliczenia"]}, headers=h).json()
    assert "rates" in state["scope"] and state["progress"] == 0

    half = api.put("/onboarding/draft/rates", json={"validFrom": "2026-12-01"}, headers=h).json()
    assert half["errors"] and half["items"]["rates"]["status"] == "missing"
    state = api.put("/onboarding/draft/rates", json=_rates_draft(), headers=h).json()
    assert state["errors"] == [] and state["items"]["rates"]["status"] == "submitted"
    assert 0 < state["progress"] < 100
    assert (PROVINCE, {"key": "rates", "action": "submitted", "via": "editor"}) in api.sent

    skipped = api.post("/onboarding/skip/distances", json={"reason": "nie mamy"}, headers=h).json()
    assert skipped["items"]["distances"]["status"] == "skipped"
    assert api.post("/onboarding/skip/rates", headers=h, json={}).status_code == 400

    admin = api.post(f"/admin/onboarding/{PROVINCE}/approve/rates").json()
    assert admin.get("items", {}).get("rates", {}).get("status") == "active", admin
    from sqlalchemy import text

    with api.engine.connect() as c:
        row = c.execute(text("SELECT content, valid_from, enabled FROM okreg_rates WHERE province='POMORSKIE'")).one()
    content = row[0] if isinstance(row[0], dict) else json.loads(row[0])
    assert content["Sędzia boiskowy"]["Junior"] == 120.5 and str(row[1]) == "2026-12-01" and row[2] is True

    after = api.get("/onboarding/state", headers=h).json()
    assert after["progress"] > state["progress"]
    pub = {m["province"]: m for m in api.get("/public/onboarding/map").json()}
    assert len(pub) == 16 and pub[PROVINCE]["progress"] == after["progress"]
    assert pub[PROVINCE]["skipped"] == ["distances"]
    assert "Anna" not in json.dumps(pub)  # zero nazwisk na publicznej mapie


@requires_pg
def test_vault_keeps_only_ciphertext_and_events_stay_clean(api, caplog):
    import logging

    # INFO jak na Railway. DEBUG biblioteki `databases` wypisuje argumenty KAŻDEGO
    # zapytania i na produkcji jest wyłączony.
    caplog.set_level(logging.INFO)
    pub = base64.b64encode(b"p" * 32).decode()
    key_id = api.put("/admin/onboarding/sealing-key", json={"public_key": pub}).json()["key_id"]
    assert api.get("/public/onboarding/sealing-key").json()["key_id"] == key_id
    code = api.post(f"/admin/onboarding/{PROVINCE}/code").json()["code"]
    h = {"X-Onboarding-Token": _enter(api, code).json()["token"]}

    plain = api.post("/onboarding/secret", headers=h, json={"key": "zprp_sync", "login": "ks_pom", "ciphertext": "haslo123", "key_id": key_id})
    assert plain.status_code == 400
    wrong_key = api.post("/onboarding/secret", headers=h, json={"key": "zprp_sync", "login": "ks_pom", "ciphertext": SEALED, "key_id": "stary"})
    assert wrong_key.status_code == 409
    state = api.post("/onboarding/secret", headers=h, json={"key": "zprp_sync", "login": "ks_pom", "ciphertext": SEALED, "key_id": key_id}).json()
    assert state["items"]["zprp_sync"]["status"] == "submitted"
    assert SEALED not in json.dumps(state) and "ks_pom" not in json.dumps(state)
    same = api.post("/onboarding/secret", headers=h, json={"key": "zprp_assign", "same_as_sync": True}).json()
    assert same["items"]["zprp_assign"]["same_as_sync"] is True

    admin = api.get(f"/admin/onboarding/{PROVINCE}").json()
    secret = admin["secrets"][0]
    assert secret["ciphertext"] == SEALED and secret["env_password"] == "ZPRP_SYNC_POMORSKIE_PASSWORD"
    assert SEALED not in json.dumps(admin["events"])
    from sqlalchemy import text

    with api.engine.connect() as c:
        payloads = [json.dumps(p) for (p,) in c.execute(text("SELECT payload FROM district_onboarding_events"))]
    assert not any(SEALED in p or "password" in p for p in payloads)
    assert SEALED not in caplog.text

    done = api.post(f"/admin/onboarding/secrets/{secret['id']}/consumed").json()
    assert done["secrets"][0]["ciphertext"] is None and done["secrets"][0]["consumed_at"]


@requires_pg
def test_files_go_to_review_and_admin_draft_awaits_district(api):
    code = api.post(f"/admin/onboarding/{PROVINCE}/code").json()["code"]
    h = {"X-Onboarding-Token": _enter(api, code).json()["token"]}
    bad = api.post("/onboarding/file", headers=h, data={"key": "rates"}, files={"file": ("x.exe", b"MZ", "application/octet-stream")})
    assert bad.status_code == 415
    ok = api.post("/onboarding/file", headers=h, data={"key": "rates"}, files={"file": ("ryczalty.pdf", b"%PDF-1.4 test", "application/pdf")}).json()
    assert ok["items"]["rates"]["status"] == "in_review" and ok["files"][0]["filename"] == "ryczalty.pdf"
    file_id = ok["files"][0]["id"]
    got = api.get(f"/admin/onboarding/{PROVINCE}/files/{file_id}")
    assert got.status_code == 200 and got.content.startswith(b"%PDF")

    admin = api.post(f"/admin/onboarding/{PROVINCE}/draft/rates", json=_rates_draft()).json()
    assert admin["items"]["rates"]["draft_by_admin"] is True
    seen = api.get("/onboarding/state", headers=h).json()["items"]["rates"]
    assert seen["draft_by_admin"] is True and seen["draft"]["content"]
    confirmed = api.put("/onboarding/draft/rates", headers=h, json=seen["draft"]).json()
    assert confirmed["items"]["rates"]["status"] == "submitted" and not confirmed["items"]["rates"]["draft_by_admin"]

    rejected = api.post(f"/admin/onboarding/{PROVINCE}/reject/rates", json={"note": "Brakuje stawek dla delegata."}).json()
    assert rejected["items"]["rates"]["status"] == "rejected"
    assert api.get("/onboarding/state", headers=h).json()["items"]["rates"]["note"] == "Brakuje stawek dla delegata."


@requires_pg
def test_go_live_needs_ready_and_turns_province_on(api):
    code = api.post(f"/admin/onboarding/{PROVINCE}/code").json()["code"]
    h = {"X-Onboarding-Token": _enter(api, code).json()["token"]}
    assert api.post(f"/admin/onboarding/{PROVINCE}/go-live").status_code == 409
    pub = base64.b64encode(b"q" * 32).decode()
    key_id = api.put("/admin/onboarding/sealing-key", json={"public_key": pub}).json()["key_id"]
    api.post("/onboarding/secret", headers=h, json={"key": "zprp_sync", "login": "ks", "ciphertext": SEALED, "key_id": key_id})
    api.put("/onboarding/people/keeper", headers=h, json={"person": {"first_name": "Jan", "last_name": "Kos", "phone": "600 100 200", "email": "jan@okreg.pl"}})
    bad = api.put("/onboarding/people/commission", headers=h, json={"people": [{"first_name": "Ola"}]})
    assert bad.status_code == 422
    api.put("/onboarding/people/commission", headers=h, json={"people": [
        {"first_name": "Ola", "last_name": "Lis", "login": "onb_test_olalis", "rights": ["assignments"]},
    ]})
    for key in ("zprp_sync", "keeper", "commission"):
        assert api.post(f"/admin/onboarding/{PROVINCE}/approve/{key}").status_code == 200
    assert api.get("/onboarding/state", headers=h).json()["stage"] == "ready"
    live = api.post(f"/admin/onboarding/{PROVINCE}/go-live").json()
    assert live["stage"] == "live" and live["progress"] == 100
    pub_map = {m["province"]: m for m in api.get("/public/onboarding/map").json()}
    assert pub_map[PROVINCE]["stage"] == "live"
    from sqlalchemy import text

    with api.engine.begin() as c:
        perms = c.execute(text("SELECT permissions_json FROM baza_vips WHERE username='onb_test_olalis'")).scalar()
        c.execute(text("DELETE FROM baza_vips WHERE username='onb_test_olalis'"))
    perms = perms if isinstance(perms, dict) else json.loads(perms)
    assert perms == {"assignments": True}


@requires_pg
async def test_notify_sends_one_bundled_push_with_deep_link(monkeypatch):
    import asyncio

    import app.admin_alerts as alerts
    from app import district_onboarding as D

    calls = []

    async def fake_notify(kind, subject, body, **kw):
        calls.append((kind, subject, body, kw))
        return 1

    monkeypatch.setattr(alerts, "notify_admins", fake_notify)
    monkeypatch.setattr(D, "_BATCHER", R.NotifyBatcher())
    monkeypatch.setattr(D, "_FLUSH", {})
    D._notify("POMORSKIE", {"key": "rates", "action": "submitted", "via": "file"})
    D._notify("POMORSKIE", {"key": "zprp_sync", "action": "submitted", "password": "x"})
    await asyncio.sleep(0.05)
    assert len(calls) == 1
    kind, subject, body, kw = calls[0]
    assert kind == "district_onboarding" and subject == "Okręg pomorski: 1 nowa rzecz" and body == "Ryczałty (plik)"
    assert kw["extra"]["province"] == "POMORSKIE" and kw["extra"]["screen"] == "district_onboarding"
    assert D._BATCHER.pending("POMORSKIE") == 1 and "POMORSKIE" in D._FLUSH
    D._FLUSH["POMORSKIE"].cancel()
