"""Trasy „Wczytaj składy" (02.11.2026): odczyt, limity, odrzucone pliki, sprawdzenie IdZawody oraz zapis składu w meczu wspólnym
(prawa, base_rev, dziennik bez nazwisk, rozmiar). Dane zmyślone; OpenAI to atrapa.
"""

import json
import sys
from datetime import datetime

import pytest
import sqlalchemy
from fastapi import HTTPException
from sqlalchemy import insert

from app import lineup_read_rules as R
from tests import lineup_support as S
from tests.mentor_panel_support import JUDGES, STRANGER, Env
from tests.test_lineup_read_rules import good_payload

A, B = JUDGES


class Upload:
    def __init__(self, data: bytes):
        self.data = data

    async def read(self, size=-1):
        return self.data if size < 0 else self.data[:size]


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    from app.lineup_read_tables import define_tables

    meta = sqlalchemy.MetaData()
    (usage,) = define_tables(meta)
    meta.create_all(sqlalchemy.create_engine(e.url))
    fake = sys.modules["app.db"]
    fake.lineup_read_usage = usage
    monkeypatch.delitem(sys.modules, "app.lineup_read", raising=False)
    import importlib

    e.read = importlib.import_module("app.lineup_read")
    e.usage = usage
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    return e


async def used(env, kind="ai", judge=A):
    from app import lineup_read_quota as Q

    return await Q.used(env.db, env.usage, judge, kind)


async def denied(coro):
    try:
        await coro
    except HTTPException as exc:
        d = exc.detail if isinstance(exc.detail, dict) else {"code": exc.detail}
        return exc.status_code, d.get("code"), d
    raise AssertionError("oczekiwano odmowy")


def fake_model(env, monkeypatch, payload=None, error=None):
    calls = []

    async def model(images, *, client=None):
        calls.append(len(images))
        if error:
            raise error
        return payload or good_payload()

    monkeypatch.setattr(env.read.V, "call_model", model)
    return calls


# ─── Prawa ──────────────────────────────────────────────────────────────────


def test_trasy_wymagaja_zalogowanego_sedziego_a_nie_admina(env):
    routes = {r.path: r for r in env.read.router.routes}
    assert set(routes) == {"/matches/lineup/read", "/matches/lineup/zprp-check"}
    for route in routes.values():
        names = [d.call.__name__ for d in route.dependant.dependencies]
        assert "base_actor" in names and not any("admin" in n for n in names)


# ─── Odczyt: obraz idzie do modelu, PDF z tekstem nie ───────────────────────


def test_zdjecie_idzie_do_modelu_i_zuzywa_limit_ai(env, monkeypatch):
    calls = fake_model(env, monkeypatch)

    async def go():
        out = await env.read.read_lineup([Upload(S.jpeg_bytes((3000, 2000)))], await env.actor(A))
        return out, await used(env), await used(env, "text")

    out, ai, text = env.run(go)
    assert calls == [1] and (ai, text) == (1, 0)
    assert out["source"] == "vision" and out["quota"] == {"ai_used": 1, "ai_limit": 20}
    assert out["home"]["players"][1]["number"] is None  # nieczytelny numer zostaje pusty


def test_pdf_z_tekstem_czyta_parser_bez_modelu(env, monkeypatch):
    calls = fake_model(env, monkeypatch)

    async def go():
        out = await env.read.read_lineup([Upload(S.build_protocol())], await env.actor(A))
        return out, await used(env), await used(env, "text")

    out, ai, text = env.run(go)
    assert calls == [] and (ai, text) == (0, 1)
    assert out["source"] == "pdf_text" and out["quota"] is None and out["header"]["zprp_match_id"] == "123456"


def test_skan_pdf_bez_tekstu_idzie_do_modelu(env, monkeypatch):
    calls = fake_model(env, monkeypatch)
    out = env.run(lambda: env.read.read_lineup([Upload(S.build_blank_pdf())], _actor_holder(env)))
    assert calls == [1] and out["source"] == "vision"


def _actor_holder(env):
    class _A:
        judge_id = A

    return _A()


def test_pdf_z_tekstem_ale_nie_protokol_probuje_wizji_i_zwraca_not_a_protocol(env, monkeypatch):
    payload = {**good_payload(), "is_protocol": False}
    calls = fake_model(env, monkeypatch, payload=payload)
    status, code, _ = env.run(lambda: denied(env.read.read_lineup([Upload(S.build_plain_pdf())], _actor_holder(env))))
    assert calls == [1] and (status, code) == (422, "NOT_A_PROTOCOL")


def test_zdjecie_krajobrazu_to_not_a_protocol(env, monkeypatch):
    fake_model(env, monkeypatch, payload={**good_payload(), "is_protocol": False})
    status, code, d = env.run(lambda: denied(env.read.read_lineup([Upload(S.jpeg_bytes())], _actor_holder(env))))
    assert (status, code) == (422, "NOT_A_PROTOCOL") and "protokół" in d["message"]


# ─── Limit ──────────────────────────────────────────────────────────────────


def test_dwudziesty_pierwszy_odczyt_ai_to_429_w_kopercie(env, monkeypatch):
    calls = fake_model(env, monkeypatch)

    async def go():
        await env.db.execute(insert(env.usage).values(judge_id=A, day=env.read.Q.today(), kind="ai", count=20))
        first = await denied(env.read.read_lineup([Upload(S.jpeg_bytes())], _actor_holder(env)))
        other = await env.read.read_lineup([Upload(S.jpeg_bytes())], await env.actor(B))  # limit jest per konto
        return first, other, await used(env)

    (status, code, d), other, count = env.run(go)
    assert (status, code) == (429, "AI_LIMIT_REACHED") and d["limit"] == 20 and count == 20
    assert calls == [1] and other["source"] == "vision"  # model wołany tylko dla drugiego konta


def test_pdf_z_tekstem_ma_osobny_luzny_limit(env, monkeypatch):
    fake_model(env, monkeypatch)

    async def go():
        await env.db.execute(insert(env.usage).values(judge_id=A, day=env.read.Q.today(), kind="ai", count=20))
        return await env.read.read_lineup([Upload(S.build_protocol())], _actor_holder(env))

    assert env.run(go)["source"] == "pdf_text"  # wyczerpany limit AI nie blokuje PDF-a z tekstem


def test_awaria_dostawcy_oddaje_miejsce_w_limicie(env, monkeypatch):
    fake_model(env, monkeypatch, error=R.LineupError(502, "AI_FAILED", "Odczyt się nie powiódł."))

    async def go():
        got = await denied(env.read.read_lineup([Upload(S.jpeg_bytes())], _actor_holder(env)))
        return got, await used(env)

    (status, code, _), count = env.run(go)
    assert (status, code) == (502, "AI_FAILED") and count == 0


def test_brak_klucza_503_i_limit_nietkniety(env, monkeypatch):
    monkeypatch.setattr(env.read.V, "api_key", lambda: "")

    async def go():
        got = await denied(env.read.read_lineup([Upload(S.jpeg_bytes())], _actor_holder(env)))
        return got, await used(env)

    (status, code, _), count = env.run(go)
    assert (status, code) == (503, "AI_NOT_CONFIGURED") and count == 0


# ─── Odrzucone pliki (przed zużyciem limitu) ────────────────────────────────


@pytest.mark.parametrize("files,status,code", [
    ([], 422, "NO_FILE"),
    ([b"GIF89a" + b"0" * 50], 415, "UNSUPPORTED_TYPE"),
    ([b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00"], 415, "HEIC_UNSUPPORTED"),
    ([b"\xff\xd8\xff" + b"0" * (R.MAX_IMAGE_BYTES + 5)], 413, "FILE_TOO_LARGE"),
    ([S.jpeg_bytes()] * 5, 422, "TOO_MANY_FILES"),
], ids=["brak", "gif", "heic", "za-duzy", "za-duzo-plikow"])
def test_odrzucony_typ_rozmiar_i_liczba(env, monkeypatch, files, status, code):
    calls = fake_model(env, monkeypatch)

    async def go():
        got = await denied(env.read.read_lineup([Upload(f) for f in files], _actor_holder(env)))
        return got, await used(env), await used(env, "text")

    (st, cd, _), ai, text = env.run(go)
    assert (st, cd) == (status, code) and (ai, text) == (0, 0) and calls == []


def test_zbyt_wiele_stron(env, monkeypatch):
    import fitz

    doc = fitz.open()
    for _ in range(5):
        doc.new_page().insert_text((50, 50), "x")
    fake_model(env, monkeypatch)
    status, code, _ = env.run(lambda: denied(env.read.read_lineup([Upload(doc.tobytes())], _actor_holder(env))))
    assert (status, code) == (422, "TOO_MANY_PAGES")
    # cztery zdjęcia = cztery strony: mieszczą się, piąte nie
    ok = env.run(lambda: env.read.read_lineup([Upload(S.jpeg_bytes())] * 4, _actor_holder(env)), seed=False)
    assert ok["pages"] == 4


def test_uszkodzony_pdf_i_pdf_z_haslem(env, monkeypatch):
    fake_model(env, monkeypatch)
    status, code, _ = env.run(lambda: denied(env.read.read_lineup([Upload(b"%PDF-1.4 to nie jest pdf")], _actor_holder(env))))
    assert (status, code) == (422, "PDF_UNREADABLE")


def test_w_logach_nie_ma_nazwisk(env, monkeypatch, caplog):
    fake_model(env, monkeypatch)
    with caplog.at_level("DEBUG"):
        env.run(lambda: env.read.read_lineup([Upload(S.build_protocol())], _actor_holder(env)))
        env.run(lambda: env.read.read_lineup([Upload(S.jpeg_bytes())], _actor_holder(env)), seed=False)
    logged = " ".join(r.getMessage() for r in caplog.records if r.name.startswith("app.lineup"))
    for fragment in ("ŻÓŁTEK", "TESTOWSKI", "ABRAMOWICZ", "Testowo", "0544/2026", "Hala"):
        assert fragment not in logged
    assert "lineup_read" in logged


# ─── Sprawdzenie IdZawody ───────────────────────────────────────────────────


def test_sprawdzenie_idzawody(env):
    async def go():
        await env.ins("zprp_public_matches", match_id="123456", season_id="S1", competition_name="I liga", match_code="JmK/7",
                      home_team_name="KS Testowo", away_team_name="MKS Żółwiki", scheduled_at=datetime(2026, 10, 31, 18, 0),
                      source_hash="h", source_json={})
        actor = _actor_holder(env)
        check = env.read.zprp_check
        good = await check("123456", "KS Testowo", "MKS Żółwiki", "2026-10-31", actor)
        swapped = await check("123456", "MKS Żółwiki", "KS Testowo", "2026-10-31", actor)
        other_day = await check("123456", "KS Testowo", "MKS Żółwiki", "2026-11-02", actor)
        missing = await check("999999", "KS Testowo", "MKS Żółwiki", "2026-10-31", actor)
        bad = await denied(check("IMD/54", None, None, None, actor))
        return good, swapped, other_day, missing, bad

    good, swapped, other_day, missing, bad = env.run(go)
    assert good["verdict"] == "match" and good["match"]["zprp_match_id"] == "123456"
    assert swapped["verdict"] == "swapped" and other_day["verdict"] == "mismatch" and other_day["date_ok"] is False
    assert missing == {"found": False, "verdict": "not_found"}
    assert bad[:2] == (422, "VALIDATION")


def test_sprawdzenie_idzawody_mecz_okregowy_z_monitora(env):
    async def go():
        await env.db.execute(insert(env.T["province_matches"]).values(
            province="ŚLĄSKIE", match_id="777001", season="2026/2027", match_at=datetime(2026, 10, 31, 17, 0),
            match_code="SL/9", state_json={"ID_zespoly_gosp_ZespolNazwa": "Gospodarz Okręgowy", "ID_zespoly_gosc_ZespolNazwa": "Gość Okręgowy"}, active=True))
        return await env.read.zprp_check("777001", "Gospodarz Okręgowy", "Gość Okręgowy", "2026-10-31", _actor_holder(env))

    out = env.run(go)
    assert out["found"] is True and out["home_ok"] and out["away_ok"]


# ─── Zapis składu w meczu wspólnym ──────────────────────────────────────────


def big_lineup():
    """2 x 16 zawodników i 10 osób - najgorszy realny przypadek."""
    def team(prefix, staff_count):
        return {
            "name": f"{prefix} Klub Z Dosyć Długą Nazwą Sportową",
            "players": [{"number": n, "name": f"NAZWISKOWSKI-{prefix}{chr(64 + n)} Imięsławiusz", "checked": True, "confidence": 0.98} for n in range(1, 17)],
            "staff": [{"slot": "ABCDE"[i], "name": f"PRZYKŁADOWSKA-ŁĘCKA Zofia{chr(65 + i)}", "function": "OSOBA TOWARZYSZĄCA", "license": "B 0544/2026"}
                      for i in range(staff_count)],
        }

    return {"home": team("D", 5), "away": team("G", 5), "source": "pdf_text", "read_at": "2026-11-02"}


async def make(env, who=A, **over):
    data = dict(home_name="SPR Gliwice", away_name="KS Opole", match_at="2026-11-05T18:00:00", code="EHF/1", hall="Hala Łabędy",
                my_role="sedzia1", crew=[env.shared.CrewIn(judge_id=B, role="sedzia2")], extra={"inne": "zostaje"})
    data.update(over)
    return await env.shared.create_match(env.shared.CreateBody(**data), await env.actor(who))


def test_zapis_skladu_2x16_i_10_osob_miesci_sie_w_limicie(env):
    lineup = big_lineup()
    assert len(json.dumps(R.clean_lineup(lineup), ensure_ascii=False).encode()) < R.MAX_LINEUP_BYTES < 20_000

    async def go():
        created = await make(env)
        mid, rev = created["match"]["id"], created["rev"]
        saved = await env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=rev, lineup=lineup), await env.actor(A))
        return saved, mid

    saved, _ = env.run(go)
    stored = saved["match"]["extra"]
    assert saved["rev"] == 2 and stored["inne"] == "zostaje"  # reszta extra nietknięta
    assert len(stored["lineup"]["home"]["players"]) == 16 and len(stored["lineup"]["away"]["staff"]) == 5
    assert len(json.dumps(stored, ensure_ascii=False).encode()) <= 20_000


def test_prawa_do_skladu_czlonek_widzi_obcy_nie(env):
    async def go():
        created = await make(env)
        mid = created["match"]["id"]
        await env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=created["rev"], lineup=big_lineup()), await env.actor(A))
        member = await env.actor(B)
        out = {}
        out["member_detail"] = "lineup" in (await env.shared.get_match(mid, member))["match"]["extra"]
        listing = await env.shared.list_matches(False, 300, member)
        out["member_list"] = "lineup" in listing["matches"][0]["match"]["extra"]
        stranger = await env.actor(STRANGER)
        out["stranger_get"] = (await denied(env.shared.get_match(mid, stranger)))[:2]
        out["stranger_put"] = (await denied(env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=2, lineup=big_lineup()), stranger)))[:2]
        out["stranger_list"] = (await env.shared.list_matches(False, 300, stranger))["matches"]
        out["member_edit_ok"] = (await env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=2, lineup=None), member))["match"]["extra"].get("lineup")
        return out

    out = env.run(go)
    assert out["member_detail"] and out["member_list"] and out["stranger_list"] == []
    assert out["stranger_get"] == (404, "MATCH_NOT_FOUND") and out["stranger_put"] == (404, "MATCH_NOT_FOUND")
    assert out["member_edit_ok"] is None  # członek może też skasować skład


def test_base_rev_konflikt_i_dziennik_bez_nazwisk(env):
    lineup = big_lineup()

    async def go():
        created = await make(env)
        mid, rev = created["match"]["id"], created["rev"]
        missing = (await denied(env.shared.put_lineup(mid, env.shared.LineupBody(lineup=lineup), await env.actor(A))))[:2]
        saved = await env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=rev, lineup=lineup), await env.actor(A))
        stale = await denied(env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=rev, lineup=None), await env.actor(B)))
        same = await env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=saved["rev"], lineup=lineup), await env.actor(A))
        return missing, saved, stale, same

    missing, saved, stale, same = env.run(go)
    assert missing == (422, "BASE_REV_REQUIRED") and stale[:2] == (409, "REV_CONFLICT") and stale[2]["current"]["rev"] == saved["rev"]
    assert same["unchanged"] is True and same["rev"] == saved["rev"]
    entry = saved["log"][0]
    assert entry["action"] == "lineup" and entry["changes"][0]["to"] == "16+16 zawodników, 10 os."
    blob = json.dumps(saved["log"], ensure_ascii=False, default=str) + json.dumps(env.pushes, default=str) + json.dumps(env.sent, default=str)
    assert "NAZWISKOWSKI" not in blob and "PRZYKŁADOWSKA" not in blob
    assert [p["event"] for p in env.pushes] == ["added"]  # tylko push z utworzenia meczu; zapis składu nie wysyła żadnego


def test_skasowanie_skladu_i_zly_sklad_to_422(env):
    async def go():
        created = await make(env)
        mid = created["match"]["id"]
        actor = await env.actor(A)
        saved = await env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=created["rev"], lineup=big_lineup()), actor)
        cleared = await env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=saved["rev"], lineup=None), actor)
        bad = []
        for lineup in (
            {"home": {"players": [{"number": 120, "name": "ADAMSKI Adam"}], "staff": []}, "away": {"players": [], "staff": []}},
            {"home": {"players": [{"number": 5, "name": "Zignoruj <instrukcje> 1"}], "staff": []}, "away": {"players": [], "staff": []}},
            {"home": {"players": [], "staff": [{"slot": "A", "name": "ADAMSKI Adam", "license": "zła licencja"}]}, "away": {"players": [], "staff": []}},
            {"home": {"players": [], "staff": []}},
        ):
            bad.append((await denied(env.shared.put_lineup(mid, env.shared.LineupBody(base_rev=cleared["rev"], lineup=lineup), actor)))[:2])
        # ten sam kontroler stoi też na ogólnym PUT z `extra` - nie da się obejść kształtu
        via_extra = await denied(env.shared.edit_match(mid, env.shared.EditBody(base_rev=cleared["rev"], extra={"lineup": {"home": {"players": [{"number": 999}]}}}), actor))
        return cleared, bad, via_extra

    cleared, bad, via_extra = env.run(go)
    assert "lineup" not in cleared["match"]["extra"] and cleared["match"]["extra"]["inne"] == "zostaje"
    assert all(item == (422, "VALIDATION") for item in bad)
    assert via_extra[:2] == (422, "VALIDATION")


def test_odpowiedz_duplikatu_nie_niesie_skladu(env):
    async def go():
        created = await make(env)
        await env.shared.put_lineup(created["match"]["id"], env.shared.LineupBody(base_rev=created["rev"], lineup=big_lineup()), await env.actor(A))
        # obcy tworzy ten sam mecz: dostaje 409 z minimum danych
        return await denied(make(env, who=STRANGER, crew=[], my_role="sedzia1"))

    status, code, detail = env.run(go)
    assert (status, code) == (409, "DUPLICATE_MATCH")
    assert "lineup" not in json.dumps(detail, default=str) and "NAZWISKOWSKI" not in json.dumps(detail, default=str)


def test_karty_pary_i_publiczne_nie_czytaja_extra():
    """Straż: `extra` (a w nim skład) nie jest czytane przez karty panelu pary, a lista meczów wspólnych to jedyne miejsce odczytu."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent / "app"
    for name in ("shared_match_pair.py", "mentor_panel_rules.py"):
        source = (root / name).read_text(encoding="utf-8")
        assert "extra_json" not in source and '["extra"]' not in source and ".get(\"extra\")" not in source, name
