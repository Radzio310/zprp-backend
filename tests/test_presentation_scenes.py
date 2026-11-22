"""Tryb prezentacji, część 2: oceny młodych, nakładka obsady i sceny giełdy / ocen.

Ta sama atrapa co `tests/test_presentation.py` (fikstura `env`: SQLite dla tabel
trybu, MagicMock dla reszty `app.db`, prawdziwy router obsady ZPRP z logowaniem,
które rzuca). Prawdziwe trasy odczytu to małe handlery dopisane do aplikacji
wewnętrznej z licznikiem wywołań.
"""

from __future__ import annotations

import gzip
import importlib
import json
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request, Response

from tests import test_presentation as base
from tests.test_presentation import ADMIN, OTHER, _save_body, auth, enable, enc, run, token

#: Ta sama fikstura co w części 1 (atrapa bazy, aplikacja wewnętrzna, licznik wywołań).
env = base.env

ORG = {"Authorization": f"Bearer {token('', 'ks_slzpr')}"}
OKREG = [{"kind": "login", "value": "ks_slzpr", "label": "Okręg"}]
SOON = datetime.now(timezone.utc) + timedelta(days=7)


def inner(env):
    return env.app.app


# ───────────────────────────── obszary ─────────────────────────────


def test_nieznany_obszar_400_i_stary_zapis_wlacza_oceny(env):
    async def go(client):
        bad = await client.put("/presentation/state", json={"enabled": True, "areas": ["market", "oceny"]}, headers=auth())
        await enable(env, client)
        # zapis sprzed dodania „ratings" (sama lista) - nowy obszar domyślnie włączony
        await env.db.execute(env.fake.presentation_state.update().values(
            areas_json=json.dumps(["market", "obsada", "settlements", "offtimes", "announcements", "events"])))
        env.PS.reset_cache()
        legacy = await client.get("/presentation/state", headers=auth())
        off = await client.put("/presentation/state", json={"enabled": True, "areas": ["market"]}, headers=auth())
        env.PS.reset_cache()
        after = await client.get("/presentation/state", headers=auth())
        return bad, legacy, off, after

    bad, legacy, off, after = run(env, go)
    assert bad.status_code == 400 and "oceny" in bad.json()["detail"]
    assert "ratings" in legacy.json()["areas"]
    assert after.json()["areas"] == ["market"]


# ───────────────────────────── oceny młodych ─────────────────────────────


def _rating_routes(env):
    app = inner(env)

    @app.post("/young_referees/ratings", status_code=201)
    async def real_create():
        env.calls.hit("rating_create")
        return {"id": 1}

    @app.get("/young_referees/ratings")
    async def real_list(province: str = "", young_referee_id: int = None):  # noqa: RUF013
        env.calls.hit("rating_list")
        rec = {"id": 7, "rating_date": "2026-10-01T10:00:00+00:00", "province": "ŚLĄSKIE", "mentor_name": "Jan Admin",
               "young_referee_name": "Młody Piotr", "young_referee_id": 3, "young_referee2_name": None,
               "young_referee2_id": None, "rating": {"avg_score": 4.0}}
        return {"records": [rec] if young_referee_id in (None, 3) else []}

    @app.get("/young_referees/ratings/{rating_id}")
    async def real_get(rating_id: int):
        env.calls.hit("rating_get")
        raise HTTPException(404, "Ocena nie znaleziona")

    @app.put("/young_referees/ratings/{rating_id}")
    async def real_put(rating_id: int):
        env.calls.hit("rating_put")
        return {"id": rating_id}

    @app.delete("/young_referees/ratings/{rating_id}")
    async def real_delete(rating_id: int):
        env.calls.hit("rating_delete")
        return {"success": True}


def _rating_body(**extra):
    return {"rating_date": "2026-11-21", "province": "śląskie", "mentor_name": "Jan Admin", "young_referee_name": "Młody Adam",
            "young_referee_id": 5, "rating": {"kind": "rating", "avg_score": 4.5, "matchNumber": "S/JM/12"}, **extra}


def test_ocena_mlodego_udawana_i_w_listach_tylko_konta_trybu(env, monkeypatch):
    _rating_routes(env)
    R = importlib.import_module("app.presentation_ratings")

    async def young(rid):
        return {"id": int(rid), "full_name": f"Młody {rid}"}

    async def rater_ok(ctx, mentor):
        return None

    async def real_row(rid):
        if rid != 7:
            return None
        return {"id": 7, "rating_date": datetime(2026, 10, 1, 10, tzinfo=timezone.utc), "province": "ŚLĄSKIE",
                "mentor_name": "Jan Admin", "young_referee_name": "Młody Piotr", "young_referee_id": 3,
                "young_referee2_name": None, "young_referee2_id": None, "rating": {"avg_score": 4.0}}

    monkeypatch.setattr(R, "_young", young)
    monkeypatch.setattr(R, "_rater_check", rater_ok)
    monkeypatch.setattr(R, "_real", real_row)

    async def go(client):
        await enable(env, client)
        created = await client.post("/young_referees/ratings", json=_rating_body(), headers=auth())
        rid = created.json()["id"]
        mine = await client.get("/young_referees/ratings", params={"province": "ŚLĄSKIE"}, headers=auth())
        per_young = await client.get("/young_referees/ratings", params={"young_referee_id": 5}, headers=auth())
        other_young = await client.get("/young_referees/ratings", params={"young_referee_id": 3}, headers=auth())
        anon = await client.get("/young_referees/ratings", params={"province": "ŚLĄSKIE"})
        other = await client.get("/young_referees/ratings", params={"province": "ŚLĄSKIE"}, headers=auth(OTHER, "inny"))
        # aplikacja czyta i zmienia ocenę gołym fetch - udawany numer wystarcza
        detail = await client.get(f"/young_referees/ratings/{rid}")
        put = await client.put(f"/young_referees/ratings/{rid}", json={"rating": {"avg_score": 3.0}})
        after_put = await client.get("/young_referees/ratings", params={"young_referee_id": 5}, headers=auth())
        # prawdziwa ocena 7: usunięta tylko w nakładce
        deleted = await client.delete("/young_referees/ratings/7", headers=auth())
        after_del = await client.get("/young_referees/ratings", params={"province": "ŚLĄSKIE"}, headers=auth())
        anon_after = await client.get("/young_referees/ratings", params={"province": "ŚLĄSKIE"})
        del_synth = await client.delete(f"/young_referees/ratings/{rid}")
        gone = await client.get(f"/young_referees/ratings/{rid}")
        ops = await client.get("/presentation/ops", headers=auth())
        return created, mine, per_young, other_young, anon, other, detail, put, after_put, deleted, after_del, anon_after, del_synth, gone, ops

    (created, mine, per_young, other_young, anon, other, detail, put, after_put,
     deleted, after_del, anon_after, del_synth, gone, ops) = run(env, go)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["id"] >= env.PS.SYNTH_BASE and body["province"] == "ŚLĄSKIE" and body["young_referee_id"] == 5
    assert env.calls.count("rating_create") == 0
    assert [r["id"] for r in mine.json()["records"]] == [body["id"], 7]  # data malejąco
    assert [r["id"] for r in per_young.json()["records"]] == [body["id"]]
    assert [r["id"] for r in other_young.json()["records"]] == [7]
    assert [r["id"] for r in anon.json()["records"]] == [7]
    assert [r["id"] for r in other.json()["records"]] == [7]
    assert detail.status_code == 200 and detail.json()["rating"]["avg_score"] == 4.5
    assert put.status_code == 200 and put.json()["rating"] == {"avg_score": 3.0}
    assert after_put.json()["records"][0]["rating"] == {"avg_score": 3.0}
    assert env.calls.count("rating_put") == 0
    assert deleted.json() == {"success": True}, (deleted.status_code, deleted.json(), deleted.headers)
    assert env.calls.count("rating_delete") == 0
    assert [r["id"] for r in after_del.json()["records"]] == [body["id"]]
    assert [r["id"] for r in anon_after.json()["records"]] == [7]
    assert del_synth.status_code == 200 and gone.status_code == 404
    assert env.calls.count("rating_get") == 0
    areas = {i["area"] for i in ops.json()["items"]}
    assert areas == {"ratings"}


def test_ocena_mlody_nie_ocenia_i_wylaczony_obszar(env, monkeypatch):
    _rating_routes(env)
    Y = importlib.import_module("app.young_referees")

    async def young_rater(payload, mentor_name=None):
        raise HTTPException(403, "Młody sędzia nie wystawia ocen - ocenia mentor, obserwator lub delegat.")

    monkeypatch.setattr(Y, "_ensure_rater_is_not_young", young_rater)

    async def go(client):
        await enable(env, client)
        denied = await client.post("/young_referees/ratings", json=_rating_body(), headers=auth())
        await client.put("/presentation/state", json={"enabled": True, "areas": ["market"]}, headers=auth())
        env.PS.reset_cache()
        real = await client.post("/young_referees/ratings", json=_rating_body(), headers=auth())
        return denied, real

    denied, real = run(env, go)
    assert denied.status_code == 403 and "Młody sędzia" in denied.json()["detail"]
    assert real.status_code == 201 and real.json() == {"id": 1} and env.calls.count("rating_create") == 1


# ───────────────────────────── nakładka obsady ─────────────────────────────


def _state(crew):
    out = {"RozgrywkiCode": "S/JM/1", "ID_zespoly_gosp_ZespolNazwa": "Gospodarz", "ID_zespoly_gosc_ZespolNazwa": "Gość",
           "Hala_nazwa": "Hala", "Hala_miasto": "Katowice"}
    for slot, (num, name) in crew.items():
        out[f"NrSedzia_{slot}"], out[f"NrSedzia_{slot}_nazwisko"] = num, name
    return out


BASE_CREW = {"pierwszy": (ADMIN, "ADMIN Jan"), "drugi": ("300", "DRUGI Marek"), "sekretarz": ("", ""), "czas": ("", "")}


def _board_routes(env, crew=BASE_CREW, match_id="12345", my_rows=()):
    app = inner(env)

    def item():
        return {"match_id": match_id, "code": "S/JM/1", "table_by_club": 0, "access": None,
                "crew": {slot: ({"number": n, "name": nm} if nm else None) for slot, (n, nm) in crew.items()},
                "status": {"gaps": 2}, "updated_at": "2026-11-01T10:00:00+00:00"}

    @app.get("/province/assignments")
    async def real_assignments(province: str):
        env.calls.hit("assignments")
        return {"province": "SLASKIE", "matches": [item()]}

    @app.get("/province/assignment/bootstrap")
    async def real_bootstrap(request: Request, province: str):
        env.calls.hit("bootstrap")
        if request.headers.get("if-none-match") == '"b1"':
            return Response(status_code=304)
        body = json.dumps({"etag": '"b1"', "matches": [item()], "draft": {"rev": 1, "changes": []}}).encode()
        return Response(gzip.compress(body), media_type="application/json",
                        headers={"Content-Encoding": "gzip", "ETag": '"b1"'})

    @app.get("/province/obsada-view/data")
    async def real_view(request: Request, province: str):
        env.calls.hit("view")
        if request.headers.get("if-none-match") == '"r1"':
            return Response(status_code=304)
        view_crew = {"first": {"name": "ADMIN Jan", "key": "admin-jan", "photo": None},
                     "second": {"name": "DRUGI Marek", "key": "drugi-marek", "photo": None},
                     "secretary": None, "time": None, "delegate": None, "delegate2": None}
        needs = {"first": False, "second": False, "secretary": True, "time": True, "delegate": False, "delegate2": False}
        return {"province": "SLASKIE", "mode": "app", "rev": "r1", "updated_at": "x",
                "matches": [{"match_id": match_id, "code": "S/JM/1", "crew": view_crew, "needs": needs}]}

    @app.get("/match-market/my-matches")
    async def real_my(province: str = ""):
        env.calls.hit("my_matches")
        return {"province": "SLASKIE", "deadlineHours": 48, "matches": [dict(r) for r in my_rows]}


def _match_row(env, monkeypatch, crew=BASE_CREW):
    async def row(province, match_id):
        return {"match_id": match_id, "match_at": SOON, "match_code": "S/JM/1", "approved": False, "state_json": _state(crew)}

    monkeypatch.setattr(env.sim, "_province_match", row)


def test_zapis_obsady_widac_w_obsadzie_na_zywo_i_moich_meczach(env, monkeypatch):
    """Obsadowy (ks_slzpr, bez tokenu) zapisuje w ZPRP sekretarza 5124 -> 5124 widzi mecz u siebie."""
    _board_routes(env)
    _match_row(env, monkeypatch, crew={**BASE_CREW, "pierwszy": ("400", "INNY Tomasz")})
    body = _save_body()
    body.pop("NrSedzia_sekretarz"), body.pop("NrSedzia_sekretarz_name")
    body.update({"NrSedzia_sekretarz": "", "NrSedzia_sekretarz_name": "Admin Jan", "assigned": {"sekretarz": ADMIN}})

    async def go(client):
        await enable(env, client, accounts=OKREG)
        saved = await client.post("/zprp/obsada/save", json=body)
        board = await client.get("/province/assignments", params={"province": "ŚLĄSKIE"}, headers=ORG)
        board_other = await client.get("/province/assignments", params={"province": "ŚLĄSKIE"}, headers=auth(OTHER, "inny"))
        boot = await client.get("/province/assignment/bootstrap", params={"province": "ŚLĄSKIE"},
                                headers={**ORG, "If-None-Match": '"b1"', "Accept-Encoding": "gzip"})
        view = await client.get("/province/obsada-view/data", params={"province": "ŚLĄSKIE"},
                                headers={**auth(), "If-None-Match": '"r1"'})
        my = await client.get("/match-market/my-matches", headers=auth())
        my_other = await client.get("/match-market/my-matches", headers=auth(OTHER, "inny"))
        return saved, board, board_other, boot, view, my, my_other

    saved, board, board_other, boot, view, my, my_other = run(env, go)
    assert saved.status_code == 200 and saved.json()["verified_slots"]["sekretarz"]["name"] == "Admin Jan"
    assert env.calls.count("zprp_login") == 0 and env.calls.count("zprp_apply") == 0
    item = board.json()["matches"][0]
    assert item["crew"]["sekretarz"] == {"number": ADMIN, "name": "ADMIN Jan"}
    assert item["status"]["table"]["have"] == 1  # stan obsady przeliczony
    assert board_other.json()["matches"][0]["crew"]["sekretarz"] is None
    assert boot.status_code == 200, boot.text  # bez 304 i rozpakowany gzip
    assert boot.json()["matches"][0]["crew"]["sekretarz"]["name"] == "ADMIN Jan"
    data = view.json()
    assert view.status_code == 200 and data["matches"][0]["crew"]["secretary"]["name"] == "ADMIN Jan"
    assert data["matches"][0]["needs"]["secretary"] is False and data["rev"] != "r1"
    rows = my.json()["matches"]
    assert [r["matchId"] for r in rows] == ["12345"]
    assert rows[0]["slots"][0]["slot"] == "sekretarz" and rows[0]["canOffer"] is True
    assert my_other.json()["matches"] == []


def test_formularz_zprp_meczu_z_nakladka(env):
    L = importlib.import_module("app.presentation_lineup")
    form = {"IdZawody": "1", "slots": {
        "sedzia1": {"options": [{"value": "0", "name": "--- ---"}, {"value": "17", "name": "ADMIN Jan", "selected": True}], "selected_value": "17"},
        "sekretarz": {"options": [{"value": "0", "name": "--- ---"}, {"value": "21", "name": "KOWALSKI Jan"}], "selected_value": "0"},
        "czas": {"options": [{"value": "0", "name": "--- ---"}], "selected_value": "0"},
    }}
    out = L.patch_match_form(form, {"pierwszy": {"number": "", "name": ""}, "sekretarz": {"number": "", "name": "Jan Kowalski"},
                                    "czas": {"number": "9", "name": "NOWY Ktoś"}})
    assert out["slots"]["sedzia1"]["selected_value"] == "0"
    assert out["slots"]["sekretarz"]["selected_value"] == "21"
    assert out["slots"]["czas"]["options"][0]["name"] == "NOWY Ktoś" and out["slots"]["czas"]["selected_value"] == "9"
    assert L.board_slot("sedzia2") == "drugi" and L.board_slot("NrSedzia_czas") == "czas" and L.board_slot("timekeeper") == "czas"


def test_formularz_meczu_rozpoznaje_konto_z_tresci(env, monkeypatch):
    seen = []

    async def spy(ctx, data):
        seen.append(ctx.account)
        return env.sim.Result(200, {"spy": True}) if data is None else data

    monkeypatch.setitem(env.sim.MERGES, "merge_match_form", spy)

    async def go(client):
        await enable(env, client, accounts=OKREG)
        mine = await client.post("/zprp/obsada/match-form", json={"username": enc("ks_slzpr"), "password": enc("x"), "IdZawody": "1", "user": ""})
        other = await client.post("/zprp/obsada/match-form", json={"username": enc("ks_inny"), "password": enc("x"), "IdZawody": "1", "user": ""})
        return mine, other

    mine, other = run(env, go)
    assert mine.json() == {"spy": True} and seen == ["login:ks_slzpr"]
    assert other.status_code == 418 and env.calls.count("zprp_login") == 1  # konto spoza trybu: prawdziwy ZPRP


# ───────────────────────────── sceny ─────────────────────────────


def _scene_stubs(env, monkeypatch, crew=BASE_CREW):
    pres = env.pres

    async def judge_row(jid):
        return {"judge_id": jid, "full_name": "Admin Jan", "province": "ŚLĄSKIE", "photo_url": ""}

    async def rows(key, *, upcoming, days, limit=600):
        when = SOON if upcoming else datetime.now(timezone.utc) - timedelta(days=3)
        return [{"match_id": "12345", "match_at": when, "match_code": "S/JM/1", "approved": False, "state_json": _state(crew)}]

    async def hours(key):
        return 48

    async def approver(jid):
        return jid == ADMIN

    async def claimers(key, exclude, count=2):
        assert ADMIN in exclude and "300" in exclude
        return [{"judge_id": "201", "name": "Nowak Anna", "photo_url": None}][:count]

    monkeypatch.setattr(pres, "judge_row", judge_row)
    monkeypatch.setattr(pres, "province_rows", rows)
    monkeypatch.setattr(pres, "market_hours", hours)
    monkeypatch.setattr(pres, "approver_of", approver)
    monkeypatch.setattr(pres, "scene_claimers", claimers)


def test_scena_oddania_meczu_i_zatwierdzenie_przestawia_obsade(env, monkeypatch):
    held = {"matchId": "12345", "match": {"matchAt": SOON.isoformat()}, "canOffer": True,
            "slots": [{"slot": "sedzia1", "label": "Sędzia 1", "offerId": None, "offerStatus": None}]}
    _board_routes(env, my_rows=[held])
    _match_row(env, monkeypatch)
    _scene_stubs(env, monkeypatch)

    async def go(client):
        await enable(env, client, accounts=OKREG)
        scene = await client.post("/presentation/scene", json={"scene": "market_giveaway_ready"}, headers=auth())
        created = scene.json()["created"]
        mine = await client.get("/match-market/offers", params={"scope": "mine"}, headers=auth())
        detail = await client.get(f"/match-market/offers/{created['offer_id']}", headers=auth())
        before = await client.get("/match-market/my-matches", headers=auth())
        approved = await client.post(f"/match-market/offers/{created['offer_id']}/approve",
                                     json={"claim_id": created["claim_id"]}, headers=auth())
        after = await client.get("/match-market/my-matches", headers=auth())
        board = await client.get("/province/assignments", params={"province": "ŚLĄSKIE"}, headers=ORG)
        view = await client.get("/province/obsada-view/data", params={"province": "ŚLĄSKIE"}, headers=auth())
        other = await client.get("/province/assignments", params={"province": "ŚLĄSKIE"}, headers=auth(OTHER, "inny"))
        history = await client.get("/match-market/offers", params={"scope": "history"}, headers=auth())
        ops = await client.get("/presentation/ops", headers=auth())
        return scene, created, mine, detail, before, approved, after, board, view, other, history, ops

    scene, created, mine, detail, before, approved, after, board, view, other, history, ops = run(env, go)
    assert scene.status_code == 200, scene.text
    assert created["match_id"] == "12345" and created["slot"] == "sedzia1" and created["status"] == "open"
    assert created["giver"]["judge_id"] == ADMIN and created["taker"]["judge_id"] == "201"
    assert created["approve"]["judge_can_approve"] is True
    offers = mine.json()["offers"]
    assert [o["id"] for o in offers] == [created["offer_id"]] and offers[0]["claimCount"] == 1
    assert [c["person"]["judgeId"] for c in detail.json()["claims"]] == ["201"]
    assert before.json()["matches"][0]["slots"][0]["offerId"] == created["offer_id"]
    assert approved.status_code == 200 and approved.json()["status"] == "done" and approved.json()["applied"] is True
    assert env.calls.count("zprp_apply") == 0
    assert after.json()["matches"] == []  # oddający zszedł z meczu
    crew = board.json()["matches"][0]["crew"]
    assert crew["pierwszy"] == {"number": "201", "name": "NOWAK Anna"} and crew["drugi"]["name"] == "DRUGI Marek"
    assert view.json()["matches"][0]["crew"]["first"]["name"] == "NOWAK Anna"
    assert other.json()["matches"][0]["crew"]["pierwszy"]["number"] == ADMIN
    assert [o["status"] for o in history.json()["offers"]] == ["done"]
    texts = [i["summary"] for i in ops.json()["items"]]
    assert any("udawany" in t and "12345" in t for t in texts)


def test_scena_oddania_bez_meczu_sedziego(env, monkeypatch):
    _scene_stubs(env, monkeypatch, crew={"pierwszy": ("400", "INNY Tomasz")})

    async def go(client):
        await enable(env, client)
        missing = await client.post("/presentation/scene", json={"scene": "market_giveaway_ready"}, headers=auth())
        foreign = await client.post("/presentation/scene", json={"scene": "market_giveaway_ready", "judge_id": "777"}, headers=auth())
        return missing, foreign

    missing, foreign = run(env, go)
    assert missing.status_code == 404 and "nie stoi w gnieździe" in missing.json()["detail"]
    assert foreign.status_code == 400 and "nie jest kontem trybu" in foreign.json()["detail"]


def test_scena_oceny_mlodego(env, monkeypatch):
    _scene_stubs(env, monkeypatch, crew={**BASE_CREW, "drugi": ("55", "MŁODY Adam")})
    youngs = [{"id": 5, "full_name": "Młody Adam", "base_judge_id": "55", "province": "ŚLĄSKIE", "is_active": True}]

    async def young_list(key):
        return youngs

    monkeypatch.setattr(env.pres, "young_referees_of", young_list)

    async def go(client):
        await enable(env, client)
        ok = await client.post("/presentation/scene", json={"scene": "young_rating_ready"}, headers=auth())
        youngs.append({"id": 6, "full_name": "Admin Jan", "base_judge_id": ADMIN, "province": "ŚLĄSKIE", "is_active": True})
        denied = await client.post("/presentation/scene", json={"scene": "young_rating_ready"}, headers=auth())
        return ok, denied

    ok, denied = run(env, go)
    assert ok.status_code == 200, ok.text
    created = ok.json()["created"]
    assert created["match_id"] == "12345" and created["young_referee"] == {"id": 5, "name": "Młody Adam", "slot": "drugi"}
    assert created["rater"]["in_crew"] is True and created["missing"] == []
    assert denied.status_code == 409 and "młody sędzia nie wystawia ocen" in denied.json()["detail"]


def test_stare_sceny_dalej_dzialaja_bez_wlaczonego_trybu(env):
    async def go(client):
        return await client.post("/presentation/scene", json={"scene": "young_rating_ready"}, headers=auth())

    assert run(env, go).status_code == 409


def test_trasy_nowe_w_tabeli(env):
    R = importlib.import_module("app.presentation_routes")
    assert R.match_write("POST", "/young_referees/ratings")[0].area == "ratings"
    assert R.match_write("DELETE", "/young_referees/ratings/9")[0].identity == "synthetic"
    assert R.match_write("GET", "/young_referees/ratings") is None
    assert R.match_read("GET", "/young_referees/ratings")[0].merge == "merge_ratings_list"
    assert R.match_read("GET", "/young_referees/ratings_visibility") is None
    assert R.match_read("POST", "/zprp/obsada/match-form")[0].identity == "body"
    assert R.match_read("GET", "/province/assignments/123")[1] == {"match_id": "123"}
    assert all(r.sim in env.sim.SIMS for r in R.WRITE_ROUTES)
    assert all(r.merge in env.sim.MERGES for r in R.READ_ROUTES)
