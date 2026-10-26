"""Sugestie przy braku chętnych: reguły (liść) i trasy z atrapami bazy."""

import importlib
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app import match_market_crew_suggest_rules as S


def load_modules():
    before = set(sys.modules)
    sys.modules["app.db"] = MagicMock()
    try:
        crew = importlib.import_module("app.match_market_crew")
        suggest = importlib.import_module("app.match_market_crew_suggest")
        return crew, suggest
    finally:
        for name in set(sys.modules) - before:
            if name.startswith("app."):
                sys.modules.pop(name, None)
        if isinstance(sys.modules.get("app.db"), MagicMock):
            sys.modules.pop("app.db", None)


M, SG = load_modules()
pytestmark = pytest.mark.asyncio


def fact(field=(), table=(), played=True, season=2025):
    return SimpleNamespace(field=tuple(field), table=tuple(table), played=played, season=season, id="x")


class TestStalyPartner:
    def test_liczy_wspolne_mecze_w_tej_samej_roli(self):
        facts = [fact(table=("1", "2")), fact(table=("1", "2")), fact(table=("1", "2"), season=2026), fact(field=("1", "3"))]
        out = S.together(facts, ["1"], "table")
        assert out["2"]["matches"] == 3 and out["2"]["last_season"] == 2026
        assert "3" not in out  # boisko to inna rola

    def test_jeden_wspolny_mecz_to_za_malo_na_stalego(self):
        assert S.together([fact(table=("1", "2"))], ["1"], "table") == {}

    def test_niezagrane_sie_nie_licza(self):
        facts = [fact(table=("1", "2"), played=False)] * 5
        assert S.together(facts, ["1"], "table") == {}

    def test_obsadzony_nie_jest_swoim_partnerem(self):
        facts = [fact(field=("1", "2"))] * 3
        assert set(S.together(facts, ["1", "2"], "field")) == set()


class TestParaMentorska:
    pairs = [{"id": "p1", "judge_ids": ["10", "11"]}, {"id": "p2", "judge_ids": '["20", "21"]'}]
    mentors = [{"pair_id": "p1", "mentor_id": "90"}]

    def test_podopieczny_dostaje_mentora_i_druga_osobe_pary(self):
        out = S.mentor_links(self.pairs, self.mentors, ["10"])
        assert out["90"][0]["relation"] == "mentor" and out["11"][0]["relation"] == "pair_mate"
        assert "10" not in out

    def test_mentor_dostaje_podopiecznych(self):
        out = S.mentor_links(self.pairs, self.mentors, ["90"])
        assert {k: v[0]["relation"] for k, v in out.items()} == {"10": "mentee", "11": "mentee"}

    def test_numery_nie_nazwiska_i_json_jako_napis(self):
        assert "21" in S.mentor_links(self.pairs, self.mentors, ["20"])

    def test_obcy_nie_ma_powiazan(self):
        assert S.mentor_links(self.pairs, self.mentors, ["777"]) == {}


class TestDyspozycja:
    def test_wolny(self):
        assert S.availability(None, [])["state"] == "free"
        assert S.availability(None, [{"level": "yellow", "overlap": False}])["state"] == "free"

    def test_niedyspozycja_wygrywa_z_kolizja(self):
        got = S.availability("Praca, 12:00-18:00", [{"overlap": True}])
        assert got["state"] == "unavailable" and "Praca" in got["text"]

    def test_kolizja_z_nakladaniem_albo_czerwienia(self):
        assert S.availability(None, [{"overlap": True, "code": "A/1"}])["state"] == "collision"
        assert S.availability(None, [{"level": "red", "overlap": False}])["state"] == "collision"


def test_ranking_wolni_przed_kolizja_przed_niedyspozycja():
    def item(name, state, matches=0):
        reasons = [{"kind": "partner", "matches": matches}] if matches else [{"kind": "mentor"}]
        return {"judge": {"name": name}, "reasons": reasons, "availability": {"state": state}, "weekMatches": 0}

    ranked = S.rank([item("C", "unavailable", 9), item("B", "free"), item("A", "free", 4), item("D", "collision", 8)])
    assert [i["judge"]["name"] for i in ranked] == ["A", "B", "D", "C"]


def test_odmowy_maja_zdanie_po_polsku():
    ok = dict(in_province=True, passes_filter=True, holds_slot=False, role_ok=True, already_claimed=False)
    assert S.refusal_for_candidate(**ok) is None
    for field in ("in_province", "passes_filter", "role_ok"):
        assert "." in S.refusal_for_candidate(**{**ok, field: False})
    assert "już w obsadzie" in S.refusal_for_candidate(**{**ok, "holds_slot": True})
    assert "zgłosił się" in S.refusal_for_candidate(**{**ok, "already_claimed": True})


def test_tekst_pusha_zaproszenia():
    title, body = S.text_invite({"match_code": "S/JmM/1", "match_snapshot": {}}, "table")
    assert title == "Obsada proponuje Ci ten mecz" and "stolikowy" in body


# ───────────────────────────── trasy z atrapami ─────────────────────────────


def panel():
    return M.PanelActor({"sub": "ksdzpr", "account_type": "org"})


def stub_common(monkeypatch, claims, offer_extra=None, invites=None):
    offer = {
        "id": 7, "province": "SLASKIE", "match_id": "123", "match_code": "S/JmM/1", "status": "open",
        "deadline_at": None, "match_at": None, "slots": ["sekretarz", "czas"],
        "badge_filter": {"mode": "none", "badges": []}, "match_snapshot": {}, **(offer_extra or {}),
    }
    cards = {
        j: {"judge_id": j, "full_name": f"Sędzia {j}", "photo_url": None, "badges": "", "province": "SLASKIE"}
        for j in ["1", "2", "3", "4", "90"]
    }
    pushed = []

    async def load(_i):
        return offer

    async def manager(_a, _p):
        return None

    async def claims_of(_i):
        return claims

    async def invites_of(_i):
        return invites or {}

    async def state_of(_o):
        return {}

    async def judge_cards(ids):
        return {i: cards[i] for i in ids if i in cards}

    async def roster(_k):
        return None

    async def metrics(_o, rows, **_kw):
        out = {}
        for row in rows:
            j = row["judge_id"]
            out[j] = {
                "city": "Zabrze", "km": {"km": 10.0, "source": "same_city"},
                "season": {"field": 1, "table": 2, "total": 3}, "week_matches": 1 if j == "2" else 0,
                "nearest": None, "gap": None,
                "collisions": [{"overlap": True, "code": "X/1", "level": "red"}] if j == "3" else [],
                "unavailable": "Praca" if j == "4" else None,
            }
        return out

    async def push(ids, text, _offer, **kw):
        pushed.append((ids, text, kw))

    monkeypatch.setattr(M, "_load_offer", load)
    monkeypatch.setattr(M, "_require_manager", manager)
    monkeypatch.setattr(M, "_claims_of", claims_of)
    monkeypatch.setattr(M, "_judge_cards", judge_cards)
    monkeypatch.setattr(M, "_roster_for", roster)
    monkeypatch.setattr(M, "_metrics", metrics)
    monkeypatch.setattr(M, "_push", push)
    monkeypatch.setattr(M, "_sweep", lambda _k: _noop())
    monkeypatch.setattr(SG, "_invites_of", invites_of)
    monkeypatch.setattr(SG, "_state_of", state_of)
    return offer, pushed


async def _noop():
    return None


def assigned_claim():
    return {"id": 1, "judge_id": "1", "status": "assigned", "role": "table", "slot": "sekretarz"}


async def test_sugestie_partner_i_mentor_z_dyspozycja(monkeypatch):
    stub_common(monkeypatch, [assigned_claim()])

    async def facts(_k):
        return [fact(table=("1", "2", "x")), fact(table=("1", "2")), fact(table=("1", "3")), fact(table=("1", "3")), fact(table=("1", "4")), fact(table=("1", "4"))]

    async def mentoring():
        return [{"id": "p", "judge_ids": ["1", "90"]}], []

    monkeypatch.setattr(SG, "_facts_for", facts)
    monkeypatch.setattr(SG, "_mentoring", mentoring)
    out = await SG.suggestions(7, panel())
    assert [s["slot"] for s in out["slots"]] == ["czas"]  # sekretarz już przydzielony
    names = [(i["judge"]["id"], i["availability"]["state"]) for i in out["slots"][0]["suggestions"]]
    assert names == [("2", "free"), ("90", "free"), ("3", "collision"), ("4", "unavailable")]
    first = out["slots"][0]["suggestions"][0]
    assert first["reasons"][0]["kind"] == "partner" and first["reasons"][0]["matches"] == 2
    assert out["slots"][0]["suggestions"][1]["reasons"][0]["relation"] == "pair_mate"
    assert first["km"]["source"] == "same_city" and first["weekMatches"] == 1


async def test_brak_sugestii_gdy_ktos_sie_zglosil_na_te_role(monkeypatch):
    pending = {"id": 2, "judge_id": "3", "status": "pending", "role": "table", "slot": None}
    stub_common(monkeypatch, [assigned_claim(), pending])
    out = await SG.suggestions(7, panel())
    assert out["slots"] == [] and out["reason"]


async def test_pomija_zgloszonych_i_nieprzydzielonych(monkeypatch):
    withdrawn = {"id": 2, "judge_id": "2", "status": "withdrawn", "role": "table", "slot": None}
    stub_common(monkeypatch, [assigned_claim(), withdrawn])

    async def facts(_k):
        return [fact(table=("1", "2"))] * 3

    async def mentoring():
        return [], []

    monkeypatch.setattr(SG, "_facts_for", facts)
    monkeypatch.setattr(SG, "_mentoring", mentoring)
    out = await SG.suggestions(7, panel())
    # wycofane zgłoszenie nie wyklucza - osoba może być podpowiedziana
    assert [i["judge"]["id"] for i in out["slots"][0]["suggestions"]] == ["2"]


async def test_zamknieta_oferta_nie_ma_sugestii(monkeypatch):
    stub_common(monkeypatch, [assigned_claim()], offer_extra={"status": "filled"})
    out = await SG.suggestions(7, panel())
    assert out["slots"] == [] and "zamknięta" in out["reason"]


async def test_zaproszenie_wysyla_osobisty_push_i_zapisuje(monkeypatch):
    offer, pushed = stub_common(monkeypatch, [assigned_claim()])
    saved = []

    async def execute(query):
        saved.append(query)

    monkeypatch.setattr(SG, "database", SimpleNamespace(execute=execute))
    monkeypatch.setattr(SG, "insert", lambda _t: SimpleNamespace(values=lambda **kw: kw))
    out = await SG.invite(7, SG.InviteRequest(judgeId="2", role="table"), panel())
    assert out["ok"] and out["invitesLeft"] == S.INVITE_LIMIT - 1
    assert saved[0]["judge_id"] == "2" and saved[0]["role"] == "table"
    ids, text, kw = pushed[0]
    assert ids == ["2"] and text[0] == "Obsada proponuje Ci ten mecz" and kw["extra"]["invite"] == "1"


async def test_zaproszenie_bez_dubli_i_z_limitem(monkeypatch):
    stub_common(monkeypatch, [assigned_claim()], invites={"2": {"judge_id": "2"}})
    with pytest.raises(HTTPException) as dup:
        await SG.invite(7, SG.InviteRequest(judgeId="2", role="table"), panel())
    assert dup.value.status_code == 409 and "już dostał" in dup.value.detail
    many = {str(i): {"judge_id": str(i)} for i in range(100, 100 + S.INVITE_LIMIT)}
    stub_common(monkeypatch, [assigned_claim()], invites=many)
    with pytest.raises(HTTPException) as lim:
        await SG.invite(7, SG.InviteRequest(judgeId="2", role="table"), panel())
    assert lim.value.status_code == 409 and "Limit" in lim.value.detail


async def test_zaproszenie_zgloszonego_lub_obsadzonego_odmowa(monkeypatch):
    stub_common(monkeypatch, [assigned_claim()])
    with pytest.raises(HTTPException) as err:
        await SG.invite(7, SG.InviteRequest(judgeId="1", role="table"), panel())
    assert err.value.status_code == 422 and "już zgłosił" in err.value.detail


async def test_zaproszenie_po_terminie_prowadzi_do_przydziel(monkeypatch):
    from datetime import datetime, timedelta, timezone

    past = datetime.now(timezone.utc) - timedelta(hours=1)
    stub_common(monkeypatch, [assigned_claim()], offer_extra={"deadline_at": past})
    with pytest.raises(HTTPException) as err:
        await SG.invite(7, SG.InviteRequest(judgeId="2", role="table"), panel())
    assert err.value.status_code == 409 and "Przydziel" in err.value.detail


async def test_przydzial_sugerowanego_tworzy_zgloszenie_i_idzie_sciezka_zgloszonego(monkeypatch):
    offer, _ = stub_common(monkeypatch, [assigned_claim()])
    made, routed, dropped = [], [], []

    async def claim_for(_o, _claims, judge_id, role):
        made.append((judge_id, role))
        return {"id": 9, "judge_id": judge_id, "status": "pending", "role": role, "source": "suggested"}, True

    async def assign_claim(_o, _c, claim, body, _a, _h, _k):
        routed.append(claim["id"])
        return {"ok": True}

    async def discard(cid):
        dropped.append(cid)

    monkeypatch.setattr(SG, "claim_for_suggestion", claim_for)
    monkeypatch.setattr(SG, "discard_suggested_claim", discard)
    monkeypatch.setattr(M, "_assign_claim", assign_claim)
    out = await M.assign(7, M.AssignRequest(judgeId="2", slot="czas"), panel())
    assert out == {"ok": True} and made == [("2", "table")] and routed == [9] and dropped == []

    async def boom(*_a):
        raise HTTPException(409, "Kolejka zajęta.")

    monkeypatch.setattr(M, "_assign_claim", boom)
    with pytest.raises(HTTPException):
        await M.assign(7, M.AssignRequest(judgeId="2", slot="czas"), panel())
    assert dropped == [9]  # nieudany przydział nie zostawia zgłoszenia, którego nikt nie złożył


async def test_przydzial_bez_claimid_i_judgeid_to_422(monkeypatch):
    stub_common(monkeypatch, [assigned_claim()])
    with pytest.raises(HTTPException) as err:
        await M.assign(7, M.AssignRequest(), panel())
    assert err.value.status_code == 422
