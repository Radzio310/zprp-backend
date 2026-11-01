"""Mecze ręczne wspólne i ręczne podpięcie ProEla w panelu pary (31.10.2026).

Prawa (twórca / członek / obcy), 409 rev, ukrycie i blokada, idempotentna migracja, duplikat i dołączenie, powtórz mecz,
karta pary `my:`, zakres wyszukiwania ProEla, oś czasu z podpięcia (klucz oficjalny, szkoleniowy, promoted_to).
"""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException, Response
from sqlalchemy import select

from tests.mentor_panel_support import ADMIN, JUDGES, MENTOR, PAIR, STRANGER, Env

A, B = JUDGES


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def denied(coro):
    try:
        await coro
    except HTTPException as exc:
        d = exc.detail if isinstance(exc.detail, dict) else {"code": exc.detail}
        return exc.status_code, d.get("code"), d
    raise AssertionError("oczekiwano odmowy")


async def make(env, who=A, **over):
    data = dict(home_name="SPR Gliwice", away_name="KS Opole", match_at="2026-11-05T18:00:00", code="EHF/1", hall="Hala Łabędy",
                my_role="sedzia1", crew=[env.shared.CrewIn(judge_id=B, role="sedzia2")])
    data.update(over)
    out = await env.shared.create_match(env.shared.CreateBody(**data), await env.actor(who))
    return out


# ─── Reguły (liść) ──────────────────────────────────────────────────────────


def test_klucz_duplikatu_bez_kolejnosci_ogonkow_i_strefy(env):
    R = env.shared_rules
    a = R.duplicate_key("SPR Gliwice", "KS Opole", R.parse_match_at("2026-11-05T23:30:00"))
    b = R.duplicate_key("ks opole", "S.P.R. Gliwice", R.parse_match_at("2026-11-05T18:00:00+01:00"))
    assert a == b and a[0] == "2026-11-05"
    # 23:30 czasu polskiego to jeszcze ten sam dzień, mimo że w UTC bywa to już następny.
    assert R.duplicate_key("A", "B", R.parse_match_at("2026-11-05T23:30:00"))[0] == "2026-11-05"
    assert R.duplicate_key("A", "", R.parse_match_at("2026-11-05")) is None


def test_kolejny_numer_serii(env):
    R = env.shared_rules
    assert R.next_series_code("EHF/1") == "EHF/2"
    assert R.next_series_code("EHF 3") == "EHF 4"
    assert R.next_series_code("EHF") == "EHF/2"
    assert R.next_series_code("EHF/1", ["ehf/2", "EHF/3"]) == "EHF/4"
    assert R.next_series_code("12") is None and R.next_series_code("") is None


def test_uprawnienia_do_obsady_i_konflikt_wersji(env):
    R = env.shared_rules
    assert R.may_remove_member(actor_id="1", creator_id="1", member_judge_id="2")
    assert not R.may_remove_member(actor_id="2", creator_id="1", member_judge_id="3")
    assert not R.may_remove_member(actor_id="1", creator_id="1", member_judge_id="1")
    assert R.may_change_role(actor_id="2", creator_id="1", member_judge_id="2")
    assert not R.may_change_role(actor_id="2", creator_id="1", member_judge_id="3")
    assert R.revision_conflict(1, 2) and R.revision_conflict(None, 1) and not R.revision_conflict("2", 2)
    assert R.like_pattern("a%b_c") == "%a\\%b\\_c%"


# ─── Prawa: twórca / członek / obcy ─────────────────────────────────────────


def test_prawa_tworcy_czlonka_i_obcego(env):
    async def go():
        created = await make(env)
        mid = created["match"]["id"]
        member, stranger, creator = await env.actor(B), await env.actor(STRANGER), await env.actor(A)
        out = {}
        out["member_read"] = (await env.shared.get_match(mid, member))["match"]["id"] == mid
        out["stranger_read"] = (await denied(env.shared.get_match(mid, stranger)))[:2]
        rev = created["rev"]
        out["stranger_edit"] = (await denied(env.shared.edit_match(mid, env.shared.EditBody(base_rev=rev, hall="X"), stranger)))[:2]
        out["member_delete"] = (await denied(env.shared.delete_match(mid, None, member)))[:2]
        crew = created["crew"]
        creator_member = next(c for c in crew if c["judge_id"] == A)["id"]
        out["member_removes_creator"] = (await denied(env.shared.remove_crew(mid, creator_member, rev, member)))[:2]
        out["creator_removes_self"] = (await denied(env.shared.remove_crew(mid, creator_member, rev, creator)))[:2]
        # Członek edytuje dane i wpisuje wynik.
        edited = await env.shared.edit_match(mid, env.shared.EditBody(base_rev=rev, hall="Hala Zabrze"), member)
        out["member_edit"] = edited["match"]["hall"] == "Hala Zabrze" and edited["rev"] == rev + 1
        scored = await env.shared.put_result(mid, env.shared.ResultBody(base_rev=edited["rev"], score_home=30, score_away=28, half_home=15, half_away=14), member)
        out["result_by"] = (scored["match"]["result"]["by"], scored["match"]["result"]["by_name"], scored["match"]["result"]["at"] is not None)
        # Twórca usuwa wszystkim; potem członek dostaje 410, obcy dalej 404.
        removed = await env.shared.delete_match(mid, None, creator)
        out["deleted"] = removed["deleted"]
        out["member_after"] = (await denied(env.shared.get_match(mid, member)))[:2]
        out["stranger_after"] = (await denied(env.shared.get_match(mid, stranger)))[:2]
        return out

    out = env.run(go)
    assert out["member_read"] and out["stranger_read"] == (404, "MATCH_NOT_FOUND")
    assert out["stranger_edit"] == (404, "MATCH_NOT_FOUND")
    assert out["member_delete"] == (403, "CREATOR_ONLY") and out["member_removes_creator"] == (403, "CREATOR_ONLY")
    assert out["creator_removes_self"] == (403, "CREATOR_STAYS")
    assert out["member_edit"] and out["result_by"] == (B, "Piotr Lis", True) and out["deleted"]
    assert out["member_after"] == (410, "MATCH_DELETED") and out["stranger_after"] == (404, "MATCH_NOT_FOUND")


def test_obsada_tylko_tworca_usuwa_i_push(env):
    async def go():
        created = await make(env, crew=[])
        mid = created["match"]["id"]
        member_actor = await env.actor(B)
        added = await env.shared.add_crew(mid, env.shared.CrewAddBody(base_rev=created["rev"], add=[env.shared.CrewIn(judge_id=B, role="sedzia2")]), await env.actor(A))
        pushes_after_add = list(env.pushes)
        # Członek dodaje osobę (wpis ręczny bez konta) - dozwolone.
        manual = await env.shared.add_crew(mid, env.shared.CrewAddBody(base_rev=added["rev"], add=[env.shared.CrewIn(name="Jan Stolik", role="czas")]), member_actor)
        manual_row = next(c for c in manual["crew"] if c["manual"])
        # Członek NIE usuwa innych.
        refused = (await denied(env.shared.remove_crew(mid, manual_row["id"], manual["rev"], member_actor)))[:2]
        # Twórca usuwa; usunięty (aplikacyjny) dostaje push, wpis ręczny nie ma kogo powiadomić.
        b_row = next(c for c in manual["crew"] if c["judge_id"] == B)
        env.pushes.clear()
        removed = await env.shared.remove_crew(mid, b_row["id"], manual["rev"], await env.actor(A))
        return pushes_after_add, refused, manual_row, removed, list(env.pushes)

    pushes_after_add, refused, manual_row, removed, pushes_after_remove = env.run(go)
    assert pushes_after_add[-1]["to"] == [B] and pushes_after_add[-1]["event"] == "added" and A not in pushes_after_add[-1]["to"]
    assert manual_row["judge_id"] is None and manual_row["role"] == "czas"
    assert refused == (403, "CREATOR_ONLY")
    assert [c["judge_id"] for c in removed["crew"] if c["judge_id"]] == [A]
    assert pushes_after_remove == [{"to": [B], "title": "Usunięto Cię z obsady meczu", "body": pushes_after_remove[0]["body"],
                                    "match_id": removed["match"]["id"], "event": "removed"}]


def test_osoba_bez_konta_w_aplikacji_tylko_jako_wpis_reczny(env):
    async def go():
        await env.ins("province_judges", judge_id="777", full_name="Bez Konta", province="ŚLĄSKIE", photo_url=None, badges=[])
        created = await make(env, crew=[])
        refused = await denied(env.shared.add_crew(created["match"]["id"], env.shared.CrewAddBody(
            base_rev=created["rev"], add=[env.shared.CrewIn(judge_id="777", role="sedzia2")]), await env.actor(A)))
        manual = await denied(env.shared.add_crew(created["match"]["id"], env.shared.CrewAddBody(
            base_rev=created["rev"], add=[env.shared.CrewIn(role="sedzia2")]), await env.actor(A)))
        return refused, manual

    refused, manual = env.run(go)
    assert refused[:2] == (422, "NOT_APP_USER") and refused[2]["judge_ids"] == ["777"]
    assert manual[:2] == (422, "MANUAL_NAME_REQUIRED")


# ─── 409: wersja ────────────────────────────────────────────────────────────


def test_zapis_na_starym_rev_daje_409_z_aktualna_wersja(env):
    async def go():
        created = await make(env)
        mid, rev = created["match"]["id"], created["rev"]
        first = await env.shared.edit_match(mid, env.shared.EditBody(base_rev=rev, hall="Hala 1"), await env.actor(A))
        conflict = await denied(env.shared.edit_match(mid, env.shared.EditBody(base_rev=rev, hall="Hala 2"), await env.actor(B)))
        no_rev = await denied(env.shared.edit_match(mid, env.shared.EditBody(hall="Hala 3"), await env.actor(B)))
        result_conflict = await denied(env.shared.put_result(mid, env.shared.ResultBody(base_rev=rev, score_home=1, score_away=0), await env.actor(B)))
        row = (await env.db.fetch_one(select(env.T["shared_matches"]).where(env.T["shared_matches"].c.id == mid)))
        log = await env.db.fetch_all(select(env.T["shared_match_log"]).where(env.T["shared_match_log"].c.match_id == mid))
        return first, conflict, no_rev, result_conflict, row, log

    first, conflict, no_rev, result_conflict, row, log = env.run(go)
    assert conflict[:2] == (409, "REV_CONFLICT") and conflict[2]["rev"] == first["rev"]
    assert conflict[2]["current"]["match"]["hall"] == "Hala 1" and conflict[2]["current"]["match"]["updated_by_name"] == "Anna Nowak"
    assert no_rev[:2] == (422, "BASE_REV_REQUIRED") and result_conflict[:2] == (409, "REV_CONFLICT")
    assert row["hall"] == "Hala 1" and row["score_home"] is None  # nic nie nadpisało się po cichu
    assert [e["action"] for e in log] == ["create", "edit"]


def test_dziennik_zapisuje_kto_i_co_zmienil(env):
    async def go():
        created = await make(env)
        mid = created["match"]["id"]
        edited = await env.shared.edit_match(mid, env.shared.EditBody(base_rev=created["rev"], hall="Nowa hala", code="EHF/9"), await env.actor(B))
        return edited

    edited = env.run(go)
    entry = edited["log"][0]
    assert entry["action"] == "edit" and entry["actor_name"] == "Piotr Lis"
    assert {(c["field"], c["from"], c["to"]) for c in entry["changes"]} == {("code", "EHF/1", "EHF/9"), ("hall", "Hala Łabędy", "Nowa hala")}


# ─── Ukrycie i blokada ──────────────────────────────────────────────────────


def test_ukrycie_nie_kasuje_u_innych_i_mozna_przywrocic(env):
    async def go():
        created = await make(env)
        mid = created["match"]["id"]
        member = await env.actor(B)
        hidden = await env.shared.hide_match(mid, None, member)
        mine = await env.shared.list_matches(False, 300, member)
        with_hidden = await env.shared.list_matches(True, 300, member)
        creator_list = await env.shared.list_matches(False, 300, await env.actor(A))
        still_open = (await env.shared.get_match(mid, member))["my"]["hidden"]
        await env.shared.restore_match(mid, member)
        back = await env.shared.list_matches(False, 300, member)
        return hidden, mine, with_hidden, creator_list, still_open, back

    hidden, mine, with_hidden, creator_list, still_open, back = env.run(go)
    assert hidden["hidden"] and mine["count"] == 0 and mine["hidden_count"] == 1
    assert with_hidden["count"] == 1 and with_hidden["matches"][0]["my"]["hidden"] is True
    assert creator_list["count"] == 1 and still_open is True and back["count"] == 1


def test_blokada_nie_dodawaj_mnie_przez_te_osobe(env):
    async def go():
        created = await make(env)
        mid = created["match"]["id"]
        hidden = await env.shared.hide_match(mid, env.shared.HideBody(block_adder=True), await env.actor(B))
        creator = await env.actor(A)
        # Nowy mecz: B pominięty i wymieniony w `skipped` (bez ciszy).
        again = await make(env, match_at="2026-11-12T18:00:00", code="EHF/2")
        # Dodanie do istniejącego meczu: 409 ADD_BLOCKED.
        other = await make(env, match_at="2026-11-19T18:00:00", code="EHF/3", crew=[])
        refused = await denied(env.shared.add_crew(other["match"]["id"], env.shared.CrewAddBody(
            base_rev=other["rev"], add=[env.shared.CrewIn(judge_id=B, role="sedzia2")]), creator))
        blocks = await env.shared.list_blocks(await env.actor(B))
        # Inna osoba (STRANGER) nadal może dodać B.
        third = await make(env, who=STRANGER, match_at="2026-11-26T18:00:00", code="Z/1", crew=[env.shared.CrewIn(judge_id=B, role="sedzia2")])
        await env.shared.remove_block(A, await env.actor(B))
        unblocked = await env.shared.add_crew(other["match"]["id"], env.shared.CrewAddBody(
            base_rev=other["rev"], add=[env.shared.CrewIn(judge_id=B, role="sedzia2")]), creator)
        return hidden, again, refused, blocks, third, unblocked

    hidden, again, refused, blocks, third, unblocked = env.run(go)
    assert hidden["blocked_via"] == A
    assert again["skipped"] == [{"judge_id": B, "reason": "BLOCKED"}] and [c["judge_id"] for c in again["crew"]] == [A]
    assert refused[:2] == (409, "ADD_BLOCKED") and refused[2]["skipped"][0]["judge_id"] == B
    assert [b["via_judge_id"] for b in blocks["blocks"]] == [A]
    assert third["skipped"] == [] and B in [c["judge_id"] for c in third["crew"]]
    assert B in [c["judge_id"] for c in unblocked["crew"]]


# ─── Migracja, duplikat, powtórz ────────────────────────────────────────────


def test_migracja_lokalnego_meczu_jest_idempotentna(env):
    async def go():
        first = await make(env, local_id="1734-k3n9x")
        second = await make(env, local_id="1734-k3n9x", hall="Zmieniona hala")
        other_user = await make(env, who=B, local_id="1734-k3n9x", crew=[], home_name="Inni", away_name="Ludzie")
        count = len(await env.db.fetch_all(select(env.T["shared_matches"])))
        await env.shared.delete_match(first["match"]["id"], None, await env.actor(A))
        after_delete = await make(env, local_id="1734-k3n9x")
        return first, second, other_user, count, after_delete

    first, second, other_user, count, after_delete = env.run(go)
    assert second["existing"] is True and second["match"]["id"] == first["match"]["id"] and second["match"]["hall"] == "Hala Łabędy"
    assert other_user["existing"] is False and other_user["match"]["id"] != first["match"]["id"]  # ten sam local_id u innego twórcy to inny mecz
    assert count == 2
    assert after_delete["existing"] is True and after_delete["deleted"] is True  # usunięty nie wraca przy ponownej migracji


def test_duplikat_pozwala_dolaczyc_tylko_do_pasujacego_meczu(env):
    async def go():
        created = await make(env, crew=[])
        mid = created["match"]["id"]
        stranger = await env.actor(STRANGER)
        body = dict(home_name="KS Opole", away_name="spr gliwice", match_at="2026-11-05T20:00:00", my_role="sedzia2")
        dup = await denied(env.shared.create_match(env.shared.CreateBody(**body), stranger))
        wrong = await denied(env.shared.join_match(env.shared.JoinBody(match_id=mid, role="sedzia2", home_name="Inna", away_name="Para",
                                                                         match_at="2026-11-05T20:00:00"), stranger))
        joined = await env.shared.join_match(env.shared.JoinBody(match_id=mid, role="sedzia2", home_name="KS Opole", away_name="spr gliwice",
                                                                  match_at="2026-11-05T20:00:00"), stranger)
        forced = await env.shared.create_match(env.shared.CreateBody(**body, force=True), await env.actor(B))
        return created, dup, wrong, joined, forced

    created, dup, wrong, joined, forced = env.run(go)
    assert dup[:2] == (409, "DUPLICATE_MATCH") and dup[2]["can_join"] and dup[2]["duplicates"][0]["id"] == created["match"]["id"]
    assert dup[2]["duplicates"][0]["already_member"] is False and dup[2]["duplicates"][0]["creator_name"] == "Anna Nowak"
    assert wrong[:2] == (403, "NOT_A_DUPLICATE")
    assert joined["joined"] and STRANGER in [c["judge_id"] for c in joined["crew"]] and joined["rev"] == created["rev"] + 1
    assert forced["existing"] is False and forced["match"]["id"] != created["match"]["id"]


def test_powtorz_mecz_kopia_z_nowa_data_i_kolejnym_numerem(env):
    async def go():
        created = await make(env)
        mid = created["match"]["id"]
        await env.shared.put_result(mid, env.shared.ResultBody(base_rev=created["rev"], score_home=20, score_away=18), await env.actor(A))
        # Nie można powtórzyć na tę samą datę bez force.
        same_day = await denied(env.shared.repeat_match(mid, env.shared.RepeatBody(match_at="2026-11-05T19:00:00"), await env.actor(B)))
        copy = await env.shared.repeat_match(mid, env.shared.RepeatBody(match_at="2026-11-12T18:00:00"), await env.actor(B))
        third = await env.shared.repeat_match(copy["match"]["id"], env.shared.RepeatBody(match_at="2026-11-19T18:00:00"), await env.actor(B))
        return created, same_day, copy, third

    created, same_day, copy, third = env.run(go)
    assert same_day[:2] == (409, "DUPLICATE_MATCH")
    assert copy["match"]["code"] == "EHF/2" and third["match"]["code"] == "EHF/3"
    assert copy["match"]["creator_id"] == B and copy["match"]["result"] is None and copy["match"]["hall"] == "Hala Łabędy"
    assert sorted(c["judge_id"] for c in copy["crew"]) == [A, B]
    assert {c["judge_id"]: c["role"] for c in copy["crew"]} == {A: "sedzia1", B: "sedzia2"}


def test_wliczanie_do_statystyk_domyslnie_wylaczone_i_osobne(env):
    async def go():
        created = await make(env)
        mid = created["match"]["id"]
        before = (await env.shared.get_match(mid, await env.actor(B)))["my"]["counts_in_stats"]
        await env.shared.put_stats(mid, env.shared.StatsBody(counts_in_stats=True), await env.actor(B))
        b = (await env.shared.get_match(mid, await env.actor(B)))["my"]["counts_in_stats"]
        a = (await env.shared.get_match(mid, await env.actor(A)))["my"]["counts_in_stats"]
        rev = (await env.shared.get_match(mid, await env.actor(A)))["rev"]
        return before, b, a, rev, created["rev"]

    before, b, a, rev, created_rev = env.run(go)
    assert (before, b, a) == (False, True, False) and rev == created_rev  # flaga osobista nie zmienia wersji meczu


def test_powiazanie_zprp_tylko_liczbowe_id_i_wynik_nie_idzie_do_zprp(env):
    async def go():
        created = await make(env)
        mid = created["match"]["id"]
        bad = await denied(env.shared.put_zprp(mid, env.shared.ZprpBody(base_rev=created["rev"], zprp_match_id="1734-k3n9x"), await env.actor(B)))
        ok = await env.shared.put_zprp(mid, env.shared.ZprpBody(base_rev=created["rev"], zprp_match_id="456789"), await env.actor(B))
        return bad, ok

    bad, ok = env.run(go)
    assert bad[:2] == (422, "VALIDATION") and ok["match"]["zprp_match_id"] == "456789" and ok["rev"] == 2
    import inspect

    assert "zprp" not in inspect.getsource(env.shared.put_result).lower().replace("zprp.", "")  # wynik ręczny nie dotyka ZPRP


# ─── Wyszukiwarka użytkowników i sugestie ───────────────────────────────────


def test_wyszukiwarka_uzytkownikow_i_sugestie(env):
    async def go():
        await env.ins("partner_offtimes", judge_id=A, full_name="Anna Nowak", partner_id=B, data_json={})
        found = await env.shared.search_users("piotr", 10, await env.actor(A))
        percent = await env.shared.search_users("%", 10, await env.actor(A))
        by_id = await env.shared.search_users(B, 10, await env.actor(A))
        await make(env, who=A, crew=[env.shared.CrewIn(judge_id=STRANGER, role="sedzia2")])
        await make(env, who=A, match_at="2026-12-01T18:00:00", crew=[env.shared.CrewIn(judge_id=STRANGER, role="sedzia2")], code="X/1")
        suggest = await env.shared.suggest_users(8, await env.actor(A))
        return found, percent, by_id, suggest

    found, percent, by_id, suggest = env.run(go)
    assert [u["judge_id"] for u in found["users"]] == [B] and by_id["users"][0]["name"] == "Piotr Lis"
    assert percent["users"] == []  # % nie jest wieloznacznikiem
    reasons = {s["judge_id"]: s["reason"] for s in suggest["suggestions"]}
    assert reasons[B] == "partner" and reasons[STRANGER] == "frequent" and A not in reasons


# ─── Panel pary: karta `my:` ────────────────────────────────────────────────


def test_mecz_wspolny_pojawia_sie_na_liscie_pary_z_prefiksem_i_znacznikiem(env):
    async def go():
        core = env.core
        created = await make(env)
        mid = created["match"]["id"]
        cards = await core.pair_match_cards(list(JUDGES))
        mine = [c for c in cards if c["match_id"].startswith("my:")]
        ctx = await core.pair_context(PAIR, await env.actor(A))
        card = await core.match_card(ctx, f"my:{mid}")
        # Para dostaje flagę i nagranie na takim id (pokój działa na zwykłych napisach).
        await env.panel.set_flag(PAIR, f"my:{mid}", env.panel.FlagBody(starred=True), await env.actor(A))
        flagged = await core.match_card(await core.pair_context(PAIR, await env.actor(A)), f"my:{mid}")
        room = await env.panel.match_room(PAIR, f"my:{mid}", await env.actor(B))
        # Obcy sędzia + A nie tworzą pary: mecz nie pojawia się w cudzej parze.
        other = [c for c in await core.pair_match_cards([A, STRANGER]) if c["match_id"].startswith("my:")]
        # Zmiana (wynik) odświeża pamięć kart i podbija rev panelu.
        rev_before = (await core.pair_context(PAIR, await env.actor(A)))["rev"]
        await env.shared.put_result(mid, env.shared.ResultBody(base_rev=created["rev"], score_home=21, score_away=19), await env.actor(A))
        after = [c for c in await core.pair_match_cards(list(JUDGES)) if c["match_id"] == f"my:{mid}"][0]
        rev_after = (await core.pair_context(PAIR, await env.actor(A)))["rev"]
        # Usunięcie przez twórcę zdejmuje kartę.
        await env.shared.delete_match(mid, None, await env.actor(A))
        gone = [c for c in await core.pair_match_cards(list(JUDGES)) if c["match_id"].startswith("my:")]
        return mid, mine, card, flagged, room, other, after, rev_before, rev_after, gone

    mid, mine, card, flagged, room, other, after, rev_before, rev_after, gone = env.run(go)
    assert [c["match_id"] for c in mine] == [f"my:{mid}"]
    assert card["shared"] is True and card["origin_kind"] == "shared" and card["match_code"] == "EHF/1" and card["season"] == "2026/2027"
    assert card["home"]["name"] == "SPR Gliwice" and card["videos"] == {"count": 0, "uploads": 0}
    assert flagged["starred"] is True and room["match"]["match_id"] == f"my:{mid}"
    assert other == []
    assert after["home"]["score"] == 21 and rev_after > rev_before
    assert gone == []


def test_obcy_lub_mecz_z_jednym_sedzia_pary_nie_tworzy_karty(env):
    async def go():
        await make(env, crew=[])  # tylko A
        await make(env, match_at="2026-12-01T18:00:00", code="Y/1", crew=[env.shared.CrewIn(judge_id=B, role="delegat")])  # B tylko jako delegat
        return [c for c in await env.core.pair_match_cards(list(JUDGES)) if c["match_id"].startswith("my:")]

    assert env.run(go) == []


# ─── ProEl: wyszukiwarka i podpięcie ────────────────────────────────────────

BLOB = {"matchConfig": {"hostTeamName": "SPR Gliwice", "guestTeamName": "KS Opole", "halfTime": 30},
        "date": "2026-11-05T17:00:00.000Z", "scoreHost": 21, "scoreGuest": 19,
        "protocol": [{"type": "goal", "team": "host", "player": 7, "time": 120000, "half": 1},
                     {"type": "penalty1", "team": "guest", "player": 4, "time": 900000, "half": 1},
                     {"type": "goal", "team": "host", "player": 7, "time": 1000, "half": 1, "shootout": True}]}


async def seed_proel(env):
    await env.ins("saved_matches", match_number="EHF/1", zprp_match_id="999", data_json=BLOB, status="finished", doc_writer_judge="555")
    await env.ins("saved_matches", match_number="T-K3N8P2WQ/EHF/1", zprp_match_id=None, data_json=BLOB, status="in_progress", doc_writer_judge=B)
    await env.ins("saved_matches", match_number="T-ABCDEFGH/EHF/1", zprp_match_id=None, data_json=BLOB, status="in_progress", doc_writer_judge="555")
    other = {**BLOB, "matchConfig": {"hostTeamName": "Inni", "guestTeamName": "Gracze"}, "date": "2025-03-01T10:00:00.000Z"}
    await env.ins("saved_matches", match_number="OSK/12", zprp_match_id=None, data_json=other, status="finished", doc_writer_judge="555")


def test_wyszukiwanie_proela_zakres_oficjalne_wszystkie_szkoleniowe_tylko_pary(env):
    async def go():
        await seed_proel(env)
        S = env.proel_link.search_proel
        everything = await S(JUDGES)
        by_number = await S(JUDGES, number="ehf/1")
        by_team = await S(JUDGES, team="opole")
        by_day = await S(JUDGES, date="2026-11-05")
        wrong_day = await S(JUDGES, date="2026-11-07")
        training = await S(JUDGES, kind="training")
        official = await S(JUDGES, kind="official")
        stranger_scope = await S(["888"])
        injection = await S(JUDGES, q="x' OR 1=1 --")
        wildcard = await S(JUDGES, number="%")
        limited = await S(JUDGES, limit=1)
        return everything, by_number, by_team, by_day, wrong_day, training, official, stranger_scope, injection, wildcard, limited

    (everything, by_number, by_team, by_day, wrong_day, training, official, stranger_scope, injection, wildcard, limited) = env.run(go)
    keys = lambda items: sorted(i["key"] for i in items)
    # Obce szkolenie (555) nigdy się nie pojawia; szkolenie partnera (B) tak.
    assert keys(everything) == ["EHF/1", "OSK/12", "T-K3N8P2WQ/EHF/1"]
    assert keys(by_number) == ["EHF/1", "T-K3N8P2WQ/EHF/1"] and keys(by_team) == ["EHF/1", "T-K3N8P2WQ/EHF/1"]
    assert keys(by_day) == ["EHF/1", "T-K3N8P2WQ/EHF/1"] and wrong_day == []
    assert keys(training) == ["T-K3N8P2WQ/EHF/1"] and keys(official) == ["EHF/1", "OSK/12"]
    assert keys(stranger_scope) == ["EHF/1", "OSK/12"]  # kto nie pisał szkolenia, widzi same oficjalne
    assert injection == [] and wildcard == [] and len(limited) == 1
    hit = next(i for i in everything if i["key"] == "EHF/1")
    assert (hit["home"], hit["away"], hit["events"], hit["kind"], hit["score_home"]) == ("SPR Gliwice", "KS Opole", 2, "official", 21)
    assert hit["date"].startswith("2026-11-05") and next(i for i in everything if i["key"].startswith("T-"))["kind"] == "training"


def test_podpiecie_proela_zakres_oraz_nie_zapisuje_w_proelu(env):
    async def go():
        await seed_proel(env)
        created = await make(env)
        card_id = f"my:{created['match']['id']}"
        P = env.proel_link
        member = await env.actor(A)
        foreign = await denied(P.put_proel_link(PAIR, card_id, P.LinkBody(proel_key="T-ABCDEFGH/EHF/1"), Response(), member))
        missing = await denied(P.put_proel_link(PAIR, card_id, P.LinkBody(proel_key="NIE/1"), Response(), member))
        own_training = await P.put_proel_link(PAIR, card_id, P.LinkBody(proel_key="T-K3N8P2WQ/EHF/1"), Response(), member)
        official = await P.put_proel_link(PAIR, "m1", P.LinkBody(proel_key="OSK/12"), Response(), member)
        stranger = await denied(P.put_proel_link(PAIR, card_id, P.LinkBody(proel_key="EHF/1"), Response(), await env.actor(STRANGER)))
        before = await env.db.fetch_all(select(env.T["saved_matches"]))
        return foreign, missing, own_training, official, stranger, before, card_id

    foreign, missing, own_training, official, stranger, before, card_id = env.run(go)
    assert foreign[:2] == (403, "PROEL_SCOPE") and missing[:2] == (404, "PROEL_NOT_FOUND") and stranger[1] in ("NO_ACCESS",)
    assert own_training["link"]["kind"] == "training" and own_training["link"]["preview"]["home"] == "SPR Gliwice"
    assert official["link"]["key"] == "OSK/12" and official["link"]["preview"]["events"] == 2
    assert len(before) == 4  # podpięcie nie dopisuje ani nie zmienia niczego w ProElu


def test_oś_czasu_z_podpiecia_klucz_szkoleniowy_promoted_to_i_pierwszenstwo_przed_automatem(env):
    async def go():
        await seed_proel(env)
        P = env.proel_link
        member = await env.actor(A)
        # m1 (ISM/1): automat nic nie znajduje. Podpinamy OFICJALNY mecz o innym ID ZPRP - świadomy wybór wygrywa.
        empty = (await env.panel.match_room(PAIR, "m1", member))["timeline"]
        await P.put_proel_link(PAIR, "m1", P.LinkBody(proel_key="EHF/1"), Response(), member)
        manual = await env.panel.match_room(PAIR, "m1", member)
        # Klucz szkoleniowy partnera.
        await P.put_proel_link(PAIR, "m1", P.LinkBody(proel_key="T-K3N8P2WQ/EHF/1"), Response(), member)
        training = (await env.panel.match_room(PAIR, "m1", member))["timeline"]
        # promoted_to: szkolenie przeniesione do oficjalnego OSK/12 -> oś z oficjalnego.
        await env.db.execute(env.T["saved_matches"].update().where(env.T["saved_matches"].c.match_number == "T-K3N8P2WQ/EHF/1")
                             .values(promoted_to="OSK/12"))
        await env.db.execute(env.T["saved_matches"].update().where(env.T["saved_matches"].c.match_number == "OSK/12")
                             .values(data_json={**BLOB, "protocol": BLOB["protocol"][:1]}))
        promoted = (await env.panel.match_room(PAIR, "m1", member))["timeline"]
        # Odpięcie wraca do automatu.
        await P.delete_proel_link(PAIR, "m1", Response(), member)
        after_unlink = (await env.panel.match_room(PAIR, "m1", member))["timeline"]
        # Klucz szkoleniowy obcego, wpisany wprost do tabeli, nie daje osi (zakres liczy się też przy odczycie).
        await env.db.execute(env.T["mentor_proel_links"].insert().values(pair_id=PAIR, match_id="m1", proel_key="T-ABCDEFGH/EHF/1",
                                                                          linked_by=A, linked_at=datetime.now(timezone.utc)))
        foreign = (await env.panel.match_room(PAIR, "m1", member))["timeline"]
        return empty, manual, training, promoted, after_unlink, foreign

    empty, manual, training, promoted, after_unlink, foreign = env.run(go)
    assert empty["available"] is False
    assert manual["match"]["has_proel"] is True and manual["match"]["proel_link"]["key"] == "EHF/1" and manual["timeline"]["available"] is True
    assert [e["type"] for e in manual["timeline"]["events"]] == ["goal", "penalty1"]  # seria karnych nie wchodzi na oś
    assert training["available"] is True and len(training["events"]) == 2
    assert promoted["available"] is True and len(promoted["events"]) == 1
    assert after_unlink["available"] is False
    assert foreign["available"] is False


def test_klucz_proela_meczu_wspolnego_jest_zaufany_i_trzyma_zakres(env):
    async def go():
        await seed_proel(env)
        created = await make(env)
        mid = created["match"]["id"]
        member = await env.actor(B)
        # Mecz prowadzony z meczu wspólnego podpina się sam (klucz ustawia aplikacja).
        linked = await env.shared.put_proel(mid, env.shared.ProelBody(base_rev=created["rev"], proel_key="T-K3N8P2WQ/EHF/1"), member)
        foreign = await denied(env.shared.put_proel(mid, env.shared.ProelBody(base_rev=linked["rev"], proel_key="T-ABCDEFGH/EHF/1"), member))
        room = await env.panel.match_room(PAIR, f"my:{mid}", member)
        return linked, foreign, room

    linked, foreign, room = env.run(go)
    assert linked["match"]["proel_key"] == "T-K3N8P2WQ/EHF/1" and foreign[:2] == (403, "PROEL_SCOPE")
    assert room["match"]["has_proel"] is True and room["timeline"]["available"] is True


def test_zapisy_pary_na_karcie_wspolnej_i_trybuna_dziala_jak_dotad(env):
    async def go():
        created = await make(env)
        card_id = f"my:{created['match']['id']}"
        ctx = await env.core.pair_context(PAIR, await env.actor(A))
        # Wątek / klip / link działają na id z prefiksem (kolumny `match_id` to zwykłe napisy).
        card = await env.core.match_card(ctx, card_id)
        return card

    card = env.run(go)
    assert card["match_id"].startswith("my:") and "source" not in card


# ─── Poprawki po przeglądzie (01.11.2026) ───────────────────────────────────


def test_duplikat_nie_czlonkowi_zwraca_tylko_minimum_a_samo_zprp_id_nie_wystarcza(env):
    async def go():
        created = await make(env, hall="Hala Tajna")
        mid = created["match"]["id"]
        await env.db.execute(env.T["shared_matches"].update().where(env.T["shared_matches"].c.id == mid).values(zprp_match_id="777"))
        stranger = await env.actor(STRANGER)
        other = dict(home_name="Zupelnie", away_name="Inni", match_at="2026-11-05T18:00:00", my_role="sedzia1")
        by_zprp_only = await env.shared.create_match(env.shared.CreateBody(**other, zprp_match_id="777"), stranger)
        join_zprp_only = await denied(env.shared.join_match(env.shared.JoinBody(
            match_id=mid, role="delegat", home_name="Zupelnie", away_name="Inni", match_at="2026-11-05T18:00:00", zprp_match_id="777"), stranger))
        dup = await denied(env.shared.create_match(env.shared.CreateBody(
            home_name="SPR Gliwice", away_name="KS Opole", match_at="2026-11-05T18:00:00", my_role="sedzia1"), stranger))
        member = await denied(env.shared.create_match(env.shared.CreateBody(
            home_name="SPR Gliwice", away_name="KS Opole", match_at="2026-11-05T18:00:00", my_role="sedzia1"), await env.actor(B)))
        return by_zprp_only, join_zprp_only, dup, member

    by_zprp_only, join_zprp_only, dup, member = env.run(go)
    assert by_zprp_only["existing"] is False  # samo zprp_match_id nie ujawnia ani nie blokuje
    assert join_zprp_only[:2] == (403, "NOT_A_DUPLICATE")
    stranger_item = dup[2]["duplicates"][0]
    assert set(stranger_item) == {"id", "home_name", "away_name", "match_at", "creator_name", "already_member", "hidden"}
    assert "hall" not in stranger_item and "crew" not in stranger_item
    assert member[2]["duplicates"][0]["hall"] == "Hala Tajna" and member[2]["duplicates"][0]["crew"]  # członek widzi pełne dane


def test_dolaczenie_pushuje_do_tworcy_i_nie_zajmuje_zajetej_roli(env, monkeypatch):
    sent = []

    async def fake_send(recipients, actor_id, title, body, match_id, event):
        sent.append((sorted(recipients), event, body))

    monkeypatch.setattr(env.shared.N, "send", fake_send)

    async def go():
        created = await make(env, crew=[])
        mid = created["match"]["id"]
        stranger = await env.actor(STRANGER)
        data = dict(match_id=mid, home_name="KS Opole", away_name="SPR Gliwice", match_at="2026-11-05T18:00:00")
        no_role = await denied(env.shared.join_match(env.shared.JoinBody(**data), stranger))
        taken = await denied(env.shared.join_match(env.shared.JoinBody(**data, role="sedzia1"), stranger))
        sent.clear()
        joined = await env.shared.join_match(env.shared.JoinBody(**data, role="sedzia2"), stranger)
        return no_role, taken, joined

    no_role, taken, joined = env.run(go)
    assert no_role[:2] == (422, "ROLE_REQUIRED") and taken[:2] == (409, "ROLE_TAKEN")
    assert joined["joined"] is True
    assert sent and sent[0][0] == [A] and sent[0][1] == "joined"


def test_wyszukiwarka_ma_limit_na_konto_i_oddaje_429(env):
    async def go():
        env.shared._search_hits.clear()
        actor = await env.actor(A)
        for _ in range(env.shared.SEARCH_LIMIT_PER_MIN):
            await env.shared.search_users("piotr", 10, actor)
        blocked = await denied(env.shared.search_users("piotr", 10, actor))
        other = await env.shared.search_users("anna", 10, await env.actor(B))
        env.shared._search_hits.clear()
        return blocked, other

    blocked, other = env.run(go)
    assert blocked[:2] == (429, "RATE_LIMITED") and "users" in other


def test_powiazanie_z_zprp_nie_dubluje_karty_a_dane_pary_nie_przepadaja(env):
    async def go():
        core = env.core
        T = env.T["shared_matches"]
        clean = await make(env)
        kept = await make(env, match_at="2026-12-01T18:00:00", code="EHF/2")
        # Dane pary wiszą pod kartą `my:` drugiego meczu (flaga) - zanim mecz zostanie powiązany z ZPRP.
        await env.panel.set_flag(PAIR, f"my:{kept['match']['id']}", env.panel.FlagBody(starred=True), await env.actor(A))
        for row, zid in ((clean, "m1"), (kept, "m2")):
            await env.db.execute(T.update().where(T.c.id == row["match"]["id"]).values(zprp_match_id=zid))
        core._match_cache.clear()
        cards = await core.pair_match_cards(list(JUDGES))
        return [c["match_id"] for c in cards], clean["match"]["id"], kept["match"]["id"], {c["match_id"]: c for c in cards}

    ids, clean_id, kept_id, by_id = env.run(go)
    assert "m1" in ids and f"my:{clean_id}" not in ids  # główna jest karta ZPRP
    assert f"my:{kept_id}" in ids and "m2" not in ids  # dane pary pod `my:` zostają dostępne
    assert sum(1 for i in ids if i in ("m1", f"my:{clean_id}")) == 1
