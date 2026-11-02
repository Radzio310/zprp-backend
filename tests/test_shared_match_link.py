"""Mecz zmigrowany: wpis ręczny w obsadzie wiązany z kontem aplikacji, karta w panelu pary, oś czasu (01.11.2026).

Osobny plik od `test_shared_matches.py` (to samo zaplecze `Env`). Cały łańcuch po stronie serwera:
mecz wspólny z dwoma sędziami z pary -> karta `my:` -> wskaźnik ProEla -> protokół w `proel_matches` -> oś czasu z danymi.
"""

from datetime import datetime, timezone

import pytest

from tests.mentor_panel_support import JUDGES, PAIR, STRANGER, Env

A, B = JUDGES

BLOB = {"matchConfig": {"hostTeamName": "SPR Gliwice", "guestTeamName": "KS Opole", "halfTime": 30},
        "date": "2026-11-05T17:00:00.000Z", "scoreHost": 21, "scoreGuest": 19,
        "protocol": [{"type": "goal", "team": "host", "player": 7, "time": 120000, "half": 1},
                     {"type": "penalty1", "team": "guest", "player": 4, "time": 900000, "half": 1},
                     {"type": "goal", "team": "host", "player": 7, "time": 1000, "half": 1, "shootout": True}]}


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def make(env, who=A, **over):
    data = dict(home_name="SPR Gliwice", away_name="KS Opole", match_at="2026-11-05T18:00:00", code="EHF/1", hall="Hala Łabędy",
                my_role="sedzia1", crew=[env.shared.CrewIn(judge_id=B, role="sedzia2")])
    data.update(over)
    return await env.shared.create_match(env.shared.CreateBody(**data), await env.actor(who))


async def manual_pair_match(env, name="LIS Piotr", role="sedzia2", **over):
    """Mecz tak, jak po starej migracji: twórca A, drugi sędzia samym nazwiskiem (wpis ręczny)."""
    return await make(env, crew=[env.shared.CrewIn(name=name, role=role)], **over)


async def legacy_manual(env, match_id, name="Piotr Lis", role="sedzia2"):
    """Stan sprzed poprawki: wpis ręczny wstawiony wprost do tabeli."""
    await env.db.execute(env.T["shared_match_members"].insert().values(
        id="legacy-m", match_id=match_id, judge_id=None, name=name, role=role, added_by=A,
        added_at=datetime.now(timezone.utc), counts_in_stats=False))
    env.shared_link.reset_account_cache()
    env.core._match_cache.clear()


def cards_of(cards):
    return [c["match_id"] for c in cards if c["match_id"].startswith("my:")]


def test_wiazanie_nazwiska_z_kontem_jednoznaczne_dokladne_bez_kolejnosci_i_ogonkow(env):
    K = env.shared_link

    def idx(*pairs):
        out = {}
        for jid, full in pairs:
            out.setdefault(K.linkable_key(full), set()).add(jid)
        return out

    accounts = idx(("1", "Radosław Witkowicz"), ("2", "Krzysztof Witkowicz"), ("3", "Jan Nowak"), ("4", "Jan Nowak"), ("5", "Karol Zając"))
    assert K.unique_account("WITKOWICZ Krzysztof", accounts) == "2"
    assert K.unique_account("witkowicz radoslaw", accounts) == "1"  # polskie znaki i wielkość liter
    assert K.unique_account("Jan Nowak", accounts) is None  # dwa konta o tym samym nazwisku = bez wiązania
    assert K.unique_account("Witkowicz", accounts) is None  # jeden człon nie wystarcza
    assert K.unique_account("Zając Karol R.", accounts) is None  # inicjał rozróżnia
    assert K.unique_account("Krzysztof Witkowicz-Kowal", accounts) is None  # nie dokładne


def test_zmigrowany_mecz_z_nazwiskiem_drugiego_sedziego_trafia_do_panelu_i_do_listy_drugiego(env):
    async def go():
        created = await manual_pair_match(env)
        mid = created["match"]["id"]
        cards = cards_of(await env.core.pair_match_cards(list(JUDGES)))
        listed = await env.shared.list_matches(False, 300, await env.actor(B))
        detail = await env.shared.get_match(mid, await env.actor(B))
        again = await env.shared_link.link_matches([mid])
        return created, cards, listed, detail, again, list(env.pushes), mid

    created, cards, listed, detail, again, pushes, mid = env.run(go)
    second = next(c for c in created["crew"] if c["role"] == "sedzia2")
    assert second["judge_id"] == B and second["manual"] is False and second["name"] == "Piotr Lis"
    assert cards == [f"my:{mid}"]  # karta w panelu pary
    assert [m["match"]["id"] for m in listed["matches"]] == [mid] and detail["my"]["role"] == "sedzia2"
    assert again == []  # idempotentnie
    added = [p for p in pushes if p["event"] == "added"]
    assert added and added[-1]["to"] == [B] and added[-1]["title"] == "Dodano Cię do meczu"


def test_mecz_zmigrowany_przed_poprawka_naprawia_sie_sam_przy_budowie_panelu(env):
    async def go():
        created = await make(env, crew=[])  # tylko A
        mid = created["match"]["id"]
        await legacy_manual(env, mid, name="Lis Piotr")
        table = env.T["shared_matches"]

        async def rev():  # odczyt wprost z bazy: GET przez członka sam by już powiązał wpis
            return (await env.db.fetch_one(table.select().where(table.c.id == mid)))["rev"]

        rev_before = await rev()
        cards = cards_of(await env.core.pair_match_cards(list(JUDGES)))
        rev_after = await rev()
        env.core._match_cache.clear()
        cards_again = cards_of(await env.core.pair_match_cards(list(JUDGES)))
        rev_final = await rev()
        listed_b = await env.shared.list_matches(False, 300, await env.actor(B))
        return cards, cards_again, rev_before, rev_after, rev_final, listed_b, mid

    cards, cards_again, rev_before, rev_after, rev_final, listed_b, mid = env.run(go)
    assert cards == [f"my:{mid}"] and cards_again == cards
    assert rev_after == rev_before + 1 and rev_final == rev_after  # jedna zmiana, potem spokój
    assert [m["match"]["id"] for m in listed_b["matches"]] == [mid]


def test_drugi_sedzia_widzi_mecz_gdy_tylko_on_otworzy_aplikacje(env):
    async def go():
        created = await make(env, crew=[])
        mid = created["match"]["id"]
        await legacy_manual(env, mid)
        return mid, await env.shared.list_matches(False, 300, await env.actor(B))  # twórca nie otwierał aplikacji

    mid, listed = env.run(go)
    assert [m["match"]["id"] for m in listed["matches"]] == [mid]
    assert next(c for c in listed["matches"][0]["crew"] if c["role"] == "sedzia2")["judge_id"] == B


def test_imiennik_o_tym_samym_nazwisku_nie_wygrywa_z_partnerem_pary(env):
    async def go():
        await env.ins("login_records", judge_id="777", full_name="Lis Piotr", province="X", photo_url=None, last_login_at=datetime.now(timezone.utc))
        env.shared_link.reset_account_cache()
        created = await manual_pair_match(env, name="Piotr Lis")
        return created, cards_of(await env.core.pair_match_cards(list(JUDGES)))

    created, cards = env.run(go)
    second = next(c for c in created["crew"] if c["role"] == "sedzia2")
    assert second["judge_id"] == B and second["manual"] is False  # partner z pary, nie imiennik 777
    assert len(cards) == 1


async def stranger_account(env, jid="888", name="Jan Kowalski"):
    await env.ins("login_records", judge_id=jid, full_name=name, province="X", photo_url=None, last_login_at=datetime.now(timezone.utc))
    env.shared_link.reset_account_cache()


def test_imiennik_spoza_partnerow_nie_dostaje_dostepu_ani_pusha_tylko_podpowiedz(env):
    async def go():
        await stranger_account(env)
        created = await make(env, crew=[env.shared.CrewIn(name="Jan Kowalski", role="czas")])
        mid = created["match"]["id"]
        listed_a = await env.shared.list_matches(False, 300, await env.actor(A))  # odczyt przez twórcę
        listed_x = await env.shared.list_matches(False, 300, await env.actor("888"))  # odwrotne wiązanie po koncie imiennika
        detail = await env.shared.get_match(mid, await env.actor(A))
        repaired = await env.shared_pair.repair_pair(A, "888")
        manual = [m for m in await env.db.fetch_all(env.T["shared_match_members"].select()) if m["judge_id"] is None]
        return created, listed_a, listed_x, detail, repaired, manual, list(env.pushes)

    created, listed_a, listed_x, detail, repaired, manual, pushes = env.run(go)
    entry = next(c for c in detail["crew"] if c["role"] == "czas")
    assert entry["manual"] is True and entry["judge_id"] is None
    assert entry["suggested_account"]["judge_id"] == "888" and entry["suggested_account"]["name"] == "Jan Kowalski"
    assert listed_x["matches"] == [] and repaired == 0 and len(manual) == 1
    assert [c["suggested_account"]["judge_id"] for c in listed_a["matches"][0]["crew"] if c["manual"]] == ["888"]
    assert not [p for p in pushes if p["event"] == "added" and "888" in p["to"]]


def test_partner_z_dyspozycji_wiaze_a_swiadomy_wpis_bez_aplikacji_nigdy(env):
    async def go():
        await stranger_account(env)
        await env.ins("partner_offtimes", judge_id=A, full_name="Anna Nowak", partner_id="888", data_json={})
        env.shared_link.reset_account_cache()
        bound = await make(env, crew=[env.shared.CrewIn(name="Kowalski Jan", role="czas")], code="EHF/2")
        kept = await make(env, crew=[env.shared.CrewIn(name="Jan Kowalski", role="czas", no_app=True)], code="EHF/3", local_id="x2", home_name="Inni", away_name="Gracze")
        await env.shared_link.link_matches([bound["match"]["id"], kept["match"]["id"]])
        again = await env.shared.get_match(kept["match"]["id"], await env.actor(A))
        return bound, again

    bound, again = env.run(go)
    assert next(c for c in bound["crew"] if c["role"] == "czas")["judge_id"] == "888"
    entry = next(c for c in again["crew"] if c["role"] == "czas")
    assert entry["manual"] is True and entry["no_auto_link"] is True
    assert entry["suggested_account"]["judge_id"] == "888"  # podpowiedź wolno pokazać


def test_jawne_przypisanie_konta_przez_trase_obsady_uprawnienia_jak_przy_dodawaniu(env):
    from fastapi import HTTPException

    async def go():
        await stranger_account(env)
        created = await make(env, crew=[env.shared.CrewIn(judge_id=B, role="sedzia2"), env.shared.CrewIn(name="Jan Kowalski", role="czas")])
        mid = created["match"]["id"]
        entry = next(c for c in created["crew"] if c["role"] == "czas")
        Body = env.shared.CrewEditBody
        try:
            await env.shared.edit_crew(mid, entry["id"], Body(base_rev=created["rev"], judge_id="888"), await env.actor(STRANGER))
            outsider = None
        except HTTPException as exc:
            outsider = exc.status_code
        try:  # konto już w obsadzie
            await env.shared.edit_crew(mid, entry["id"], Body(base_rev=created["rev"], judge_id=B), await env.actor(A))
            dup = None
        except HTTPException as exc:
            dup = exc.detail["code"]
        done = await env.shared.edit_crew(mid, entry["id"], Body(base_rev=created["rev"], judge_id="888"), await env.actor(B))  # nie twórca
        return outsider, dup, done, list(env.pushes)

    outsider, dup, done, pushes = env.run(go)
    assert outsider == 404 and dup == "ALREADY_MEMBER"
    row = next(c for c in done["crew"] if c["role"] == "czas")
    assert row["judge_id"] == "888" and row["manual"] is False and row["suggested_account"] is None
    assert [p for p in pushes if p["event"] == "added" and p["to"] == ["888"]]


def test_jawne_przypisanie_szanuje_blokade_dodawania(env):
    from fastapi import HTTPException

    async def go():
        await stranger_account(env)
        created = await make(env, crew=[env.shared.CrewIn(name="Jan Kowalski", role="czas")])
        await env.db.execute(env.T["shared_match_blocks"].insert().values(judge_id="888", via_judge_id=A, created_at=datetime.now(timezone.utc)))
        entry = next(c for c in created["crew"] if c["role"] == "czas")
        try:
            await env.shared.edit_crew(created["match"]["id"], entry["id"], env.shared.CrewEditBody(base_rev=created["rev"], judge_id="888"), await env.actor(A))
        except HTTPException as exc:
            return exc.status_code, exc.detail["code"]

    assert env.run(go) == (409, "ADD_BLOCKED")


def test_blokada_dodawania_nie_jest_omijana_przez_wiazanie_po_nazwisku(env):
    async def go():
        created = await make(env, crew=[])
        await env.db.execute(env.T["shared_match_blocks"].insert().values(judge_id=B, via_judge_id=A, created_at=datetime.now(timezone.utc)))
        await legacy_manual(env, created["match"]["id"])
        return await env.shared_link.link_matches([created["match"]["id"]])

    assert env.run(go) == []


def test_lancuch_mecz_wspolny_dwoch_sedziow_karta_zapis_protokolu_os_czasu(env):
    """Cały łańcuch po stronie serwera. Zapis protokołu to wiersz `proel_matches` wstawiony tak, jak robi to PUT /proel
    (sama trasa wymaga Postgresa, więc test nie woła `app.proel`)."""
    async def go():
        created = await make(env)  # A + B jako konta
        mid = created["match"]["id"]
        member = await env.actor(B)
        cards = cards_of(await env.core.pair_match_cards(list(JUDGES)))
        before = await env.panel.match_room(PAIR, f"my:{mid}", member)
        linked = await env.shared.put_proel(mid, env.shared.ProelBody(base_rev=created["rev"], proel_key="EHF/1"), member)
        pointer_only = await env.panel.match_room(PAIR, f"my:{mid}", member)
        await env.ins("saved_matches", match_number="EHF/1", zprp_match_id=None, data_json=BLOB, status="in_progress", doc_writer_judge=A)
        after = await env.panel.match_room(PAIR, f"my:{mid}", await env.actor(A))
        return cards, before, linked, pointer_only, after, mid

    cards, before, linked, pointer_only, after, mid = env.run(go)
    assert cards == [f"my:{mid}"]
    assert before["timeline"]["available"] is False
    assert linked["match"]["proel_key"] == "EHF/1"
    assert pointer_only["timeline"]["available"] is False  # wskaźnik jest, protokołu jeszcze nie ma
    assert after["match"]["has_proel"] is True
    assert after["timeline"]["available"] is True and [e["type"] for e in after["timeline"]["events"]] == ["goal", "penalty1"]


def test_wektory_skrotu_tulei_zgadzaja_sie_z_aplikacja():
    """Te same trzy wektory sprawdza `utils/__tests__/sharedProelKey-test.ts` - skrót musi być identyczny po obu stronach."""
    from app.proel_match_key import stem_from_local, stem_from_server_id

    assert stem_from_local("123", "1730000000000-abc123") == "KDL2W2JS"
    assert stem_from_local("local", "sm_x") == "RCFQTZ2Y"
    assert stem_from_local("0456", "ł-ó") == "XWVGMABT"
    assert stem_from_local("123", "") == "" and stem_from_server_id("3f9a0c21deadbeef") == "3F9A0C21"


def test_klucz_meczu_recznego_jest_oficjalny_i_pokazuje_sam_numer():
    from app.proel_match_key import is_shared_key, number_of_key, shared_key_of, shared_stem_of_key
    from app.proel_training_key import is_training_key, key_conflicts_with_blob, match_number_from_key

    key = shared_key_of("kdl2w2js", "ehf/1")
    assert key == "M-KDL2W2JS/EHF/1" and is_shared_key(key) and shared_stem_of_key(key) == "KDL2W2JS"
    assert not is_training_key(key)  # mecz zostaje oficjalny: lista oficjalnych go nie gubi
    assert match_number_from_key(key) == number_of_key(key) == "EHF/1"
    assert match_number_from_key("T-K3N8P2WQ/EHF/1") == "EHF/1" and match_number_from_key("EHF/1") == "EHF/1"
    assert not is_shared_key("EHF/1") and not is_shared_key("M-AB/EHF/1") and not is_shared_key("T-K3N8P2WQ/EHF/1")
    assert key_conflicts_with_blob(key, {"matchConfig": {"origin": "manual"}}) is False  # _guard_training_key przepuszcza
    assert key_conflicts_with_blob(key, {"matchConfig": {"origin": "training"}}) is True


def test_dwa_mecze_ehf_1_roznych_tworcow_maja_rozne_klucze_i_osobne_protokoly(env):
    from app.proel_match_key import shared_key_of

    async def go():
        first = await make(env, who=A, local_id="1730000000000-aaa")
        second = await make(env, who=B, local_id="1730000000000-aaa", crew=[env.shared.CrewIn(judge_id=A, role="sedzia2")],
                            home_name="Inni", away_name="Gracze")
        keys = [shared_key_of(m["match"]["key_stem"], m["match"]["code"]) for m in (first, second)]
        # ten sam numer, ten sam local_id, dwóch twórców: to dwa różne mecze, więc dwa wiersze protokołu
        for key, who in zip(keys, (A, B)):
            await env.ins("saved_matches", match_number=key, zprp_match_id=None, data_json=BLOB, status="in_progress", doc_writer_judge=who)
        rows = await env.db.fetch_all(env.T["saved_matches"].select())
        return keys, [r["match_number"] for r in rows]

    keys, stored = env.run(go)
    assert keys[0] != keys[1] and all(k.startswith("M-") and k.endswith("/EHF/1") for k in keys)
    assert sorted(stored) == sorted(keys)


def test_dwa_telefony_obsady_widza_ten_sam_klucz_a_klucz_z_offline_zgadza_sie_z_serwerem(env):
    from app.proel_match_key import shared_key_of, stem_from_local

    async def go():
        created = await make(env, local_id="1730000000000-abc")
        mid = created["match"]["id"]
        as_creator = await env.shared.get_match(mid, await env.actor(A))
        as_member = await env.shared.get_match(mid, await env.actor(B))
        return created, as_creator, as_member

    created, as_creator, as_member = env.run(go)
    stem = created["match"]["key_stem"]
    assert stem == as_creator["match"]["key_stem"] == as_member["match"]["key_stem"]
    # telefon twórcy policzył klucz offline z (twórca, lokalne Id) - to dokładnie ta tuleja
    assert stem == stem_from_local(A, "1730000000000-abc")
    assert shared_key_of(stem, "EHF/1") == f"M-{stem}/EHF/1"


def test_mecz_bez_local_id_i_wiersz_sprzed_kolumny_maja_tuleje_z_id_serwera(env):
    from app.proel_match_key import stem_of_row

    async def go():
        created = await make(env)  # bez local_id
        mid = created["match"]["id"]
        await env.db.execute(env.T["shared_matches"].update().where(env.T["shared_matches"].c.id == mid).values(proel_stem=None))
        return mid, (await env.shared.get_match(mid, await env.actor(A)))["match"]["key_stem"]

    mid, after_wipe = env.run(go)
    assert after_wipe == mid[:8].upper() == stem_of_row({"id": mid, "proel_stem": None})


def test_wskaznik_klucza_przezywa_restart_i_nie_przyjmuje_cudzej_tulei(env):
    from fastapi import HTTPException

    async def go():
        created = await make(env, local_id="1730000000000-abc")
        mid, stem = created["match"]["id"], created["match"]["key_stem"]
        key = f"M-{stem}/EHF/1"
        member = await env.actor(B)
        linked = await env.shared.put_proel(mid, env.shared.ProelBody(base_rev=created["rev"], proel_key=key), member)
        again = await env.shared.get_match(mid, await env.actor(A))  # wznowienie: odczyt od zera
        try:
            await env.shared.put_proel(mid, env.shared.ProelBody(base_rev=linked["rev"], proel_key="M-ZZZZZZZZ/EHF/1"), member)
            foreign = None
        except HTTPException as exc:
            foreign = exc
        return key, linked, again, foreign

    key, linked, again, foreign = env.run(go)
    assert linked["match"]["proel_key"] == key == again["match"]["proel_key"]
    assert foreign is not None and foreign.status_code == 422 and foreign.detail["code"] == "PROEL_KEY_FOREIGN"


def test_wyszukiwarka_znajduje_mecz_reczny_po_numerze_jako_oficjalny_tylko_dla_piszacego(env):
    async def go():
        for key, who in (("M-KDL2W2JS/EHF/1", A), ("M-ABCDEFGH/EHF/1", "555"), ("EHF/2", "555")):
            await env.ins("saved_matches", match_number=key, zprp_match_id=None, data_json=BLOB, status="finished", doc_writer_judge=who)
        S = env.proel_link.search_proel
        return (await S(JUDGES, number="EHF/1"), await S(JUDGES, kind="official"), await S(JUDGES, kind="training"),
                await S(["888"], number="EHF/1"))

    by_number, official, training, stranger = env.run(go)
    assert [i["key"] for i in by_number] == ["M-KDL2W2JS/EHF/1"]  # cudzego meczu ręcznego (M-ABCDEFGH) nie widać
    hit = by_number[0]
    assert hit["kind"] == "official" and hit["official"] is True and hit["number"] == "EHF/1"  # bez prefiksu M-
    assert sorted(i["key"] for i in official) == ["EHF/2", "M-KDL2W2JS/EHF/1"] and training == []
    assert stranger == []


def test_os_czasu_w_panelu_dziala_przez_klucz_m_takze_bez_wskaznika(env):
    from app.proel_match_key import shared_key_of

    async def go():
        created = await make(env, local_id="1730000000000-abc")
        mid, stem = created["match"]["id"], created["match"]["key_stem"]
        # protokół napisał trzeci członek obsady, wskaźnik jeszcze nie dotarł z telefonu
        await env.ins("saved_matches", match_number=shared_key_of(stem, "EHF/1"), zprp_match_id=None, data_json=BLOB,
                      status="in_progress", doc_writer_judge="777")
        return await env.panel.match_room(PAIR, f"my:{mid}", await env.actor(B))

    room = env.run(go)
    assert room["timeline"]["available"] is True and [e["type"] for e in room["timeline"]["events"]] == ["goal", "penalty1"]


def test_link_brief_pokazuje_numer_bez_prefiksu_m():
    from app.mentor_proel_link import link_brief

    brief = link_brief({"proel_key": "M-KDL2W2JS/EHF/1", "linked_by": A, "linked_at": None})
    assert brief["key"] == "M-KDL2W2JS/EHF/1" and brief["number"] == "EHF/1" and brief["kind"] == "official"


def test_statystyki_proela_licza_numer_bez_prefiksu_m():
    from app.proel_stats_rules import match_summary

    summary = match_summary("M-KDL2W2JS/EHF/1", "finished", {"matchConfig": {"matchNumber": "EHF/1"}, "scoreHost": 1, "scoreGuest": 0})
    assert summary["training"] is False
