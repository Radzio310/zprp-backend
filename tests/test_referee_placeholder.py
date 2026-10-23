"""Brak obsady w ZPRP („--- ---", „-- --") nie jest sędzią.

Zgłoszenie: profil sędziego „--- ---" z 4287 meczami w 334 rozgrywkach, a u WITKOWICZA
Radosława „-- -- 10 meczów razem" jako drugi partner w parze. Decyzja: wszędzie jako brak
obsady - nie liczy się w statystykach, parach, wyszukiwarce; stary link mówi, czym to jest.
"""

import asyncio
import importlib
import sys
import types
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest
import sqlalchemy
from databases import Database
from fastapi import HTTPException
from sqlalchemy import insert, select

from app.national_distance_tables import define_tables as define_national
from app.zprp_public import referee_placeholder as RP
from app.zprp_public import referee_stats as RS
from app.zprp_public_tables import define_tables as define_public

MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras")


@pytest.fixture(autouse=True)
def _fresh_registry():
    RP.forget_ids()
    yield
    RP.forget_ids()


# ---------------------------------------------------------------------------
# Reguły (czyste)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["--- ---", "-- --", "---", "-", " - - ", "—", "– –", ".", "...", "_", "?", "·",
                                  "brak", "BRAK", "Brak obsady", "NN", "N.N.", "n n", "--- ---          O"])
def test_znacznik_braku_obsady(name):
    assert RP.is_placeholder_name(name) and RP.is_blank_name(name)
    assert RP.is_placeholder_referee("1234", name)       # numer wspólny dla tysięcy meczów - decyduje nazwisko
    assert RP.is_placeholder_referee("", name)
    assert RP.clean_official("1234", name) == (None, None)


@pytest.mark.parametrize("name", ["WITKOWICZ Radosław", "KOWALCZYK Jan          O", "Nowak-Brak Anna", "Ann", "Na"])
def test_prawdziwe_nazwisko_to_sedzia(name):
    assert not RP.is_placeholder_name(name) and not RP.is_blank_name(name)
    assert not RP.is_placeholder_referee("r1", name)


def test_puste_pola_i_numery():
    assert RP.is_blank_name(None) and RP.is_blank_name("") and not RP.is_placeholder_name("")
    # Prawdziwy numer bez nazwiska w terminarzu - to wyznaczony sędzia, nie wakat.
    assert not RP.is_placeholder_referee("r59", "") and RP.clean_official("r59", "") == ("r59", None)
    for junk in ("", None, "0", "000", "-", "---", " "):
        assert RP.is_placeholder_id(junk)
        assert RP.is_placeholder_referee(junk, None)
    # Śmieciowy numer przy prawdziwym nazwisku: nazwisko zostaje, numer nie.
    assert RP.clean_official("0", "NOWAK Jan") == (None, "NOWAK Jan")
    # Numer z rejestru placeholderów - brak obsady także bez nazwiska.
    assert not RP.is_placeholder_id("999")
    RP.remember_ids(["999"])
    assert RP.is_placeholder_id("999") and RP.is_placeholder_referee("999", "")


def test_kandydaci_na_numer_placeholdera():
    pairs = [("999", "--- ---", 4000), ("999", None, 3), ("998", "-- --", 10),
             ("1107", "--- ---", 100), ("1107", "KOWAL Jan", 1),  # choć raz z nazwiskiem = osoba
             ("r1", "WITKOWICZ Radosław", 50), ("", "--- ---", 7)]
    assert RP.candidate_ids(pairs) == {"999": 4000, "998": 10}


def test_czyszczenie_slownika_meczu_tylko_obecne_klucze():
    card = {"match_id": "m", "referee_1_id": "r1", "referee_1_name": "WITKOWICZ Radosław",
            "referee_2_id": "999", "referee_2_name": "--- ---", "delegate_1_name": "---"}
    RP.clean_match_officials(card)
    assert card["referee_2_id"] is None and card["referee_2_name"] is None
    assert card["delegate_1_name"] is None and "delegate_1_id" not in card
    assert card["referee_1_name"] == "WITKOWICZ Radosław"
    assert RP.clean_match_officials({"match_id": "m"}) == {"match_id": "m"}


def test_obsada_strony_meczu_placeholder_jak_puste_pole():
    # „--- ---" to puste pole: znika, bez wolnego miejsca i napisu „brak obsady".
    one = RP.match_officials({"referee_1_id": "r1", "referee_1_name": "A", "referee_2_id": "999",
                              "referee_2_name": "--- ---", "delegate_1_name": "D"})
    assert one == [{"role": "Sędzia", "id": "r1", "name": "A"}, {"role": "Delegat", "id": None, "name": "D"}]
    assert all("vacant" not in o for o in one)
    pair = RP.match_officials({"referee_1_id": "r1", "referee_1_name": "A", "referee_2_id": "r2", "referee_2_name": "B"})
    assert [o["name"] for o in pair] == ["A", "B"]
    assert RP.match_officials({"referee_1_name": "--- ---", "referee_2_name": ""}) == []
    assert RP.match_officials({"secretary_name": "S"}) == [{"role": "Sekretarz", "id": None, "name": "S"}]


def test_lista_sedziow_okregu_bez_placeholdera():
    """„Para z: --- ---" i wiersz „--- ---" na liście ZPRP to puste pole, nie osoba."""
    from app.zprp.officials import _normalize_partner_name, _parse_officials_page

    assert _normalize_partner_name("--- ---") == "" and _normalize_partner_name("-- --") == ""
    assert _normalize_partner_name("KASZNIA Wojciech") == "Wojciech Kasznia"

    def row(nr, name):
        return (f"<tr><td title='{nr}'>1.</td><td></td><td>{name}</td><td>Katowice</td>"
                f"<td></td><td></td><td>Sędzia<br>Para z : --- ---</td><td></td></tr>")

    html = "<table id='tabelka'>" + row("465", "BLOCH Wojciech") + row("1107", "--- ---") + "</table>"
    parsed = _parse_officials_page(html)
    assert list(parsed["officials"]) == ["465"]
    assert parsed["officials"]["465"]["partner"] == ""


def test_para_bez_placeholdera_i_licznik_meczow_bez_partnera():
    def row(i, pid, pname):
        return {"match_id": f"m{i}", "referee_1_id": "r1", "referee_1_name": "WITKOWICZ Radosław",
                "referee_2_id": pid, "referee_2_name": pname, "score_home": 1, "score_away": 0}

    rows = [row(1, "r2", "PARA Adam"), row(2, "r2", "PARA Adam"), row(3, "999", "--- ---"), row(4, "998", "-- --"),
            row(5, None, None), row(6, "", "")]
    out = RS.summarize(rows, "r1", {}, venue_key=lambda n, c: f"{n}|{c}", display_city=lambda c: str(c))
    assert [p["referee_id"] for p in out["partners"]] == ["r2"]
    assert out["no_partner_matches"] == 4
    assert RS.partner_of(rows[2], "r1") == (None, None)


# ---------------------------------------------------------------------------
# Synchronizacja: placeholder zapisany jako NULL
# ---------------------------------------------------------------------------


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    tables = list(define_public(metadata)) + list(define_national(metadata))
    try:
        from app.zprp_public_geocode_tables import define_tables as define_geo

        tables.append(define_geo(metadata))
    except ImportError:
        pass
    url = f"sqlite:///{tmp_path / 'ph.db'}"
    engine = sqlalchemy.create_engine(url)
    metadata.create_all(engine)
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in tables:
        setattr(fake, table.name, table)
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    for name in MODULES:
        sys.modules.pop(name, None)
    extras = importlib.import_module("app.zprp_public.extras")
    extras.clear_cache()
    importlib.import_module("app.zprp_public.enrich").invalidate()
    portal = importlib.import_module("app.zprp_public.portal")
    sync = importlib.import_module("app.zprp_public.sync")
    yield types.SimpleNamespace(extras=extras, portal=portal, sync=sync, db=fake.database, engine=engine,
                                T={t.name: t for t in tables})
    engine.dispose()
    pkg = sys.modules.get("app.zprp_public")
    for name in MODULES:
        sys.modules.pop(name, None)
        if pkg is not None:
            pkg.__dict__.pop(name.rsplit(".", 1)[1], None)


def test_synchronizacja_zapisuje_brak_obsady_jako_null(env):
    item = {"Id": "m1", "NrSedzia_pierwszy": "r1", "NrSedzia_pierwszy_nazwisko": "WITKOWICZ Radosław",
            "NrSedzia_drugi": "999", "NrSedzia_drugi_nazwisko": "--- ---",
            "NrSedzia_delegat": "0", "NrSedzia_delegat_nazwisko": "-- --",
            "NrSedzia_sekretarz": "", "NrSedzia_sekretarz_nazwisko": "KOWAL Ewa"}
    v = env.sync._match_values(item)
    assert (v["referee_1_id"], v["referee_1_name"]) == ("r1", "WITKOWICZ Radosław")
    assert v["referee_2_id"] is None and v["referee_2_name"] is None
    assert v["delegate_1_id"] is None and v["delegate_1_name"] is None
    assert (v["secretary_id"], v["secretary_name"]) == (None, "KOWAL Ewa")
    # Numer z rejestru (wspólny numer placeholdera) bez nazwiska - też brak obsady.
    RP.remember_ids(["999"])
    v2 = env.sync._match_values({"Id": "m2", "NrSedzia_drugi": "999", "NrSedzia_drugi_nazwisko": ""})
    assert v2["referee_2_id"] is None and v2["referee_2_name"] is None


# ---------------------------------------------------------------------------
# Trasy i sprzątanie na małej bazie
# ---------------------------------------------------------------------------


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


BASE = datetime(2026, 3, 7, 12, 0)
PAIR = 6        # WITKOWICZ z prawdziwym partnerem
DASH3 = 5       # WITKOWICZ z „--- ---" (wspólny numer 999)
DASH2 = 10      # WITKOWICZ z „-- --" (numer 998)
OTHERS = 4      # inne mecze z numerem 999 - w tych samych godzinach co mecze WITKOWICZA


async def _seed(db, T):
    def ins(table, /, **v):
        return db.execute(insert(T[table]).values(**v))

    await ins("zprp_public_seasons", season_id="S1", start_year=2025, name="2025/26", active=True, **_h())
    await ins("zprp_public_clubs", club_id="c1", name="KS Kielce", city="Kielce", archived=False, **_h())
    await ins("zprp_public_competitions", competition_id="K1", season_id="S1", name="Liga", category="Seniorzy", gender="M", **_h())
    n = 0

    async def match(at, r1, r1n, r2, r2n):
        nonlocal n
        n += 1
        await ins("zprp_public_matches", match_id=f"m{n}", season_id="S1", competition_id="K1", competition_name="Liga",
                  home_team_id="t1", away_team_id="t2", home_club_id="c1", away_club_id="c1", home_team_name="A",
                  away_team_name="B", score_home=25, score_away=22, scheduled_at=at, venue_name="Hala", venue_city="Kielce",
                  referee_1_id=r1, referee_1_name=r1n, referee_2_id=r2, referee_2_name=r2n, **_h())

    for i in range(PAIR):
        await match(BASE - timedelta(days=100 + i), "r1", "WITKOWICZ Radosław", "r2", "PARA Adam")
    for i in range(DASH3):
        await match(BASE - timedelta(days=i), "r1", "WITKOWICZ Radosław", "999", "--- ---")
    for i in range(DASH2):
        await match(BASE - timedelta(days=50 + i), "r1", "WITKOWICZ Radosław", "998", "-- --")
    # Ten sam numer 999 o tej samej godzinie w innej hali - jedna osoba tak nie potrafi.
    for i in range(OTHERS):
        await match(BASE - timedelta(days=i), "r5", "INNY Piotr", "999", "--- ---")
    # Prawdziwy sędzia z ukrytym nazwiskiem (jak nr 1107 w Śląskiem): bez kolizji godzin.
    await match(BASE - timedelta(days=300), "1107", "--- ---", "r2", "PARA Adam")


def run(env, factory):
    async def go():
        await env.db.connect()
        try:
            await _seed(env.db, env.T)
            return await factory(env)
        finally:
            await env.db.disconnect()

    return asyncio.run(go())


def test_profil_i_statystyki_bez_placeholdera(env):
    async def go(e):
        stats = await e.extras.referee_stats("r1", "all")
        prof = await e.extras.referee_profile("r1", 1000)
        errors = []
        for rid in ("999", "998", "0"):
            try:
                await e.extras.referee_stats(rid, "")
            except HTTPException as exc:
                errors.append((exc.status_code, exc.detail))
        return stats, prof, errors

    stats, prof, errors = run(env, go)
    total = PAIR + DASH3 + DASH2
    assert stats["matches"] == total == prof["matches_total"]          # mecze sędziego zostają w całości
    assert [p["referee_id"] for p in stats["partners"]] == ["r2"]
    assert all(p["name"] not in ("--- ---", "-- --") for p in stats["partners"])
    assert stats["no_partner_matches"] == DASH3 + DASH2
    # Karty meczów: drugie miejsce puste, nie „--- ---".
    names = {m.get("referee_2_name") for m in prof["matches"]}
    assert "--- ---" not in names and "-- --" not in names
    assert errors == [(404, {"detail": RP.ERROR_MESSAGE, "code": RP.ERROR_CODE})] * 3


def test_wyszukiwarka_bez_placeholdera(env):
    async def go(e):
        index = await e.portal._build_referee_index()
        e.portal._REF_INDEX.update(rows=index)
        return index, e.portal._match_referees(index, "---", 5)

    index, hits = run(env, go)
    ids = {e["referee_id"] for e in index}
    assert {"r1", "r2", "r5"} <= ids and not ids & {"999", "998", "1107"}
    assert hits == []


def test_sprzatanie_idempotentne_i_stary_link(env):
    async def go(e):
        first = RP.cleanup(e.engine, batch=3, tables=(e.T["zprp_public_matches"], e.T["zprp_public_sync_state"]))
        second = RP.cleanup(e.engine, batch=3, tables=(e.T["zprp_public_matches"], e.T["zprp_public_sync_state"]))
        M = e.T["zprp_public_matches"]
        left = await e.db.fetch_all(select(M.c.match_id).where(
            sqlalchemy.or_(M.c.referee_1_name.in_(["--- ---", "-- --"]), M.c.referee_2_name.in_(["--- ---", "-- --"]),
                           M.c.referee_2_id.in_(["999", "998"]))))
        state = await e.db.fetch_one(select(e.T["zprp_public_sync_state"].c.value_json)
                                     .where(e.T["zprp_public_sync_state"].c.key == RP.STATE_KEY))
        e.extras.clear_cache()
        RP.forget_ids()  # inny proces: rejestr tylko w bazie
        out = {}
        for rid in ("999", "998", "1107"):
            try:
                await e.extras.referee_profile(rid, 0)
                out[rid] = "ok"
            except HTTPException as exc:
                out[rid] = exc.detail
        stats = await e.extras.referee_stats("r1", "all")
        return first, second, left, RP.ids_from_state(state["value_json"]), out, stats

    first, second, left, stored, out, stats = run(env, go)
    assert first["updated"] == DASH3 + DASH2 + OTHERS + 1 and second["updated"] == 0
    assert left == []
    # Do rejestru tylko numer, który nie może być jedną osobą (kolizje godzin).
    assert stored == {"999"}
    assert out["999"] == {"detail": RP.ERROR_MESSAGE, "code": RP.ERROR_CODE}
    assert out["998"] == "Nie znaleziono sędziego" and out["1107"] == "Nie znaleziono sędziego"
    assert stats["no_partner_matches"] == DASH3 + DASH2 and [p["referee_id"] for p in stats["partners"]] == ["r2"]
