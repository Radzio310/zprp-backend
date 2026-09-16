"""Archiwum meczów okręgu (`app/archive_rules.py`) - zgodność z kodem Statystyk.

Serwer ma oddawać sezon w dokładnie tym kształcie, który dziś składa
przeglądarka (`utils/province-stats/toSlim.ts`, `outside.ts`). Oczekiwany wynik
w `fixtures/archive_parity/expected_ts.json` wygenerował KOD TYPESCRIPT
(Sucrase + Node z TZ=Europe/Warsaw) na prawdziwych meczach Śląska 2025/2026;
składy zawodników w wejściu okrojono do pól, które wchodzą do liczenia.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from app import archive_rules as AR

FIXTURES = Path(__file__).parent / "fixtures" / "archive_parity"


def _norm(value):
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {key: _norm(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_norm(item) for item in value]
    return value


@pytest.fixture(scope="module")
def parity():
    source = json.loads((FIXTURES / "input.json").read_text(encoding="utf-8"))
    expected = json.loads((FIXTURES / "expected_ts.json").read_text(encoding="utf-8"))
    return source, expected


def test_mecze_okregowe_jak_w_przegladarce(parity):
    source, expected = parity
    built = []
    for row in source["rows"]:
        slim = AR.to_slim(row, origin="district", round_name=row["_runda"], series=row["_kolejka"])
        det = AR.details_from_payload(source["details"].get(row["Id"]))
        built.append(AR.enrich_with_details(slim, det) if det else slim)
    assert _norm(built) == _norm(expected["district"])


def test_mecze_spoza_okregu_jak_w_przegladarce(parity):
    source, expected = parity
    ids = sorted(source["lists"], key=int)
    candidates, skipped = AR.collect_outside_candidates(
        [(judge, source["lists"][judge]) for judge in ids], set(source["known"]), source["officials"]
    )
    built = []
    for candidate in candidates:
        det = AR.details_from_payload(source["details"].get(candidate["id"]))
        # Co dziesiąty (numer na „7") świadomie bez szczegółów - ścieżka z samego wiersza.
        if det and candidate["id"].endswith("7"):
            slim = AR.row_to_slim(candidate)
        elif det:
            slim = AR.details_to_slim(candidate, det)
        else:
            slim = AR.row_to_slim(candidate)
        built.append({"slim": slim, "contributors": candidate["contributors"]})
    assert skipped == expected["skippedWithoutId"]
    assert _norm(built) == _norm(expected["outside"])


def test_data_z_godzina_liczy_sie_w_warszawie_a_sama_data_w_utc():
    # 20.09.2026 16:45 w Warszawie (CEST, UTC+2) = 14:45 UTC
    assert AR.parse_zprp_ms("2026-09-20 16:45:00") == 1789915500000
    # sama data - północ UTC, jak `Date.parse("2026-09-20")`
    assert AR.parse_zprp_ms("2026-09-20") == 1789862400000
    assert AR.local_parts(AR.parse_zprp_ms("2026-09-20 16:45:00")) == (0, 16)  # niedziela
    assert AR.parse_zprp_ms("") is None
    assert AR.parse_zprp_ms("20.09.2026") is None


def test_pusty_napis_w_czasie_to_zero_jak_number():
    assert AR.timeout_seconds("00:19:50") == 1190
    assert AR.timeout_seconds("19:50") == 1190
    assert AR.timeout_seconds("00:19:") == 1140
    assert AR.timeout_seconds("ab:cd") is None
    assert AR.timeout_seconds(None) is None


def test_nazwisko_i_numer_sedziego():
    assert AR.pretty_person_name("KOWALSKA-NOWAK Anna Maria") == "Anna Maria Kowalska-Nowak"
    assert AR.pretty_person_name("ŁUCZAK Jan") == "Jan Łuczak"
    assert AR.pretty_person_name("--- ---") == ""
    assert AR.clean_ref_id("0") is None
    assert AR.clean_ref_id(" 465 ") == "465"
    assert AR.name_key("Łukasz WIŚNIEWSKI") == AR.name_key("wisniewski lukasz")


def test_krzaki_iso_8859_2_rozpoznane():
    raw = '{"Nazwa":"Śląska Liga"}'.encode("iso-8859-2")
    assert AR.decode_api_bytes(raw) == {"Nazwa": "Śląska Liga"}
    assert AR.decode_api_bytes('{"a":"ż"}'.encode("utf-8")) == {"a": "ż"}
    assert AR.decode_api_bytes(b"null") is None


def test_szczegoly_w_obu_ksztaltach():
    bare = [[{"Id": "1", "RozgrywkiCode": "S/A/1"}]]
    full = {"0": [{"Id": "1"}], "gosp": {"1": {"bramki": "3"}}, "gosp_osoby": {"a": {}}}
    assert AR.details_from_payload(bare)["match"]["Id"] == "1"
    assert AR.details_from_payload(bare)["gosp"] == {}
    assert AR.details_from_payload(full)["gosp"] == {"1": {"bramki": "3"}}
    assert AR.details_from_payload([None]) is None
    assert AR.details_from_payload(None) is None


def test_wyciag_szczegolow_daje_ten_sam_mecz_co_pelne_wzbogacenie(parity):
    source, _ = parity
    row = next(row for row in source["rows"] if AR.details_from_payload(source["details"].get(row["Id"])))
    slim = AR.to_slim(row, origin="district")
    det = AR.details_from_payload(source["details"][row["Id"]])
    extract = json.loads(json.dumps(AR.extract_details(det, slim["ts"])))  # przez JSON jak z bazy
    assert AR.apply_details(slim, extract) == AR.enrich_with_details(slim, det)


def test_kiedy_pytac_o_szczegoly_drugi_raz():
    now = 2_000_000_000_000
    played = {"ts": now - 1000, "gH": 30, "gA": 28, "refs": {"first": "1"}, "protoOk": True}
    assert AR.needs_details(played, None, None, now)
    assert AR.needs_details(played, played, None, now)
    assert not AR.needs_details(played, dict(played), {"roster": {}}, now)
    assert AR.needs_details({**played, "gA": 29}, played, {"roster": {}}, now)
    waiting = {**played, "protoOk": False}
    assert AR.needs_details(waiting, dict(waiting), {"roster": {}}, now)
    future = {**waiting, "ts": now + 86_400_000}
    assert not AR.needs_details(future, dict(future), {"roster": {}}, now)


def test_paczka_jest_powtarzalna():
    payload = {"b": 1, "a": ["ż"]}
    first, tag = AR.pack(payload)
    second, tag2 = AR.pack(payload)
    assert first == second and tag == tag2
    assert json.loads(gzip.decompress(first)) == payload


def test_rozgrywki_wojewodztwa():
    comps = [
        {"NrWZPR": "12", "NazwaWZPR": "ŚLĄSKIE", "Wystartowano": "1", "code": "S/JmM"},
        {"NrWZPR": "12", "NazwaWZPR": "ŚLĄSKIE", "Wystartowano": "0", "code": "S/JK"},
        {"NrWZPR": "12", "NazwaWZPR": "ŚLĄSKIE", "Wystartowano": "1", "code": "test"},
        {"NrWZPR": "1", "NazwaWZPR": "DOLNOŚLĄSKIE", "Wystartowano": "1", "code": "D/JmM"},
    ]
    assert AR.resolve_wzpr_code(comps, "Śląskie") == "12"
    assert AR.resolve_wzpr_code([], "SLASKIE") == "12"
    assert [c["code"] for c in AR.filter_province_competitions(comps, "12")] == ["S/JmM"]
    entry = AR.competition_entry({"Id_rozgrywki": "9", "code_export": "S/JmM", "Nazwa": "L", "Plec": "M", "IleZespolow": "x"})
    assert entry["teams"] == 0 and "category" not in entry


def test_plan_budowy_najpierw_biezacy_potem_zalegle():
    from datetime import datetime, timedelta, timezone

    from app.assignment_scope import season_catalog

    catalog = season_catalog(None)  # zapas: 2007..2026
    now = datetime(2026, 9, 16, 12, tzinfo=timezone.utc)
    fresh = now - timedelta(hours=2)
    rows = {
        "195": {"built_at": fresh, "schema": AR.ARCHIVE_SCHEMA},
        "194": {"built_at": fresh, "schema": AR.ARCHIVE_SCHEMA},
        "193": {"built_at": fresh, "schema": 0},  # starszy schemat - do przebudowy
    }
    plan = AR.plan_builds(catalog, rows, current=2026, now=now, max_age=timedelta(hours=20), oldest=2012, batch=2)
    assert [season.start for season in plan] == [2024, 2023]

    stale = {**rows, "195": {"built_at": now - timedelta(hours=30), "schema": AR.ARCHIVE_SCHEMA}}
    plan = AR.plan_builds(catalog, stale, current=2026, now=now, max_age=timedelta(hours=20), oldest=2012, batch=1)
    assert [season.start for season in plan] == [2026, 2024]

    everything = {season.id: {"built_at": fresh, "schema": AR.ARCHIVE_SCHEMA} for season in catalog.values()}
    assert AR.plan_builds(catalog, everything, current=2026, now=now, max_age=timedelta(hours=20), oldest=2012, batch=3) == []
    # sezonów sprzed `oldest` nie budujemy wcale
    assert all(
        season.start >= 2012
        for season in AR.plan_builds(catalog, {}, current=2026, now=now, max_age=timedelta(hours=20), oldest=2012, batch=99)
    )
