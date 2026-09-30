"""Oceny delegatów zbierane w tle: reguły i praca w tle.

`app.db` łączy się z Postgresem przy imporcie, więc podmieniamy go małą bazą
SQLite z tą samą tabelą archiwum - reszta modułu działa naprawdę.
"""

import asyncio
import gzip
import pathlib
import sys
import types

import pytest
import sqlalchemy
from databases import Database

from app import delegate_evaluation_archive_rules as R
from app.delegate_evaluation_archive_tables import define_tables


OCENA = "index.php?a=statystyki&b=ocena2&Id=9"


def test_przyjmuje_tylko_formularz_ocen_zprp():
    assert R.normalize_document_path("https://baza.zprp.pl/" + OCENA) == "/index.php?Id=9&a=statystyki&b=ocena2"
    for bad in (
        "https://evil.example/index.php?b=ocena2",
        "./statystyki_sedzia_oc_PDF.php?Id=7&IdZawody=5",  # stare PDF-y pomijamy
        "./sedzia_ryczalt_PDF.php?Id=1",
        "./../etc/ocena2.php",
        "javascript:alert(1)",
        "",
    ):
        with pytest.raises(ValueError):
            R.normalize_document_path(bad)


def test_ta_sama_ocena_w_innej_kolejnosci_parametrow_to_jeden_arkusz():
    a = R.normalize_document_path("./index.php?b=ocena2&Id=9&a=statystyki")
    b = R.normalize_document_path(OCENA)
    assert R.source_key(a) == R.source_key(b)


def test_tylko_zeszly_i_biezacy_sezon():
    base = {"url": OCENA, "match_id": "206769"}
    assert R.validated_candidate({**base, "season": "2025/2026"})["season"] == "2025/2026"
    assert R.validated_candidate({**base, "season": "2026/2027"})
    for season in ("2024/2025", "", "sezon"):
        with pytest.raises(ValueError):
            R.validated_candidate({**base, "season": season})


def test_kandydat_czysci_dane_i_wymaga_idzawody():
    item = R.validated_candidate({
        "url": OCENA,
        "match_id": "206769",
        "referee_ids": ["123", "x", ""],
        "referee_names": ["  KOWALSKI   Jan ", ""],
        "season": "2025/2026",
    })
    assert item["referee_ids"] == ["123"]
    assert item["referee_names"] == ["KOWALSKI Jan"]
    with pytest.raises(ValueError):
        R.validated_candidate({"url": OCENA, "match_id": "abc", "season": "2025/2026"})


def test_strona_logowania_i_pusty_formularz():
    assert R.looks_like_login_page('<input type="password" name="haslo">')
    assert not R.looks_like_login_page("<h1>Ocena sędziów</h1>")
    assert not R.has_grades({"sections": []})
    assert R.has_grades({"sections": [{"key": "I"}]})


class _Response:
    def __init__(self, body: bytes, status: int = 200):
        self.status_code = status
        self._body = body

    async def aread(self):
        return self._body


class _Client:
    def __init__(self, pages):
        self.pages = pages
        self.closed = False
        self.calls = []

    async def get(self, path, timeout=None):
        self.calls.append(path)
        return self.pages[path]

    async def aclose(self):
        self.closed = True


@pytest.fixture
def archive(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    table = define_tables(metadata)
    url = f"sqlite:///{tmp_path / 'archive.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake_db = types.ModuleType("app.db")
    fake_db.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake_db.delegate_evaluation_documents = table
    monkeypatch.setitem(sys.modules, "app.db", fake_db)
    fake_session = types.ModuleType("app.zprp_session")
    fake_session.decrypt_field = lambda value, key: value
    fake_session.login_and_client = None
    monkeypatch.setitem(sys.modules, "app.zprp_session", fake_session)
    fake_deps = types.ModuleType("app.deps")
    fake_deps.Settings = object
    fake_deps.get_rsa_keys = lambda: (None, None)
    fake_deps.get_settings = lambda: None
    monkeypatch.setitem(sys.modules, "app.deps", fake_deps)
    fake_delegate = types.ModuleType("app.delegate")
    fake_delegate._decode_html_bytes = lambda raw, ct: raw.decode("utf-8")
    monkeypatch.setitem(sys.modules, "app.delegate", fake_delegate)
    sys.modules.pop("app.delegate_evaluation_archive", None)
    import app.delegate_evaluation_archive as module

    monkeypatch.setattr(module, "_PAUSE_BETWEEN_DOCUMENTS", 0)
    stored = []

    async def store(candidate, judge_id, province, evaluation):
        stored.append((candidate["match_id"], judge_id, province, [s["key"] for s in evaluation["sections"]]))
        return "inserted"

    monkeypatch.setattr(module, "_store_evaluation", store)
    yield module, fake_db.database, table, stored
    sys.modules.pop("app.delegate_evaluation_archive", None)


FIXTURE = (pathlib.Path(__file__).parent / "fixtures" / "delegate_evaluation_ocena2.html").read_bytes()


def test_harvest_odpowiada_od_razu_a_w_tle_przerabia_ocene(archive, monkeypatch):
    module, database, table, stored = archive
    client = _Client({
        "/index.php?Id=2&a=statystyki&b=ocena2": _Response(FIXTURE),
        "/index.php?Id=3&a=statystyki&b=ocena2": _Response(b'<form><input name="haslo"></form>'),
        "/index.php?Id=4&a=statystyki&b=ocena2": _Response(b"<html><body>Formularz jeszcze pusty - brak ocen</body></html>"),
    })

    async def login(user, password, settings):
        assert (user, password) == ("login", "haslo")
        return client

    monkeypatch.setattr(module, "login_and_client", login)

    def link(id_, match_id, season="2025/2026"):
        return module.ArchiveCandidate(
            url=f"index.php?a=statystyki&b=ocena2&Id={id_}", match_id=match_id,
            season=season, referee_ids=["555", "556"],
        )

    body = module.ArchiveHarvestRequest(
        username="login",
        password="haslo",
        judge_id="555",
        province="śląskie",
        links=[
            link(2, "200"),
            link(3, "300", "2026/2027"),
            link(4, "400", "2026/2027"),
            link(5, "500", "2023/2024"),  # stary sezon - odrzucony
            module.ArchiveCandidate(url="./statystyki_sedzia_oc_PDF.php?Id=1", match_id="600", season="2025/2026"),
        ],
    )

    async def scenario():
        await database.connect()
        try:
            first = await module.harvest_delegate_evaluations(body, settings=None, keys=(None, None))
            assert first == {"accepted": 3, "known": 0, "rejected": 2, "processing": True}
            await asyncio.gather(*list(module._bg_tasks))
            rows = {r["match_id"]: dict(r) for r in await database.fetch_all(sqlalchemy.select(table))}

            assert rows["200"]["status"] == "done" and rows["200"]["error"] is None
            assert gzip.decompress(rows["200"]["html_gz"]) == FIXTURE
            assert rows["200"]["submitted_by"] == "555"
            assert stored == [("200", "555", "śląskie", ["I", "II"])]
            assert rows["300"]["status"] == "failed" and "logowania" in rows["300"]["error"]
            assert rows["400"]["status"] == "done" and rows["400"]["error"] == "empty"
            assert client.closed

            # Drugie pobranie: zeszły sezon nie idzie drugi raz do ZPRP.
            again = await module.harvest_delegate_evaluations(body, settings=None, keys=(None, None))
            assert again["accepted"] == 0 and again["processing"] is False
        finally:
            await database.disconnect()

    asyncio.run(scenario())
