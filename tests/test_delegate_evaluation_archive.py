"""Archiwum arkuszy ocen delegatów: reguły i praca w tle.

`app.db` łączy się z Postgresem przy imporcie, więc podmieniamy go małą bazą
SQLite z tą samą tabelą archiwum - reszta modułu działa naprawdę.
"""

import asyncio
import gzip
import sys
import types

import pytest
import sqlalchemy
from databases import Database

from app import delegate_evaluation_archive_rules as R
from app.delegate_evaluation_archive_tables import define_tables


def test_przyjmuje_tylko_arkusze_zprp():
    path, kind = R.normalize_document_path("./statystyki_sedzia_oc_PDF.php?IdZawody=5&Id=7")
    assert (path, kind) == ("/statystyki_sedzia_oc_PDF.php?Id=7&IdZawody=5", "legacy_pdf")
    path, kind = R.normalize_document_path("https://baza.zprp.pl/index.php?a=statystyki&b=ocena2&Id=9")
    assert kind == "html" and path.startswith("/index.php?")
    for bad in (
        "https://evil.example/statystyki_sedzia_oc_PDF.php?Id=1",
        "./sedzia_ryczalt_PDF.php?Id=1",
        "./../etc/ocena2.php",
        "javascript:alert(1)",
        "",
    ):
        with pytest.raises(ValueError):
            R.normalize_document_path(bad)


def test_ta_sama_ocena_w_innej_kolejnosci_parametrow_to_jeden_arkusz():
    a, _ = R.normalize_document_path("./statystyki_sedzia_oc_PDF.php?Id=7&IdZawody=5")
    b, _ = R.normalize_document_path("statystyki_sedzia_oc_PDF.php?IdZawody=5&Id=7")
    assert R.source_key(a) == R.source_key(b)


def test_kandydat_czysci_dane_i_wymaga_idzawody():
    item = R.validated_candidate({
        "url": "./statystyki_sedzia_oc_PDF.php?Id=7",
        "match_id": "206769",
        "referee_ids": ["123", "x", ""],
        "referee_names": ["  KOWALSKI   Jan ", ""],
        "season": "2024/2025",
    })
    assert item["referee_ids"] == ["123"]
    assert item["referee_names"] == ["KOWALSKI Jan"]
    with pytest.raises(ValueError):
        R.validated_candidate({"url": "./statystyki_sedzia_oc_PDF.php?Id=7", "match_id": "abc"})


def test_rodzaj_po_tresci_i_strona_logowania():
    assert R.document_kind(b"%PDF-1.4 ...", "html") == "legacy_pdf"
    assert R.document_kind(b"<html>ocena</html>", "html") == "html"
    with pytest.raises(ValueError):
        R.document_kind(b"<html>login</html>", "legacy_pdf")
    assert R.looks_like_login_page('<input type="password" name="haslo">')
    assert not R.looks_like_login_page("<h1>Ocena sędziów</h1>")


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

    async def legacy(candidate, judge_id, province, text):
        stored.append((candidate["match_id"], judge_id, text))

    monkeypatch.setattr(module, "_store_legacy_evaluation", legacy)
    yield module, fake_db.database, table, stored
    sys.modules.pop("app.delegate_evaluation_archive", None)


def test_harvest_odpowiada_od_razu_a_w_tle_archiwizuje(archive, monkeypatch):
    module, database, table, stored = archive
    pdf = b"%PDF-1.4 fake"
    html = "<html><body>Ocena sędziów - arkusz</body></html>".encode("utf-8")
    client = _Client({
        "/statystyki_sedzia_oc_PDF.php?Id=1&IdZawody=100": _Response(pdf),
        "/index.php?Id=2&a=statystyki&b=ocena2": _Response(html),
        "/index.php?Id=3&a=statystyki&b=ocena2": _Response(b'<form><input name="haslo"></form>'),
    })

    async def login(user, password, settings):
        assert (user, password) == ("login", "haslo")
        return client

    monkeypatch.setattr(module, "login_and_client", login)
    monkeypatch.setattr(module, "_pdf_text", lambda data: "Tekst oceny")

    body = module.ArchiveHarvestRequest(
        username="login",
        password="haslo",
        judge_id="555",
        province="śląskie",
        links=[
            module.ArchiveCandidate(url="./statystyki_sedzia_oc_PDF.php?IdZawody=100&Id=1", match_id="100",
                                    season="2023/2024", referee_ids=["555", "556"]),
            module.ArchiveCandidate(url="index.php?a=statystyki&b=ocena2&Id=2", match_id="200", season="2026/2027"),
            module.ArchiveCandidate(url="index.php?a=statystyki&b=ocena2&Id=3", match_id="300", season="2026/2027"),
            module.ArchiveCandidate(url="https://evil.example/x.php", match_id="400"),
        ],
    )

    async def scenario():
        await database.connect()
        try:
            first = await module.harvest_delegate_evaluations(body, settings=None, keys=(None, None))
            assert first == {"accepted": 3, "known": 0, "rejected": 1, "processing": True}
            await asyncio.gather(*list(module._bg_tasks))
            rows = {r["match_id"]: dict(r) for r in await database.fetch_all(sqlalchemy.select(table))}

            assert rows["100"]["status"] == "done" and rows["100"]["kind"] == "legacy_pdf"
            assert gzip.decompress(rows["100"]["pdf_gz"]) == pdf
            assert rows["100"]["pdf_text"] == "Tekst oceny"
            assert rows["100"]["submitted_by"] == "555"
            assert gzip.decompress(rows["200"]["html_gz"]).decode("utf-8").count("Ocena sędziów") == 1
            assert rows["300"]["status"] == "failed" and "logowania" in rows["300"]["error"]
            assert stored == [("100", "555", "Tekst oceny")]
            assert client.closed

            # Drugie pobranie: znane arkusze nie idą ponownie do ZPRP.
            again = await module.harvest_delegate_evaluations(body, settings=None, keys=(None, None))
            assert again["accepted"] == 0 and again["processing"] is False
        finally:
            await database.disconnect()

    asyncio.run(scenario())
