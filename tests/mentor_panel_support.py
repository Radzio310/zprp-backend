"""Wspólne zaplecze testów panelu „Mentor": mała baza SQLite zamiast `app.db`.

Nie importuje produkcyjnego `app.db` (otwiera prawdziwą bazę). Moduły panelu
ładujemy na nowo na atrapie modułu z prawdziwymi schematami tabel.
"""

import asyncio
import importlib
import sys
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import sqlalchemy
from databases import Database
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Table, insert

from app.mentor_auto_found_tables import define_tables as define_auto_found
from app.mentor_bastion_tables import define_tables as define_bastion
from app.mentor_evaluation_tables import define_tables as define_evaluations
from app.mentor_panel_tables import define_tables as define_panel
from app.mentor_trybuna_tables import define_tables as define_trybuna
from app.mentoring_tables import define_tables as define_mentoring
from app.stream_tables import define_tables as define_streams
from app.zprp_public_tables import define_tables as define_public

MODULES = (
    "app.mentor_panel", "app.mentor_panel_core", "app.mentor_panel_auth", "app.mentor_panel_library",
    "app.mentor_panel_media", "app.mentor_panel_reports", "app.mentor_panel_notify", "app.mentor_evaluations",
    "app.mentor_panel_handoff", "app.mentor_bastion", "app.mentor_bastion_jobs", "app.mentor_bastion_client",
    "app.mentoring", "app.proel_auth", "app.streams.store", "app.streams.worker", "app.mentor_panel_streams", "app.mentor_video_trash",
    "app.mentor_bastion_search", "app.mentor_trybuna", "app.mentor_trybuna_rules", "app.mentor_trybuna_feed", "app.mentor_trybuna_thumbs", "app.mentor_trybuna_rank", "app.mentor_trybuna_suggest",
    "app.delegate_sharing", "app.mentor_auto_found", "app.mentor_auto_found_rules",
)

PAIR = "pair-1"
JUDGES = ("101", "102")
MENTOR = "201"
ADMIN = "900"
COMMITTEE = "301"
STRANGER = "555"
PROVINCE = "ŚLĄSKIE"


def _extra_tables(metadata):
    judges = Table("province_judges", metadata, Column("judge_id", String, primary_key=True), Column("full_name", String),
                   Column("province", String), Column("photo_url", String), Column("badges", JSON))
    matches = Table("province_matches", metadata, Column("province", String, primary_key=True),
                    Column("match_id", String, primary_key=True), Column("season", String),
                    Column("match_at", DateTime(timezone=True)), Column("match_code", String), Column("state_json", JSON),
                    Column("active", Boolean), Column("updated_at", DateTime(timezone=True)))
    match_judges = Table("province_match_judges", metadata, Column("province", String, primary_key=True),
                         Column("match_id", String, primary_key=True), Column("judge_id", String, primary_key=True),
                         Column("active", Boolean))
    archive = Table("zprp_archive_matches", metadata, Column("province", String, primary_key=True),
                    Column("season_id", String, primary_key=True), Column("match_id", String, primary_key=True),
                    Column("code", String), Column("match_at", DateTime(timezone=True)), Column("slim_json", JSON))
    delegate = Table("delegate_evaluations", metadata, Column("id", Integer, primary_key=True, autoincrement=True),
                     Column("match_id", String), Column("season", String), Column("province", String),
                     Column("match_number", String), Column("match_date", String), Column("referee_ids", JSON),
                     Column("referee_names", JSON), Column("delegate_name", String), Column("evaluation_json", JSON))
    sharing = Table("delegate_evaluation_sharing", metadata, Column("judge_id", String, primary_key=True),
                    Column("sharing_enabled", Boolean), Column("updated_at", DateTime(timezone=True)))
    saved = Table("proel_matches", metadata, Column("match_number", String, primary_key=True), Column("zprp_match_id", String),
                  Column("data_json", JSON), Column("status", String), Column("updated_at", DateTime(timezone=True)))
    admins = Table("admin_settings", metadata, Column("id", Integer, primary_key=True), Column("allowed_admins", JSON))
    return {"province_judges": judges, "province_matches": matches, "province_match_judges": match_judges,
            "zprp_archive_matches": archive, "delegate_evaluations": delegate, "saved_matches": saved,
            "delegate_evaluation_sharing": sharing,
            "admin_settings": admins}


class Env:
    def __init__(self, monkeypatch, tmp_path):
        metadata = sqlalchemy.MetaData()
        tables = {}
        names = ("mentoring_config", "mentoring_pairs", "mentoring_members", "mentoring_assignments", "mentoring_audit")
        tables.update(zip(names, define_mentoring(metadata)))
        tables.update(zip(("mentor_evaluations", "mentor_evaluation_versions", "mentor_evaluation_requests", "mentor_match_videos"),
                          define_evaluations(metadata)))
        for table in define_panel(metadata):
            tables[table.name] = table
        for table in define_bastion(metadata):
            tables[table.name] = table
        for table in define_trybuna(metadata):
            tables[table.name] = table
        for table in define_auto_found(metadata):
            tables[table.name] = table
        for table in define_public(metadata):
            tables[table.name] = table
        for table in define_streams(metadata):
            tables[table.name] = table
        tables.update(_extra_tables(metadata))
        self.url = f"sqlite:///{tmp_path / 'mentor.db'}"
        metadata.create_all(sqlalchemy.create_engine(self.url))
        fake = types.ModuleType("app.db")
        fake.database = Database(self.url.replace("sqlite://", "sqlite+aiosqlite://"))
        fake.DATABASE_URL = self.url
        for name, table in tables.items():
            setattr(fake, name, table)
        fake.__getattr__ = lambda name: MagicMock()
        market = types.ModuleType("app.match_market")
        market.Actor = type("Actor", (), {})
        market.market_actor = lambda: None
        monkeypatch.setitem(sys.modules, "app.db", fake)
        monkeypatch.setitem(sys.modules, "app.match_market", market)
        import app as app_package

        for name in MODULES:
            monkeypatch.delitem(sys.modules, name, raising=False)
            # `from app import mentor_panel_core` bierze atrybut pakietu, jeśli jest -
            # bez tego moduły z poprzedniego testu trzymałyby starą bazę.
            parent_name, leaf = name.rsplit(".", 1)
            parent = app_package if parent_name == "app" else sys.modules.get(parent_name)
            if parent is not None:
                monkeypatch.delattr(parent, leaf, raising=False)
        self.db = fake.database
        self.T = tables
        self.panel = importlib.import_module("app.mentor_panel")
        self.core = importlib.import_module("app.mentor_panel_core")
        self.auth = importlib.import_module("app.mentor_panel_auth")
        self.library = importlib.import_module("app.mentor_panel_library")
        self.media = importlib.import_module("app.mentor_panel_media")
        self.reports = importlib.import_module("app.mentor_panel_reports")
        self.notify = importlib.import_module("app.mentor_panel_notify")
        self.bastion = importlib.import_module("app.mentor_bastion")
        self.bastion_client = importlib.import_module("app.mentor_bastion_client")
        self.bastion_jobs = importlib.import_module("app.mentor_bastion_jobs")
        self.trybuna = importlib.import_module("app.mentor_trybuna")
        self.trybuna_feed = importlib.import_module("app.mentor_trybuna_feed")
        self.trybuna_rules = importlib.import_module("app.mentor_trybuna_rules")
        self.trybuna_suggest = importlib.import_module("app.mentor_trybuna_suggest")
        self.auto_found = importlib.import_module("app.mentor_auto_found")
        self.auto_rules = importlib.import_module("app.mentor_auto_found_rules")
        self.sent = []

        async def fake_notify(ctx, actor_id, title, body, **kwargs):
            self.sent.append({"actor": actor_id, "title": title, "body": body, **kwargs})
            return {"push": None, "queued": 0}

        monkeypatch.setattr(self.notify, "notify", fake_notify)
        monkeypatch.setattr(self.auth, "_secret", lambda: "test-secret")
        self.core._match_cache.clear()
        self.core._rev_cache.clear()
        self.core._presence.clear()

    def run(self, factory, *, seed=True):
        async def go():
            await self.db.connect()
            try:
                if seed:
                    await self.seed()
                return await factory()
            finally:
                await self.db.disconnect()

        return asyncio.run(go())

    async def ins(self, table, **values):
        await self.db.execute(insert(self.T[table]).values(**values))

    async def seed(self, *, enabled=True):
        now = datetime.now(timezone.utc)
        people = [(JUDGES[0], "Anna Nowak"), (JUDGES[1], "Piotr Lis"), (MENTOR, "Jan Mentor"), (ADMIN, "Ada Admin"),
                  (COMMITTEE, "Kamil Komisja"), (STRANGER, "Obcy Sędzia")]
        for judge_id, name in people:
            badges = ["Komisja sędziowska"] if judge_id == COMMITTEE else []
            await self.ins("province_judges", judge_id=judge_id, full_name=name, province=PROVINCE, photo_url=None, badges=badges)
        await self.ins("admin_settings", id=1, allowed_admins=[ADMIN])
        await self.ins("mentoring_pairs", id=PAIR, province=PROVINCE, judge_ids=list(JUDGES), created_by=COMMITTEE,
                       program="province", created_at=now - timedelta(days=200))
        await self.ins("mentoring_assignments", pair_id=PAIR, mentor_id=MENTOR, started_at=now - timedelta(days=200),
                       show_home=True, notify=True)
        await self.ins("mentor_panels", pair_id=PAIR, enabled=enabled, rev=0, settings_json="{}", updated_at=now)
        h = {"source_hash": "h", "source_json": {}}
        await self.ins("zprp_public_clubs", club_id="c1", name="SPR Gliwice", archived=False, logo_url="https://l/c1.png", **h)
        await self.ins("zprp_public_competitions", competition_id="K1", season_id="S1", name="I liga mężczyzn", category="Seniorzy", **h)
        await self.ins("zprp_public_competitions", competition_id="K2", season_id="S1", name="Liga juniorów", category="Junior", **h)
        local = datetime.now().replace(microsecond=0)
        # m1: rozegrany (hurtownia), m2: za tydzień (hurtownia, sędziowie odwrotnie), m3 tylko w monitorze,
        # m4 tylko w archiwum, m5 inna para (nie nasz).
        await self.ins("zprp_public_matches", match_id="m1", season_id="S1", competition_id="K1", competition_name="I liga mężczyzn",
                       match_code="ISM/1", home_team_name="SPR Gliwice", away_team_name="KS Opole", home_club_id="c1",
                       scheduled_at=local - timedelta(days=3), score_home=30, score_away=28, halftime_home=15, halftime_away=14,
                       referee_1_id=JUDGES[0], referee_2_id=JUDGES[1], delegate_1_name="Delegat Dobry", **h)
        await self.ins("zprp_public_matches", match_id="m2", season_id="S1", competition_id="K2", competition_name="Liga juniorów",
                       match_code="LJ/7", home_team_name="UKS Mali", away_team_name="MKS Młodzi",
                       scheduled_at=local + timedelta(days=7), referee_1_id=JUDGES[1], referee_2_id=JUDGES[0], **h)
        await self.ins("zprp_public_matches", match_id="m5", season_id="S1", competition_id="K1", competition_name="I liga mężczyzn",
                       match_code="ISM/9", home_team_name="A", away_team_name="B", scheduled_at=local,
                       referee_1_id=JUDGES[0], referee_2_id=STRANGER, **h)
        state = {"NrSedzia_pierwszy": JUDGES[0], "NrSedzia_drugi": JUDGES[1], "RozgrywkiCode": "SL/3",
                 "ID_zespoly_gosp_ZespolNazwa": "Gospodarz", "ID_zespoly_gosc_ZespolNazwa": "Gość", "Hala_miasto": "Zabrze"}
        await self.ins("province_matches", province=PROVINCE, match_id="m3", season="2026/2027", match_at=now - timedelta(days=10),
                       match_code="SL/3", state_json=state, active=True, updated_at=now)
        for judge in JUDGES:
            await self.ins("province_match_judges", province=PROVINCE, match_id="m3", judge_id=judge, active=True)
        # m1 też w monitorze - ma się scalić z hurtownią (jeden mecz).
        await self.ins("province_matches", province=PROVINCE, match_id="m1", season="2026/2027", match_at=now - timedelta(days=3),
                       match_code="ISM/1", state_json={**state, "RozgrywkiCode": "ISM/1", "Hala_miasto": "Gliwice"}, active=True,
                       updated_at=now)
        for judge in JUDGES:
            await self.ins("province_match_judges", province=PROVINCE, match_id="m1", judge_id=judge, active=True)
        slim = {"id": "m4", "code": "SL/OLD", "home": "Stary", "away": "Mecz", "gH": 20, "gA": 21,
                "refs": {"first": JUDGES[1], "second": JUDGES[0]}, "refNames": {"delegate": "Archiwalny Delegat"}, "city": "Bytom"}
        await self.ins("zprp_archive_matches", province=PROVINCE, season_id="old", match_id="m4", code="SL/OLD",
                       match_at=now - timedelta(days=500), slim_json=slim)
        await self.ins("delegate_evaluations", match_id="m1", season="2026/2027", province=PROVINCE, match_number="ISM/1",
                       match_date=(now - timedelta(days=3)).date().isoformat(), referee_ids=list(JUDGES),
                       referee_names=["Anna Nowak", "Piotr Lis"], delegate_name="Delegat Dobry",
                       evaluation_json={"sections": [{"key": "I", "mainGrade": "D"}, {"key": "V", "mainGrade": "F"}],
                                        "keySituations": [{"time": "12:30", "category": "Błędna", "description": "Faul w ataku"}],
                                        "priorities": [{"title": "Współpraca przy linii 6 m"}]})
        await self.ins("mentor_match_videos", id="v1", match_id="m1", pair_key="|".join(sorted(JUDGES)),
                       url="https://youtu.be/abcdefghijk", normalized_url="https://youtu.be/abcdefghijk", provider="youtube",
                       added_by=JUDGES[0], created_at=now, duration_s=4000, kind="link",
                       markers_json='[{"id": "mk1", "label": "Akcja", "video_s": 100, "end_s": 130}]')

    async def actor(self, judge_id, via="jwt"):
        return await self.core.load_actor(judge_id, via=via)
