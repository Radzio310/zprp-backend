"""Przepływ raport -> konfiguracja -> wysyłka. Izolowana SQLite w pamięci.

Import app.db zastępujemy lokalnym modułem, bo prawdziwy robi create_all na
produkcyjnym DATABASE_URL. Transport Discord i API ZPRP są zawsze atrapami.
"""
import base64
import sys
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import Column, DateTime, Integer, JSON, MetaData, String, Table, create_engine

from app import extra_reports as reports
from app.proel_auth import Actor

URL = "https://discord.com/api/webhooks/123456/test_token"
ACTOR = Actor(judge_id="12", installation_id="test", name="Jan Test", verified=True)


@pytest.fixture
def report_db(monkeypatch):
    metadata = MetaData()
    groups = Table("extra_report_recipients", metadata,
        Column("id", Integer, primary_key=True), Column("name", String),
        Column("categories", JSON), Column("emails", JSON), Column("order_index", Integer),
        Column("discord_webhook_url", String), Column("updated_at", DateTime(timezone=True)),
    )
    provinces = Table("extra_report_province_recipients", metadata,
        Column("province", String, primary_key=True), Column("emails", JSON),
        Column("discord_webhook_url", String), Column("updated_at", DateTime(timezone=True)),
    )
    docs = Table("extra_reports", metadata,
        Column("id", Integer, primary_key=True), Column("match_key", String), Column("kind", String),
        Column("entries", JSON), Column("match_number", String), Column("zprp_match_id", String),
        Column("generated_by", String), Column("generated_by_name", String),
        Column("generated_at", DateTime(timezone=True)),
    )
    engine = create_engine("sqlite://")
    metadata.create_all(engine)
    conn = engine.connect()

    class Database:
        async def fetch_all(self, query):
            return list(conn.execute(query).mappings())

        async def fetch_one(self, query):
            return conn.execute(query).mappings().first()

        async def execute(self, query):
            conn.execute(query)

        @asynccontextmanager
        async def transaction(self):
            with conn.begin_nested():
                yield

    module = SimpleNamespace(database=Database(), extra_reports=docs,
        extra_report_recipients=groups, extra_report_province_recipients=provinces)
    monkeypatch.setitem(sys.modules, "app.db", module)
    monkeypatch.setattr(reports, "is_admin", AsyncMock(return_value=True))
    monkeypatch.setattr(reports, "fetch_match_province", AsyncMock(return_value="SLASKIE"))
    monkeypatch.setattr(reports, "build_extra_report_pdf", lambda **kwargs: b"%PDF-test")
    monkeypatch.setattr(reports, "stash_for_download", lambda pdf: "test-token")
    # Zabronione prawdziwe wywołanie Discord w każdym teście tego przepływu.
    monkeypatch.setattr(reports, "send_report_copies", AsyncMock(return_value={"status": "sent", "deliveries": []}))
    yield module
    conn.close()
    engine.dispose()


async def seed(report_db):
    await report_db.database.execute(report_db.extra_report_recipients.insert().values(
        name="II liga", categories=["IIM"], emails=["league@test.pl"],
        discord_webhook_url=URL, order_index=0,
    ))
    for province in ["SLASKIE", "MALOPOLSKIE"]:
        await report_db.database.execute(report_db.extra_report_province_recipients.insert().values(
            province=province, emails=[province.lower() + "@test.pl"],
            discord_webhook_url=URL + "_" + province,
        ))
    await report_db.database.execute(report_db.extra_reports.insert().values(
        match_key="321", kind="referees", entries=[{"text": "Raport zapisany"}],
        match_number="IIM4/1", zprp_match_id="321",
    ))


async def test_public_recipients_merge_emails_but_never_expose_webhooks(report_db):
    await seed(report_db)
    result = await reports.recipients_for_category("IIM", "321")
    assert result["emails"] == ["league@test.pl", "slaskie@test.pl"]
    assert result["discordDestinations"] == ["II liga", "SLASKIE"]
    assert result["province"] == "SLASKIE"
    assert "test_token" not in str(result)
    assert "_discordTargets" not in result
    central = await reports.recipients_for_category("OSM", "321")
    assert central["discordDestinations"] == []
    assert central["province"] == ""
    reports.fetch_match_province.assert_awaited_once_with("321")


async def test_generate_sends_exact_pdf_to_group_and_correct_province(report_db):
    await seed(report_db)
    result = await reports.generate_pdf("321", "referees", reports.GeneratePdfBody(
        category="IIM", zprpMatchId="999", names=["Jan Test"], teams=["A", "B"],
    ), ACTOR)
    assert base64.b64decode(result["pdfBase64"]) == b"%PDF-test"
    assert result["discord"]["status"] == "sent"
    args = reports.send_report_copies.call_args.kwargs
    assert args["pdf"] == b"%PDF-test"
    assert [t["name"] for t in args["targets"]] == ["II liga", "SLASKIE"]
    reports.fetch_match_province.assert_awaited_once_with("321")  # zapisany ID, nie podsunięty


@pytest.mark.parametrize("body", [
    reports.GeneratePdfBody(category="IIM", localOnly=True),
    reports.GeneratePdfBody(category="IIM", entries=[{"text": "Test"}]),
    reports.GeneratePdfBody(),  # starszy klient bez kategorii
])
async def test_test_reports_and_older_clients_never_dispatch(report_db, body):
    await seed(report_db)
    result = await reports.generate_pdf("321", "referees", body, ACTOR)
    assert result["discord"]["status"] == "skipped"
    reports.send_report_copies.assert_not_called()


async def test_inline_without_saved_report_never_dispatches(report_db):
    result = await reports.generate_pdf("n:TEST-1", "referees", reports.GeneratePdfBody(
        category="IIM", entries=[{"text": "Test"}],
    ), ACTOR)
    assert result["pdfBase64"]
    reports.send_report_copies.assert_not_called()


async def test_dispatch_failure_does_not_lose_generated_pdf(report_db):
    await seed(report_db)
    reports.send_report_copies.side_effect = RuntimeError(URL)
    result = await reports.generate_pdf("321", "referees", reports.GeneratePdfBody(category="IIM"), ACTOR)
    assert result["pdfBase64"]
    assert result["downloadUrl"]
    assert result["discord"]["status"] == "failed"
    assert "test_token" not in str(result)


async def test_unknown_province_is_not_guessed_and_warns_only_if_configured(report_db):
    reports.fetch_match_province.return_value = ""
    empty = await reports._resolve_recipients("IIM", "321")
    assert empty["discordProvinceUnresolved"] is False
    await seed(report_db)
    result = await reports.generate_pdf("321", "referees", reports.GeneratePdfBody(category="IIM"), ACTOR)
    assert "Nie ustalono okręgu" in result["discord"]["warning"]
    assert [t["name"] for t in reports.send_report_copies.call_args.kwargs["targets"]] == ["II liga"]


async def test_admin_saves_discord_only_groups_and_preserves_older_payloads(report_db):
    saved = await reports.save_recipients(reports.RecipientGroups(groups=[reports.RecipientGroup(
        name="Liga", categories=["OSM"], emails=[], discordWebhookUrl=URL,
    )]), ACTOR)
    assert saved.groups[0].discordWebhookUrl == URL
    older = reports.RecipientGroup(id=saved.groups[0].id, name="Liga", categories=["OSM"], emails=["a@test.pl"])
    again = await reports.save_recipients(reports.RecipientGroups(groups=[older]), ACTOR)
    assert again.groups[0].discordWebhookUrl == URL
    again.groups[0].discordWebhookUrl = ""
    cleared = await reports.save_recipients(again, ACTOR)
    assert cleared.groups[0].discordWebhookUrl == ""


async def test_admin_saves_province_without_email_and_requires_explicit_clear(report_db):
    body = reports.ProvinceRecipientList(provinces=[reports.ProvinceRecipients(
        province="ŚLĄSKIE", emails=[], discordWebhookUrl=URL,
    )])
    saved = await reports.save_province_recipients(body, ACTOR)
    assert saved.provinces[0].province == "SLASKIE"
    assert saved.provinces[0].discordWebhookUrl == URL
    older = await reports.save_province_recipients(reports.ProvinceRecipientList(), ACTOR)
    assert older.provinces[0].discordWebhookUrl == URL
    saved.provinces[0].discordWebhookUrl = ""
    cleared = await reports.save_province_recipients(saved, ACTOR)
    assert cleared.provinces == []


async def test_non_admin_cannot_read_or_change_secrets(report_db):
    reports.is_admin.return_value = False
    for call in [
        lambda: reports.list_recipients(ACTOR),
        lambda: reports.list_province_recipients(ACTOR),
        lambda: reports.save_recipients(reports.RecipientGroups(), ACTOR),
        lambda: reports.save_province_recipients(reports.ProvinceRecipientList(), ACTOR),
    ]:
        with pytest.raises(HTTPException) as error:
            await call()
        assert error.value.status_code == 403


async def test_invalid_webhook_cannot_erase_existing_configuration(report_db):
    await seed(report_db)
    with pytest.raises(HTTPException) as error:
        await reports.save_recipients(reports.RecipientGroups(groups=[reports.RecipientGroup(
            name="Bad", discordWebhookUrl="http://localhost/private",
        )]), ACTOR)
    assert error.value.status_code == 422
    assert (await reports.list_recipients(ACTOR)).groups[0].name == "II liga"
