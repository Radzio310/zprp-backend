from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_public_handball_router_and_scheduler_are_wired():
    main = (ROOT / "main.py").read_text(encoding="utf-8")

    assert "app.include_router(handball_public_router)" in main
    assert "app.include_router(handball_sync_admin_router)" in main
    assert "run_zprp_public_scheduler" in main
    assert "_zprp_public_sync_task.cancel()" in main


def test_public_tables_are_registered_before_create_all():
    db_source = (ROOT / "app" / "db.py").read_text(encoding="utf-8")

    registration = db_source.index("_define_zprp_public_tables(metadata)")
    create_all = db_source.index("metadata.create_all(engine)")
    assert registration < create_all


def test_public_portal_overview_is_exposed_as_single_startup_payload():
    api_source = (ROOT / "app" / "zprp_public" / "api.py").read_text(encoding="utf-8")

    assert '@router.get("/portal/overview")' in api_source
    assert '"freshness"' in api_source
    assert '"today"' in api_source
    assert '"leaders"' in api_source
    assert "source_json" not in api_source[api_source.index("async def portal_overview"):api_source.index('@router.get("/seasons")')]

