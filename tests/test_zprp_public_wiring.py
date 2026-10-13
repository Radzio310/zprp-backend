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

