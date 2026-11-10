"""Formularze okręgowe - wiązania (bez żywej bazy): trasy, otwarte ścieżki, zakres tokenu, AASA, wydarzenia."""
from __future__ import annotations

import ast
import datetime
import pathlib

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from tests.test_optional_jwt import ALGO, REQUIRED_ENV, SECRET  # noqa: F401

ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def functions(path: str):
    text = source(path)
    tree = ast.parse(text)
    return text, {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def routes(path: str):
    """(metoda, ścieżka) z dekoratorów `@router.<metoda>("...")`."""
    tree = ast.parse(source(path))
    out = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute) and deco.args:
                arg = deco.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    out.add((deco.func.attr.upper(), arg.value))
    return out


def test_routery_zamontowane_w_main():
    main = source("main.py")
    assert "from app.district_forms import router as district_forms_router" in main
    assert "from app.district_forms_public import router as district_forms_public_router" in main
    assert "app.include_router(district_forms_router)" in main
    assert "app.include_router(district_forms_public_router)" in main


def test_tabele_i_migracje_w_db():
    db = source("app/db.py")
    assert "_define_district_forms_tables(metadata)" in db
    assert "_DISTRICT_FORMS_MIGRATIONS" in db


def test_wszystkie_trasy_kontraktu_istnieja():
    app_routes = routes("app/district_forms.py")
    expected = {
        ("GET", ""), ("GET", "/pending"), ("GET", "/templates"), ("GET", "/people"), ("POST", "/audience/preview"),
        ("POST", ""), ("GET", "/{form_id}"), ("GET", "/by-code/{code}"), ("PATCH", "/{form_id}"),
        ("POST", "/{form_id}/publish"), ("POST", "/{form_id}/close"), ("POST", "/{form_id}/reopen"),
        ("POST", "/{form_id}/archive"), ("POST", "/{form_id}/unarchive"), ("POST", "/{form_id}/restore"),
        ("DELETE", "/{form_id}"), ("POST", "/{form_id}/duplicate"), ("PUT", "/{form_id}/me"),
        ("POST", "/{form_id}/me/confirm"), ("GET", "/{form_id}/rows"), ("PATCH", "/{form_id}/rows/{judge_id}"),
        ("POST", "/{form_id}/rows/bulk"), ("GET", "/{form_id}/log"), ("GET", "/{form_id}/stats"),
        ("GET", "/{form_id}/responses"), ("GET", "/{form_id}/export"), ("POST", "/{form_id}/remind"),
        ("POST", "/{form_id}/web"), ("POST", "/{form_id}/invite-to-event"), ("POST", "/{form_id}/uploads"),
        ("GET", "/{form_id}/files/{token}"), ("POST", "/pair/{code}/approve"), ("GET", "/file/{token}"),
        ("GET", "/inbox"),
    }
    assert expected <= app_routes, expected - app_routes
    public = routes("app/district_forms_public.py")
    assert {
        ("GET", "/{code}"), ("PUT", "/{code}/rows/{judge_id}"), ("PUT", "/{code}/responses"),
        ("POST", "/{code}/qr"), ("GET", "/qr/{pair_code}"), ("GET", "/{code}/files/{token}"),
    } <= public


def test_stale_trasy_przed_zmienna_form_id():
    """`/pending`, `/templates`, `/inbox` itd. muszą stać PRZED `/{form_id}` - inaczej je połknie."""
    text = source("app/district_forms.py")
    first_var = text.index('@router.get("/{form_id}"')
    for fixed in ('"/pending"', '"/templates"', '"/people"', '"/inbox"', '"/by-code/{code}"', '"/file/{token}"'):
        assert text.index(f"@router.get({fixed}") < first_var, fixed


def test_otwarte_sciezki_webu_i_pliku():
    from app.client_key_rules import is_open_path

    for path, method in (
        ("/public/forms/ab23cd45", "GET"),
        ("/public/forms/ab23cd45/rows/12345", "PUT"),
        ("/public/forms/ab23cd45/responses", "PUT"),
        ("/public/forms/ab23cd45/qr", "POST"),
        ("/public/forms/qr/ab23cd45", "GET"),
        ("/public/forms/ab23cd45/files/0123456789abcdef", "GET"),
        ("/district-forms/file/0123456789abcdef0123456789abcdef", "GET"),
    ):
        assert is_open_path(path, method=method), path
    assert not is_open_path("/district-forms/0123456789abcdef")
    assert not is_open_path("/district-forms")
    assert not is_open_path("/public/forms/ab23cd45/rows/1/extra")


def test_aasa_zawiera_formularze():
    from app import event_links as L

    for detail in L.apple_app_site_association("TEAM")["applinks"]["details"]:
        assert {"/": "/f/*", "comment": "Formularz okręgowy i logowanie strony formularza"} in detail["components"]
        assert "/f/*" in detail["paths"]
        # Stare ścieżki zostają.
        assert detail["components"][0]["/"] == "/e/*"


@pytest.fixture()
def env(monkeypatch):
    for key, value in REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)


def _client():
    from app.deps import get_jwt_payload

    app = FastAPI()
    forms, exams = APIRouter(prefix="/district-forms"), APIRouter(prefix="/exams")

    @forms.get("/{form_id}")
    async def one(form_id: str, p: dict = Depends(get_jwt_payload)):
        return {"ok": p["sub"]}

    @exams.get("/mine")
    async def mine(p: dict = Depends(get_jwt_payload)):
        return {"ok": p["sub"]}

    app.include_router(forms)
    app.include_router(exams)
    return TestClient(app)


def test_token_form_web_dziala_tylko_pod_district_forms(env):
    from app.deps import FORM_WEB_SCOPE, scope_allows

    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    token = jwt.encode({"sub": "form-web:1", "judge_id": "1", "scope": FORM_WEB_SCOPE, "form_id": "f" * 16, "exp": exp}, SECRET, algorithm=ALGO)
    client = _client()
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/district-forms/abc", headers=headers).status_code == 200
    assert client.get("/exams/mine", headers=headers).status_code == 401
    assert FORM_WEB_SCOPE == "form-web"
    assert not scope_allows({"scope": FORM_WEB_SCOPE}, None)


def test_token_strony_ma_zakres_formularz_i_12_godzin():
    text, funcs = functions("app/district_forms_public.py")
    issue = ast.get_source_segment(text, funcs["issue_token"])
    assert '"scope": FORM_WEB_SCOPE' in issue and '"form_id": form_id' in issue
    assert "R.WEB_TOKEN_HOURS" in issue
    from app import district_forms_rules as R

    assert R.WEB_TOKEN_HOURS == 12 and R.PAIR_TTL == datetime.timedelta(minutes=5)
    router_text, router_funcs = functions("app/district_forms.py")
    who = ast.get_source_segment(router_text, router_funcs["who_dep"])
    # Token strony działa tylko dla formularza, dla którego go wydano.
    assert 'request.path_params.get("form_id")' in who and "form_web_scope" in who


def test_zapis_z_weba_zostawia_slad_i_pyta_wlasciciela():
    text, funcs = functions("app/district_forms_service.py")
    write = ast.get_source_segment(text, funcs["write_cells"])
    assert "R.web_row_refusal" in write and "R.cell_refusal" in write
    assert "with_for_update" in source("app/district_forms_service.py")
    assert "notify_web_review" in write and "await _log(" in write
    review = ast.get_source_segment(text, funcs["notify_web_review"])
    assert "R.WEB_REVIEW_DEDUP" in review and "Zaznaczono Cię przez stronę" in review
    notify = ast.get_source_segment(text, funcs["notify"])
    # Najpierw wpis w dzienniku (unikalny klucz), potem push.
    assert notify.index("on_conflict_do_nothing") < notify.index("send_push_to_judges_report")


def test_wydarzenia_czytaja_rsvp_z_formularza():
    text, funcs = functions("app/province_events.py")
    responses = ast.get_source_segment(text, funcs["_responses"])
    assert "_form_overlay" in responses and "overlay_responses" in responses
    rsvp = ast.get_source_segment(text, funcs["rsvp"])
    assert "rsvp_through_form" in rsvp
    assert rsvp.index("rsvp_through_form") < rsvp.index("pg_insert(province_event_responses)")
    sweep = ast.get_source_segment(text, funcs["sweep_event_reminders"])
    assert "linked_event_ids" in sweep and 'kind != "rsvp"' in sweep
    loop = ast.get_source_segment(text, funcs["run_event_reminder_sweep"])
    assert "sweep_district_forms" in loop
    for name in ("feed", "item"):
        assert "form=_form_summary(" in ast.get_source_segment(text, funcs[name])
    view = ast.get_source_segment(text, funcs["_view"])
    assert '"form": form' in view


def test_moduly_regul_nie_lacza_sie_z_baza():
    for path in ("app/district_forms_rules.py", "app/district_form_schema.py", "app/district_form_templates.py",
                 "app/district_forms_tables.py"):
        assert "app.db" not in source(path), path


def test_tryb_cichy_kolumna_trasa_i_jedna_bramka_wysylki():
    tables = source("app/district_forms_tables.py")
    assert 'Column("silent", Boolean' in tables
    assert "ADD COLUMN IF NOT EXISTS silent BOOLEAN" in tables
    assert ("POST", "/{form_id}/silent") in routes("app/district_forms.py")
    service, fns = functions("app/district_forms_service.py")
    notify_src = ast.get_source_segment(service, fns["notify"])
    # Bramka przed dziennikiem: wyciszony push nie zjada slotu publikacji.
    assert notify_src.index("R.pushes_muted(form)") < notify_src.index("pg_insert(NOTES)")
    assert "FORMS.c.silent" in ast.get_source_segment(service, fns["sweep_district_forms"])
    # Wszystkie pushe list idą przez `notify` (bez bezpośredniego send_push poza nim).
    assert service.count("send_push_to_judges_report(") == 1
    api, api_fns = functions("app/district_forms.py")
    assert 'ctx.form.get("silent")' in ast.get_source_segment(api, api_fns["remind"])
    assert "send_push" not in api


def test_strona_www_dziala_w_szkicu():
    public, fns = functions("app/district_forms_public.py")
    assert "published_at" not in ast.get_source_segment(public, fns["_form_by_code"])


def test_usuniecie_odpowiedzi_trasa_historia_i_rsvp():
    assert ("POST", "/{form_id}/rows/{judge_id}/clear") in routes("app/district_forms.py")
    service, fns = functions("app/district_forms_service.py")
    clear = ast.get_source_segment(service, fns["clear_entry"])
    assert "_log(" in clear and "mirror_rsvp(" in clear and "cleared_entry_values" in clear
    assert "notify" not in clear
