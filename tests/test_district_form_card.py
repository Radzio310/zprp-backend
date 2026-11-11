"""Formularze okręgowe - podgląd linku (§19): karta 1200×630, znaczniki Open Graph, otwarte trasy."""
from __future__ import annotations

import ast
import io
import pathlib
from datetime import datetime, timedelta, timezone

import pytest
from PIL import Image

from app import district_form_card as C
from app import district_form_share as SH

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def _jpeg(data: bytes) -> Image.Image:
    img = Image.open(io.BytesIO(data))
    assert img.format == "JPEG"
    assert img.size == (1200, 630)
    return img


def _photo(color=(200, 120, 60), size=(800, 500)) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", size, color).save(out, "PNG")
    return out.getvalue()


def _form(**extra):
    form = {
        "id": "f" * 16, "kind": "list", "title": "Turniej Żaków – obsada", "description": "Zgłoś dyspozycyjność.",
        "cover_json": {"tone": "red", "emoji": "🏐"}, "closes_at": NOW + timedelta(days=28),
        "published_at": NOW - timedelta(days=1), "closed_at": None, "archived_at": None, "deleted_at": None,
        "web_enabled": True, "province": "SLASKIE",
    }
    form.update(extra)
    return form


@pytest.fixture(autouse=True)
def _clean_cache():
    C._CACHE.clear()
    C._STANDIN.clear()
    yield
    C._CACHE.clear()
    C._STANDIN.clear()


# ---------------------------------------------------------------------------
# Karta
# ---------------------------------------------------------------------------


def test_karta_w_barwie_ma_rozmiar_i_format():
    card = SH.form_card(_form(), province_label="Śląskie", now=NOW)
    _jpeg(C.render(card))


@pytest.mark.parametrize("tone", ["gold", "red", "blue", "green", "violet", "slate", "nieznany"])
def test_kazdy_ton_i_bez_emoji(tone):
    _jpeg(C.render(C.CardData(title="Ankieta po sezonie", kind="form", meta="Formularz · Śląskie", tone=tone)))


def test_karta_okladki_z_grafika_jest_pelna():
    card = C.CardData(title="Zgłoszenia", meta="Lista deklaracji · Śląskie", status="Zapisy do pt. 5 grudnia, 23:59",
                      cta=SH.CTA_APP, photo="/static/x.png:1:2")
    jpeg, full = C._render(card, _photo())
    assert full
    _jpeg(jpeg)
    # Grafika jest widoczna: karta okładki nie jest kartą w barwie.
    assert jpeg != C.render(C.CardData(**{**card.__dict__, "photo": None}))


def test_zepsuta_grafika_daje_karte_w_barwie_tylko_na_chwile():
    card = C.CardData(title="Zgłoszenia", photo="https://example.test/x.png")
    jpeg = C.card_jpeg(card, b"to nie jest obraz")
    _jpeg(jpeg)
    assert C.version(card) not in C._CACHE  # pełna pamięć tylko dla pełnej karty
    assert C.cached(card) == jpeg  # seria pytań komunikatora dostaje to samo bez pobierania
    C._STANDIN[C.version(card)] = (0.0, jpeg)
    assert C.cached(card) is None  # po minucie - znowu próba z grafiką


def test_grafika_bez_pobrania_tez_daje_karte():
    card = C.CardData(title="Zgłoszenia", photo="https://example.test/x.png")
    jpeg, full = C._render(card, None)
    assert not full
    _jpeg(jpeg)


def test_karta_marki_dla_nieznanego_kodu():
    jpeg, full = C._render(SH.brand_card(), None)
    assert full
    _jpeg(jpeg)


def test_karta_wycofanego_linku_mowi_co_dalej():
    card = SH.retired_card()
    assert card.brand and card.title == SH.RETIRED_TITLE and "nowy link" in card.meta
    assert SH.version(card) != SH.version(SH.brand_card()) if hasattr(SH, "version") else True
    jpeg, full = C._render(card, None)
    assert full
    _jpeg(jpeg)


def test_pamiec_lru_ma_limit():
    for i in range(C.CACHE_MAX + 5):
        C._CACHE[f"k{i}"] = b"x"
    C.card_jpeg(C.CardData(title="Nowa"))
    assert len(C._CACHE) == C.CACHE_MAX
    assert "k0" not in C._CACHE


def test_emoji_bez_kroju_rysuje_znak_rodzaju(monkeypatch):
    monkeypatch.setattr(C, "_EMOJI_FONTS", ())
    C._emoji_image.cache_clear()
    try:
        assert C._emoji_image("🏐") is None
        _jpeg(C.render(C.CardData(title="Lista", emoji="🏐", kind="list")))
        _jpeg(C.render(C.CardData(title="Formularz", emoji="🏐", kind="form", photo="p"), _photo()))
    finally:
        C._emoji_image.cache_clear()


def test_wersja_zmienia_sie_z_trescia():
    a = C.CardData(title="A")
    assert C.version(a) == C.version(C.CardData(title="A"))
    assert C.version(a) != C.version(C.CardData(title="B"))
    assert C.version(a) != C.version(C.CardData(title="A", photo="/static/a.png:1:1"))
    assert len(C.version(a)) == 12


# ---------------------------------------------------------------------------
# Tekst: polskie znaki, łamanie, wielokropek
# ---------------------------------------------------------------------------


def test_fontastique_ma_polskie_litery_a_brak_znaku_daje_geist():
    assert C.display_covers("Zażółć gęślą jaźń – ĄĆĘŁŃÓŚŹŻ")
    assert not C.display_covers("Zebranie #3")
    assert C._title_font("Zebranie #3", 60).path.endswith("Geist-Bold.ttf")
    assert C._title_font("Zebranie nr 3", 60).path.endswith("FontastiquePL.ttf")


def test_dlugi_tytul_najwyzej_trzy_linie_z_wielokropkiem():
    title = ("Bardzo długi tytuł listy deklaracji na turniej międzywojewódzki młodzików i juniorów "
             "młodszych w Gliwicach oraz w Zabrzu – edycja zimowa 2026/2027 z dodatkowymi meczami")
    font, lines, size = C.fit_title(title, (72, 60, 48), 640, 3)
    assert size == 48 and len(lines) == 3
    assert lines[-1].endswith("…")
    assert all(font.getlength(line) <= 640 * C._S for line in lines)
    # Bez wiszącego jednoliterowego słowa przed wielokropkiem.
    assert not lines[-1][:-1].split()[-1].isalpha() or len(lines[-1][:-1].split()[-1]) > 1


def test_krotki_tytul_bierze_najwiekszy_rozmiar():
    _font, lines, size = C.fit_title("Szkolenie", (72, 60, 48), 640, 3)
    assert size == 72 and lines == ["Szkolenie"]


def test_sierotki_jada_z_nastepnym_slowem_i_dlugie_slowo_sie_lamie():
    assert C._words("Turniej w Gliwicach i Zabrzu") == ["Turniej", "w Gliwicach", "i Zabrzu"]
    font = C._geist("Bold", 40)
    lines, fits = C.wrap("Konstantynopolitańczykowianeczka", font, 200 * C._S, 3)
    assert not fits and all(font.getlength(x) <= 200 * C._S for x in lines)


# ---------------------------------------------------------------------------
# Dane karty i opis
# ---------------------------------------------------------------------------


def test_termin_po_polsku_z_dniem_tygodnia():
    closes = datetime(2026, 12, 9, 22, 59, tzinfo=timezone.utc)  # 23:59 w Warszawie
    assert SH.deadline_label("list", closes, NOW) == "Zapisy do śr. 9 grudnia, 23:59"
    assert SH.deadline_label("form", closes, NOW).startswith("Odpowiedzi do śr. 9 grudnia")
    assert SH.deadline_label("list", datetime(2027, 1, 5, 11, 0, tzinfo=timezone.utc), NOW) == "Zapisy do wt. 5 stycznia 2027, 12:00"
    assert SH.deadline_label("list", None, NOW) == ""


def test_karta_formularza_otwartego_zamknietego_i_bez_weba():
    card = SH.form_card(_form(), province_label="Śląskie", now=NOW)
    assert card.meta == "Lista deklaracji · Śląskie"
    assert card.status.startswith("Zapisy do ") and not card.closed
    assert card.cta == SH.CTA_WEB and card.tone == "red" and card.emoji == "🏐"
    closed = SH.form_card(_form(closed_at=NOW), province_label="Śląskie", now=NOW)
    assert closed.closed and closed.status == "Zamknięte" and closed.cta == ""
    past = SH.form_card(_form(closes_at=NOW - timedelta(minutes=1)), province_label="", now=NOW)
    assert past.closed and past.meta == "Lista deklaracji"
    app_only = SH.form_card(_form(web_enabled=False, kind="form", cover_json={"tone": "zly"}), province_label="Opolskie", now=NOW)
    assert app_only.cta == SH.CTA_APP and app_only.tone == "gold" and app_only.emoji is None
    assert app_only.meta == "Formularz · Opolskie"


def test_opis_bez_weba_nie_zdradza_opisu_formularza():
    form = _form(web_enabled=False, description="Tajny opis komisji")
    card = SH.form_card(form, province_label="Śląskie", now=NOW)
    desc = SH.description(form, card)
    assert "Tajny" not in desc and "Odpowiedz w aplikacji BAZA" in desc
    assert desc.startswith("Lista deklaracji · Śląskie. Zapisy do ")
    web = _form(description="Słowo " * 80)
    web_desc = SH.description(web, SH.form_card(web, province_label="Śląskie", now=NOW))
    assert web_desc.endswith("….") and len(web_desc) < 260
    closed = _form(closed_at=NOW)
    assert "Zapisy są zamknięte" in SH.description(closed, SH.form_card(closed, province_label="", now=NOW))


def test_grafika_wydarzenia_tylko_static_albo_https():
    assert SH.event_photo_url({"data_json": {"title_image": {"url": "/static/province-events/title-images/a.png"}}})
    assert SH.event_photo_url({"data_json": '{"title_image": {"url": "https://cdn.example/a.png"}}'})
    assert SH.event_photo_url({"data_json": {"title_image": {"url": "http://10.0.0.1/a.png"}}}) is None
    assert SH.event_photo_url(None) is None


# ---------------------------------------------------------------------------
# Strona dla czytników kart
# ---------------------------------------------------------------------------


def test_strona_ma_komplet_znacznikow_i_poprawne_adresy(monkeypatch):
    monkeypatch.delenv("PUBLIC_API_HOST", raising=False)
    form = _form(title='Lista "<b>Żaków</b>" & spółka')
    card = SH.form_card(form, province_label="Śląskie", now=NOW)
    html = SH.page("jjy4ep7m", card, SH.description(form, card))
    image = f"https://api.bazapodreka.app/public/forms/jjy4ep7m/card.jpg?v={C.version(card)}"
    assert f'<meta property="og:image" content="{image}">' in html
    assert '<meta property="og:url" content="https://www.bazapodreka.app/f/jjy4ep7m">' in html
    for tag in ('property="og:title"', 'property="og:description"', 'property="og:image:width" content="1200"',
                'property="og:image:height" content="630"', 'property="og:image:type" content="image/jpeg"',
                'property="og:image:alt"', 'property="og:site_name" content="BAZA"', 'property="og:locale" content="pl_PL"',
                'name="twitter:card" content="summary_large_image"', 'name="twitter:image"', 'name="theme-color"'):
        assert tag in html, tag
    assert '<html lang="pl">' in html
    assert "<b>Żaków</b>" not in html and "&lt;b&gt;Żaków&lt;/b&gt;" in html and "&quot;" in html and "&amp; spółka" in html
    # Bez przekierowania i bez skryptów - robot czyta te znaczniki, człowiek klika link.
    assert "http-equiv" not in html and "<script" not in html
    assert 'href="https://www.bazapodreka.app/f/jjy4ep7m"' in html


def test_adres_api_z_env_i_kod_w_adresie_zakodowany(monkeypatch):
    monkeypatch.setenv("PUBLIC_API_HOST", "api.example.test/")
    card = SH.brand_card()
    assert SH.card_url("a/b c", card).startswith("https://api.example.test/public/forms/a%2Fb%20c/card.jpg?v=")
    assert SH.page_url('x"><script>') == "https://www.bazapodreka.app/f/x%22%3E%3Cscript%3E"
    html = SH.page('x"><script>', card, SH.BRAND_DESCRIPTION)
    assert "<script" not in html


def test_plik_static_nie_wychodzi_poza_katalog(tmp_path, monkeypatch):
    monkeypatch.setenv("RAILWAY_VOLUME_MOUNT_PATH", str(tmp_path))
    (tmp_path / "static" / "province-events").mkdir(parents=True)
    pic = tmp_path / "static" / "province-events" / "a.png"
    pic.write_bytes(_photo())
    (tmp_path / "sekret.txt").write_text("x")
    assert C.static_file("/static/province-events/a.png") == pic.resolve()
    assert C.photo_key("/static/province-events/a.png").startswith("/static/province-events/a.png:")
    assert C.static_file("/static/../sekret.txt") is None
    assert C.static_file("/static/province-events/brak.png") is None
    assert C.photo_key("/static/province-events/brak.png") is None
    assert C.photo_key("https://cdn.example/a.png") == "https://cdn.example/a.png"
    assert C.photo_key("http://cdn.example/a.png") is None


async def test_grafika_z_dysku_trafia_na_karte(tmp_path, monkeypatch):
    monkeypatch.setenv("RAILWAY_VOLUME_MOUNT_PATH", str(tmp_path))
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "a.png").write_bytes(_photo())
    assert await C.photo_bytes("/static/a.png") == (tmp_path / "static" / "a.png").read_bytes()
    assert await C.photo_bytes("/static/brak.png") is None
    assert await C.photo_bytes("ftp://x/a.png") is None


# ---------------------------------------------------------------------------
# Wiązania: trasy, otwarte ścieżki, odpowiedź HTTP
# ---------------------------------------------------------------------------


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_trasy_podgladu_istnieja_i_przyjmuja_head():
    tree = ast.parse(_source("app/district_forms_public.py"))
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            for deco in node.decorator_list:
                if isinstance(deco, ast.Call) and getattr(deco.func, "attr", "") == "api_route":
                    methods = next(k.value for k in deco.keywords if k.arg == "methods")
                    found[deco.args[0].value] = {e.value for e in methods.elts}
    assert found["/{code}/card.jpg"] == {"GET", "HEAD"}
    assert found["/{code}/share"] == {"GET", "HEAD"}


def test_trasy_podgladu_sa_otwarte_bez_klucza():
    from app.client_key_rules import is_open_path

    for method in ("GET", "HEAD"):
        assert is_open_path("/public/forms/jjy4ep7m/share", method=method)
        assert is_open_path("/public/forms/jjy4ep7m/card.jpg", method=method)
    assert not is_open_path("/public/forms/jjy4ep7m/share/extra")
    assert not is_open_path("/public/forms/jjy4ep7m/cardXjpg")


async def test_nieznany_kod_daje_karte_marki_a_znany_karte_formularza():
    """`_share_target` wykonany na podmienionych zależnościach (bez bazy)."""
    from app import district_forms_rules as R

    text = _source("app/district_forms_public.py")
    fn = next(n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.AsyncFunctionDef) and n.name == "_share_target")
    forms = {"jjy4ep7m": _form(event_id=7)}

    async def _form_by_code(code):
        if code not in forms:
            raise R.not_found()
        return forms[code]

    class S:  # noqa: N801
        @staticmethod
        async def events_by_id(ids):
            return {7: {"data_json": {"title_image": {"url": "https://cdn.example/a.png"}}}}

        @staticmethod
        def now():
            return NOW

    ns = {"R": R, "S": S, "SHARE": SH, "CARD": C, "_form_by_code": _form_by_code, "display": lambda p: "ŚLĄSKIE"}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "share", "exec"), ns)  # noqa: S102
    form, card, photo = await ns["_share_target"]("zz")
    assert form is None and card.brand and photo is None
    form, card, photo = await ns["_share_target"]("jjy4ep7m")
    assert form is forms["jjy4ep7m"] and card.title == "Turniej Żaków – obsada"
    assert card.meta == "Lista deklaracji · Śląskie" and photo == "https://cdn.example/a.png" == card.photo


def test_odpowiedz_obrazka_ma_typ_i_pamiec():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()

    @app.get("/card.jpg")
    async def card():
        return await C.respond(C.CardData(title="Zgłoszenia", meta="Lista deklaracji · Śląskie"), None)

    response = TestClient(app).get("/card.jpg")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.headers["cache-control"] == "public, max-age=86400"
    _jpeg(response.content)
