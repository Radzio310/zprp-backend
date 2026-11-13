"""Flagi reprezentacji na planszach filmu i klipu (13.11.2026): te same zasady co aplikacja (`utils/countries-test.ts`)."""

import asyncio
import io

import pytest
from PIL import Image

from app import mentor_clip_card as K
from app import mentor_montage_cards as MC
from app import team_flags as F

POLSKA = ['Polska', 'POLSKA', 'polska', '  Polska  ', 'Polska U-21', 'Polska U21', 'Polska U 21', 'Polska K', 'Polska M', 'Polska B', 'Polska (K)', 'Polska - K', 'Polska K U-21', 'Polska U-18 M', 'Polska Kobiety', 'Polska do lat 19', 'Reprezentacja Polski', 'REPREZENTACJA POLSKI', 'Reprezentacja Polski K', 'Reprezentacja Polski U-21', 'Reprezentacja Polski Kobiet', 'Reprezentacja Polska', 'Młodzieżowa reprezentacja Polski', 'Kadra Polski', 'Poland', 'POLAND', 'Poland U-21', 'Poland Women', 'Poland National Team']
PAIRS = [('Słowenia', 'si'), ('Slowenia', 'si'), ('SŁOWENIA U-20', 'si'), ('Slovenia', 'si'), ('Reprezentacja Słowenii', 'si'), ('Reprezentacja Slowenii', 'si'), ('Węgry', 'hu'), ('Wegry K', 'hu'), ('Czarnogora', 'me'), ('Reprezentacja Niemiec', 'de'), ('Niemcy U-19', 'de'), ('Germany', 'de'), ('Bośnia i Hercegowina', 'ba'), ('Bosnia & Herzegovina', 'ba'), ('Macedonia Północna', 'mk'), ('Macedonia', 'mk'), ('Türkiye', 'tr'), ('Turkiye', 'tr'), ('USA', 'us'), ('Korea Południowa K', 'kr'), ('Wyspy Owcze U-18', 'fo'), ('Portugalia', 'pt')]
CLUBS = ['Polonia Warszawa', 'Polonia', 'Słowenia Team Kielce', 'Czarni Polska Cerekiew', 'Polska Cerekiew', 'Portugalia Handball Club', 'Poland HC', 'MKS Polska', 'UKS Polska 2', 'Polanie', 'Polski', 'Niemiec', 'Polska Azoty', 'Azoty Polska', 'Reprezentacja Śląska', 'Reprezentacja', 'Kadra', 'U-21', 'K', 'KS Austria', 'Austria Wien', 'Kuba Team', 'Industria Kielce', '']


@pytest.mark.parametrize("name", POLSKA)
def test_nazwy_polski_daja_flage(name):
    assert F.flag_iso(name) == "pl"


@pytest.mark.parametrize("name,iso", PAIRS)
def test_inne_reprezentacje(name, iso):
    assert F.flag_iso(name) == iso


@pytest.mark.parametrize("name", CLUBS)
def test_kluby_bez_flagi(name):
    assert F.flag_iso(name) is None and F.team_flag(name) is None


def test_kazdy_kraj_ma_plik_i_trzy_nazwy():
    isos = [c[0] for c in F.COUNTRIES]
    assert len(set(isos)) == len(isos) >= 60
    for iso, pl, en, genitive, _aliases in F.COUNTRIES:
        assert F.flag_png(iso) is not None and F.flag_png(iso).iso == iso
        assert F.flag_iso(pl) == F.flag_iso(en) == F.flag_iso(f"Reprezentacja {genitive}") == iso
    assert F.flag_png("zz") is None and F.flag_png("../x") is None and F.flag_iso(None) is None


def _px(img, x, y):
    return img.convert("RGBA").getpixel((int(x), int(y)))


def test_flaga_wypelnia_ksztalt_a_rogi_sa_przezroczyste():
    tile = K.flag_tile(F.team_flag("Polska"), 120, 120, 60)
    assert tile.size == (120, 120)
    assert _px(tile, 2, 2)[3] == 0  # koło: róg pusty
    top, bottom = _px(tile, 60, 35), _px(tile, 60, 90)
    assert min(top[:3]) > 225 and top[3] == 255  # biel z połyskiem, nie przemalowana
    assert bottom[0] > 170 and bottom[1] < 60 and bottom[2] < 90  # czerwień
    assert K.flag_tile(b"zly plik", 50, 50, 25) is None


def test_flaga_na_kamyku_medalionie_i_planszy_klipu():
    flag = F.team_flag("Słowenia")
    stone = MC.stone(flag, "Słowenia", None, 200, 1.0)
    cx = stone.width / 2
    assert _px(stone, cx, stone.height / 2 + 60)[0] > 150  # czerwony pas na dole kamyka, nie ciemna tarcza
    medal = MC.medallion(flag, "Słowenia", "#0000bf", 240, 1.0)
    mid = _px(medal, medal.width / 2, medal.height / 2 + 30)
    assert mid[2] > 120 and mid[0] < 80  # niebieski pas flagi w środku medalionu
    crest = K.crest_or_flag(flag, "Słowenia", None, 160)
    assert crest.size == (int(160 * 0.86), int(160 * 0.86))
    # Klub bez logo dalej ma tarczę z inicjałami.
    assert K.crest_or_flag(None, "KS Azoty-Puławy", None, 160).size != crest.size


def test_okladka_i_rozdzial_z_flagami_mieszcza_sie_w_kadrze():
    pl, si = F.team_flag("Polska"), F.team_flag("Słowenia")
    match = {"home": "Polska", "away": "Słowenia", "code": "EHF/1", "code_color": "#555", "date": "06.11.2026",
             "crests": {"home": pl, "away": si}, "colors": {}}
    cover = MC.compose_cover(MC.cover_data("Obszar kołowego", "", [match], 3, 42, [0, 0, 0], [None] * 3), 1280, 720)
    assert MC.flatten(cover).size == (1280, 720)
    chapter = MC.compose_chapter({**match, "clips": 3, "number": 1, "total": 1}, 1280, 720)
    assert MC.flatten(chapter).size == (1280, 720)


@pytest.fixture
def DL(monkeypatch, tmp_path):
    from tests.mentor_panel_support import Env

    return Env(monkeypatch, tmp_path).download


def test_karta_meczu_bez_logo_daje_flagi_i_barwy(DL):
    crests, colors = asyncio.run(DL.card_assets({"home": "Polska", "away": "Reprezentacja Słowenii", "home_logo": None, "away_logo": ""}))
    assert F.is_flag(crests["home"]) and crests["home"].iso == "pl"
    assert F.is_flag(crests["away"]) and crests["away"].iso == "si"
    assert colors["home"] and colors["away"] and colors["home"] != colors["away"]
    assert DL.flag_marks(crests) == {"away": "si", "home": "pl"}
    assert DL.flag_marks({"home": b"logo", "away": None}) == {}


def test_logo_klubu_ma_pierwszenstwo_a_niewczytane_logo_reprezentacji_daje_flage(DL, monkeypatch):
    logo = io.BytesIO()
    Image.new("RGBA", (64, 64), (0, 120, 60, 255)).save(logo, "PNG")

    async def fake_asset(url):
        return (logo.getvalue(), "#00783c") if url == "https://ok/logo.png" else (None, None)

    monkeypatch.setattr(DL, "crest_asset", fake_asset)
    crests, _ = asyncio.run(DL.card_assets({"home": "Polska", "away": "Słowenia", "home_logo": "https://ok/logo.png",
                                             "away_logo": "https://zly/logo.png"}))
    assert not F.is_flag(crests["home"]) and crests["home"] == logo.getvalue()
    assert F.is_flag(crests["away"])


def test_flaga_w_podpisie_planszy_a_kluby_bez_zmian(monkeypatch, tmp_path):
    """Bajtów herbów nie ma w podpisach: bez znacznika flagi stara okładka z tarczą „P” wróciłaby z pamięci podręcznej."""
    from tests.mentor_panel_support import Env

    env = Env(monkeypatch, tmp_path)
    montage = env.montage
    match = {"home": "Polska", "away": "Słowenia", "code": "EHF/1", "date": "2026-11-06"}
    with_flags = montage._match_view(match, {"home": F.team_flag("Polska"), "away": F.team_flag("Słowenia")}, {})
    assert with_flags["flags"] == {"away": "si", "home": "pl"}
    club = montage._match_view({**match, "home": "KS Azoty", "away": "Wisła"}, {"home": b"logo", "away": None}, {})
    assert "flags" not in club
