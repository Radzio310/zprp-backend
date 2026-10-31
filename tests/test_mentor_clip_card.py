"""Plansza klipu „Pojedynek herbów”: barwy, herby, układ i graf ffmpeg (czyste, bez bazy i sieci)."""

import io
import shutil
import subprocess

import pytest
from PIL import Image, ImageDraw

from app import mentor_clip_card as K
from app import mentor_clip_download_rules as D

LINES = ["2026-10-10 AZS - ENE (LCM-32)", "26m23", "Kara 2 min", "Do dyskusji"]
DETAILS = {"half": "II połowa", "competition": "Superliga", "date": "10.10.2026", "code": "LCM-32", "home": "AZS AWF Biała Podlaska",
           "away": "Energa MKS Kalisz", "category_color": "amber"}
LONG = "Międzyszkolny Uczniowski Klub Sportowy Skałka Śląsk Świętochłowice Żółta Gęś " * 3


def crest_jpeg(size=50, color=(200, 20, 30)):
    image = Image.new("RGB", (size, size), (255, 255, 255))
    ImageDraw.Draw(image).ellipse([size // 6, size // 6, size * 5 // 6, size * 5 // 6], fill=color)
    out = io.BytesIO()
    image.save(out, "JPEG", quality=85)
    return out.getvalue()


def test_tlo_pod_tekstem_jest_czytelne_przy_kazdej_barwie():
    for color in ((255, 230, 0), (250, 250, 250), (255, 122, 89), (0, 255, 120), (10, 10, 60), None):
        image = K.render_background(320, 180, color, color, [(60, 70, 0.3), (260, 70, 0.3)])
        lightest = max(K.luminance(px) for px in image.resize((64, 36)).getdata())
        assert (1.05) / (lightest + 0.05) >= 4.5, color


def test_tlo_ma_barwy_po_swoich_stronach_i_szum_przeciw_pasmom():
    image = K.render_background(640, 360, (200, 0, 0), (0, 0, 200), [(100, 130, 0.3), (540, 130, 0.3)])
    left, right = image.getpixel((90, 180)), image.getpixel((550, 180))
    assert left[0] > left[2] and right[2] > right[0]
    row = [image.getpixel((x, 180)) for x in range(300, 340)]
    assert len(set(row)) > 3


def test_barwa_herbu_to_nie_biel_ani_czern():
    assert K.parse_color(K.dominant_color(crest_jpeg()))[0] > 150
    white = io.BytesIO()
    Image.new("RGB", (40, 40), (255, 255, 255)).save(white, "PNG")
    assert K.dominant_color(white.getvalue()) is None
    assert K.dominant_color(b"<svg></svg>") is None


def test_herb_jpeg_na_bialym_traci_tlo_i_zachowuje_srodek():
    crest = K.prepare_crest(crest_jpeg(), 280)
    assert crest is not None and crest.mode == "RGBA"
    assert crest.getchannel("A").getpixel((crest.width // 2, crest.height // 2)) == 255
    assert crest.getchannel("A").getpixel((0, 0)) < 40
    assert max(crest.size) <= 50 * K.MAX_CREST_ENLARGE


def test_zly_herb_nie_zatrzymuje_planszy():
    assert K.normalize_crest(b"to nie obraz") is None
    assert K.prepare_crest(b"to nie obraz", 200) is None
    data = K.card_data(LINES, DETAILS, {"home": b"to nie obraz", "away": None})
    assert K.flatten(K.compose(data, 640, 360)).size == (640, 360)


def test_inicjaly_bez_form_prawnych_i_numerow():
    assert K.initials("AZS AWF Biała Podlaska") == "AA"
    assert K.initials("Energa MKS Kalisz") == "EK"
    assert K.initials("MTS II Żory") == "Ż"
    assert K.initials("MKS") == "MKS"
    assert K.initials("") == ""
    assert K.shield_crest("", None, 200).getchannel("A").getbbox()


@pytest.mark.parametrize("size", [(1280, 720), (1920, 1080), (1080, 1920), (720, 720), (1920, 800), (480, 854), (320, 180)])
@pytest.mark.parametrize("details,title", [(DETAILS, "Kara 2 min"), ({**DETAILS, "home": LONG, "away": LONG, "competition": LONG}, LONG), ({}, "Klip")])
def test_uklad_miesci_sie_w_kadrze(size, details, title):
    width, height = size
    data = K.card_data([LINES[0], LINES[1], title, LONG if details.get("home") == LONG else LINES[3]], details)
    composition = K.compose(data, width, height)
    assert composition["background"].size == size and composition["text"].size == size
    for layer in composition["layers"]:
        assert layer["x"] >= -2 and layer["x"] + layer["image"].width <= width + 2, layer["motion"]
        box = layer["image"].getchannel("A").point(lambda v: 255 if v > 60 else 0).getbbox()
        assert layer["y"] + box[1] >= 0 and layer["y"] + box[3] <= height, layer["motion"]
    assert [layer["motion"] for layer in composition["layers"]] == ["home", "away"]
    # Tekst nie wychodzi poza kadr, a herb nie wchodzi na kafelki.
    ink = composition["text"].getchannel("A").point(lambda v: 255 if v > 200 else 0).getbbox()
    assert ink[0] >= 0 and ink[2] <= width and ink[3] <= height
    # Tekst od krawędzi: pełny kadr nie ucina nazw drużyn.
    if width >= 720:
        assert ink[0] > 0 and ink[2] < width


def test_maly_herb_nie_jest_rozciagany_a_duzy_wypelnia_skrzynke():
    small = K.prepare_crest(crest_jpeg(50), 400)
    assert max(small.size) <= 50 * K.MAX_CREST_ENLARGE
    big = K.prepare_crest(crest_jpeg(600), 200)
    assert 100 < max(big.size) <= 200


def test_nazwy_druzyn_stoja_na_stalej_linii_przy_kazdym_herbie():
    """Warstwa tekstu nie zależy od rozmiaru herbu, a herb stoi na podstawie skrzynki."""
    with_small = K.compose(K.card_data(LINES, DETAILS, {"home": crest_jpeg(50), "away": crest_jpeg(600)}), 1280, 720)
    without = K.compose(K.card_data(LINES, DETAILS), 1280, 720)
    assert with_small["text"].getchannel("A").getbbox() == without["text"].getchannel("A").getbbox()
    bottoms = [layer["y"] + layer["image"].height for layer in with_small["layers"]]
    assert abs(bottoms[0] - bottoms[1]) <= 1


def test_tytul_na_miniaturze_jest_czytelny():
    """Przy szerokości 200 px nazwa klipu ma co najmniej 9 px kroju (bez skracania przy zwykłej długości)."""
    from PIL import Image

    draw = ImageDraw.Draw(Image.new("L", (4, 4)))
    font, rows = K._title_fit(draw, "Kara 2 min za faul w ataku przy linii pola bramkowego", 1280 * 0.92, 300, [(116, 2), (102, 2), (88, 3)])
    assert font.size * 200 / 1280 >= 9 and not any(r.endswith("…") for r in rows)


def test_kafelek_numeru_nie_zmienia_pisowni_i_jest_czytelny():
    for color in D.MATCH_NUMBER_COLORS.values():
        assert K.contrast(K.parse_color(color), K.on_color(K.parse_color(color))) >= 4.5
    data = K.card_data(LINES, {**DETAILS, "code": "W/JmK/4"})
    assert data["code"] == "W/JmK/4"


def test_zawijanie_skraca_na_koncu_i_zostawia_polskie_znaki():
    draw = ImageDraw.Draw(Image.new("L", (4, 4)))
    from PIL import ImageFont

    font = ImageFont.truetype(K.FONT_CLOCK, 40)
    rows = K.wrap_lines(draw, "Zażółć gęślą jaźń " * 8, font, 500, 2)
    assert len(rows) == 2 and rows[1].endswith("…") and "ż" in rows[0]
    assert all(draw.textlength(r, font=font) <= 500 for r in rows)
    assert K.wrap_lines(draw, "A" * 300, font, 500, 2)[0].endswith("…")


def test_graf_ffmpeg_trzyma_dzwiek_w_synchronizacji(tmp_path):
    plan = K.write_layers(K.card_data(LINES, DETAILS), 640, 360, str(tmp_path))
    args = K.ffmpeg_args(plan, "klip.mp4", "wynik.mp4", 640, 360, True)
    graph = args[args.index("-filter_complex") + 1]
    assert f"offset={D.CARD_SECONDS - D.CARD_FADE_S:.3f}" in graph
    assert f"duration={D.CARD_FADE_S:.3f}" in graph
    assert "adelay=1750:all=1" in graph
    assert graph.count("overlay=") == 2  # rusza się tylko herb, tekst leży na tle od klatki 0
    assert "fade=t=in:st" not in graph.replace("afade=t=in:st", "")
    assert args[-1] == "wynik.mp4"
    silent = K.ffmpeg_args(plan, "klip.mp4", "wynik.mp4", 640, 360, False)
    assert "-an" in silent and "adelay" not in silent[silent.index("-filter_complex") + 1]


def test_barwa_numeru_jak_w_aplikacji():
    assert D.match_number_color("IKB/12") == "#e56b6f"
    assert D.match_number_color("LCM/32") == "#8338ec"
    assert D.match_number_color("W/JmK/4") == "#83c5be"
    assert D.match_number_color("IIM/7") == "#ffd6a5"  # nie I liga, choć „IM” jest w środku
    assert D.match_number_color("IIIK/7") == "#ffaa00"
    assert D.match_number_color("S/DzK/1") == "#cdb4db"
    assert D.match_number_color("XYZ/1") == "#888888"
    assert D.match_number_color("W/JMK/4") != D.match_number_color("W/JmK/4")  # wielkość liter niesie znaczenie


def test_kolor_kategorii_zawsze_czytelny():
    for color in ("amber", "slate", "#101010", "nie-ma", None):
        assert K.contrast(K.category_ink(color), (24, 26, 32)) >= 4.5


def test_podpis_zalezy_od_wygladu_i_tresci(monkeypatch):
    base = D.card_signature(LINES, DETAILS)
    assert base == D.card_signature(LINES, dict(reversed(list(DETAILS.items()))))
    assert base != D.card_signature(LINES, {**DETAILS, "code": "INNY"})
    assert base != D.card_signature(LINES, {**DETAILS, "code_color": "#123456"})
    monkeypatch.setattr(D, "CARD_LOOK_VERSION", D.CARD_LOOK_VERSION + 1)
    assert base != D.card_signature(LINES, DETAILS)


def test_podpis_pod_minuta_mowi_prawde_o_zrodle():
    sync = {"match_start_s": 100, "second_half_s": 2200, "half_minutes": 30}
    assert D.card_time_label(1_000_000, 50.0, {}) == "I połowa"
    assert D.card_time_label(1_900_000, 50.0, {}) == "II połowa"
    assert D.card_time_label(1_600_000, 50.0, {"half_minutes": 25}) == "II połowa"
    assert D.card_time_label(None, 500.0, sync) == "I połowa"
    assert D.card_time_label(None, 2300.0, sync) == "II połowa"
    assert D.card_time_label(None, 500.0, {}) == "Czas nagrania"
    assert D.card_date("2026-10-10T18:00:00") == "10.10.2026"
    assert D.card_date(None) == ""


@pytest.mark.skipif(not shutil.which("ffmpeg"), reason="brak ffmpeg (jest w obrazie Dockera)")
def test_prawdziwy_plik_ma_plansze_i_klip(tmp_path):
    source = tmp_path / "klip.mp4"
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "testsrc2=s=320x180:r=30:d=2",
                    "-f", "lavfi", "-i", "sine=f=440:d=2", "-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac", str(source)], check=True)
    plan = K.write_layers(K.card_data(LINES, DETAILS, {"home": crest_jpeg()}), 320, 180, str(tmp_path))
    target = tmp_path / "wynik.mp4"
    done = subprocess.run(K.ffmpeg_args(plan, str(source), str(target), 320, 180, True), capture_output=True, text=True)
    assert done.returncode == 0, done.stderr[-800:]
    probe = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(target)], capture_output=True, text=True)
    assert abs(float(probe.stdout) - 3.75) < 0.2
