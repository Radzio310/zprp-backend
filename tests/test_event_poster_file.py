"""Plik plakatu do pobrania: PDF A4/A5 bezstratnie, PNG grafik bez zmian, twarde odmowy."""

import io
import re
import zlib

import pytest
from PIL import Image

from app import event_poster_file as P


def png(size, color=(11, 18, 36), mode="RGB") -> bytes:
    image = Image.new(mode, size, color if mode == "RGB" else (*color, 255))
    # Kod QR w miniaturze: ostre krawędzie mają przetrwać co do piksela.
    for x in range(0, size[0], 7):
        for y in range(0, size[1], 11):
            image.putpixel((x, y), (255, 255, 255) if mode == "RGB" else (255, 255, 255, 255))
    out = io.BytesIO()
    image.save(out, "PNG")
    return out.getvalue()


def test_plakat_a4_to_pdf_w_rozmiarze_kartki_bez_strat():
    source = png((827, 1170))
    body, ext = P.build_download(source, "a4")
    assert ext == "pdf"
    assert body.startswith(b"%PDF-1.4") and body.rstrip().endswith(b"%%EOF")
    assert b"/MediaBox [0 0 595.28 841.89]" in body

    stream = re.search(rb"/Length (\d+) >>\nstream\n", body)
    start = stream.end()
    pixels = zlib.decompress(body[start : start + int(stream.group(1))])
    assert pixels == Image.open(io.BytesIO(source)).convert("RGB").tobytes()

    fitz = pytest.importorskip("fitz")
    doc = fitz.open(stream=body, filetype="pdf")
    assert doc.page_count == 1
    page = doc[0]
    assert round(page.rect.width, 1) == 595.3 and round(page.rect.height, 1) == 841.9
    info = page.get_images(full=True)[0]
    assert (info[2], info[3]) == (827, 1170)


def test_plakat_a5_z_przezroczystoscia_drukuje_sie_na_bialym():
    image = Image.new("RGBA", (583, 827), (0, 0, 0, 0))
    out = io.BytesIO()
    image.save(out, "PNG")
    body, ext = P.build_download(out.getvalue(), "a5")
    assert ext == "pdf"
    assert b"/MediaBox [0 0 419.53 595.28]" in body
    stream = re.search(rb"/Length (\d+) >>\nstream\n", body)
    pixels = zlib.decompress(body[stream.end() : stream.end() + int(stream.group(1))])
    assert set(pixels) == {255}


def test_grafika_wraca_jako_ten_sam_png():
    source = png((1440, 2560))
    assert P.build_download(source, "story") == (source, "png")
    assert P.build_download(png((2048, 2048)), "square")[1] == "png"


@pytest.mark.parametrize(
    "data, variant, message",
    [
        (b"", "a4", "Pusty plik"),
        (b"%PDF-1.4 nie obraz", "a4", "To nie jest obraz PNG"),
        (png((1000, 1000)), "a4", "inne proporcje"),
        (png((2480, 3508)), "a5", "inny rozmiar"),
        (png((300, 424)), "a4", "inny rozmiar"),
        (P.PNG_SIGNATURE + b"smieci", "square", "Nie da się odczytać"),
    ],
    ids=["pusty", "pdf-zamiast-png", "kwadrat-na-a4", "a4-na-a5", "za-maly", "smieci"],
)
def test_odmowy(data, variant, message):
    with pytest.raises(P.PosterFileError, match=message):
        P.build_download(data, variant)


def test_urwany_png_to_odmowa_a_nie_awaria():
    source = png((2048, 2048))
    with pytest.raises(P.PosterFileError):
        P.build_download(source[: len(source) // 2], "square")
    with pytest.raises(P.PosterFileError):
        P.build_download(png((827, 1170))[:-40], "a4")


def test_za_duzy_plik():
    with pytest.raises(P.PosterFileError, match="za duży"):
        P.build_download(P.PNG_SIGNATURE + b"0" * P.MAX_UPLOAD_BYTES, "a4")


def test_format_i_nazwa():
    assert P.check_variant(" A4 ") == "a4"
    with pytest.raises(P.PosterFileError):
        P.check_variant("a3")
    assert P.download_name("baza-obecnosc-plakat-a4-kurs-dla-mlodych-sedziow-2026-09-18", "pdf") == (
        "baza-obecnosc-plakat-a4-kurs-dla-mlodych-sedziow-2026-09-18.pdf"
    )
    assert P.download_name("Szkolenie Śląskie żółć.png", "png") == "szkolenie-slaskie-zolc.png"
    assert P.download_name('../../"x"; rm', "pdf") == "x-rm.pdf"
    assert P.download_name("", "png") == "baza-obecnosc.png"
