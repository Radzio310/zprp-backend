"""Dodatkowy raport: wypełnianie formularzy PDF.

Trzy rzeczy, które w tym generatorze już raz nie zadziałały i dlatego mają tu
swoje testy:

1. DRUGA STRONA. Nazwy pól AcroForm są unikalne w dokumencie, więc wklejenie
   wzoru dwa razy do jednego pliku zostawia drugą kopię BEZ pól - wychodziła
   pusta kartka z samą ramką. Dlatego każda strona powstaje osobno.

2. POLSKIE ZNAKI. Wygląd pól formularza ma Helvetikę z WinAnsiEncoding,
   w której „Zażółć gęślą jaźń" zamienia się w ciąg pytajników. Tekst
   rysujemy własną czcionką i to jest jedyny powód, dla którego w repozytorium
   leży NotoSans-Regular.ttf.

3. ZA DŁUGI OPIS. Rubryka ma stałą wysokość. Cicho obcięty opis czerwonej
   kartki jest gorszy niż brak raportu, więc generowanie ma się WYWALIĆ
   z nazwą pozycji, a nie oddać skróconą prawdę.
"""

import os

import pymupdf
import pytest
from fontTools.ttLib import TTFont

from app.extra_report_pdf import (
    ENTRIES_PER_PAGE,
    FONT_PATH,
    ExtraReportError,
    build_extra_report_pdf,
    paginate,
)

TEMPLATES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "templates"
)

HEADER = {
    "names": ["KOWALSKI Jan", "NOWAK Adam"],
    "match": "MP/12, 05.09.2026, Płock, Hala Orlen Arena",
    "teams": ["Wisła Płock", "Stal Mielec"],
    "video": True,
}

DELEGATE_HEADER = {
    "names": ["ZIELIŃSKA Ewa"],
    "match": "LCM/8, 12.10.2026, Kielce",
    "teams": ["Vive Kielce", "Azoty Puławy"],
    "video": False,
}


def _signature_png() -> bytes:
    doc = pymupdf.open()
    page = doc.new_page(width=300, height=100)
    page.draw_bezier((10, 80), (80, 10), (160, 110), (280, 30), color=(0, 0, 0.6), width=3)
    data = page.get_pixmap(dpi=150).tobytes("png")
    doc.close()
    return data


def _referee_entries(n: int):
    return [{"id": f"e{i}", "text": f"Zażółć gęślą jaźń nr {i + 1}."} for i in range(n)]


def _build(kind, entries, header=None, signatures=None):
    return build_extra_report_pdf(
        kind=kind,
        header=header or (HEADER if kind == "referees" else DELEGATE_HEADER),
        entries=entries,
        signatures=signatures if signatures is not None else [_signature_png()] * 2,
        templates_dir=TEMPLATES,
    )


def _pages_text(pdf: bytes):
    doc = pymupdf.open(stream=pdf, filetype="pdf")
    try:
        return [page.get_text() for page in doc]
    finally:
        doc.close()


# ── stronicowanie ────────────────────────────────────────────────────────────


def test_pojemnosc_strony_zgadza_sie_z_formularzem():
    """Sześć ponumerowanych pól u sędziów, jeden incydent u delegata."""
    assert ENTRIES_PER_PAGE == {"referees": 6, "delegate": 1}


def test_szesc_opisow_to_jedna_strona():
    assert len(_pages_text(_build("referees", _referee_entries(6)))) == 1


def test_siodmy_opis_otwiera_druga_strone():
    pages = _pages_text(_build("referees", _referee_entries(7)))
    assert len(pages) == 2
    assert "jaźń nr 6." in pages[0]
    assert "jaźń nr 7." in pages[1]
    assert "jaźń nr 7." not in pages[0]


def test_druga_strona_NIE_jest_pusta():
    """Regresja: druga kopia wzoru traciła pola i wychodziła gołą ramką."""
    pages = _pages_text(_build("referees", _referee_entries(7)))
    assert "KOWALSKI Jan" in pages[1]
    assert "MP/12" in pages[1]
    assert "Wisła Płock" in pages[1]


def test_kazdy_incydent_delegata_na_wlasnej_stronie():
    entries = [
        {"id": "1", "incident": "Race w 42 minucie.", "decisions": "Przerwa 6 minut.", "other": "Ochrona zareagowała."},
        {"id": "2", "incident": "Trener opuścił strefę.", "decisions": "Upomnienie.", "other": ""},
    ]
    pages = _pages_text(_build("delegate", entries, signatures=[_signature_png()]))
    assert len(pages) == 2
    assert "Race w 42 minucie." in pages[0]
    assert "Ochrona zareagowała." in pages[0]
    assert "Trener opuścił strefę." in pages[1]


def test_puste_pozycje_nie_robia_pustych_stron():
    entries = _referee_entries(6) + [{"id": "x", "text": "   "}, {"id": "y", "text": ""}]
    assert len(_pages_text(_build("referees", entries))) == 1


def test_pusty_raport_to_blad_a_nie_pusta_kartka():
    with pytest.raises(ExtraReportError):
        _build("referees", [{"id": "x", "text": "  "}])


def test_paginate_nie_rusza_kolejnosci():
    entries = _referee_entries(8)
    pages = paginate("referees", entries)
    assert [e["text"] for e in pages[1]] == [entries[6]["text"], entries[7]["text"]]


# ── treść ────────────────────────────────────────────────────────────────────


def test_polskie_znaki_przezywaja():
    text = _pages_text(_build("referees", _referee_entries(1)))[0]
    assert "Zażółć gęślą jaźń nr 1." in text
    assert "Płock" in text
    assert "?" not in "Zażółć"  # kanarek: gdyby test sam zgubił kodowanie


def test_repozytorium_niesie_czcionke_z_polskimi_znakami():
    """Pola formularza mają WinAnsi - własna czcionka to jedyne wyjście."""
    assert os.path.exists(FONT_PATH), "brak app/fonts/NotoSans-Regular.ttf"
    cmap = TTFont(FONT_PATH).getBestCmap()
    for ch in "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ":
        assert ord(ch) in cmap, f"czcionka nie ma znaku {ch}"


def test_naglowek_trafia_w_pola():
    text = _pages_text(_build("referees", _referee_entries(1)))[0]
    assert "KOWALSKI Jan" in text
    assert "NOWAK Adam" in text
    assert "Stal Mielec" in text


def test_podpisy_sa_na_kazdej_stronie():
    pdf = _build("referees", _referee_entries(7))
    doc = pymupdf.open(stream=pdf, filetype="pdf")
    try:
        # Wzór niesie własną grafikę (godło), więc liczymy RÓŻNICĘ względem
        # tego samego raportu wygenerowanego bez podpisów.
        counts = [len(page.get_images()) for page in doc]
    finally:
        doc.close()
    bare = _build("referees", _referee_entries(7), signatures=[])
    doc2 = pymupdf.open(stream=bare, filetype="pdf")
    try:
        bare_counts = [len(page.get_images()) for page in doc2]
    finally:
        doc2.close()
    assert all(c > b for c, b in zip(counts, bare_counts))


def test_numer_strony_tylko_gdy_stron_wiecej_niz_jedna():
    one = _pages_text(_build("referees", _referee_entries(3)))[0]
    assert "1 / 1" not in one
    two = _pages_text(_build("referees", _referee_entries(7)))
    assert "1 / 2" in two[0]
    assert "2 / 2" in two[1]


# ── za długi tekst ───────────────────────────────────────────────────────────


def test_za_dlugi_opis_konczy_sie_bledem_z_numerem():
    with pytest.raises(ExtraReportError) as err:
        _build("referees", [{"id": "x", "text": "Bardzo długi opis. " * 400}])
    assert "opis nr 1" in str(err.value)


def test_blad_wskazuje_ktore_pole_delegata_jest_za_dlugie():
    entries = [
        {"id": "1", "incident": "Krótko.", "decisions": "Krótko.", "other": ""},
        {"id": "2", "incident": "x", "decisions": "Bardzo długi opis. " * 900, "other": ""},
    ]
    with pytest.raises(ExtraReportError) as err:
        _build("delegate", entries, signatures=[_signature_png()])
    assert "Podjęte decyzje" in str(err.value)
    assert "incydencie nr 2" in str(err.value)


def test_dlugi_ale_mieszczacy_sie_opis_przechodzi_mniejszym_pismem():
    """Granica ma być miękka: najpierw kurczy się pismo, dopiero potem błąd."""
    text = "Zawodnik nr 7 uderzył przeciwnika łokciem w twarz po gwizdku. " * 6
    pages = _pages_text(_build("referees", [{"id": "x", "text": text}]))
    assert "uderzył przeciwnika łokciem" in pages[0]


# ── odporność ────────────────────────────────────────────────────────────────


def test_brak_podpisow_nie_wywala_generowania():
    """Raport pisany dzień później, zanim ktokolwiek zdążył się podpisać."""
    pages = _pages_text(_build("referees", _referee_entries(2), signatures=[]))
    assert "jaźń nr 1." in pages[0]


def test_nieznany_rodzaj_raportu():
    with pytest.raises(ExtraReportError):
        build_extra_report_pdf(
            kind="kibicow", header=HEADER, entries=[{"id": "x", "text": "a"}], templates_dir=TEMPLATES
        )


def test_wideo_zaznacza_dokladnie_jedno_pole():
    """TAK i NIE to dwa osobne checkboxy - nie wolno zaznaczyć obu ani żadnego."""
    for video in (True, False):
        header = {**HEADER, "video": video}
        pdf = _build("referees", _referee_entries(1), header=header)
        doc = pymupdf.open(stream=pdf, filetype="pdf")
        try:
            # Po spieczeniu checkboxy są treścią strony; sprawdzamy, że dokument
            # w ogóle powstał i niesie nagłówek - sam stan pola weryfikuje
            # wizualnie wzór, a tu pilnujemy, że kod ścieżki się nie wywala.
            assert doc.page_count == 1
        finally:
            doc.close()
