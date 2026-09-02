# app/training_spk_pdf.py
#
# Materiał szkoleniowy SPK/1 jako prezentacja PDF - jedna akcja na stronę.
#
# PO CO PDF, skoro slajdy są w aplikacji. Bo to dwie różne sytuacje. W aplikacji
# sędzia ćwiczy sam, na własnym telefonie. PDF idzie na rzutnik: prowadzący
# przewija strony, a cała sala prowadzi ten sam mecz naraz i nikt nie ma
# odpowiedzi przed sobą. Jedno bez drugiego nie zastępuje.
#
# JEDNO ŹRÓDŁO ZDAŃ. Treść poleceń składa `app/training_spk_slides.py` - ten
# sam moduł, z którego żyją slajdy w aplikacji. Gdyby PDF pisał zdania po
# swojemu, prowadzący czytałby z rzutnika co innego, niż sędzia ma na ekranie.
#
# POZIOMA A4. Format prezentacyjny, nie dokumentowy: to się wyświetla, a nie
# czyta z kartki. Jedna akcja na stronę i pismo, które widać z końca sali -
# stąd rozmiary, które w dokumencie byłyby absurdalne.
#
# POLSKIE ZNAKI. Standardowe czcionki PDF mają WinAnsiEncoding i „Zażółć gęślą
# jaźń" wychodzi z nich jako ciąg pytajników. Rysujemy własną (Noto Sans, OFL,
# `app/fonts/`), tą samą, którą wypełnia się raport dodatkowy.

from __future__ import annotations

import os
from io import BytesIO
from typing import Any, Dict, List, Optional

import pymupdf

from app.training_spk_slides import slides_from_timeline, slides_header

FONT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fonts", "NotoSans-Regular.ttf"
)

#: A4 poziomo w punktach.
PAGE_W, PAGE_H = 842.0, 595.0

#: Barwy BAZA/ProEl - te same, co szkło w aplikacji (`utils/glassTheme.ts`).
CREAM = (1.0, 0.973, 0.941)      # #FFF8F0
INK = (0.141, 0.102, 0.078)      # #241A14
BRAND = (0.467, 0.286, 0.212)    # #774936
MUTED = (0.545, 0.451, 0.396)


class SpkPdfError(RuntimeError):
    """Materiału nie da się złożyć - z powodem po polsku."""


def _font() -> pymupdf.Font:
    return pymupdf.Font(fontfile=FONT_PATH)


def _bg(page: pymupdf.Page) -> None:
    page.draw_rect(pymupdf.Rect(0, 0, PAGE_W, PAGE_H), color=None, fill=CREAM)


def _text(
    page: pymupdf.Page,
    point: pymupdf.Point,
    text: str,
    *,
    size: float,
    color=INK,
) -> None:
    if not text:
        return
    page.insert_text(
        point, text, fontsize=size, fontname="noto", fontfile=FONT_PATH, color=color
    )


def _centered(
    page: pymupdf.Page,
    font: pymupdf.Font,
    y: float,
    text: str,
    *,
    size: float,
    color=INK,
    max_width: float = PAGE_W - 120,
) -> float:
    """Napis wyśrodkowany, zwężany aż się zmieści. Zwraca użyty rozmiar.

    Zmniejszamy pismo zamiast łamać wiersz: polecenie ma być jednym rzutem oka
    z końca sali, a złamane w połowie przestaje nim być. Dopiero gdy zejście
    do granicy czytelności nie starczy, tekst łamiemy - i wtedy jest to
    świadoma ostateczność, a nie przypadek.
    """
    used = size
    while used > 20 and font.text_length(text, fontsize=used) > max_width:
        used -= 1
    width = font.text_length(text, fontsize=used)
    _text(page, pymupdf.Point((PAGE_W - width) / 2, y), text, size=used, color=color)
    return used


def _wrapped_centered(
    page: pymupdf.Page,
    font: pymupdf.Font,
    y: float,
    text: str,
    *,
    size: float,
    color=INK,
    max_width: float = PAGE_W - 120,
) -> None:
    """Ostateczność dla poleceń, które nie mieszczą się nawet po zmniejszeniu."""
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if font.text_length(candidate, fontsize=size) > max_width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    for index, line in enumerate(lines):
        width = font.text_length(line, fontsize=size)
        _text(
            page,
            pymupdf.Point((PAGE_W - width) / 2, y + index * (size * 1.25)),
            line,
            size=size,
            color=color,
        )


def _cover(doc: pymupdf.Document, font: pymupdf.Font, head: Dict[str, str], total: int) -> None:
    page = doc.new_page(width=PAGE_W, height=PAGE_H)
    _bg(page)
    page.draw_rect(pymupdf.Rect(0, 0, PAGE_W, 10), color=None, fill=BRAND)

    _centered(page, font, 190, "Materiał szkoleniowy", size=26, color=MUTED)
    _centered(page, font, 260, head.get("teams") or "Mecz szkoleniowy", size=44)
    _centered(page, font, 320, head.get("matchNumber", ""), size=28, color=BRAND)

    line = " · ".join(
        x for x in (head.get("date", ""), f"wynik {head.get('result', '')}") if x.strip(" ·")
    )
    _centered(page, font, 380, line, size=20, color=MUTED)
    _centered(
        page,
        font,
        470,
        f"{total} akcji do zapisania - jedna na stronę",
        size=18,
        color=MUTED,
    )
    _centered(
        page,
        font,
        505,
        "Czas gry przy każdej akcji jest częścią zadania",
        size=16,
        color=MUTED,
    )


def _slide_page(
    doc: pymupdf.Document,
    font: pymupdf.Font,
    slide: Dict[str, Any],
    total: int,
    head: Dict[str, str],
) -> None:
    page = doc.new_page(width=PAGE_W, height=PAGE_H)
    _bg(page)
    page.draw_rect(pymupdf.Rect(0, 0, PAGE_W, 10), color=None, fill=BRAND)

    # Nagłówek: skąd ten materiał. Mały, żeby nie konkurował z poleceniem.
    _text(page, pymupdf.Point(48, 54), head.get("matchNumber", ""), size=13, color=MUTED)
    teams = head.get("teams", "")
    if teams:
        width = font.text_length(teams, fontsize=13)
        _text(
            page,
            pymupdf.Point(PAGE_W - 48 - width, 54),
            teams,
            size=13,
            color=MUTED,
        )

    # Czas gry - największa liczba na stronie po samym poleceniu, bo to od niej
    # zaczyna się czynność sędziego.
    half = "seria rzutów karnych" if slide.get("shootout") else f"{slide.get('half', 1)}. połowa"
    _centered(page, font, 200, slide.get("clock", ""), size=76, color=BRAND)
    _centered(page, font, 240, half, size=18, color=MUTED)

    text = str(slide.get("text") or "")
    used = _centered(page, font, 360, text, size=46)
    if used <= 20 and font.text_length(text, fontsize=used) > PAGE_W - 120:
        # Zmniejszanie nie starczyło - dopiero teraz łamiemy wiersz.
        page.draw_rect(pymupdf.Rect(0, 320, PAGE_W, 420), color=None, fill=CREAM)
        _wrapped_centered(page, font, 350, text, size=28)

    footer = f"{slide.get('n', 0)} / {total}"
    width = font.text_length(footer, fontsize=14)
    _text(
        page,
        pymupdf.Point(PAGE_W - 48 - width, PAGE_H - 40),
        footer,
        size=14,
        color=MUTED,
    )


def build_slides_pdf(timeline: Any, meta: Optional[Dict[str, Any]] = None) -> bytes:
    """Cała prezentacja jako jeden plik PDF.

    Pusta oś czasu kończy się BŁĘDEM, a nie plikiem z samą okładką: materiał bez
    akcji wygląda na gotowy i dopiero na sali okazuje się pusty.
    """
    slides = slides_from_timeline(timeline, meta)
    if not slides:
        raise SpkPdfError(
            "Wzorzec nie ma ani jednej akcji - nie ma z czego złożyć materiału."
        )

    head = slides_header(meta)
    font = _font()
    doc = pymupdf.open()
    try:
        _cover(doc, font, head, len(slides))
        for slide in slides:
            _slide_page(doc, font, slide, len(slides), head)
        buffer = BytesIO()
        doc.save(buffer, deflate=True)
        return buffer.getvalue()
    finally:
        doc.close()


def build_slides_markdown(timeline: Any, meta: Optional[Dict[str, Any]] = None) -> str:
    """Ta sama treść jako Markdown - do wklejenia gdziekolwiek.

    Powstaje z tej samej listy slajdów, więc nie da się jej rozjechać z PDF-em
    ani z aplikacją. Kosztuje kilkanaście linijek, a bywa jedynym formatem,
    który da się szybko poprawić i rozesłać.
    """
    slides = slides_from_timeline(timeline, meta)
    head = slides_header(meta)

    out: List[str] = []
    out.append(f"# {head.get('teams') or 'Mecz szkoleniowy'}")
    out.append("")
    details = [head.get("matchNumber", ""), head.get("date", "")]
    result = head.get("result", "")
    if result:
        details.append(f"wynik {result}")
    half = head.get("halfResult", "")
    if half:
        details.append(f"do przerwy {half}")
    out.append(" · ".join(d for d in details if d))
    out.append("")
    out.append(f"Akcji do zapisania: **{len(slides)}**.")
    out.append("")

    current_half = None
    for slide in slides:
        marker = "Seria rzutów karnych" if slide["shootout"] else f"{slide['half']}. połowa"
        if marker != current_half:
            out.append(f"## {marker}")
            out.append("")
            current_half = marker
        out.append(f"{slide['n']}. **{slide['clock']}** - {slide['text']}")
    out.append("")
    return "\n".join(out)
