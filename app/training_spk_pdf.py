# app/training_spk_pdf.py
#
# Materiał szkoleniowy SPK/1 jako prezentacja PDF - jedna akcja na stronę.
#
# PO CO PDF, skoro slajdy są w aplikacji. Bo to dwie różne sytuacje. W aplikacji
# sędzia ćwiczy sam, na własnym telefonie. PDF idzie na rzutnik: prowadzący
# przewija strony, a cała sala prowadzi ten sam mecz naraz i nikt nie ma
# odpowiedzi przed sobą. Jedno nie zastępuje drugiego.
#
# SZABLON HTML, NIE RYSOWANIE PO STRONIE. Ta sama droga, którą idą komunikaty
# BAZA Beach (`app/beach/final_report.py`): Jinja2 składa
# `app/templates/szkolenie_spk.html`, WeasyPrint zamienia go na PDF. Powód jest
# praktyczny: układ prezentacji poprawia się wtedy w CSS, a nie w rachunku
# współrzędnych - a przy materiale, który ktoś wyświetli na sali, poprawek
# układu będzie więcej niż poprawek treści.
#
# IMPORTY LENIWE. `weasyprint` ciągnie za sobą biblioteki systemowe i nie ma go
# w środowisku testowym; cały moduł importowany na starcie przewróciłby aplikację
# wszędzie tam, gdzie PDF nie jest potrzebny. Beachowe raporty robią dokładnie
# to samo i z tego samego powodu.
#
# JEDNO ŹRÓDŁO ZDAŃ. Treść poleceń składa `app/training_spk_slides.py` - ten
# sam moduł, z którego żyją slajdy w aplikacji. Gdyby PDF pisał zdania po
# swojemu, prowadzący czytałby z rzutnika co innego, niż sędzia ma na ekranie.

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.training_spk_slides import slides_from_timeline, slides_header

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATE_NAME = "szkolenie_spk.html"

#: Barwy BAZA/ProEl - te same, co szkło w aplikacji (`utils/glassTheme.ts`).
CREAM = "#FFF8F0"
INK = "#241A14"
ACCENT = "#774936"
MUTED = "#8B7365"

#: Progi długości polecenia, po których pismo schodzi o stopień.
#:
#: Liczone w znakach, a nie mierzone w punktach, bo WeasyPrint nie da nam tu
#: szerokości tekstu przed złożeniem strony. Progi są dobrane tak, żeby
#: najdłuższe realne polecenie („Rzut karny niewykorzystany, gospodarzy nr 16")
#: mieściło się w jednym wierszu na szerokości A4 poziomo.
SIZE_STEPS = ((34, "s1"), (52, "s2"))


class SpkPdfError(RuntimeError):
    """Materiału nie da się złożyć - z powodem po polsku."""


def _size_class(text: str) -> str:
    """Klasa rozmiaru pisma dla tego polecenia.

    Zmniejszamy pismo zamiast łamać wiersz: polecenie ma być jednym rzutem oka
    z końca sali, a złamane w połowie przestaje nim być.
    """
    length = len(text or "")
    for limit, name in SIZE_STEPS:
        if length <= limit:
            return name
    return "s3"


def build_slides_context(
    timeline: Any, meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Wszystko, czego potrzebuje szablon - i nic ponad to.

    Wydzielone, żeby dało się sprawdzić testem BEZ WeasyPrinta: to tutaj
    zapadają decyzje (kolejność, scalanie akcji, rozmiar pisma), a samo
    złożenie PDF-a jest już mechaniczne.
    """
    slides: List[Dict[str, Any]] = []
    for slide in slides_from_timeline(timeline, meta):
        entry = dict(slide)
        entry["sizeClass"] = _size_class(entry["actions"][0])
        slides.append(entry)

    return {
        "slides": slides,
        "head": slides_header(meta),
        "cream": CREAM,
        "ink": INK,
        "accent": ACCENT,
        "muted": MUTED,
    }


def render_slides_html(
    timeline: Any, meta: Optional[Dict[str, Any]] = None
) -> str:
    """Gotowy HTML prezentacji. Osobno od PDF, bo bywa potrzebny sam.

    Podgląd w przeglądarce nie wymaga wtedy WeasyPrinta - a to jest najszybszy
    sposób, żeby zobaczyć poprawkę układu.
    """
    from jinja2 import Environment, FileSystemLoader  # lazy — patrz nagłówek

    context = build_slides_context(timeline, meta)
    if not context["slides"]:
        raise SpkPdfError(
            "Wzorzec nie ma ani jednej akcji - nie ma z czego złożyć materiału."
        )
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    return env.get_template(TEMPLATE_NAME).render(**context)


def build_slides_pdf(timeline: Any, meta: Optional[Dict[str, Any]] = None) -> bytes:
    """Cała prezentacja jako jeden plik PDF.

    Pusta oś czasu kończy się BŁĘDEM, a nie plikiem z samą okładką: materiał bez
    akcji wygląda na gotowy i dopiero na sali okazuje się pusty.
    """
    html = render_slides_html(timeline, meta)

    import weasyprint  # lazy — patrz nagłówek modułu

    tmp_dir = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp_dir, "szkolenie.html")
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(html)
        return weasyprint.HTML(filename=html_path).write_pdf()
    finally:
        # Katalog tymczasowy znika ZAWSZE, także gdy WeasyPrint się wywróci -
        # inaczej każda nieudana próba zostawiałaby po sobie plik na dysku
        # serwera, a te nikną dopiero przy restarcie kontenera.
        import shutil

        shutil.rmtree(tmp_dir, ignore_errors=True)
