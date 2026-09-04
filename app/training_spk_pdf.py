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

import base64
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
    timeline: Any,
    meta: Optional[Dict[str, Any]] = None,
    shootout: Any = None,
) -> Dict[str, Any]:
    """Wszystko, czego potrzebuje szablon - i nic ponad to.

    Wydzielone, żeby dało się sprawdzić testem BEZ WeasyPrinta: to tutaj
    zapadają decyzje (kolejność, scalanie akcji, rozmiar pisma), a samo
    złożenie PDF-a jest już mechaniczne.
    """
    slides: List[Dict[str, Any]] = []
    for slide in slides_from_timeline(timeline, meta, shootout=shootout):
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
    timeline: Any,
    meta: Optional[Dict[str, Any]] = None,
    shootout: Any = None,
) -> str:
    """Gotowy HTML prezentacji. Osobno od PDF, bo bywa potrzebny sam.

    Podgląd w przeglądarce nie wymaga wtedy WeasyPrinta - a to jest najszybszy
    sposób, żeby zobaczyć poprawkę układu.
    """
    from jinja2 import Environment, FileSystemLoader  # lazy — patrz nagłówek

    context = build_slides_context(timeline, meta, shootout=shootout)
    if not context["slides"]:
        raise SpkPdfError(
            "Wzorzec nie ma ani jednej akcji - nie ma z czego złożyć materiału."
        )
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    return env.get_template(TEMPLATE_NAME).render(**context)


def build_slides_pdf(
    timeline: Any,
    meta: Optional[Dict[str, Any]] = None,
    shootout: Any = None,
) -> bytes:
    """Cała prezentacja jako jeden plik PDF.

    Pusta oś czasu kończy się BŁĘDEM, a nie plikiem z samą okładką: materiał bez
    akcji wygląda na gotowy i dopiero na sali okazuje się pusty.
    """
    html = render_slides_html(timeline, meta, shootout=shootout)

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


REPORT_TEMPLATE_NAME = "raport_spk.html"

#: Druga barwa okładki - jaśniejsza miedź, ta sama, którą tonuje się ikonę
#: powiadomienia. Gradient z jednym kolorem jest płaski jak kartka.
ACCENT_2 = "#C38E70"

#: Herby okręgów - te same pliki, co w aplikacji, tylko pomniejszone do
#: rozmiaru, w jakim drukuje je raport.
CRESTS_DIR = TEMPLATE_DIR / "okregi"
LOGO_FILE = TEMPLATE_DIR / "baza_logo.png"


def _b64(path: Path) -> str:
    """Obraz jako base64 albo pusto. WeasyPrint nie sięgnie po plik sam."""
    try:
        return base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError:
        logger.warning("SPK: nie udało się wczytać obrazu %s", path)
        return ""


def _crest_images(context: Dict[str, Any]) -> Dict[str, str]:
    """Tylko te herby, które w tym raporcie naprawdę występują.

    Szesnaście herbów w każdym PDF-ie to ćwierć megabajta na okręgi, których w
    zestawieniu nie ma. Zbieramy nazwy z gotowego kontekstu, bo to on wie, co
    zostanie narysowane.
    """
    wanted = {str(context.get("scopeCrest") or "")}
    for key in ("byProvince", "ranking", "guided"):
        for row in context.get(key) or []:
            wanted.add(str(row.get("crest") or ""))
    out: Dict[str, str] = {}
    for slug in sorted(w for w in wanted if w):
        data = _b64(CRESTS_DIR / f"{slug}.png")
        if data:
            out[slug] = data
    return out


def render_report_html(context: Dict[str, Any]) -> str:
    """Gotowy HTML raportu wyników - kontekst składa `training_spk_report.py`.

    Osobno od PDF z tego samego powodu, co przy prezentacji: podgląd w
    przeglądarce bez WeasyPrinta to najszybsza droga do poprawki układu.
    """
    from jinja2 import Environment, FileSystemLoader  # lazy — patrz nagłówek

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    return env.get_template(REPORT_TEMPLATE_NAME).render(
        cream=CREAM,
        ink=INK,
        accent=ACCENT,
        accent2=ACCENT_2,
        muted=MUTED,
        logo_b64=_b64(LOGO_FILE),
        crests=_crest_images(context),
        **context,
    )


def build_report_pdf(context: Dict[str, Any]) -> bytes:
    """Raport wyników jako jeden plik PDF."""
    html = render_report_html(context)

    import weasyprint  # lazy — patrz nagłówek modułu

    tmp_dir = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp_dir, "raport.html")
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(html)
        return weasyprint.HTML(filename=html_path).write_pdf()
    finally:
        try:
            for name in os.listdir(tmp_dir):
                os.remove(os.path.join(tmp_dir, name))
            os.rmdir(tmp_dir)
        except OSError:
            logger.warning("SPK: nie udało się posprzątać katalogu %s", tmp_dir)

