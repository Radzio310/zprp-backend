"""Dodatkowy raport sędziów i delegata - wypełnianie formularzy PDF.

Oba wzory (`templates/raport_sedziow.pdf`, `templates/raport_delegata.pdf`) są
formularzami AcroForm z nazwanymi polami, więc nie zgadujemy współrzędnych -
bierzemy prostokąty z pól. Nazwy pól wygenerowało narzędzie, którym powstał
formularz, i nic nie znaczą; mapa niżej wiąże je z etykietą stojącą NAD polem,
odczytaną z układu strony.

Dwie różnice między wzorami przesądzają o stronicowaniu:

  • raport SĘDZIÓW ma sześć ponumerowanych pól „decyzja wraz z uzasadnieniem",
    więc siódmy opis otwiera drugą stronę;
  • raport DELEGATA opisuje JEDEN incydent w trzech polach (opis, decyzje, inne
    informacje), więc każdy kolejny incydent to kolejna strona.

Trzy rzeczy, których nie da się zrobić „po prostu polem formularza":

1. **Druga strona.** Nazwy pól AcroForm są unikalne w obrębie dokumentu, więc
   wklejenie wzoru dwa razy do jednego pliku zostawia drugą kopię BEZ pól -
   sprawdzone, `page.widgets()` oddaje wtedy pustą listę. Dlatego każda strona
   powstaje w osobnym dokumencie, jest wypełniana i spiekana, a dopiero potem
   dokładana do wyniku.

2. **Polskie znaki.** Pola formularza mają w wyglądzie Helvetikę z
   WinAnsiEncoding - „Zażółć gęślą jaźń" wychodzi z niej jako ciąg pytajników.
   Dlatego tekst RYSUJEMY własną czcionką (Noto Sans, OFL, w `app/fonts/`),
   a pole tekstowe wcześniej kasujemy.

3. **Za długi opis.** Rubryki mają stałą wysokość, a opis incydentu potrafi
   mieć tysiąc znaków. Pismo zmniejsza się samo do granicy czytelności, a gdy
   i to nie starczy, generowanie KOŃCZY SIĘ BŁĘDEM z numerem opisu. Cicho
   obcięty raport jest gorszy niż brak raportu: sędzia wysłałby do związku
   dokument, w którym w połowie zdania urywa się opis czerwonej kartki.

PODPISY. Pola podpisu są typu Signature, czyli miejscem na podpis CYFROWY,
a my mamy obrazek narysowany palcem. Widget kasujemy, w jego prostokąt
wstawiamy PNG - wygląda tak samo i nie udaje kryptografii, której tu nie ma.
"""

from __future__ import annotations

import logging
import os
from io import BytesIO
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pymupdf

logger = logging.getLogger(__name__)

TEMPLATES = {
    "referees": "raport_sedziow.pdf",
    "delegate": "raport_delegata.pdf",
}

#: Ile pozycji mieści jedna strona. Lustro `ENTRIES_PER_PAGE`
#: w `utils/extraReportRules.ts` - obie liczby muszą się zgadzać, inaczej
#: aplikacja obiecuje inną liczbę stron, niż wychodzi z generatora.
ENTRIES_PER_PAGE = {"referees": 6, "delegate": 1}

FONT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts", "NotoSans-Regular.ttf")
FONT_ALIAS = "bazaNoto"

#: Pismo opisu: zaczynamy od czytelnego, schodzimy tylko tak nisko, jak trzeba.
AREA_MAX_SIZE = 9.0
AREA_MIN_SIZE = 6.0
#: Pola jednowierszowe (nazwiska, numer meczu, drużyny) - te wolno ścisnąć
#: mocniej, bo to krótkie napisy, a nie tekst do czytania akapitami.
LINE_MAX_SIZE = 9.5
LINE_MIN_SIZE = 5.5

#: Odsunięcie od krawędzi rubryki, żeby tekst nie kleił się do linii.
PAD_X = 3.0
PAD_Y = 2.0

FIELDS: Dict[str, Dict[str, Any]] = {
    "referees": {
        "names_top": ["text_1lixj", "text_2qyju"],
        "match": "text_3uppx",
        "teams": ["text_4txwc", "text_5lbcb"],
        "video_yes": "checkbox_6jvku",
        "video_no": "checkbox_7eeaz",
        "entries": [
            "textarea_8lnsz",
            "textarea_9rwlq",
            "textarea_10qcws",
            "textarea_11fjdk",
            "textarea_12lazy",
            "textarea_13crin",
        ],
        "names_bottom": ["text_14gnhm", "text_15gejn"],
        "signatures": ["signature_16nolx", "signature_17hmni"],
        "drop": [],
    },
    "delegate": {
        "names_top": ["text_1vxoa"],
        "match": "text_2cmkc",
        "teams": ["text_3tahl", "text_4snez"],
        "video_yes": "checkbox_11prfo",
        "video_no": "checkbox_12hvrg",
        "entries": {
            "incident": "textarea_5oiua",
            "decisions": "textarea_7oyhg",
            "other": "textarea_8eyfd",
        },
        "names_bottom": ["text_9qoqy"],
        "signatures": ["signature_14vgtl"],
        # Pole leżące POZA stroną (x od 555 przy szerokości 595) - zostało we
        # wzorze po edycji i nigdy się nie drukuje. Kasujemy, żeby nie zostało
        # po nim nic w spieczonym dokumencie.
        "drop": ["text_6qkh"],
    },
}

#: Etykiety pól opisowych - do komunikatu o zbyt długim opisie.
ENTRY_LABELS = {
    "incident": "Opis incydentu",
    "decisions": "Podjęte decyzje",
    "other": "Inne informacje",
}


class ExtraReportError(RuntimeError):
    """Nie da się złożyć raportu - i wiadomo dlaczego."""


def _template_path(kind: str, templates_dir: str) -> str:
    name = TEMPLATES.get(kind)
    if not name:
        raise ExtraReportError(f"Nieznany rodzaj raportu: {kind!r}")
    path = os.path.join(templates_dir, name)
    if not os.path.exists(path):
        raise ExtraReportError(f"Brak wzoru {name}")
    return path


def _entry_texts(kind: str, entry: Dict[str, Any]) -> Dict[str, str]:
    """Treść jednej pozycji sprowadzona do pól formularza."""
    if kind == "referees":
        return {"text": str(entry.get("text") or "").strip()}
    return {
        "incident": str(entry.get("incident") or "").strip(),
        "decisions": str(entry.get("decisions") or "").strip(),
        "other": str(entry.get("other") or "").strip(),
    }


def _is_filled(kind: str, entry: Dict[str, Any]) -> bool:
    return any(v for v in _entry_texts(kind, entry).values())


def paginate(kind: str, entries: Sequence[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """Podział pozycji na strony. Puste odpadają PRZED liczeniem."""
    filled = [e for e in (entries or []) if _is_filled(kind, e)]
    per = ENTRIES_PER_PAGE[kind]
    return [filled[i : i + per] for i in range(0, len(filled), per)]


# ── rysowanie tekstu ─────────────────────────────────────────────────────────


def _inset(rect: pymupdf.Rect) -> pymupdf.Rect:
    return pymupdf.Rect(
        rect.x0 + PAD_X,
        rect.y0 + PAD_Y,
        rect.x1 - PAD_X,
        rect.y1 - PAD_Y,
    )


def _draw_line(page, rect: pymupdf.Rect, text: str) -> None:
    """Jeden wiersz, wyśrodkowany w pionie, zwężany aż zmieści się w szerokość.

    Nazwa hali albo długa nazwa klubu nie ma prawa zablokować raportu, więc
    tutaj zamiast błędu jest zmniejszanie pisma - do granicy, poniżej której
    i tak nikt by tego nie odczytał.
    """
    text = (text or "").strip()
    if not text:
        return
    box = _inset(rect)
    font = pymupdf.Font(fontfile=FONT_PATH)
    size = LINE_MAX_SIZE
    while size > LINE_MIN_SIZE and font.text_length(text, fontsize=size) > box.width:
        size -= 0.25
    baseline = box.y0 + (box.height + size * 0.66) / 2
    page.insert_text(
        pymupdf.Point(box.x0, baseline),
        text,
        fontname=FONT_ALIAS,
        fontfile=FONT_PATH,
        fontsize=size,
    )


def _draw_area(page, rect: pymupdf.Rect, text: str) -> bool:
    """Akapit w rubryce. `False`, gdy nie mieści się nawet najmniejszym pismem."""
    text = (text or "").strip()
    if not text:
        return True
    box = _inset(rect)
    size = AREA_MAX_SIZE
    while size >= AREA_MIN_SIZE:
        rc = page.insert_textbox(
            box,
            text,
            fontname=FONT_ALIAS,
            fontfile=FONT_PATH,
            fontsize=size,
            align=pymupdf.TEXT_ALIGN_LEFT,
        )
        if rc >= 0:
            return True
        size -= 0.5
    return False


# ── składanie strony ─────────────────────────────────────────────────────────


def _widgets(page) -> Dict[str, Any]:
    return {w.field_name: w for w in (page.widgets() or [])}


def _take_rect(page, by_name: Dict[str, Any], field: str) -> Optional[pymupdf.Rect]:
    """Prostokąt pola i skasowanie samego pola - dalej rysujemy po nim sami."""
    w = by_name.get(field)
    if not w:
        return None
    rect = pymupdf.Rect(w.rect)
    try:
        page.delete_widget(w)
    except Exception:
        pass
    return rect


def _fill_page(
    page,
    *,
    kind: str,
    header: Dict[str, Any],
    entries: Sequence[Dict[str, Any]],
    signatures: Sequence[bytes],
    page_index: int,
) -> List[str]:
    """Wypełnia jedną stronę. Zwraca listę opisów, które się nie zmieściły."""
    spec = FIELDS[kind]
    by_name = _widgets(page)
    overflow: List[str] = []

    # Checkboxy zostają polami - bake narysuje je poprawnie, a znaczek „X"
    # nie ma polskich znaków, więc Helvetica z wyglądu pola wystarcza.
    video = bool(header.get("video"))
    for field, checked in ((spec["video_yes"], video), (spec["video_no"], not video)):
        w = by_name.get(field)
        if w:
            w.field_value = bool(checked)
            w.update()

    names = [str(n or "").strip() for n in (header.get("names") or [])]
    for slot, field in enumerate(spec["names_top"]):
        rect = _take_rect(page, by_name, field)
        if rect:
            _draw_line(page, rect, names[slot] if slot < len(names) else "")
    for slot, field in enumerate(spec["names_bottom"]):
        rect = _take_rect(page, by_name, field)
        if rect:
            _draw_line(page, rect, names[slot] if slot < len(names) else "")

    rect = _take_rect(page, by_name, spec["match"])
    if rect:
        _draw_line(page, rect, str(header.get("match") or ""))

    teams = [str(t or "").strip() for t in (header.get("teams") or [])]
    for slot, field in enumerate(spec["teams"]):
        rect = _take_rect(page, by_name, field)
        if rect:
            _draw_line(page, rect, teams[slot] if slot < len(teams) else "")

    per = ENTRIES_PER_PAGE[kind]
    if kind == "referees":
        for slot, field in enumerate(spec["entries"]):
            rect = _take_rect(page, by_name, field)
            if not rect:
                continue
            text = _entry_texts(kind, entries[slot])["text"] if slot < len(entries) else ""
            if not _draw_area(page, rect, text):
                overflow.append(f"opis nr {page_index * per + slot + 1}")
    else:
        entry = entries[0] if entries else {}
        texts = _entry_texts(kind, entry)
        for key, field in spec["entries"].items():
            rect = _take_rect(page, by_name, field)
            if not rect:
                continue
            if not _draw_area(page, rect, texts.get(key, "")):
                label = ENTRY_LABELS.get(key, key)
                overflow.append(f"{label} w incydencie nr {page_index + 1}")

    for field in spec.get("drop", []):
        _take_rect(page, by_name, field)

    for slot, field in enumerate(spec["signatures"]):
        rect = _take_rect(page, by_name, field)
        if not rect:
            continue
        img = signatures[slot] if slot < len(signatures) else None
        if not img:
            continue
        try:
            page.insert_image(rect, stream=img, keep_proportion=True, overlay=True)
        except Exception as exc:
            logger.warning("Nie udało się wstawić podpisu %s: %s", field, exc)

    return overflow


def _stamp_page_number(page, index: int, total: int) -> None:
    """Numer strony w dolnym marginesie - tylko gdy stron jest więcej niż jedna.

    Wzór nie ma na to rubryki, więc wpis idzie PONIŻEJ treści (podpisy kończą
    się na y≈779, strona ma 842). Bez tego dwie kartki tego samego raportu są
    po wydrukowaniu nie do rozróżnienia.
    """
    if total <= 1:
        return
    page.insert_text(
        pymupdf.Point(page.rect.width - 78, page.rect.height - 24),
        f"{index + 1} / {total}",
        fontname=FONT_ALIAS,
        fontfile=FONT_PATH,
        fontsize=8,
        color=(0.45, 0.45, 0.45),
    )


def build_extra_report_pdf(
    *,
    kind: str,
    header: Dict[str, Any],
    entries: Sequence[Dict[str, Any]],
    signatures: Optional[Sequence[bytes]] = None,
    templates_dir: str,
) -> bytes:
    """Gotowy PDF raportu - tyle stron, ile trzeba.

    `header` = {names: [...], match: "...", teams: [A, B], video: bool}
    `entries` w kształcie z aplikacji (patrz `utils/extraReportRules.ts`).
    """
    if kind not in TEMPLATES:
        raise ExtraReportError(f"Nieznany rodzaj raportu: {kind!r}")
    if not os.path.exists(FONT_PATH):
        # Bez własnej czcionki raport wyszedłby z pytajnikami zamiast polskich
        # znaków - lepiej nie wyprodukować go wcale.
        raise ExtraReportError("Brak czcionki raportu (app/fonts/NotoSans-Regular.ttf)")

    pages = paginate(kind, entries)
    if not pages:
        raise ExtraReportError("Raport jest pusty - nie ma czego generować.")

    template = _template_path(kind, templates_dir)
    sigs = list(signatures or [])
    out = pymupdf.open()
    overflow: List[str] = []
    try:
        for index, page_entries in enumerate(pages):
            # Każda strona w OSOBNYM dokumencie - patrz komentarz na górze
            # pliku: druga kopia wzoru w jednym pliku traci pola formularza.
            single = pymupdf.open(template)
            try:
                page = single[0]
                overflow += _fill_page(
                    page,
                    kind=kind,
                    header=header,
                    entries=page_entries,
                    signatures=sigs,
                    page_index=index,
                )
                _stamp_page_number(page, index, len(pages))
                try:
                    single.bake()
                except Exception as exc:
                    logger.warning("Nie udało się spiec formularza: %s", exc)
                out.insert_pdf(single, from_page=0, to_page=0)
            finally:
                single.close()

        if overflow:
            raise ExtraReportError(
                "Za długi tekst, nie mieści się w rubryce: "
                + ", ".join(overflow)
                + ". Skróć opis albo rozbij go na kolejną pozycję."
            )

        buf = BytesIO()
        out.save(buf, garbage=3, deflate=True)
        return buf.getvalue()
    finally:
        out.close()


def entry_capacity(kind: str, field: str = "text") -> Tuple[float, float]:
    """Wymiary rubryki w punktach - do policzenia budżetu znaków w aplikacji."""
    spec = FIELDS[kind]
    fields = spec["entries"]
    name = fields[0] if isinstance(fields, list) else fields[field]
    doc = pymupdf.open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", TEMPLATES[kind])
    )
    try:
        for w in doc[0].widgets() or []:
            if w.field_name == name:
                r = _inset(pymupdf.Rect(w.rect))
                return (r.width, r.height)
    finally:
        doc.close()
    raise ExtraReportError(f"Nie znaleziono pola {name}")
