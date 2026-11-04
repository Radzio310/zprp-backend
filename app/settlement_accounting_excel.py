"""
Skoroszyt księgowej (04.11.2026) - plik do wczytania ryczałtów w enova365.

Szablon to skoroszyt księgowej 1:1 (`templates/ksiegowa_ryczalty.xlsx`:
„Import", „dane do importu", „Zestaw. umów", „Uwagi" ze zrzutami enova), bez
jej danych. Na początek dochodzi zakładka „Ryczałty sędziowskie" - źródło,
z którego dane PRZERZUCAJĄ SIĘ formułami: Ryczałty sędziowskie → dane do
importu → Import (formuły zakładki Import są jej, bez zmian). Księgowa
poprawia kod albo kwotę w jednym miejscu, reszta idzie za tym sama.

Formuły dostają też gotowy wynik (wartość z pamięci podręcznej), więc plik
czyta się poprawnie także w podglądzie na telefonie i w poczcie, które
niczego nie przeliczają. Excel i tak przelicza wszystko przy otwarciu.

MODUŁ BEZ BAZY: wejście to wiersze z `settlement_accounting_rules.sheet_rows`
i metryka dokumentu - żeby cały plik dało się sprawdzić w teście.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Optional
from xml.sax.saxutils import escape

from app import settlement_accounting_rules as A

TEMPLATE = Path(__file__).resolve().parent / "templates" / "ksiegowa_ryczalty.xlsx"

SUMMARY = "Ryczałty sędziowskie"
IMPORT = "Import"
DATA = "dane do importu"
NOTES = "Uwagi"

#: Pierwszy wiersz danych w zakładce „Ryczałty sędziowskie" (nad nim nagłówek).
FIRST = 7
HEADER = FIRST - 1

#: Barwy BAZA: granat i złoto z PDF-u zestawienia, pomarańcz szkicu.
NAVY = "0B4F9E"
GOLD = "F0A500"
INK = "16233C"
MUTED = "5A6478"
ZEBRA = "F4F7FC"
SOFT_GOLD = "FFF8E8"
DRAFT = "E8590C"
DRAFT_SOFT = "FFF1E6"
WARN = "FFE8B3"
ALERT = "FAD4D1"
OK = "E3F4EA"

#: Format kwot księgowej: „1 234,56", zero jako kreska.
MONEY = "#,##0.00;\\-#,##0.00;\\-"
DATE = "dd.mm.yyyy"


@dataclass
class Meta:
    #: Numer na dokumencie; na szkicu - podpowiedź rejestru.
    number: str
    draft: bool
    org_name: str
    period_from: Optional[date]
    period_to: Optional[date]
    period_label: str
    payout_date: Optional[date]
    formula: str
    enova: dict = field(default_factory=lambda: dict(A.ENOVA_DEFAULTS))
    list_letter: str = ""
    generated_at: Optional[datetime] = None


def _excel_serial(day: date) -> float:
    return float((day - date(1899, 12, 30)).days)


class _Cache:
    """Wyniki formuł do wpisania w plik: {arkusz: {„B7": wartość}}."""

    def __init__(self) -> None:
        self.values: dict[str, dict[str, Any]] = {}

    def put(self, sheet: str, coord: str, value: Any) -> None:
        self.values.setdefault(sheet, {})[coord] = value


def build_workbook(rows: list[A.SheetRow], meta: Meta) -> bytes:
    """Gotowy plik .xlsx (bajty)."""
    from openpyxl import load_workbook

    wb = load_workbook(TEMPLATE)
    cache = _Cache()
    summary = wb.create_sheet(SUMMARY, 0)
    _summary_sheet(summary, rows, meta, cache)
    _data_sheet(wb[DATA], rows, meta, cache)
    _import_sheet(wb[IMPORT], wb[NOTES], rows, meta, cache)
    if meta.draft:
        for ws in wb.worksheets:
            ws.sheet_properties.tabColor = DRAFT
    else:
        summary.sheet_properties.tabColor = GOLD
        wb[IMPORT].sheet_properties.tabColor = NAVY
    wb.active = 0
    for ws in wb.worksheets:
        ws.sheet_view.tabSelected = ws.title == SUMMARY
    wb.properties.creator = "BAZA"
    wb.properties.lastModifiedBy = "BAZA"
    wb.properties.title = f"Ryczałty sędziowskie {meta.number}".strip()
    buffer = io.BytesIO()
    wb.save(buffer)
    return _inject_cached(buffer.getvalue(), cache.values)


# ---------------------------------------------------------------------------
# „Ryczałty sędziowskie" - źródło i kontrola
# ---------------------------------------------------------------------------

COLUMNS = [
    ("A", "Lp", 5),
    ("B", "Nazwisko", 22),
    ("C", "Imię", 15),
    ("D", "Kod w enova", 19),
    ("E", "Numer dokumentu", 16),
    ("F", "Okres", 23),
    ("G", "Data wypłaty", 13),
    ("H", "Kwota brutto", 14),
    ("I", "KUP", 12),
    ("J", "Podstawa opodatkowania", 15),
    ("K", "Podatek", 11),
    ("L", "Do wypłaty", 14),
    ("M", "Uwagi", 46),
]


def _summary_sheet(ws, rows: list[A.SheetRow], meta: Meta, cache: _Cache) -> None:
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.worksheet.page import PageMargins

    fill = lambda color: PatternFill("solid", fgColor=color)  # noqa: E731
    thin = Side(style="thin", color="D7DCE6")
    grid = Border(left=thin, right=thin, top=thin, bottom=thin)
    last_col = COLUMNS[-1][0]

    for letter, _title, width in COLUMNS:
        ws.column_dimensions[letter].width = width
    ws.sheet_view.showGridLines = False
    ws.sheet_view.zoomScale = 110

    # Pas tytułowy.
    ws.merge_cells(f"A1:{last_col}1")
    ws["A1"] = "RYCZAŁTY SĘDZIOWSKIE"
    ws["A1"].font = Font(name="Calibri", size=18, bold=True, color="FFFFFF")
    ws["A1"].fill = fill(NAVY)
    ws["A1"].alignment = Alignment(vertical="center", indent=1)
    ws.row_dimensions[1].height = 34

    number = meta.number or "bez numeru"
    title = f"Zestawienie {number}" + (" (szkic)" if meta.draft else "")
    period = A.period_text(meta.period_from, meta.period_to) or meta.period_label
    bits = [title, meta.org_name, f"okres {period}" if period else ""]
    if meta.list_letter:
        bits.append(f"lista {meta.list_letter}")
    ws.merge_cells(f"A2:{last_col}2")
    ws["A2"] = "  ·  ".join(b for b in bits if b)
    ws["A2"].font = Font(name="Calibri", size=12, bold=True, color=INK)
    ws["A2"].fill = fill(SOFT_GOLD)
    ws["A2"].alignment = Alignment(vertical="center", indent=1)
    ws.row_dimensions[2].height = 24

    made = (meta.generated_at or datetime.now()).strftime("%d.%m.%Y %H:%M")
    ws.merge_cells(f"A3:{last_col}3")
    ws["A3"] = (
        f"Data wypłaty: {A.pl_date(meta.payout_date) or 'do uzupełnienia'}"
        f"  ·  Formuła podatku: {A.formula_label(meta.formula)}"
        f"  ·  Wygenerowano w BAZA {made}"
    )
    ws["A3"].font = Font(name="Calibri", size=9.5, color=MUTED)
    ws["A3"].alignment = Alignment(vertical="center", indent=1)

    ws.merge_cells(f"A4:{last_col}4")
    if meta.draft:
        ws["A4"] = (
            f"SZKIC - NIE IMPORTOWAĆ DO ENOVA. Numer {meta.number or '-'} to tylko podpowiedź rejestru, "
            "a kolumna Opis w zakładce Import jest pusta. Plik do importu powstaje z oficjalnego dokumentu w Rejestrze."
        )
        ws["A4"].font = Font(name="Calibri", size=10, bold=True, color="FFFFFF")
        ws["A4"].fill = fill(DRAFT)
    else:
        last = len(rows) + 1
        ws["A4"] = (
            f"Gotowe do importu: zakładka „Import”, wiersze 2–{last} → enova, Podgląd tabel | Kadry | Umowa. "
            "Zmiana kodu albo kwoty tutaj przenosi się sama do „dane do importu” i „Import”."
        )
        ws["A4"].font = Font(name="Calibri", size=10, bold=True, color="0E5A2E")
        ws["A4"].fill = fill(OK)
    ws["A4"].alignment = Alignment(vertical="center", indent=1, wrap_text=True)
    ws.row_dimensions[4].height = 30

    # Nagłówek tabeli.
    for letter, label, _width in COLUMNS:
        cell = ws[f"{letter}{HEADER}"]
        cell.value = label
        cell.font = Font(name="Calibri", size=9.5, bold=True, color="FFFFFF")
        cell.fill = fill(NAVY)
        cell.border = grid
        cell.alignment = Alignment(
            horizontal="left" if letter in "BCDEFM" else "center" if letter == "A" else "right",
            vertical="center",
            wrap_text=True,
        )
    ws.row_dimensions[HEADER].height = 30

    period_text = A.period_text(meta.period_from, meta.period_to)
    other_label = A.formula_short(A.other_formula(meta.formula))
    for index, row in enumerate(rows):
        r = FIRST + index
        values = {
            "A": index + 1,
            "B": row.surname,
            "C": row.given,
            "D": row.code,
            "E": meta.number,
            "F": period_text,
            "G": meta.payout_date,
            "H": row.gross,
            "I": row.costs,
            "J": row.taxable,
            "K": row.tax,
            "L": row.net,
            "M": row.note(other_label),
        }
        for letter, value in values.items():
            cell = ws[f"{letter}{r}"]
            cell.value = value
            cell.border = grid
            cell.font = Font(name="Calibri", size=10, color=INK, bold=letter in ("B", "L"))
            if index % 2:
                cell.fill = fill(ZEBRA)
            if letter in "HIJKL":
                cell.number_format = MONEY
                cell.alignment = Alignment(horizontal="right")
            elif letter == "G":
                cell.number_format = DATE
                cell.alignment = Alignment(horizontal="center")
            elif letter == "A":
                cell.alignment = Alignment(horizontal="center")
                cell.font = Font(name="Calibri", size=9, color=MUTED)
            elif letter == "M":
                cell.font = Font(name="Calibri", size=9, color=MUTED)
                cell.alignment = Alignment(wrap_text=True, vertical="top")
        ws[f"L{r}"].fill = fill(SOFT_GOLD)
        if row.code_conflict:
            ws[f"D{r}"].fill = fill(ALERT)
        elif row.code_source != "saved":
            ws[f"D{r}"].fill = fill(WARN)
        if row.differs:
            ws[f"K{r}"].fill = fill(WARN)

    # Suma.
    total_row = FIRST + len(rows)
    sums = A.totals(rows)
    ws[f"B{total_row}"] = "RAZEM"
    for letter in "ABCDEFGM":
        cell = ws[f"{letter}{total_row}"]
        cell.fill = fill("EAF1FB")
        cell.border = Border(top=Side(style="medium", color=NAVY))
    ws[f"B{total_row}"].font = Font(name="Calibri", size=10.5, bold=True, color=NAVY)
    ws[f"G{total_row}"] = f"{sums['people']} os."
    ws[f"G{total_row}"].font = Font(name="Calibri", size=9, color=MUTED)
    ws[f"G{total_row}"].alignment = Alignment(horizontal="center")
    for letter, key in (("H", "gross"), ("I", "costs"), ("J", "taxable"), ("K", "tax"), ("L", "net")):
        coord = f"{letter}{total_row}"
        ws[coord] = f"=SUM({letter}{FIRST}:{letter}{total_row - 1})" if rows else 0
        if rows:
            cache.put(SUMMARY, coord, sums[key])
        ws[coord].number_format = MONEY
        ws[coord].font = Font(name="Calibri", size=10.5, bold=True, color="2A1C00" if letter == "L" else NAVY)
        ws[coord].fill = fill(GOLD if letter == "L" else "EAF1FB")
        ws[coord].border = Border(top=Side(style="medium", color=NAVY))
        ws[coord].alignment = Alignment(horizontal="right")
    ws.row_dimensions[total_row].height = 22

    # Kontrola - to, co księgowa sprawdza przed importem.
    box = total_row + 2
    checks = [
        ("Osób / wierszy importu", f"{sums['people']} / {sums['rows']}", None),
        (
            "Kody do potwierdzenia",
            "brak" if not sums["unconfirmed"] else f"{sums['unconfirmed']} - podpowiedziane z nazwiska (żółte)",
            WARN if sums["unconfirmed"] else OK,
        ),
        (
            "Ten sam kod u dwóch osób",
            "brak" if not sums["conflicts"] else f"{sums['conflicts']} - popraw przed importem (czerwone)",
            ALERT if sums["conflicts"] else OK,
        ),
        (
            f"Inny podatek {other_label}",
            "żadnego wiersza" if not sums["differs"] else f"{sums['differs']} wiersz(e) - różnica 1 zł (żółte)",
            WARN if sums["differs"] else OK,
        ),
    ]
    ws.merge_cells(f"A{box}:D{box}")
    ws[f"A{box}"] = "KONTROLA PRZED IMPORTEM"
    ws[f"A{box}"].font = Font(name="Calibri", size=9, bold=True, color=MUTED)
    for offset, (label, value, color) in enumerate(checks, start=1):
        r = box + offset
        ws.merge_cells(f"A{r}:D{r}")
        ws.merge_cells(f"E{r}:H{r}")
        ws[f"A{r}"] = label
        ws[f"A{r}"].font = Font(name="Calibri", size=10, color=INK)
        ws[f"E{r}"] = value
        ws[f"E{r}"].font = Font(name="Calibri", size=10, bold=True, color=INK)
        if color:
            for letter in "EFGH":
                ws[f"{letter}{r}"].fill = fill(color)

    ws.freeze_panes = f"C{FIRST}"
    if rows:
        ws.auto_filter.ref = f"A{HEADER}:{last_col}{total_row - 1}"
    ws.print_title_rows = f"{HEADER}:{HEADER}"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.paperSize = ws.PAPERSIZE_A4
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_margins = PageMargins(left=0.4, right=0.4, top=0.5, bottom=0.5)
    ws.oddFooter.right.text = "str. &P z &N"
    ws.oddFooter.left.text = f"Ryczałty sędziowskie {meta.number}"


def _ref(column: str, index: int) -> str:
    return f"='{SUMMARY}'!{column}{FIRST + index}"


# ---------------------------------------------------------------------------
# „dane do importu" - jej zakładka, kolumny jak u niej
# ---------------------------------------------------------------------------

def _data_sheet(ws, rows: list[A.SheetRow], meta: Meta, cache: _Cache) -> None:
    from openpyxl.styles import Font

    period_text = A.period_text(meta.period_from, meta.period_to)
    ws["B1"] = "Nazwisko i imię"
    for index, row in enumerate(rows):
        r = 2 + index
        own = A.tax_parts(row.gross, meta.formula)
        formulas = A.excel_formulas(meta.formula, r)
        cells = {
            "B": (f"={_ref('B', index)[1:]}&\" \"&{_ref('C', index)[1:]}", row.name),
            "C": (_ref("D", index), row.code),
            "D": (_ref("C", index), row.given),
            "E": (_ref("F", index), period_text),
            "F": (_ref("E", index), meta.number),
            "G": (_ref("G", index), meta.payout_date),
            "H": (_ref("H", index), row.gross),
            "I": (formulas["I"], own["costs"]),
            "J": (formulas["J"], own["taxable"]),
            "K": (formulas["K"], own["tax"]),
            "L": (formulas["L"], own["net"]),
        }
        for letter, (formula, value) in cells.items():
            coord = f"{letter}{r}"
            ws[coord] = formula
            cache.put(DATA, coord, value)
            if letter == "G":
                ws[coord].number_format = DATE
            elif letter in "HIJKL":
                ws[coord].number_format = MONEY
    if meta.draft:
        ws["N1"] = "SZKIC - nie importować"
        ws["N1"].font = Font(name="Calibri", bold=True, color=DRAFT)


# ---------------------------------------------------------------------------
# „Import" - kolumny enova, formuły księgowej
# ---------------------------------------------------------------------------

def _import_sheet(ws, notes, rows: list[A.SheetRow], meta: Meta, cache: _Cache) -> None:
    from openpyxl.styles import Font

    enova = {**A.ENOVA_DEFAULTS, **(meta.enova or {})}
    # Element:Nazwa szedł u księgowej formułą =Uwagi!$A$18. Zostaje, póki
    # w „Uwagach" stoi ten sam element; inny element z ustawień - wprost.
    element_ref = notes["A18"].value == enova["element"]
    day = meta.period_to
    period_enova = A.period_text(meta.period_from, meta.period_to, enova=True)
    for index, row in enumerate(rows):
        r = 2 + index
        data_ref = f"'{DATA}'!"
        cells: dict[str, tuple[Any, Any]] = {
            "A": (enova["class"], None),
            "B": (enova["definition"], None),
            "C": (f"={data_ref}C{r}", row.code),
            "D": (day, None),
            "E": (enova["department"], None),
            "F": (enova["series"], None),
            # Szkic: pusty Opis - bez numeru enova nie przyjmie umowy po cichu.
            "G": (None, None) if meta.draft else (f"={data_ref}F{r}", meta.number),
            "H": (enova["title"], None),
            "I": (f"=SUBSTITUTE({data_ref}E{r},\"…\",\"...\")", period_enova),
            "J": (f"={data_ref}H{r}", row.gross),
            "K": ("=Uwagi!$A$18", enova["element"]) if element_ref else (enova["element"], None),
            "L": (enova["settlement"], None),
        }
        for letter, (value, cached) in cells.items():
            coord = f"{letter}{r}"
            ws[coord] = value
            if cached is not None:
                cache.put(IMPORT, coord, cached)
        ws[f"D{r}"].number_format = DATE
        ws[f"J{r}"].number_format = MONEY
    if meta.draft:
        ws["W1"] = "SZKIC - nie importować (Opis pusty)"
        ws["W1"].font = Font(name="Calibri", bold=True, color=DRAFT)


# ---------------------------------------------------------------------------
# Wyniki formuł w pliku
# ---------------------------------------------------------------------------

_SHEET_TAG = re.compile(r'<sheet\b[^>]*?name="([^"]+)"[^>]*?r:id="([^"]+)"')
_REL_TAG = re.compile(r'<Relationship\b[^>]*?Target="([^"]+)"[^>]*?Id="([^"]+)"|<Relationship\b[^>]*?Id="([^"]+)"[^>]*?Target="([^"]+)"')


def _sheet_paths(archive: zipfile.ZipFile) -> dict[str, str]:
    from html import unescape

    book = archive.read("xl/workbook.xml").decode("utf-8")
    rels = archive.read("xl/_rels/workbook.xml.rels").decode("utf-8")
    targets: dict[str, str] = {}
    for match in _REL_TAG.finditer(rels):
        target, rid = (match.group(1), match.group(2)) if match.group(1) else (match.group(4), match.group(3))
        targets[rid] = target.lstrip("/") if target.startswith("/") else f"xl/{target}"
    return {unescape(name): targets.get(rid, "") for name, rid in _SHEET_TAG.findall(book)}


def _cached_xml(value: Any) -> tuple[str, str]:
    """(atrybut typu, zawartość <v>) dla wyniku formuły."""
    if isinstance(value, bool):
        return ' t="b"', "1" if value else "0"
    if isinstance(value, datetime):
        value = value.date()
    if isinstance(value, date):
        return "", repr(_excel_serial(value))
    if isinstance(value, (int, float)):
        return "", repr(float(value)) if isinstance(value, float) else str(value)
    return ' t="str"', escape(str(value))


def _inject_cached(data: bytes, values: dict[str, dict[str, Any]]) -> bytes:
    """
    Wpisuje wyniki formuł (<v>) w arkusze. openpyxl zapisuje formułę z pustym
    wynikiem - Excel przelicza ją przy otwarciu (`fullCalcOnLoad`), ale podgląd
    w telefonie i w poczcie pokazałby puste kolumny.
    """
    if not values:
        return data
    source = zipfile.ZipFile(io.BytesIO(data))
    paths = _sheet_paths(source)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            payload = source.read(info.filename)
            sheet = next((name for name, path in paths.items() if path == info.filename), None)
            if sheet and values.get(sheet):
                cells = values[sheet]

                def fill(match: re.Match) -> str:
                    coord, attrs, formula = match.group(1), match.group(2) or "", match.group(3)
                    if coord not in cells:
                        return match.group(0)
                    kind, text = _cached_xml(cells[coord])
                    attrs = re.sub(r'\s+t="[^"]*"', "", attrs)
                    return f'<c r="{coord}"{attrs}{kind}><f>{formula}</f><v>{text}</v></c>'

                xml = payload.decode("utf-8")
                xml = re.sub(
                    r'<c r="([A-Z]+[0-9]+)"((?:\s+[a-z]+="[^"]*")*)><f>(.*?)</f>(?:<v\s*/>|<v></v>)?</c>',
                    fill,
                    xml,
                )
                payload = xml.encode("utf-8")
            target.writestr(info, payload)
    return out.getvalue()
