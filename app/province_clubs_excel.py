"""
Szablon wplat i wyplat - eksport i import.

Okreg woli wypelnic jeden arkusz niz klikac po kilkudziesieciu klubach, wiec
panel generuje plik z gotowa lista druzyn, a po wgraniu czyta go z powrotem
i pokazuje podsumowanie do zatwierdzenia.

⚠ W pliku siedzi kolumna z NUMEREM DRUZYNY. Nazwe da sie w Excelu poprawic
albo skrocic i dopasowanie po nazwie by padlo; numer jest jedynym pewnym
kluczem. Kolumna jest wyszarzona i opisana, ale zostaje widoczna - ukryta
kolumna, ktora psuje import po edycji, byla by gorsza niz brzydsza tabela.

MODUL-LISC: buduje i czyta bajty skoroszytu, bez bazy i sieci.
"""

from __future__ import annotations

import io
import re
from typing import Any, Iterable, Optional

#: Naglowki w kolejnosci kolumn. Import szuka ich po nazwie, wiec kolejnosc
#: w pliku moze sie zmienic - nie zmieniaj samych NAPISOW.
HEADERS = [
    "Nr drużyny",
    "Klub",
    "Drużyna",
    "Kategoria",
    "Wpłata",
    "Opis wpłaty",
    "Wypłata",
    "Opis wypłaty",
]

NAVY = "0B4F9E"
GOLD = "F0A500"
IN_FILL = "E7F6EC"
IN_TEXT = "1B5E20"
OUT_FILL = "FDECEA"
OUT_TEXT = "B3261E"
MONEY_FORMAT = "#,##0.00 zł"


def _amount(value: Any) -> Optional[float]:
    """Kwota z komorki: liczba albo napis („1 200,50", „1200.5 zl", „-")."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    text = text.replace(" ", " ").replace(" ", "")
    text = re.sub(r"(?i)(zł|zl|pln)", "", text)
    text = text.replace(",", ".")
    text = re.sub(r"[^0-9.\-]", "", text)
    if not text or text in {"-", ".", "-."}:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def build_workbook(rows: Iterable[dict], *, title: str, subtitle: str = "") -> bytes:
    """
    Skoroszyt z lista druzyn i pustymi kolumnami na wplaty i wyplaty.

    `rows`: `{team_id, team_name, club_name, category}`.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = (re.sub(r"[\\/*?:\[\]]", " ", title) or "Wpłaty")[:31]

    sheet["A1"] = title
    sheet["A1"].font = Font(size=14, bold=True, color=NAVY)
    sheet["A2"] = subtitle or "Wypełnij kolumny Wpłata i Wypłata, potem wgraj plik z powrotem w panelu."
    sheet["A2"].font = Font(size=9, italic=True, color="6B7280")
    sheet.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(HEADERS))
    sheet.merge_cells(start_row=2, start_column=1, end_row=2, end_column=len(HEADERS))

    header_row = 4
    for index, name in enumerate(HEADERS, start=1):
        cell = sheet.cell(row=header_row, column=index, value=name)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=NAVY)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    widths = [12, 30, 32, 14, 14, 34, 14, 34]
    for index, width in enumerate(widths, start=1):
        sheet.column_dimensions[get_column_letter(index)].width = width

    grey = Font(color="9AA1AC", size=9)
    for offset, row in enumerate(rows):
        line = header_row + 1 + offset
        sheet.cell(row=line, column=1, value=str(row.get("team_id") or "")).font = grey
        sheet.cell(row=line, column=2, value=str(row.get("club_name") or ""))
        sheet.cell(row=line, column=3, value=str(row.get("team_name") or ""))
        sheet.cell(row=line, column=4, value=str(row.get("category") or ""))
        for column in (5, 6):
            cell = sheet.cell(row=line, column=column)
            cell.fill = PatternFill("solid", fgColor=IN_FILL)
            cell.font = Font(color=IN_TEXT, bold=column == 5)
        for column in (7, 8):
            cell = sheet.cell(row=line, column=column)
            cell.fill = PatternFill("solid", fgColor=OUT_FILL)
            cell.font = Font(color=OUT_TEXT, bold=column == 7)
        sheet.cell(row=line, column=5).number_format = MONEY_FORMAT
        sheet.cell(row=line, column=7).number_format = MONEY_FORMAT

    sheet.freeze_panes = sheet.cell(row=header_row + 1, column=1)

    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def parse_workbook(data: bytes) -> list[dict]:
    """
    Czyta wypelniony szablon. Zwraca wiersze z kwotami - puste pomija.

    Kazdy wiersz to `{row, team_id, team_name, club_name, in_amount, in_note,
    out_amount, out_note}`. Nic nie waliduje wzgledem bazy - to robi panel,
    ktory zna aktualna liste druzyn.
    """
    from openpyxl import load_workbook

    workbook = load_workbook(io.BytesIO(data), data_only=True)
    out: list[dict] = []

    for sheet in workbook.worksheets:
        header_row = None
        columns: dict[str, int] = {}
        for row in sheet.iter_rows(min_row=1, max_row=12):
            values = {
                str(cell.value).strip(): cell.column
                for cell in row
                if cell.value is not None and str(cell.value).strip()
            }
            if "Drużyna" in values and ("Wpłata" in values or "Wypłata" in values):
                header_row = row[0].row
                columns = values
                break
        if header_row is None:
            continue

        def get(row_cells, name: str) -> Any:
            index = columns.get(name)
            if not index:
                return None
            cell = row_cells[index - 1] if index - 1 < len(row_cells) else None
            return cell.value if cell is not None else None

        for row_cells in sheet.iter_rows(min_row=header_row + 1):
            team_name = str(get(row_cells, "Drużyna") or "").strip()
            team_id = str(get(row_cells, "Nr drużyny") or "").strip()
            in_amount = _amount(get(row_cells, "Wpłata"))
            out_amount = _amount(get(row_cells, "Wypłata"))
            if not team_name and not team_id:
                continue
            if not in_amount and not out_amount:
                continue
            out.append(
                {
                    "row": row_cells[0].row,
                    "sheet": sheet.title,
                    "team_id": team_id,
                    "team_name": team_name,
                    "club_name": str(get(row_cells, "Klub") or "").strip(),
                    "category": str(get(row_cells, "Kategoria") or "").strip(),
                    "in_amount": round(in_amount, 2) if in_amount else None,
                    "in_note": str(get(row_cells, "Opis wpłaty") or "").strip(),
                    "out_amount": round(out_amount, 2) if out_amount else None,
                    "out_note": str(get(row_cells, "Opis wypłaty") or "").strip(),
                }
            )

    return out
