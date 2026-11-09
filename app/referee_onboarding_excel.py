"""Odczyt pliku z listą nowych sędziów (kreator BAZA_web, 09.11.2026) - bez bazy i sieci.

Przyjmuje .xlsx / .xlsm (openpyxl), stare .xls (xlrd) i .csv / .tsv / .txt.
Zwraca SUROWE wiersze z numerem wiersza z arkusza i znacznikiem `hidden`
(ukryty ręcznie, zwinięty w grupie albo odfiltrowany) - rozpoznanie kolumn,
normalizacja i walidacja dzieją się w kreatorze, żeby każda poprawka była
widoczna od razu. Komórki są napisami: daty jako RRRR-MM-DD, liczby całkowite
bez „.0" (PESEL z Excela przychodzi jako liczba).
"""

from __future__ import annotations

import csv
import datetime as _dt
import io
from typing import Any, Dict, List

MAX_ROWS = 3000
MAX_COLS = 80
MAX_BYTES = 8 * 1024 * 1024


class SheetError(ValueError):
    """Pliku nie da się odczytać - komunikat idzie do użytkownika."""


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "TAK" if value else "NIE"
    if isinstance(value, _dt.datetime):
        if value.time() == _dt.time(0, 0):
            return value.date().isoformat()
        return value.strftime("%Y-%m-%d %H:%M")
    if isinstance(value, _dt.date):
        return value.isoformat()
    if isinstance(value, _dt.time):
        return value.strftime("%H:%M")
    if isinstance(value, float):
        if value.is_integer() and abs(value) < 1e15:
            return str(int(value))
        return repr(value)
    return str(value).replace("\r\n", "\n").strip()


def _trim(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Bez pustych wierszy i pustych kolumn na końcu."""
    rows = [r for r in rows if any(c for c in r["cells"])]
    width = 0
    for r in rows:
        for i in range(len(r["cells"]) - 1, -1, -1):
            if r["cells"][i]:
                width = max(width, i + 1)
                break
    for r in rows:
        r["cells"] = (r["cells"] + [""] * width)[:width]
    return rows


def _sheet(name: str, hidden: bool, rows: List[Dict[str, Any]], hidden_cols: List[int]) -> Dict[str, Any]:
    rows = _trim(rows)
    width = len(rows[0]["cells"]) if rows else 0
    return {
        "name": name,
        "hidden": hidden,
        "rows": rows,
        "hidden_columns": sorted(c for c in hidden_cols if c < width),
        "hidden_rows": sum(1 for r in rows if r["hidden"]),
        "truncated": False,
    }


def _read_xlsx(data: bytes) -> List[Dict[str, Any]]:
    from openpyxl import load_workbook
    from openpyxl.utils import column_index_from_string

    # read_only=False: tylko wtedy openpyxl czyta wymiary wierszy (ukrycie).
    wb = load_workbook(io.BytesIO(data), data_only=True)
    sheets = []
    for ws in wb.worksheets:
        hidden_rows = {idx for idx, dim in ws.row_dimensions.items() if dim.hidden}
        hidden_cols: List[int] = []
        for key, dim in ws.column_dimensions.items():
            if not dim.hidden:
                continue
            lo = dim.min or column_index_from_string(key)
            hi = dim.max or lo
            hidden_cols.extend(range(lo - 1, min(hi, MAX_COLS)))
        rows = []
        truncated = False
        for idx, values in enumerate(ws.iter_rows(max_col=MAX_COLS, values_only=True), start=1):
            if len(rows) >= MAX_ROWS:
                truncated = True
                break
            rows.append({"row": idx, "hidden": idx in hidden_rows, "cells": [_cell(v) for v in values]})
        sheet = _sheet(ws.title, ws.sheet_state != "visible", rows, hidden_cols)
        sheet["truncated"] = truncated
        sheets.append(sheet)
    return sheets


def _read_xls(data: bytes) -> List[Dict[str, Any]]:
    import xlrd

    try:
        book = xlrd.open_workbook(file_contents=data, formatting_info=True)
        formatting = True
    except Exception:  # noqa: BLE001 - część plików .xls nie ma formatowania czytelnego dla xlrd
        book = xlrd.open_workbook(file_contents=data)
        formatting = False
    sheets = []
    for sh in book.sheets():
        rows = []
        for r in range(min(sh.nrows, MAX_ROWS)):
            cells = []
            for c in range(min(sh.ncols, MAX_COLS)):
                cell = sh.cell(r, c)
                if cell.ctype == xlrd.XL_CELL_DATE:
                    try:
                        cells.append(_cell(xlrd.xldate_as_datetime(cell.value, book.datemode)))
                        continue
                    except Exception:  # noqa: BLE001
                        pass
                cells.append(_cell(cell.value))
            info = sh.rowinfo_map.get(r) if formatting else None
            rows.append({"row": r + 1, "hidden": bool(info and info.hidden), "cells": cells})
        hidden_cols = (
            [c for c, info in sh.colinfo_map.items() if info.hidden] if formatting else []
        )
        sheet = _sheet(sh.name, getattr(sh, "visibility", 0) != 0, rows, hidden_cols)
        sheet["truncated"] = sh.nrows > MAX_ROWS
        sheets.append(sheet)
    return sheets


def _decode_text(data: bytes) -> str:
    for enc in ("utf-8-sig", "cp1250", "iso-8859-2"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _read_csv(data: bytes) -> List[Dict[str, Any]]:
    text = _decode_text(data)
    sample = text[:4096]
    try:
        delimiter = csv.Sniffer().sniff(sample, delimiters=";,\t|").delimiter
    except csv.Error:
        counts = {d: sample.count(d) for d in (";", ",", "\t", "|")}
        delimiter = max(counts, key=counts.get)
    rows = []
    for idx, values in enumerate(csv.reader(io.StringIO(text), delimiter=delimiter), start=1):
        if len(rows) >= MAX_ROWS:
            break
        rows.append({"row": idx, "hidden": False, "cells": [_cell(v) for v in values[:MAX_COLS]]})
    return [_sheet("CSV", False, rows, [])]


def detect_kind(data: bytes, filename: str = "") -> str:
    name = (filename or "").lower()
    if data[:2] == b"PK":
        return "xlsx"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "xls"
    if name.endswith((".ods", ".numbers")):
        raise SheetError("Ten format nie jest obsługiwany - zapisz plik jako .xlsx albo .csv.")
    return "csv"


def read_table(data: bytes, filename: str = "") -> Dict[str, Any]:
    if not data:
        raise SheetError("Plik jest pusty.")
    if len(data) > MAX_BYTES:
        raise SheetError("Plik jest za duży (limit 8 MB).")
    kind = detect_kind(data, filename)
    try:
        if kind == "xlsx":
            sheets = _read_xlsx(data)
        elif kind == "xls":
            sheets = _read_xls(data)
        else:
            sheets = _read_csv(data)
    except SheetError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SheetError(f"Nie udało się odczytać pliku ({kind}): {exc}") from exc
    sheets = [sh for sh in sheets if sh["rows"]]
    if not sheets:
        raise SheetError("W pliku nie ma żadnych danych.")
    return {"file_name": filename, "kind": kind, "sheets": sheets}
