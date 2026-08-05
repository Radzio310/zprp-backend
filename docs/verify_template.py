# -*- coding: utf-8 -*-
"""Sprawdza, że nowy szablon to dokładnie stary przesunięty o jedną kolumnę."""
import os
from openpyxl import load_workbook
from openpyxl.utils import column_index_from_string, get_column_letter
from openpyxl.utils.cell import coordinate_from_string

TPL = r"c:\Users\radek\Desktop\BAZA_ALL\zprp-backend\app\templates"
OLD = os.path.join(TPL, "protocol_template_BACKUP_preExamCol.xlsx")
NEW = os.path.join(TPL, "protocol_template.xlsx")

SHIFT = 1


def shift(ref: str) -> str:
    col, row = coordinate_from_string(ref.replace("$", ""))
    return "%s%d" % (get_column_letter(column_index_from_string(col) + SHIFT), row)


wb_old = load_workbook(OLD)
wb_new = load_workbook(NEW)
ws_old, ws_new = wb_old.active, wb_new.active

problems = []

# 1) wartości komórek
checked = 0
for row in ws_old.iter_rows():
    for cell in row:
        if cell.value is None:
            continue
        checked += 1
        tgt = shift(cell.coordinate)
        got = ws_new[tgt].value
        want = cell.value
        # Formuła musi wskazywać na PRZESUNIĘTĄ komórkę — inaczej =C4 pokazywałoby
        # sąsiada zamiast nazwy drużyny.
        if isinstance(want, str) and want.startswith("="):
            want = "=" + shift(want[1:])
        if got != want:
            problems.append("wartość %s -> %s: %r != %r" % (cell.coordinate, tgt, want, got))

# 2) nowa kolumna A musi być pusta
for r in range(1, ws_new.max_row + 1):
    if ws_new.cell(row=r, column=1).value is not None:
        problems.append("nowa kolumna A niepusta w wierszu %d" % r)

# 3) scalenia
old_m = sorted(str(m) for m in ws_old.merged_cells.ranges)
new_m = sorted(str(m) for m in ws_new.merged_cells.ranges)
if len(old_m) != len(new_m):
    problems.append("liczba scaleń %d != %d" % (len(old_m), len(new_m)))
else:
    exp = sorted(":".join(shift(p) for p in m.split(":")) for m in old_m)
    if exp != new_m:
        diff = [(a, b) for a, b in zip(exp, new_m) if a != b][:5]
        problems.append("scalenia się różnią, np. %r" % diff)

# 4) szerokości kolumn
for letter, dim in ws_old.column_dimensions.items():
    if dim.width is None:
        continue
    tgt = get_column_letter(column_index_from_string(letter) + SHIFT)
    got = ws_new.column_dimensions[tgt].width
    if got is None or abs(got - dim.width) > 1e-6:
        problems.append("szerokość %s -> %s: %r != %r" % (letter, tgt, dim.width, got))

new_a = ws_new.column_dimensions["A"].width
if new_a is None or new_a < 3:
    problems.append("nowa kolumna A ma szerokość %r" % new_a)

# 5) wysokości wierszy
for r, dim in ws_old.row_dimensions.items():
    got = ws_new.row_dimensions[r].height
    if dim.height is not None and (got is None or abs(got - dim.height) > 1e-6):
        problems.append("wysokość wiersza %s: %r != %r" % (r, dim.height, got))

# 6) obrazki
if len(ws_old._images) != len(ws_new._images):
    problems.append("liczba obrazków %d != %d" % (len(ws_old._images), len(ws_new._images)))

# 7) obszar wydruku
print("print_area stary:", ws_old.print_area, " nowy:", ws_new.print_area)
print("scale stary:", ws_old.page_setup.scale, " nowy:", ws_new.page_setup.scale)

print("sprawdzonych komórek:", checked)
print("scaleń:", len(new_m))
print("obrazków:", len(ws_new._images))
print("nowa kolumna A width:", new_a)

if problems:
    print("\n!!! PROBLEMY (%d):" % len(problems))
    for p in problems[:25]:
        print("  -", p)
    raise SystemExit(1)
print("\nOK — nowy szablon = stary przesunięty o 1 kolumnę.")
