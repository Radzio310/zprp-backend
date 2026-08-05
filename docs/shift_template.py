# -*- coding: utf-8 -*-
"""
Wstawia JEDNĄ nową kolumnę PRZED kolumną A w protocol_template.xlsx.

Nowa kolumna A jest pusta i służy wyłącznie na ptaszki badań lekarskich.
Cała dotychczasowa zawartość arkusza przesuwa się o kolumnę w prawo, więc
`results.py` adresuje ją przez nakładkę ShiftedWS (PROTOCOL_COL_SHIFT = 1).

openpyxl.insert_cols NIE nadaje się do tego zadania — gubi scalenia i obrazki.
Dlatego przesunięcie robimy na surowym XML-u wewnątrz zipa.
"""
import os
import re
import shutil
import zipfile

TPL_DIR = r"c:\Users\radek\Desktop\BAZA_ALL\zprp-backend\app\templates"
SRC = os.path.join(TPL_DIR, "protocol_template.xlsx")
BACKUP = os.path.join(TPL_DIR, "protocol_template_BACKUP_preExamCol.xlsx")
OUT = os.path.join(TPL_DIR, "protocol_template.xlsx")
TMP = os.path.join(TPL_DIR, "_protocol_template_shifted.tmp.xlsx")

NEW_COL_WIDTH = "6"       # ~47 px — mieści znaczek 44x15 px z dopiskiem WZPR
SHIFT = 1


# ─────────────────── helpery na literach kolumn ───────────────────

def col_to_idx(letters: str) -> int:
    n = 0
    for ch in letters.upper():
        n = n * 26 + (ord(ch) - 64)
    return n


def idx_to_col(idx: int) -> str:
    out = ""
    while idx > 0:
        idx, rem = divmod(idx - 1, 26)
        out = chr(65 + rem) + out
    return out


CELL_RE = re.compile(r"^(\$?)([A-Z]{1,3})(\$?)(\d+)$")


def shift_cell(ref: str) -> str:
    m = CELL_RE.match(ref.strip())
    if not m:
        raise ValueError("nieznany adres: %r" % ref)
    d1, col, d2, row = m.groups()
    return "%s%s%s%s" % (d1, idx_to_col(col_to_idx(col) + SHIFT), d2, row)


def shift_range(ref: str) -> str:
    return ":".join(shift_cell(part) for part in ref.split(":"))


# ─────────────────── transformacje plików ───────────────────

def transform_sheet(xml: str) -> str:
    # dimension
    xml = re.sub(
        r'(<dimension ref=")([^"]+)(")',
        lambda m: m.group(1) + shift_range(m.group(2)) + m.group(3),
        xml,
    )
    # selection activeCell + sqref
    xml = re.sub(
        r'(<selection activeCell=")([^"]+)(" sqref=")([^"]+)(")',
        lambda m: m.group(1)
        + shift_cell(m.group(2))
        + m.group(3)
        + shift_range(m.group(4))
        + m.group(5),
        xml,
    )
    # kolumny: min/max +1
    xml = re.sub(
        r'(<col min=")(\d+)(" max=")(\d+)(")',
        lambda m: m.group(1)
        + str(int(m.group(2)) + SHIFT)
        + m.group(3)
        + str(int(m.group(4)) + SHIFT)
        + m.group(5),
        xml,
    )
    # nowa, pusta kolumna ptaszków na samym początku bloku <cols>
    assert "<cols>" in xml, "brak bloku <cols>"
    xml = xml.replace(
        "<cols>",
        '<cols><col min="1" max="1" width="%s" customWidth="1"/>' % NEW_COL_WIDTH,
        1,
    )
    # spans w wierszach
    xml = re.sub(
        r'(<row r="\d+" spans=")(\d+):(\d+)(")',
        lambda m: m.group(1)
        + str(int(m.group(2)) + SHIFT)
        + ":"
        + str(int(m.group(3)) + SHIFT)
        + m.group(4),
        xml,
    )
    # komórki
    xml = re.sub(
        r'(<c r=")([A-Z]{1,3}\d+)(")',
        lambda m: m.group(1) + shift_cell(m.group(2)) + m.group(3),
        xml,
    )
    # scalenia
    xml = re.sub(
        r'(<mergeCell ref=")([^"]+)(")',
        lambda m: m.group(1) + shift_range(m.group(2)) + m.group(3),
        xml,
    )
    # formuły (są dwie: =C4, =C7)
    xml = re.sub(
        r"(<f>)([A-Z]{1,3}\d+)(</f>)",
        lambda m: m.group(1) + shift_cell(m.group(2)) + m.group(3),
        xml,
    )
    return xml


def transform_workbook(xml: str) -> str:
    # Obszar wydruku: lewa krawędź ZOSTAJE na $A$1, żeby nowa kolumna się
    # drukowała; przesuwamy tylko prawą krawędź.
    def fix(m):
        left, right = m.group(2), m.group(3)
        return m.group(1) + left + ":" + shift_cell(right) + m.group(4)

    return re.sub(
        r"(<definedName name=\"_xlnm.Print_Area\"[^>]*>[^<!]*?!)(\$[A-Z]+\$\d+):(\$[A-Z]+\$\d+)(</definedName>)",
        fix,
        xml,
    )


def transform_drawing(xml: str) -> str:
    return re.sub(
        r"(<xdr:col>)(\d+)(</xdr:col>)",
        lambda m: m.group(1) + str(int(m.group(2)) + SHIFT) + m.group(3),
        xml,
    )


def transform_calcchain(xml: str) -> str:
    return re.sub(
        r'(<c r=")([A-Z]{1,3}\d+)(")',
        lambda m: m.group(1) + shift_cell(m.group(2)) + m.group(3),
        xml,
    )


TRANSFORMS = {
    "xl/worksheets/sheet1.xml": transform_sheet,
    "xl/workbook.xml": transform_workbook,
    "xl/drawings/drawing1.xml": transform_drawing,
    "xl/calcChain.xml": transform_calcchain,
}


def main() -> None:
    if not os.path.exists(BACKUP):
        shutil.copy2(SRC, BACKUP)
        print("backup ->", os.path.basename(BACKUP))
    else:
        print("backup już istnieje, nie nadpisuję")

    src_zip = zipfile.ZipFile(BACKUP)  # zawsze transformujemy z kopii oryginału
    with zipfile.ZipFile(TMP, "w", zipfile.ZIP_DEFLATED) as out:
        for info in src_zip.infolist():
            data = src_zip.read(info.filename)
            fn = TRANSFORMS.get(info.filename)
            if fn:
                before = data.decode("utf-8")
                after = fn(before)
                assert after != before, "transformacja nic nie zmieniła: " + info.filename
                data = after.encode("utf-8")
            out.writestr(info, data)
    src_zip.close()

    shutil.move(TMP, OUT)
    print("zapisano ->", os.path.basename(OUT))


if __name__ == "__main__":
    main()
