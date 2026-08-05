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

SHIFT = 1

# Szerokość kolumny ptaszków w pikselach (96 dpi, przed skalą wydruku).
#
# Górna granica NIE jest kwestią gustu: kolumna musi zmieścić się w dawnym LEWYM
# MARGINESIE (0,19685" = 5 mm), bo dokładnie tyle marginesu jej oddajemy. Przy
# skali 90 % daje to 0,19685 * 96 / 0,9 ≈ 21 px, więc 20 px zostawia jeszcze
# ułamek milimetra marginesu. Szerzej = tabela nie mieści się na A4.
NEW_COL_PX = 20


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

# Szerokość kolumny (w „znakach") na piksele, wzorem z ECMA-376: wartość w XML-u
# ma już wliczony 5-pikselowy padding, więc mnożymy wyłącznie przez szerokość
# najszerszej cyfry (Calibri 11 → 7 px).
MDW = 7


def col_width_px(width_chars: float) -> int:
    return int(((256 * width_chars + int(128.0 / MDW)) / 256.0) * MDW)


def px_to_col_width(px: int) -> float:
    """Odwrotność `col_width_px` — celuje w środek przedziału, żeby zaokrąglenia
    w Excelu/LibreOffice nie zeszły o piksel."""
    width = (px + 0.5) / MDW - int(128.0 / MDW) / 256.0
    width = round(width, 4)
    assert col_width_px(width) == px, (
        "szerokość %r daje %d px, a chcieliśmy %d" % (width, col_width_px(width), px)
    )
    return width


NEW_COL_WIDTH = "%g" % px_to_col_width(NEW_COL_PX)


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
    return compensate_centering(xml)


def compensate_centering(xml: str) -> str:
    """
    Kolumna ptaszków zjada LEWY MARGINES i nic więcej.

    Arkusz drukuje się z `horizontalCentered="1"`, więc wyśrodkowaniu podlega
    cały obszar wydruku — sama dołożona kolumna przesuwałaby tabelę w prawo o
    pół swojej szerokości. Ptaszki mają być dodatkiem NA MARGINESIE, a nie
    częścią kompozycji.

    Poprawka: zmniejszamy LEWY margines dokładnie o szerokość nowej kolumny na
    papierze. To jedyny wariant, który jednocześnie nie rusza treści i NIE
    POGARSZA mieszczenia się na A4 — i da się to pokazać rachunkiem, bez
    zgadywania, jak szeroka jest tabela:

        U  = 210 − L − R                    (obszar wydruku, stary)
        U' = 210 − (L − a) − R = U + a      (nowy — urósł o a)

        lewy brzeg treści, stary:  L + (U − W)/2
        lewy brzeg treści, nowy:   (L − a) + (U + a − (W + a))/2 + a
                                 = L + (U − W)/2                      ✔ bez zmian

        mieszczenie się, stare:  W ≤ U
        mieszczenie się, nowe:   W + a ≤ U + a  ⇔  W ≤ U              ✔ bez zmian

    Zabranie miejsca z PRAWEJ też utrzymuje treść na miejscu, ale kurczy obszar
    wydruku o `a` — i wtedy prawy skraj tabeli wyjeżdża na kolejną stronę.
    Dlatego `a` nie może przekroczyć lewego marginesu (patrz NEW_COL_PX).
    """
    assert 'horizontalCentered="1"' in xml, (
        "arkusz nie jest wyśrodkowany w poziomie — ten rachunek zakłada "
        "horizontalCentered i bez niego nie obowiązuje"
    )

    scale_m = re.search(r"<pageSetup[^>]*\bscale=\"(\d+)\"", xml)
    scale = int(scale_m.group(1)) / 100.0 if scale_m else 1.0
    # Szerokość kolumny na papierze: piksele (96 dpi) przeskalowane wydrukiem.
    col_in = NEW_COL_PX / 96.0 * scale

    def shrink(m):
        left = float(m.group(2)) - col_in
        assert left >= 0, (
            "kolumna ptaszków (%.4f\") jest szersza niż lewy margines (%s\") — "
            "zmniejsz NEW_COL_PX, inaczej trzeba by ukraść miejsce z prawej i "
            "tabela nie zmieści się na A4" % (col_in, m.group(2))
        )
        return "%s%.17g%s" % (m.group(1), left, m.group(3))

    out, n = re.subn(r'(<pageMargins[^>]*\bleft=")([\d.]+)(")', shrink, xml)
    assert n == 1, "nie znalazłem lewego marginesu w pageMargins"
    return out


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
