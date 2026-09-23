"""
Tekst z PDF-a faktury (PyMuPDF) i odczyt regułami - bez bazy i bez sieci.

Dwa odczyty tej samej strony, bo programy fakturowe różnie składają kolumny:
  - `get_text("text", sort=True)` - linie w kolejności czytania (góra-dół,
    lewo-prawo); przy dwóch kolumnach obok siebie potrafi je przepleść,
  - bloki (`get_text("blocks", sort=True)`) - każdy blok (np. cały „Nabywca")
    zostaje w jednym kawałku.
Wygrywa odczyt, któremu brakuje mniej pól; przy remisie - pierwszy.

`pdftotext` NIE wchodzi w grę (pamięć „Pułapki PDF-ów ZPRP" - gubi układ),
a skan bez warstwy tekstu rozpoznajemy po pustym tekście i oddajemy AI.
"""

from __future__ import annotations

from typing import Any

from app.invoice_parse_rules import clean_text, parse_invoice_text

#: Minimum znaków, żeby uznać, że PDF ma warstwę tekstu (a nie jest skanem).
MIN_TEXT_CHARS = 40


def is_pdf(data: bytes) -> bool:
    """Po sygnaturze, nie po rozszerzeniu - „faktura.pdf" bywa zdjęciem."""
    return bytes(data[:1024]).lstrip().startswith(b"%PDF-")


def extract_texts(data: bytes) -> tuple[list[str], int]:
    """([tekst liniami, tekst blokami], liczba stron)."""
    import fitz  # PyMuPDF

    lines: list[str] = []
    blocks: list[str] = []
    with fitz.open(stream=data, filetype="pdf") as doc:
        pages = doc.page_count
        for page in doc:
            lines.append(page.get_text("text", sort=True))
            for block in page.get_text("blocks", sort=True):
                # (x0, y0, x1, y1, tekst, numer, typ) - typ 0 to tekst, 1 obraz.
                if len(block) >= 7 and block[6] == 0:
                    blocks.append(str(block[4]))
    return [clean_text("\n".join(lines)), clean_text("\n".join(blocks))], pages


def analyze_pdf(data: bytes) -> dict[str, Any]:
    """
    {text, pages, has_text, parsed} - `parsed` z lepszego z dwóch odczytów.

    Rzuca wyjątek tylko przy pliku, którego PyMuPDF w ogóle nie otworzy.
    """
    texts, pages = extract_texts(data)
    has_text = any(len(text.replace(" ", "")) >= MIN_TEXT_CHARS for text in texts)
    best_text, best = texts[0], parse_invoice_text(texts[0])
    for text in texts[1:]:
        candidate = parse_invoice_text(text)
        if _filled(candidate) > _filled(best):
            best_text, best = text, candidate
    return {"text": best_text, "pages": pages, "has_text": has_text, "parsed": best}


def _filled(parsed: dict) -> int:
    """Ile ważnych pól odczytano - brak kwoty/nabywcy waży najwięcej."""
    score = 0
    for key in ("invoice_no", "issue_date", "buyer_nip", "seller_nip", "buyer_name"):
        if parsed.get(key):
            score += 1
    if parsed.get("items"):
        score += 1
    return score - 10 * len(parsed.get("missing") or [])
