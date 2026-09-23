"""
Awaryjny odczyt faktury przez OpenAI - tylko gdy reguły zawiodą.

Dwie drogi:
  - PDF z tekstem, w którym reguły nie znalazły kwoty albo nabywcy: tekst idzie
    do modelu z wymuszonym JSON-em (wzorzec z importu terminarza Beach),
  - skan bez warstwy tekstu: pierwsze strony renderujemy PyMuPDF-em do PNG
    i wysyłamy obraz modelowi z wizją (gpt-4o).

Brak `OPENAI_API_KEY` to NIE błąd: pozycja wraca jako „nie odczytano" i panel
prosi o ręczne uzupełnienie. Odpowiedź modelu przechodzi przez
`invoice_parse_rules.sanitize_ai`, więc do bazy trafiają tylko pola i typy,
których się spodziewamy.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Optional

from app.invoice_parse_rules import sanitize_ai

logger = logging.getLogger(__name__)

#: Ile stron skanu wysyłamy modelowi - faktura to zwykle jedna strona.
VISION_PAGES = 2

_PROMPT = """Jesteś asystentem księgowym. Z polskiej faktury wyciągnij pola i odpowiedz
WYŁĄCZNIE poprawnym JSON-em z kluczami:
- "invoice_no": numer faktury (napis, np. "77/SL/2026"),
- "issue_date": data wystawienia w formacie RRRR-MM-DD,
- "sale_date": data sprzedaży/wykonania usługi RRRR-MM-DD albo null,
- "due_date": termin płatności RRRR-MM-DD albo null,
- "seller_name", "seller_nip": sprzedawca i jego NIP (same cyfry),
- "buyer_name", "buyer_nip": nabywca i jego NIP (same cyfry),
- "gross": kwota brutto do zapłaty (liczba, kropka dziesiętna),
- "paid": kwota już zapłacona albo null, "remaining": pozostało do zapłaty albo null,
- "currency": waluta (np. "PLN"),
- "items": lista pozycji [{"name": nazwa, "quantity": liczba, "unit": jednostka, "gross": wartość brutto}].
Nie zgaduj: pole, którego nie ma na fakturze, ustaw na null (listę na [])."""


def api_key() -> str:
    return (os.getenv("OPENAI_API_KEY") or "").strip()


def render_pages(pdf_bytes: bytes, pages: int = VISION_PAGES, zoom: float = 2.0) -> list[str]:
    """Pierwsze strony PDF jako obrazy PNG w base64 (do modelu z wizją)."""
    import fitz  # PyMuPDF - import leniwy, testy reguł go nie potrzebują

    out: list[str] = []
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        for index in range(min(pages, doc.page_count)):
            pix = doc[index].get_pixmap(matrix=fitz.Matrix(zoom, zoom))
            out.append(base64.b64encode(pix.tobytes("png")).decode("ascii"))
    return out


async def read_invoice(*, text: str, pdf_bytes: bytes, has_text: bool) -> tuple[Optional[dict], str, str]:
    """
    (pola albo None, metoda, powód porażki).

    Metoda: "ai-text" albo "ai-vision". Powód porażki to zdanie do pokazania
    w panelu - nigdy cicha pustka.
    """
    key = api_key()
    if not key:
        return None, "", "Brak klucza OpenAI na serwerze - uzupełnij dane ręcznie."

    if has_text:
        method = "ai-text"
        user_content: object = f"Tekst wyekstrahowany z faktury PDF:\n\n{text[:16000]}"
    else:
        method = "ai-vision"
        try:
            images = render_pages(pdf_bytes)
        except Exception as exc:  # noqa: BLE001 - uszkodzony plik to zwykła porażka odczytu
            return None, method, f"Nie udało się otworzyć PDF-a: {exc}"
        if not images:
            return None, method, "PDF nie ma żadnej strony."
        user_content = [{"type": "text", "text": "Skan faktury (bez warstwy tekstu):"}] + [
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image}", "detail": "high"}}
            for image in images
        ]

    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=key)
        response = await client.chat.completions.create(
            model=os.getenv("OPENAI_INVOICE_MODEL", "gpt-4o"),
            messages=[
                {"role": "system", "content": _PROMPT},
                {"role": "user", "content": user_content},
            ],
            response_format={"type": "json_object"},
            temperature=0,
            timeout=90,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("[invoice_ai] zapytanie nieudane: %s", exc)
        return None, method, f"Odczyt przez AI nie powiódł się: {exc}"

    raw = (response.choices[0].message.content or "").strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("[invoice_ai] niepoprawny JSON: %s", raw[:300])
        return None, method, "AI zwróciło nieczytelną odpowiedź - uzupełnij dane ręcznie."
    return sanitize_ai(data), method, ""
