"""Reguły pola uwag meczu w ZPRP i ramki dodatkowego raportu - liść bez bazy.

Pełna blokada z 29.09.2026 (mecz LCK/17): raport dodatkowy PDF powstał, a w
polu uwag na baza.zprp.pl go nie było. Aplikacja pilnuje ramki po swojej
stronie (`BAZA/utils/zprpCommentGuard.ts`), a serwer ma dwie rzeczy do
dopilnowania sam:

1. DZIENNIK. Samodzielne dopisanie ramki (po złożeniu PDF, ze szczegółów
   meczu, z kolejki dopisku) jest osobnym zdarzeniem
   `zprp.extra_report_comment_sent`. Dotąd wpadało jako `zprp.comment_sent`,
   czyli część pełnych danych - a seria pełnych danych bez końca pokazuje się
   jako „Przerwana wysyłka pełnych danych". Starszy klient nie przysyła
   `purpose` i dostaje dawne zdarzenie.

2. DROGA AWARYJNA (formularz strony, `app/results.py`). Ma własny limit
   długości i przycinała tekst OD KOŃCA - a ramka raportu stoi na końcu, więc
   ginęła pierwsza. Teraz przycinamy verte PRZED ramką i mówimy, że było
   przycięcie. Tekst bez ramki, a ramka w polu - ramka zostaje.

Moduł-liść: bez `app.db`, bez sieci - do sprawdzenia testem.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

#: Ta sama ramka co w aplikacji (`utils/zprpCommentAppendix.ts`).
EXTRA_REPORT_HEADER = "-------- DODATKOWY RAPORT PDF --------"
EXTRA_REPORT_FOOTER = "-" * len(EXTRA_REPORT_HEADER)

#: Zdarzenia dziennika dla zapisu uwag.
EVENT_COMMENT = "zprp.comment_sent"
EVENT_EXTRA_REPORT_COMMENT = "zprp.extra_report_comment_sent"
EVENT_EXTRA_REPORT_VERIFIED = "zprp.extra_report_in_zprp"

#: Cel zapisu przysyłany przez aplikację.
PURPOSE_EXTRA_REPORT = "extra-report"

#: Limit drogi awaryjnej - bez zmian względem dawnego `[:2000]`.
LEGACY_COMMENT_LIMIT = 2000


def _unix(text: Any) -> str:
    return str(text or "").replace("\r\n", "\n").replace("\r", "\n")


def has_extra_block(text: Any) -> bool:
    return EXTRA_REPORT_HEADER in _unix(text)


def extract_extra_block(text: Any) -> str:
    """Ostatnia ramka raportu (od nagłówka po dolną krawędź) albo ""."""
    src = _unix(text)
    start = src.rfind(EXTRA_REPORT_HEADER)
    if start < 0:
        return ""
    after = start + len(EXTRA_REPORT_HEADER)
    footer = src.find(EXTRA_REPORT_FOOTER, after)
    end = len(src) if footer < 0 else footer + len(EXTRA_REPORT_FOOTER)
    return src[start:end].strip()


def strip_extra_blocks(text: Any) -> str:
    """Tekst bez żadnej ramki raportu (verte z brzegami przyciętymi od środka)."""
    out = _unix(text)
    while True:
        start = out.find(EXTRA_REPORT_HEADER)
        if start < 0:
            return out
        after = start + len(EXTRA_REPORT_HEADER)
        footer = out.find(EXTRA_REPORT_FOOTER, after)
        end = len(out) if footer < 0 else footer + len(EXTRA_REPORT_FOOTER)
        head = out[:start].rstrip()
        tail = out[end:].lstrip()
        out = (f"{head}\n\n{tail}" if head else tail) if tail else head


def compose(verte: str, block: str) -> str:
    head = _unix(verte).rstrip()
    block = (block or "").strip()
    if not block:
        return _unix(verte)
    return f"{head}\n\n{block}" if head else block


def preserve_extra_block(current: Any, desired: Any) -> str:
    """Ramka stojąca w polu nie znika przez zapis tekstu bez niej."""
    want = _unix(desired)
    if has_extra_block(want):
        return want
    block = extract_extra_block(current)
    if not block:
        return want
    return compose(want, block)


def fit_comment_limit(text: Any, limit: int = LEGACY_COMMENT_LIMIT) -> Tuple[str, bool]:
    """Tekst mieszczący się w limicie + czy trzeba było przyciąć.

    Ramka raportu jest nietykalna: tniemy verte przed nią. Dopiero gdy sama
    ramka nie mieści się w limicie, tniemy ją od końca - i to też zgłaszamy.
    """
    src = _unix(text).strip()
    if len(src) <= limit:
        return src, False
    block = extract_extra_block(src)
    if not block:
        return src[:limit].rstrip(), True
    if len(block) >= limit:
        return block[:limit].rstrip(), True
    body = strip_extra_blocks(src).strip()
    room = limit - len(block) - 2  # "\n\n" między verte a ramką
    body = body[: max(0, room)].rstrip()
    return (compose(body, block) if body else block), True


def comment_journal_event(
    purpose: Optional[str], komentarz: Any
) -> Tuple[str, Dict[str, Any]]:
    """Zdarzenie dziennika dla jednego zapisu uwag + szczegóły.

    `hasExtraBlock` i `length` pozwalają administratorowi odpowiedzieć na
    pytanie „czy w tym zapisie była ramka raportu" bez zgadywania.
    """
    text = "" if komentarz is None else str(komentarz)
    details: Dict[str, Any] = {
        "hasExtraBlock": has_extra_block(text),
        "length": len(text),
    }
    if str(purpose or "").strip().lower() == PURPOSE_EXTRA_REPORT:
        return EVENT_EXTRA_REPORT_COMMENT, details
    return EVENT_COMMENT, details
