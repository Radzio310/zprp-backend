# app/client_version.py
#
# Wersja aplikacji klienta i funkcje, które wymagają nowszej wersji.
#
# Liść bez bazy. Wersję urządzenie zgłasza przy rejestracji tokenu push
# (`push_tokens.app_version`) oraz w nagłówku `X-App-Version`. BRAK wersji
# znaczy „stara aplikacja": APK sprzed tej funkcji nie wysyłają jej wcale, a
# właśnie one nie mogą dostać powiadomienia, którego nie umieją otworzyć.

from __future__ import annotations

import re
from typing import Any, Tuple

#: Pierwsza wersja aplikacji z obsługą ofert obsadowego na giełdzie
#: (utils/crewMarket*.ts, push data.kind="match_market_crew").
MIN_CREW_MARKET_VERSION = "2.1.3"


def parse_version(value: Any) -> Tuple[int, ...]:
    """'2.1.3' -> (2, 1, 3); sufiks po myślniku/plusie ('2.1.3-dev') jest pomijany.
    Pusty lub nieczytelny napis -> () czyli „nieznana"."""
    text = str(value if value is not None else "").strip()
    if not text:
        return ()
    core = re.split(r"[-+ ]", text, maxsplit=1)[0]
    parts = core.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return ()
    return tuple(int(p) for p in parts)


def version_at_least(value: Any, minimum: str) -> bool:
    """Czy wersja >= minimum. Nieznana wersja (brak, śmieci) jest za stara."""
    have = parse_version(value)
    if not have:
        return False
    want = parse_version(minimum)
    width = max(len(have), len(want))
    return have + (0,) * (width - len(have)) >= want + (0,) * (width - len(want))


def supports_crew_market(value: Any) -> bool:
    return version_at_least(value, MIN_CREW_MARKET_VERSION)


CREW_MARKET_UPDATE_MESSAGE = (
    "Oferty obsadowego na giełdzie wymagają nowszej wersji aplikacji "
    f"(co najmniej {MIN_CREW_MARKET_VERSION}). Zaktualizuj BAZĘ w sklepie i spróbuj ponownie."
)
