"""
Bramka klucza klienta - REGUŁY (moduł-liść: bez bazy, bez sieci, bez FastAPI).

Decyzja właściciela (05.11.2026): danych serwera nie może pobierać dowolna
osoba ani dowolny skrypt. Każde żądanie musi przyjść:
  - z kluczem klienta w nagłówku `X-Baza-Key` (strona BAZA pod RĘKĄ, panel
    BAZA Web, aplikacja BAZA, strona bazaapp.online - każdy ma swój klucz), ALBO
  - z tokenem zalogowanego użytkownika (`Authorization: Bearer <JWT>`)
    podpisanym przez ten serwer.
Wyjątki to adresy, które z natury otwiera „goła” przeglądarka albo obcy
serwer i które bronią się same: zdrowie, `.well-known`, logowanie, powroty
OAuth, webhooki, kanały iCal z tokenem w adresie, linki z tokenem, pliki
statyczne (obrazki w <img>), preflight CORS.

Tryby (`CLIENT_KEY_MODE`):
  off      - bramka nic nie robi (domyślnie, gdy nie ustawiono kluczy),
  report   - przepuszcza wszystko, ale zapisuje w logu, co BY zablokowała
             (bezpieczny tydzień obserwacji przed włączeniem),
  enforce  - 401 `CLIENT_KEY_REQUIRED` dla żądań bez klucza i bez tokenu.

Uczciwie: klucz zaszyty w przeglądarce da się podejrzeć w narzędziach
deweloperskich, więc to zamek na drzwiach, a nie sejf. Odcina skrypty,
scrapery i przypadkowe wejścia, pozwala policzyć i odciąć klienta (rotacja
klucza bez wdrażania serwera), a dane osobowe dalej chroni logowanie.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Tuple

HEADER = "x-baza-key"
QUERY_PARAM = "baza_key"

MODES = ("off", "report", "enforce")

#: Ścieżki zawsze otwarte - dokładne.
OPEN_EXACT: Tuple[str, ...] = (
    "/",
    "/health",
    "/healthz",
    "/favicon.ico",
    "/robots.txt",
    "/openapi.json",
    "/docs",
    "/redoc",
)

#: Ścieżki zawsze otwarte - przedrostki (pełny segment: "/static" łapie
#: "/static/x.png", ale nie "/staticky").
OPEN_PREFIXES: Tuple[str, ...] = (
    "/.well-known",
    "/static",
)


@dataclass(frozen=True)
class Settings:
    mode: str = "off"
    keys: Tuple[str, ...] = ()
    #: Dodatkowe otwarte ścieżki z konfiguracji (przedrostki, rozdzielone przecinkami).
    extra_open: Tuple[str, ...] = ()
    #: Przedrostki, gdzie sam klucz NIE wystarcza... (zarezerwowane, dziś puste).
    names: Mapping[str, str] = field(default_factory=dict)


def parse_settings(mode: Optional[str], keys: Optional[str], extra_open: Optional[str] = None) -> Settings:
    """Ustawienia z env. Klucze: `nazwa:klucz,nazwa2:klucz2` albo same klucze.

    Brak kluczy = tryb `off` bez względu na `mode` - wdrożenie bez konfiguracji
    niczego nie psuje.
    """
    parsed: list = []
    names: dict = {}
    for i, raw in enumerate((keys or "").split(",")):
        raw = raw.strip()
        if not raw:
            continue
        name, sep, key = raw.partition(":")
        if not sep:
            name, key = f"klucz{i + 1}", raw
        key = key.strip()
        if len(key) < 16:
            # Krótki klucz to pomyłka w konfiguracji - pomijamy, nie otwieramy.
            continue
        parsed.append(key)
        names[key] = name.strip() or f"klucz{i + 1}"
    m = (mode or "").strip().lower()
    if m not in MODES:
        m = "report" if parsed else "off"
    if not parsed:
        m = "off"
    extra = tuple(p.strip().rstrip("/") for p in (extra_open or "").split(",") if p.strip().startswith("/"))
    return Settings(mode=m, keys=tuple(parsed), extra_open=extra, names=names)


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def is_open_path(path: str, extra: Iterable[str] = ()) -> bool:
    """Czy ścieżka jest otwarta bez klucza (wyjątki z natury publiczne)."""
    p = path or "/"
    if p in OPEN_EXACT:
        return True
    for prefix in (*OPEN_PREFIXES, *OPEN_PATHS, *extra):
        if _under(p, prefix.rstrip("/")):
            return True
    return any(p.startswith(x) for x in OPEN_STARTS)


def key_name(settings: Settings, presented: Optional[str]) -> Optional[str]:
    """Nazwa klienta dla poprawnego klucza (porównanie w stałym czasie) albo None."""
    if not presented:
        return None
    got = presented.strip().encode()
    for key in settings.keys:
        if hmac.compare_digest(got, key.encode()):
            return settings.names.get(key, "klucz")
    return None


@dataclass(frozen=True)
class Verdict:
    allow: bool
    #: Powód do logu / nagłówka: open, preflight, key:<nazwa>, token, missing, off.
    reason: str
    #: Czy w trybie report zalogować, że w enforce byłoby 401.
    would_block: bool = False


def decide(
    settings: Settings,
    method: str,
    path: str,
    presented_key: Optional[str],
    token_valid: bool,
) -> Verdict:
    """Werdykt bramki dla jednego żądania. `token_valid` liczy wołający
    (podpis JWT tego serwera; data ważności NIE jest wymagana - stara
    aplikacja z wygasłym tokenem dalej jest „swoja”, a trasa i tak sprawdza
    token po swojemu)."""
    if settings.mode == "off":
        return Verdict(True, "off")
    if (method or "").upper() == "OPTIONS":
        return Verdict(True, "preflight")
    if is_open_path(path, settings.extra_open):
        return Verdict(True, "open")
    name = key_name(settings, presented_key)
    if name:
        return Verdict(True, f"key:{name}")
    if token_valid:
        return Verdict(True, "token")
    if settings.mode == "report":
        return Verdict(True, "missing", would_block=True)
    return Verdict(False, "missing", would_block=True)


# Wyjątki konkretnych tras - uzupełniane z audytu tras (patrz testy).
OPEN_PATHS: Tuple[str, ...] = ()
OPEN_STARTS: Tuple[str, ...] = ()
