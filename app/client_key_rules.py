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
    # Przed logowaniem (szyfrowanie hasła) i samo logowanie każdego klienta.
    "/public_key",
    "/auth/login",
    "/baza_web/login",
    "/api/v1/pod-reka/auth/login",
    "/mentor-panel/auth/login",
    "/exam-web/login",
    "/exam-live/web-login",
    "/beach/users/login",
    "/proel/users/login",
    "/proel/zprp/auth",
    # Aplikacja musi zawsze móc usłyszeć „zaktualizuj” i „wyloguj” - inaczej
    # stara wersja bez klucza nigdy nie dostanie prośby o aktualizację.
    "/admin/versions",
    "/admin/forced_logout/next",
    # Powroty OAuth (przychodzą z Google) i webhook z własnym sekretem.
    "/calendar/oauth2callback",
    "/beach/calendar/oauth2callback",
    "/mentor-panel/drive/callback",
    "/beach/webhooks/brevo/transactional",
    # Obrazki w mailach.
    "/beach/auth/assets/logo.png",
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
    #: Klucz -> nazwa klienta (do logu).
    names: Mapping[str, str] = field(default_factory=dict)
    #: Klucz -> przedrostki, które otwiera (puste = wszystkie). Klucz strony
    #: produktu leży jawnie w jej JS, więc otwiera tylko swoje sumy.
    scopes: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)


def parse_settings(mode: Optional[str], keys: Optional[str], extra_open: Optional[str] = None) -> Settings:
    """Ustawienia z env. Klucze: `nazwa:klucz,nazwa2:klucz2` albo same klucze;
    zawężenie do ścieżek: `www:klucz@/public/baza-stats|/national-distances`.

    Brak kluczy = tryb `off` bez względu na `mode` - wdrożenie bez konfiguracji
    niczego nie psuje.
    """
    parsed: list = []
    names: dict = {}
    scopes: dict = {}
    for i, raw in enumerate((keys or "").split(",")):
        raw = raw.strip()
        if not raw:
            continue
        name, sep, key = raw.partition(":")
        if not sep:
            name, key = f"klucz{i + 1}", raw
        key, _at, scope = key.strip().partition("@")
        key = key.strip()
        prefixes = tuple(x.strip().rstrip("/") for x in scope.split("|") if x.strip().startswith("/"))
        if len(key) < 16:
            # Krótki klucz to pomyłka w konfiguracji - pomijamy, nie otwieramy.
            continue
        parsed.append(key)
        names[key] = name.strip() or f"klucz{i + 1}"
        if prefixes:
            scopes[key] = prefixes
    m = (mode or "").strip().lower()
    if m not in MODES:
        m = "report" if parsed else "off"
    if not parsed:
        m = "off"
    extra = tuple(p.strip().rstrip("/") for p in (extra_open or "").split(",") if p.strip().startswith("/"))
    return Settings(mode=m, keys=tuple(parsed), extra_open=extra, names=names, scopes=scopes)


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def is_open_path(path: str, extra: Iterable[str] = (), method: str = "GET") -> bool:
    """Czy ścieżka jest otwarta bez klucza (wyjątki z natury publiczne)."""
    p = path or "/"
    if (method or "").upper() == "POST" and p.rstrip("/") in OPEN_POST:
        return True
    if p in OPEN_EXACT:
        return True
    for prefix in (*OPEN_PREFIXES, *OPEN_PATHS, *extra):
        if _under(p, prefix.rstrip("/")):
            return True
    return any(p.startswith(x) for x in OPEN_STARTS) or _matches_pattern(p)


def key_name(settings: Settings, presented: Optional[str], path: str = "/") -> Optional[str]:
    """Nazwa klienta dla poprawnego klucza (porównanie w stałym czasie), który
    otwiera tę ścieżkę, albo None."""
    if not presented:
        return None
    got = presented.strip().encode()
    for key in settings.keys:
        if hmac.compare_digest(got, key.encode()):
            scope = settings.scopes.get(key)
            if scope and not any(_under(path or "/", p) for p in scope):
                return None
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
    if is_open_path(path, settings.extra_open, method):
        return Verdict(True, "open")
    name = key_name(settings, presented_key, path)
    if name:
        return Verdict(True, f"key:{name}")
    if token_valid:
        return Verdict(True, "token")
    if settings.mode == "report":
        return Verdict(True, "missing", would_block=True)
    return Verdict(False, "missing", would_block=True)


# Wyjątki z audytu tras (05.11.2026) - adresy otwierane przez „gołą”
# przeglądarkę, kalendarz albo cudzy serwer, które bronią się same (token
# albo kod w adresie, własny sekret) albo są drzwiami wejściowymi.
OPEN_PATHS: Tuple[str, ...] = (
    "/mail-assets",
    "/province/alerts/logo",
    "/mentor-panel/auth/qr",
    "/exam-web/qr",
    "/beach/auth",
    "/beach/password-reset",
    "/proel/users/auth",
    "/exam-live/assets/img",
    "/exam-live/card.png",
    "/exam-live/join",
    "/exam-live/j",
    "/exam-live/projector",
    "/exam-live/guest",
    "/exam-live/peek",
    "/exam-live/ws",
    "/e",
    "/mentor-panel/public",
    "/mentor-panel/handoff/short",
    "/mentor-panel/trybuna/thumb",
    "/public/exam-results",
    "/temp",
    "/exam-exports/files",
    "/province-events/pdf",
    "/province-events/poster",
    "/training/spk/slides.pdf",
    "/training/spk/report.pdf",
)

#: Wzorce adresów z tokenem pobierania i kanału kalendarza (regex na całą ścieżkę).
OPEN_PATTERNS: Tuple[str, ...] = (
    r"^/.+/download/[^/]+$",
    r"^/.+/download-zip/[^/]+$",
    r"^/.+-download/[^/]+$",
    r"^/api/v1/handball/teams/[^/]+/calendar\.ics$",
    r"^/api/v1/handball/crest$",
    r"^/proel/evidence/package/[^/]+/file$",
    # Formularze okręgowe na stronie /f/<kod> (docs/formularze-okregowe.md §12): kod w adresie,
    # zapisy z limitem na IP; plik eksportu z jednorazowym tokenem (15 minut).
    r"^/public/forms/[^/]+$",
    r"^/public/forms/[^/]+/rows/[^/]+$",
    r"^/public/forms/[^/]+/responses$",
    r"^/public/forms/[^/]+/qr$",
    r"^/public/forms/[^/]+/files/[^/]+$",
    r"^/public/forms/qr/[^/]+$",
    r"^/district-forms/file/[^/]+$",
)

#: Rejestracja nowego konta: tylko POST (GET tej samej ścieżki to lista użytkowników).
OPEN_POST: Tuple[str, ...] = ("/beach/users", "/proel/users")
OPEN_STARTS: Tuple[str, ...] = ()

import re as _re

_OPEN_RE = tuple(_re.compile(p) for p in OPEN_PATTERNS)


def _matches_pattern(path: str) -> bool:
    return any(r.match(path) for r in _OPEN_RE)
