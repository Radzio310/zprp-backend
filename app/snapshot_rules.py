"""Migawki meczu - czyste reguły, bez bazy i bez sieci.

PO CO TO ISTNIEJE. `proel_matches` trzyma JEDNĄ, bieżącą treść meczu, a
`proel_doc_history` tylko te wersje, które przegrały spór. Gdy protokół
zepsuje się po cichu - ktoś skasował skład, nadpisał przebieg, wszedł na
cudzym urządzeniu - nie ma do czego wrócić. Migawka powstaje z KAŻDEGO
przyjętego pełnego zapisu i daje odpowiedź na dwa pytania naraz: „jak ten mecz
wyglądał o 18:40" i „kto to zmienił".

TRZY DECYZJE, KTÓRE DECYDUJĄ O KOSZCIE (zmierzone 14.09.2026 na realistycznym
meczu: 2x16 zawodników, 70 zdarzeń, komplet obsady):

  * PODPISY NIE WCHODZĄ DO MIGAWKI. Blob bez podpisów to ~12 KB, z ośmioma
    podpisami ~175 KB. Podpisy i tak żyją w overlayu (`proel_match_state`),
    który serwer nakłada przy każdym zapisie - więc przywracanie ich nie
    potrzebuje. W migawce zostaje ŚLAD: rozmiar i odcisk, żeby w panelu było
    widać „tu doszedł podpis" i „ten podpis się zmienił".
  * MIGAWKA TO SKOMPRESOWANE BAJTY, nie JSONB. Do środka nigdy nie zaglądamy
    zapytaniem - czytamy ją w całości. zlib daje 8,5x, JSONB (pglz) 2-4x.
    Wszystko, po czym się szuka, stoi w osobnych kolumnach.
  * ZAPIS, KTÓRY NICZEGO NIE ZMIENIŁ, NIE TWORZY MIGAWKI. Odcisk treści
    (`snapshot_hash`) odsiewa powtórki - telefon z zapauzowanym meczem wysyła
    co minutę to samo i nie ma powodu, żeby to odkładać.

Bliźniak po stronie aplikacji: `BAZA/utils/matchSnapshots.ts` (pierścień
lokalny i dosyłka po ciszy sieciowej).
"""

from __future__ import annotations

import hashlib
import json
import re
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

# ─────────────────────────── limity i retencja ───────────────────────────

#: Ile trzymamy zwykłe migawki. Okno, w którym ktoś dzwoni „zepsuło się".
RETENTION_DAYS = 7

#: Kamienie milowe (start, przerwa, koniec, zatwierdzenie, spór) - dłużej.
#: Jest ich kilka na mecz, a to one odpowiadają na pytania sprzed tygodni.
MILESTONE_RETENTION_DAYS = 90

#: Górny rozmiar migawki PO odchudzeniu. Blob meczu to ~12 KB, więc pół
#: megabajta to zapas na nietypowy mecz, a nie zaproszenie. Większa treść
#: zostawia sam wiersz metadanych - w osi czasu wersja ma być widoczna nawet
#: wtedy, gdy nie da się jej przechować.
MAX_SNAPSHOT_BYTES = 512 * 1024

#: ODSTĘPU MIĘDZY MIGAWKAMI NIE MA - i to jest decyzja, nie przeoczenie.
#:
#: Stało tu 20 s i zjadało dokładnie to, po co ta funkcja powstała. Aplikacja
#: zapisuje mecz nie tylko taktem 60-sekundowym: KAŻDA akcja sędziego - bramka,
#: upomnienie, kara, cofnięcie - woła `saveNow` i idzie na serwer od razu.
#: Akcje dzielą sekundy, więc odstęp wycinał całe serie i w historii zostawał
#: co dwudziesty moment meczu. Sędzia ma mieć mecz KROK PO KROKU.
#:
#: Czym więc bronimy bazy, skoro nie odstępem:
#:   * ODCISK TREŚCI - zapis, który niczego nie zmienił, nie tworzy wiersza
#:     (a to jest dokładnie kształt klienta w pętli),
#:   * LIMIT DOBOWY niżej - twardy sufit niezależny od tempa.
#: Te dwie zapory nie mają skutku ubocznego w postaci gubienia prawdziwych
#: chwil meczu, a odstęp miał.

#: Twardy limit na mecz na dobę. Realny mecz to ~200 migawek (konfiguracja,
#: 60-90 minut gry, wypełnianie protokołu); po zmniejszeniu odstępu wyżej
#: gęstość rośnie, więc zapas też. Po przekroczeniu zbieramy WYŁĄCZNIE
#: kamienie milowe - ich jest kilka i to one są ważne.
MAX_PER_MATCH_PER_DAY = 600

# ─────────────────────────── odchudzanie ───────────────────────────

#: Klucze, których wartość jest podpisem. Dopasowanie po NAZWIE, nie po
#: miejscu: podpisy siedzą w `matchConfig.extras` (drużyny), w `officials`,
#: w `medic` i przy osobach towarzyszących, a kształt bloba bywał zmieniany.
_SIGNATURE_KEY = re.compile(r"signature", re.IGNORECASE)

#: Znacznik, który zostaje po zdjętym podpisie. Jest NAPISEM, żeby nie zmienić
#: typu pola - blob po odchudzeniu ma dać się obejrzeć tak samo jak oryginał.
_MARK_PREFIX = "[zdjęto:"

#: Obrazek wklejony w pole tekstowe (albo podpis pod nieoczekiwaną nazwą).
#: Ten sam mechanizm broni przed migawką, w której ktoś zostawił zdjęcie.
_DATA_URI = re.compile(r"^data:[a-z]+/[a-z0-9.+-]+;base64,", re.IGNORECASE)

#: Poniżej tego progu nie ma po co niczego zdejmować.
_HEAVY_BYTES = 512


def _mark(kind: str, value: str) -> str:
    """Ślad po zdjętej wartości: rodzaj, rozmiar i odcisk.

    Odcisk jest po to, żeby panel umiał powiedzieć „ten podpis się ZMIENIŁ"
    bez przechowywania samej treści.
    """
    raw = value.encode("utf-8", "replace")
    digest = hashlib.sha256(raw).hexdigest()[:12]
    return f"{_MARK_PREFIX} {kind}, {max(1, len(raw) // 1024)} KB, {digest}]"


def is_stripped(value: Any) -> bool:
    """Czy w tym miejscu stoi ślad po zdjętej wartości, a nie prawdziwa treść."""
    return isinstance(value, str) and value.startswith(_MARK_PREFIX)


def _heavy_kind(key: Any, value: Any) -> Optional[str]:
    """Czy tę wartość zdejmujemy - i jak ją nazwać w śladzie."""
    if not isinstance(value, str) or len(value) < _HEAVY_BYTES:
        return None
    if isinstance(key, str) and _SIGNATURE_KEY.search(key):
        return "podpis"
    if _DATA_URI.match(value):
        return "obrazek"
    return None


def strip_heavy(blob: Any) -> Tuple[Any, Dict[str, int]]:
    """Blob bez podpisów i wklejonych obrazków - kopia, oryginał nietknięty.

    Zwraca `(odchudzony, statystyki)`. Statystyki mówią, ile wartości zdjęto
    i ile bajtów to oszczędziło - panel pokazuje to przy migawce, żeby nikt
    nie szukał podpisu, którego świadomie tam nie ma.
    """
    stats = {"stripped": 0, "saved_bytes": 0}

    def walk(node: Any, key: Any = None) -> Any:
        kind = _heavy_kind(key, node)
        if kind:
            stats["stripped"] += 1
            stats["saved_bytes"] += len(node.encode("utf-8", "replace"))
            return _mark(kind, node)
        if isinstance(node, dict):
            return {k: walk(v, k) for k, v in node.items()}
        if isinstance(node, list):
            # Klucz rodzica jedzie dalej: podpisy bywają w tablicach
            # (osoby towarzyszące), a tam element nie ma własnej nazwy.
            return [walk(item, key) for item in node]
        return node

    return walk(blob), stats


def _signature_paths(node: Any, key: Any = None, path: Tuple = ()) -> List[Tuple]:
    """Ścieżki do PRAWDZIWYCH podpisów - do przeniesienia ich w przód."""
    out: List[Tuple] = []
    if isinstance(node, str):
        if (
            isinstance(key, str)
            and _SIGNATURE_KEY.search(key)
            and node.strip()
            and not is_stripped(node)
        ):
            out.append(path)
        return out
    if isinstance(node, dict):
        for k, v in node.items():
            out.extend(_signature_paths(v, k, path + (k,)))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            out.extend(_signature_paths(item, key, path + (i,)))
    return out


def _at(node: Any, path: Tuple) -> Any:
    for step in path:
        try:
            node = node[step]
        except (KeyError, IndexError, TypeError):
            return None
    return node


def _set_at(node: Any, path: Tuple, value: Any) -> bool:
    """Wstaw wartość, ale TYLKO gdy pojemnik już istnieje. Inaczej `False`."""
    for step in path[:-1]:
        try:
            node = node[step]
        except (KeyError, IndexError, TypeError):
            return False
    try:
        node[path[-1]] = value
        return True
    except (KeyError, IndexError, TypeError):
        return False


def merge_signatures_forward(restored: Any, current: Any) -> Any:
    """Przywracana treść dostaje podpisy z wersji BIEŻĄCEJ.

    PRZYWRACANIE NIGDY NIE USUWA PODPISU - to jest twarda reguła, nie
    uprzejmość. Sędzia, który podpisał protokół o 20:10, nie ma prawa stracić
    podpisu przez to, że administrator cofnął mecz do 18:40.

    Serwer robi to samo z drugiej strony - nakłada overlay przy każdym zapisie,
    a podpisy w nim siedzą. To jest druga warstwa, dla treści, która przez
    rejestr pól nigdy nie przeszła (starsze zapisy, blob z cudzego wydania).

    Puste miejsce i ślad po odchudzeniu liczą się TAK SAMO: oba znaczą „tu nie
    ma podpisu", więc oba przyjmują bieżący.
    """
    if not isinstance(restored, (dict, list)) or not isinstance(current, (dict, list)):
        return restored
    for path in _signature_paths(current):
        here = _at(restored, path)
        if isinstance(here, str) and here.strip() and not is_stripped(here):
            continue  # przywracana wersja ma własny podpis - zostaje
        _set_at(restored, path, _at(current, path))
    return restored


# ─────────────────────────── pakowanie ───────────────────────────


def pack(blob: Any) -> bytes:
    """Migawka jako skompresowane bajty - patrz nagłówek modułu."""
    raw = json.dumps(blob, ensure_ascii=False, separators=(",", ":"), default=str)
    return zlib.compress(raw.encode("utf-8"), 6)


def unpack(payload: Optional[bytes]) -> Any:
    """Treść migawki albo `None`, gdy jej nie ma (za duża, wygasła)."""
    if not payload:
        return None
    try:
        return json.loads(zlib.decompress(bytes(payload)).decode("utf-8"))
    except (zlib.error, ValueError, UnicodeDecodeError):
        return None


#: Pola, które zmieniają się przy KAŻDYM zapisie, nie niosąc treści meczu.
#:
#: `savedAtMs` to znacznik „kiedy to zapisano" dokładany przez telefon w każdym
#: takcie (`computeClockFields`). Liczony do odcisku sprawiał, że KAŻDA migawka
#: wyglądała na nową - odsiew powtórek nie działał wcale, a mecz stojący
#: z zapauzowanym zegarem zużywał limit dobowy na kopie tej samej chwili.
#:
#: Zegar (`mainTime`) zostaje w odcisku ŚWIADOMIE: gdy idzie, to naprawdę
#: zmienia stan meczu i taka migawka ma prawo powstać.
_VOLATILE_KEYS = ("savedAtMs",)


def snapshot_hash(blob: Any) -> str:
    """Odcisk treści PO odchudzeniu - po nim odsiewamy powtórki."""
    if isinstance(blob, dict):
        blob = {k: v for k, v in blob.items() if k not in _VOLATILE_KEYS}
    raw = json.dumps(blob, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def too_big(blob: Any) -> bool:
    """Czy tej treści już nie przechowujemy - patrz `MAX_SNAPSHOT_BYTES`."""
    return len(json.dumps(blob, ensure_ascii=False, default=str).encode("utf-8")) > MAX_SNAPSHOT_BYTES


# ─────────────────────────── kamienie milowe ───────────────────────────

#: Chwile, które chcemy mieć także za trzy tygodnie.
MILESTONES = (
    "start",       # pierwsza migawka meczu
    "live",        # pierwszy gwizdek
    "halftime",    # druga połowa
    "end",         # koniec meczu
    "approve",     # zatwierdzenie protokołu
    "unapprove",   # cofnięcie zatwierdzenia
    "conflict",    # spór wersji - odmowa zapisu
    "restore",     # przywrócenie starszej wersji przez administratora
)


def milestone_of(
    *,
    prev: Optional[Dict[str, Any]],
    phase: str,
    status: Optional[str],
    first_half: Optional[bool],
) -> Optional[str]:
    """Czy ta migawka jest chwilą, którą warto trzymać dłużej.

    Liczymy z RÓŻNICY wobec poprzedniej migawki tego meczu, bo kamieniem
    milowym jest przejście, a nie stan: dziesiąta migawka drugiej połowy nie
    jest przerwą.
    """
    if prev is None:
        return "start"
    if status and status != prev.get("status"):
        if status == "approved":
            return "approve"
        if prev.get("status") == "approved":
            return "unapprove"
        if status == "finished":
            return "end"
    if phase != prev.get("phase") and phase == "live":
        return "live"
    if first_half is False and prev.get("first_half") is True:
        return "halftime"
    return None


def expires_at(now: datetime, milestone: Optional[str]) -> datetime:
    """Do kiedy trzymamy tę migawkę."""
    days = MILESTONE_RETENTION_DAYS if milestone else RETENTION_DAYS
    return now + timedelta(days=days)


def may_store(
    *,
    now: datetime,
    last_at: Optional[datetime],
    today_count: int,
    milestone: Optional[str],
    from_device: bool = False,
) -> Tuple[bool, str]:
    """Czy wolno odłożyć tę migawkę - i dlaczego nie, gdy nie wolno.

    Kamień milowy przechodzi ZAWSZE. Limit dobowy i odstęp bronią przed
    klientem w pętli, a nie przed meczem, który naprawdę się dzieje.

    `last_at` i `from_device` zostają w podpisie, choć dziś nic nie rozstrzygają
    (odstępu między migawkami nie ma - patrz nota wyżej). Wołający i tak
    je zna, a przywrócenie jakiegokolwiek progu nie powinno wymagać zmiany
    wszystkich wywołań.
    """
    if milestone:
        return True, ""
    if today_count >= MAX_PER_MATCH_PER_DAY:
        return False, "limit"
    return True, ""
