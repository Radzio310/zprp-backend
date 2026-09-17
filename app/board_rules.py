"""
Tablica Komisji Okręgowej - reguły bez bazy i bez sieci.

Decyzje użytkownika z 16.09.2026 (przebudowa tablicy w BAZA_web):
  - DOSTĘP: tablicę okręgu czyta i edytuje tylko komisja tego okręgu - sędzia
    z odznaką „Komisja Sędziowska" w tym okręgu, osoba dopisana do komisji
    ręcznie, konto VIP tego okręgu z uprawnieniem tablicy i admin BAZY.
    Wcześniej czytał każdy zalogowany, a pisało każde konto organizacji
    z dowolnego województwa,
  - SKŁAD: domyślnie sędziowie z odznaką; opis, rolę i wygląd edytuje się
    ręcznie. Można dopisać osobę spoza odznaki. Komu zdjęto odznakę, ten zostaje
    w historii jako były członek, ale znika z list wyboru,
  - USUWANIE: od razu, z „Cofnij" w dymku; na serwerze kosz na 30 dni,
  - ZADANIA przeciąga się między kolumnami i w kolumnie.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.match_market_access import badge_names

# ---------------------------------------------------------------------------
# Słowniki
# ---------------------------------------------------------------------------

POST_TYPES = ("announcement", "decision", "note", "link")
TASK_STATUSES = ("todo", "in_progress", "done")
PRIORITIES = ("low", "medium", "high")
TARGET_TYPES = ("post", "task", "event", "comment")
#: Rodzaje, które da się wrzucić do kosza i z niego przywrócić.
TRASH_KINDS = ("post", "task", "event", "member", "comment", "attachment")
TRASH_DAYS = 30

COMMITTEE_BADGES = frozenset({"komisja", "komisja sędziowska", "komisja sedziowska"})

#: Załącznik: PDF i zdjęcia. Tablica nie jest dyskiem - pliki leżą w bazie
#: i wychodzą tylko przez trasę, która sprawdza dostęp komisji.
ATTACHMENT_MAX_BYTES = 10 * 1024 * 1024
ATTACHMENTS_PER_TARGET = 12
ATTACHMENT_MIME = {
    "application/pdf": ".pdf",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/heic": ".heic",
    "image/gif": ".gif",
}
_EXT_MIME = {
    ".pdf": "application/pdf",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".heic": "image/heic",
    ".gif": "image/gif",
}

TITLE_MAX = 200
TEXT_MAX = 20_000
COMMENT_MAX = 4_000

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_COLOR = re.compile(r"^#[0-9A-Fa-f]{6}$")


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


# ---------------------------------------------------------------------------
# Dostęp
# ---------------------------------------------------------------------------

NO_ACCESS_ACCOUNT = "Tego konta nie da się rozpoznać - zaloguj się ponownie kontem sędziego albo okręgu"
NO_ACCESS_VIP_PROVINCE = "Konto okręgu ma ustawione inne województwo niż ta tablica"
NO_ACCESS_VIP_PERMISSION = "Konto okręgu nie ma uprawnienia do tablicy komisji"
NO_ACCESS_JUDGE = "Tablicę widzi tylko komisja okręgu - potrzebna odznaka „Komisja Sędziowska” w tym okręgu"


def has_committee_badge(badges_raw: Any) -> bool:
    return any(name.strip().casefold() in COMMITTEE_BADGES for name in badge_names(badges_raw))


def vip_permissions(raw: Any) -> Dict[str, Any]:
    """`permissions_json` jako słownik - JSONB potrafi wrócić napisem."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return dict(raw) if isinstance(raw, dict) else {}


def vip_sees_board(permissions: Any) -> bool:
    """Ta sama reguła, co kafel w BAZA_web: `district_board`, a bez klucza `assignments`."""
    perms = vip_permissions(permissions)
    if perms.get("admin"):
        return True
    if "district_board" in perms:
        return bool(perms.get("district_board"))
    return bool(perms.get("assignments"))


def resolve_access(
    *,
    is_org: bool,
    is_judge: bool,
    is_admin: bool = False,
    vip_same_province: bool = False,
    vip_permissions_raw: Any = None,
    has_badge: bool = False,
    manual_member: bool = False,
) -> Dict[str, Any]:
    """Kto czyta i pisze tablicę JEDNEGO okręgu. Odmowa zawsze mówi dlaczego."""

    def verdict(allowed: bool, role: str, reason: str) -> Dict[str, Any]:
        return {
            "can_read": allowed,
            "can_write": allowed,
            "role": role if allowed else None,
            "reason": "" if allowed else reason,
        }

    if is_admin:
        return verdict(True, "admin", "")
    if is_org:
        if not vip_same_province:
            return verdict(False, "", NO_ACCESS_VIP_PROVINCE)
        if not vip_sees_board(vip_permissions_raw):
            return verdict(False, "", NO_ACCESS_VIP_PERMISSION)
        return verdict(True, "vip", "")
    if not is_judge:
        return verdict(False, "", NO_ACCESS_ACCOUNT)
    if has_badge:
        return verdict(True, "member", "")
    if manual_member:
        return verdict(True, "member", "")
    return verdict(False, "", NO_ACCESS_JUDGE)


@dataclass(frozen=True)
class Actor:
    """Kto wykonuje zmianę - wyłącznie z tokenu, nigdy z treści żądania."""

    key: str
    name: str
    judge_id: str
    is_org: bool


def actor_from_payload(payload: Mapping[str, Any], judge_name: str = "") -> Optional[Actor]:
    judge_id = _s(payload.get("judge_id"))
    login = _s(payload.get("sub"))
    label = _s(payload.get("display_name")).split("|")[0].strip()
    if judge_id:
        return Actor(key=f"judge:{judge_id}", name=judge_name or label or f"Sędzia {judge_id}", judge_id=judge_id, is_org=False)
    if _s(payload.get("account_type")) == "org" and login:
        return Actor(key=f"org:{login}", name=label or login, judge_id="", is_org=True)
    return None


# ---------------------------------------------------------------------------
# Skład komisji
# ---------------------------------------------------------------------------


@dataclass
class MemberSync:
    inserts: List[Dict[str, str]]
    activate: List[int]
    deactivate: List[int]


def plan_member_sync(
    badge_judges: Sequence[Mapping[str, Any]],
    rows: Sequence[Mapping[str, Any]],
) -> MemberSync:
    """Co zmienić w `board_members`, żeby skład zgadzał się z odznakami.

    `badge_judges`: sędziowie okręgu z odznaką (`judge_id`, `full_name`).
    `rows`: nieusunięte wiersze komisji (`id`, `judge_id`, `source`, `active`).

    Wiersz z odznaki bez odznaki = były członek (`active=False`), a nie
    usunięcie: zostaje w historii zadań. Osoba dopisana ręcznie nie zależy od
    odznaki. Sędzia z odznaką, który ma już wiersz (także ręczny), nie dostaje
    drugiego.
    """
    badge_ids = {_s(judge.get("judge_id")) for judge in badge_judges if _s(judge.get("judge_id"))}
    by_judge: Dict[str, Mapping[str, Any]] = {}
    for row in sorted(rows, key=lambda item: int(item.get("id") or 0)):
        judge_id = _s(row.get("judge_id"))
        if judge_id and judge_id not in by_judge:
            by_judge[judge_id] = row

    inserts = [
        {"judge_id": _s(judge.get("judge_id")), "name": _s(judge.get("full_name")) or _s(judge.get("judge_id"))}
        for judge in badge_judges
        if _s(judge.get("judge_id")) and _s(judge.get("judge_id")) not in by_judge
    ]
    # Ten sam sędzia dwa razy na liście odznak nie może dać dwóch wierszy.
    seen: set[str] = set()
    inserts = [item for item in inserts if not (item["judge_id"] in seen or seen.add(item["judge_id"]))]

    activate: List[int] = []
    deactivate: List[int] = []
    for row in rows:
        if _s(row.get("source")) != "badge":
            continue
        active = bool(row.get("active", True))
        in_badge = _s(row.get("judge_id")) in badge_ids
        if in_badge and not active:
            activate.append(int(row["id"]))
        elif not in_badge and active:
            deactivate.append(int(row["id"]))
    return MemberSync(inserts=inserts, activate=sorted(activate), deactivate=sorted(deactivate))


def dedupe_members(rows: Sequence[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    """Jeden wiersz na sędziego (najstarszy) - dwa równoległe odczyty mogły dopisać drugi."""
    out: List[Mapping[str, Any]] = []
    seen: set[str] = set()
    for row in sorted(rows, key=lambda item: int(item.get("id") or 0)):
        judge_id = _s(row.get("judge_id"))
        if judge_id:
            if judge_id in seen:
                continue
            seen.add(judge_id)
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# Zadania: przeciąganie
# ---------------------------------------------------------------------------


def plan_task_move(
    tasks: Sequence[Mapping[str, Any]],
    task_id: int,
    status: str,
    index: int,
) -> List[Tuple[int, str, int]]:
    """Nowa kolejność po upuszczeniu karty: `(id, status, order_index)` do zapisu.

    Liczymy od nowa obie dotknięte kolumny (skąd i dokąd), żeby kolejność
    zawsze była 0, 1, 2... bez dziur i remisów - stare wiersze mają po kilka
    zer. Zwracamy tylko to, co się zmieniło.
    """
    if status not in TASK_STATUSES:
        raise ValueError("status")
    moving = next((task for task in tasks if int(task["id"]) == int(task_id)), None)
    if moving is None:
        raise KeyError(task_id)
    source = _s(moving.get("status"))

    def column(name: str) -> List[Mapping[str, Any]]:
        rows = [task for task in tasks if _s(task.get("status")) == name and int(task["id"]) != int(task_id)]
        return sorted(rows, key=lambda task: (int(task.get("order_index") or 0), int(task["id"])))

    target = column(status)
    index = max(0, min(int(index), len(target)))
    target.insert(index, moving)

    changes: List[Tuple[int, str, int]] = []
    for position, task in enumerate(target):
        if int(task["id"]) == int(task_id) or int(task.get("order_index") or 0) != position or _s(task.get("status")) != status:
            changes.append((int(task["id"]), status, position))
    if source != status:
        for position, task in enumerate(column(source)):
            if int(task.get("order_index") or 0) != position:
                changes.append((int(task["id"]), source, position))
    return changes


# ---------------------------------------------------------------------------
# Kosz
# ---------------------------------------------------------------------------


def trash_cutoff(now: datetime) -> datetime:
    return now - timedelta(days=TRASH_DAYS)


def restorable(deleted_at: Optional[datetime], now: datetime) -> bool:
    return deleted_at is not None and deleted_at >= trash_cutoff(now)


def days_left(deleted_at: datetime, now: datetime) -> int:
    left = (deleted_at + timedelta(days=TRASH_DAYS)) - now
    return max(0, left.days + (1 if left.seconds else 0))


# ---------------------------------------------------------------------------
# Historia (oś zdarzeń)
# ---------------------------------------------------------------------------

#: Filtry okna „Historia". Zdarzenie pasuje, gdy rodzaj jego celu ALBO
#: czynność jest na liście - komentarz do zadania trafia i do „Zadań", i do
#: „Rozmów i plików".
ACTIVITY_KINDS: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "tasks": {"targets": ("task",), "actions": ()},
    "posts": {"targets": ("post",), "actions": ()},
    "events": {"targets": ("event",), "actions": ()},
    "members": {"targets": ("member",), "actions": ()},
    "talk": {"targets": ("comment", "attachment"), "actions": ("commented", "attached")},
    "trash": {"targets": (), "actions": ("deleted", "restored")},
}
#: Autor „system" = zmiany bez człowieka (skład z odznak).
SYSTEM_ACTOR = "system"


def activity_filter(kind: Any = None, actor: Any = None) -> Dict[str, Any]:
    """Filtr historii z parametrów zapytania. Nieznany rodzaj to błąd, nie cisza."""
    key = _s(kind).lower()
    if key and key not in ACTIVITY_KINDS:
        raise Invalid("Nieznany rodzaj zmian w historii")
    spec = ACTIVITY_KINDS.get(key, {"targets": (), "actions": ()})
    who = _s(actor)
    return {
        "targets": spec["targets"],
        "actions": spec["actions"],
        "system": who == SYSTEM_ACTOR,
        "actor": who if who and who != SYSTEM_ACTOR else None,
    }


def activity_matches(item: Mapping[str, Any], spec: Mapping[str, Any]) -> bool:
    """To samo co warunek SQL w `/board/activity` - dla testów i porządku."""
    if spec["targets"] or spec["actions"]:
        if item.get("target_type") not in spec["targets"] and item.get("action") not in spec["actions"]:
            return False
    if spec["system"]:
        return not item.get("actor_key")
    if spec["actor"]:
        return item.get("actor_key") == spec["actor"]
    return True


# ---------------------------------------------------------------------------
# Walidacja
# ---------------------------------------------------------------------------


class Invalid(ValueError):
    """Błąd z polskim zdaniem dla człowieka."""


def clean_title(value: Any, *, required: bool, label: str = "Tytuł") -> Optional[str]:
    text = _s(value)
    if not text:
        if required:
            raise Invalid(f"{label} nie może być pusty")
        return None
    if len(text) > TITLE_MAX:
        raise Invalid(f"{label} ma najwyżej {TITLE_MAX} znaków")
    return text


def clean_text(value: Any, limit: int = TEXT_MAX) -> Optional[str]:
    text = str(value if value is not None else "").strip()
    if not text:
        return None
    if len(text) > limit:
        raise Invalid(f"Tekst ma najwyżej {limit} znaków")
    return text


def clean_choice(value: Any, allowed: Iterable[str], label: str, *, nullable: bool = True) -> Optional[str]:
    text = _s(value)
    if not text:
        if nullable:
            return None
        raise Invalid(f"Brak pola: {label}")
    if text not in tuple(allowed):
        raise Invalid(f"Nieznana wartość pola {label}: {text}")
    return text


def clean_date(value: Any, *, required: bool = False) -> Optional[str]:
    text = _s(value)
    if not text:
        if required:
            raise Invalid("Brak daty")
        return None
    if not _DATE.match(text):
        raise Invalid("Data ma format RRRR-MM-DD")
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError as error:
        raise Invalid("Taki dzień nie istnieje") from error
    return text


def clean_time(value: Any) -> Optional[str]:
    text = _s(value)
    if not text:
        return None
    if not _TIME.match(text):
        raise Invalid("Godzina ma format GG:MM")
    return text


def clean_time_range(start: Optional[str], end: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if end and not start:
        raise Invalid("Koniec wydarzenia bez początku")
    if start and end and end <= start:
        raise Invalid("Koniec wydarzenia musi być później niż początek")
    return start, end


def clean_color(value: Any) -> Optional[str]:
    text = _s(value)
    if not text:
        return None
    if not _COLOR.match(text):
        raise Invalid("Kolor ma format #RRGGBB")
    return text.upper()


def clean_url(value: Any) -> Optional[str]:
    text = _s(value)
    if not text:
        return None
    if not re.match(r"^https?://", text, re.IGNORECASE):
        text = f"https://{text}"
    if len(text) > 2048 or " " in text:
        raise Invalid("Niepoprawny adres linku")
    return text


def clean_checklist(items: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, Mapping):
            continue
        text = _s(item.get("text"))
        if not text:
            continue
        out.append({"id": _s(item.get("id")) or f"c{len(out) + 1}", "text": text[:500], "done": bool(item.get("done"))})
    return out[:100]


# ---------------------------------------------------------------------------
# Załączniki
# ---------------------------------------------------------------------------


def attachment_mime(filename: str, declared: str) -> Optional[str]:
    """Typ pliku z nagłówka, a gdy przeglądarka go nie poda - z rozszerzenia."""
    declared = _s(declared).lower().split(";")[0]
    if declared in ATTACHMENT_MIME:
        return declared
    ext = "." + _s(filename).rsplit(".", 1)[-1].lower() if "." in _s(filename) else ""
    return _EXT_MIME.get(ext)


def sniff_matches(mime: str, head: bytes) -> bool:
    """Pierwsze bajty muszą pasować do typu - sama nazwa pliku niczego nie dowodzi."""
    if mime == "application/pdf":
        return head.startswith(b"%PDF")
    if mime == "image/jpeg":
        return head.startswith(b"\xff\xd8\xff")
    if mime == "image/png":
        return head.startswith(b"\x89PNG")
    if mime == "image/gif":
        return head.startswith(b"GIF8")
    if mime == "image/webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if mime == "image/heic":
        return head[4:8] == b"ftyp"
    return False


def safe_filename(name: str, mime: str) -> str:
    """Nazwa do nagłówka pobrania: bez ścieżek, znaków sterujących i cudzysłowów."""
    base = _s(name).replace("\\", "/").rsplit("/", 1)[-1]
    base = "".join(ch for ch in base if unicodedata.category(ch)[0] != "C" and ch not in '"<>|:*?')
    base = base.strip(" .")[:120]
    ext = ATTACHMENT_MIME.get(mime, "")
    if not base:
        base = f"zalacznik{ext}"
    elif ext and not base.lower().endswith(ext) and not (mime == "image/jpeg" and base.lower().endswith(".jpeg")):
        base = f"{base}{ext}"
    return base


def ascii_filename(name: str) -> str:
    """Zapasowa nazwa ASCII do `Content-Disposition` (pełna idzie w `filename*`)."""
    folded = unicodedata.normalize("NFKD", name.replace("ł", "l").replace("Ł", "L"))
    return "".join(ch for ch in folded if ord(ch) < 128 and not unicodedata.combining(ch)) or "zalacznik"
