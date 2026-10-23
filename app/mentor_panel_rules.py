"""
Reguły panelu „Mentor" - LIŚĆ bez bazy i sieci (testowalny bez połączenia).

Kontrakt: `docs/mentor-panel.md`. Tu mieszka wszystko, co da się policzyć
bez bazy: rola w parze i macierz uprawnień (sekcja 3), kategorie domyślne
i ich przywracanie, walidacja klipów, kolejność zestawień, scalanie meczów
z trzech źródeł, trendy arkuszy, podsumowanie raportu, projekcja publiczna
(bez nazwisk zawodników i bez arkuszy) i daty retencji nagrań.
"""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.mentoring_rules import CROSS_PROVINCE, PROGRAM_2028, may_manage
from app.zprp_public.referee_placeholder import is_blank_name

# ─── Drobne ─────────────────────────────────────────────────────────────────


class RuleError(Exception):
    """Odmowa reguły: kod HTTP, kod maszynowy i komunikat po polsku."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def json_value(value: Any, fallback: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return fallback
    return value if isinstance(value, type(fallback)) else fallback


def plain(text: Any, limit: int) -> str:
    """Tekst od użytkownika: bez długich myślników (zasada BAZY), przycięty."""
    out = str(text or "").replace("—", "-").replace("–", "-").replace("\r\n", "\n").strip()
    return out[:limit]


def aware(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def new_id() -> str:
    import uuid

    return uuid.uuid4().hex


# ─── Rola w parze i uprawnienia (sekcja 3) ──────────────────────────────────

ROLES = ("pair", "mentor", "admin", "committee")


def committee_scope(actor: Mapping[str, Any], pair: Mapping[str, Any], config: Optional[Mapping[str, Any]]) -> bool:
    """Menedżer mentoringu okręgu pary (lista admina albo odznaka komisji wg `may_manage`).

    Nigdy dla par „Mentor 2028" i międzyokręgowych - tam wyłącznie administrator.
    Województwa porównuje wołający PO kanonizacji (`mentoring.prov`).
    """
    province = s(pair.get("province"))
    if not province or province == CROSS_PROVINCE or s(pair.get("program")) == PROGRAM_2028:
        return False
    return may_manage(
        False,
        s(actor.get("judge_id")),
        s(actor.get("province")),
        actor.get("badges") or (),
        province,
        dict(config) if config else None,
    )


def role_in_pair(
    actor: Mapping[str, Any],
    pair: Mapping[str, Any],
    assignments: Iterable[Mapping[str, Any]],
    config: Optional[Mapping[str, Any]] = None,
) -> Optional[str]:
    """`pair` | `mentor` | `admin` | `committee` | None - w tej kolejności pierwszeństwa."""
    judge_id = s(actor.get("judge_id"))
    if not judge_id:
        return None
    if judge_id in {s(j) for j in json_value(pair.get("judge_ids"), [])}:
        return "pair"
    for link in assignments or ():
        if s(link.get("mentor_id")) == judge_id and link.get("ended_at") is None and s(link.get("pair_id") or pair.get("id")) == s(pair.get("id")):
            return "mentor"
    if actor.get("is_admin"):
        return "admin"
    # Bez konfiguracji okręgu (None) komisji nie sprawdzamy - wołający
    # dociąga ją dopiero, gdy pytający nie jest ani w parze, ani mentorem.
    if config is not None and committee_scope(actor, pair, config):
        return "committee"
    return None


#: Akcje macierzy z sekcji 3 kontraktu.
WRITE_ACTIONS = ("flag", "video", "create", "categories", "publish")
ACTIONS = ("view", "sheets", "edit", "toggle", *WRITE_ACTIONS)


def can(action: str, role: Optional[str], *, is_admin: bool = False, enabled: bool = True,
        owner: bool = False, manages: bool = False) -> bool:
    """Macierz uprawnień panelu.

    - administrator może wszystko (także przy wyłączonym panelu),
    - para i mentorzy: podgląd i zapisy tylko przy WŁĄCZONYM panelu; edycja i
      usuwanie wyłącznie własnych rzeczy,
    - komisja: podgląd i arkusze (przy włączonym panelu), bez zapisów,
    - włączanie panelu: administrator albo komisja okręgu (`manages`).
    """
    if action not in ACTIONS:
        return False
    if is_admin:
        return True
    if action == "toggle":
        return bool(manages)
    if role not in ("pair", "mentor", "committee") or not enabled:
        return False
    if action in ("view", "sheets"):
        return True
    if role == "committee":
        return False
    if action == "edit":
        return bool(owner)
    return action in WRITE_ACTIONS


def require(action: str, role: Optional[str], **kwargs: Any) -> None:
    if can(action, role, **kwargs):
        return
    if not kwargs.get("enabled", True) and role in ("pair", "mentor", "committee") and action != "toggle":
        raise RuleError(403, "PANEL_DISABLED", "Panel Mentor tej pary nie jest jeszcze włączony.")
    if action == "edit":
        raise RuleError(403, "NOT_OWNER", "Możesz zmieniać i usuwać tylko to, co sam dodałeś.")
    if role == "committee":
        raise RuleError(403, "READ_ONLY", "Komisja ogląda panel pary bez prawa zmian.")
    if action == "toggle":
        raise RuleError(403, "NO_TOGGLE", "Panel włącza administrator albo komisja okręgu pary.")
    raise RuleError(403, "NO_ACCESS", "Nie masz dostępu do panelu tej pary.")


def pair_role_sees_delegate_sheet(role: Optional[str], referee_ids: Iterable[Any], pair_judge_ids: Iterable[Any]) -> bool:
    """Nowa reguła dostępu do arkuszy delegatów (21.10.2026): każda rola w parze
    widzi arkusze meczów TEJ pary (oboje sędziowie arkusza = para, dowolna kolejność)."""
    if role not in ROLES:
        return False
    refs = {s(r) for r in referee_ids or () if s(r)}
    judges = {s(j) for j in pair_judge_ids or () if s(j)}
    return len(judges) == 2 and refs == judges


# ─── Logowanie web ──────────────────────────────────────────────────────────

#: Bez 0/O, 1/I/L - kod przepisywany z ekranu nie może być dwuznaczny.
QR_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
QR_LENGTH = 8
QR_TTL = timedelta(minutes=3)
SESSION_TTL = timedelta(days=30)


def new_qr_code(rand=secrets.choice) -> str:
    return "".join(rand(QR_ALPHABET) for _ in range(QR_LENGTH))


def normalize_qr_code(value: Any) -> str:
    code = re.sub(r"[\s-]", "", s(value)).upper()
    return code if len(code) == QR_LENGTH and all(ch in QR_ALPHABET for ch in code) else ""


def qr_status(row: Optional[Mapping[str, Any]], now: datetime) -> str:
    """`waiting` | `approved` | `expired` (także: zużyty albo nieznany)."""
    if not row or row.get("consumed_at"):
        return "expired"
    if row.get("approved_by") and row.get("approved_at"):
        return "approved"
    expires = aware(row.get("expires_at"))
    if not expires or expires <= now:
        return "expired"
    return "waiting"


def device_hint(user_agent: Any) -> str:
    """„Chrome na Windows" - żeby zatwierdzający wiedział, który komputer loguje."""
    ua = s(user_agent)
    if not ua:
        return "Nieznana przeglądarka"
    browser = (
        "Edge" if "Edg/" in ua else
        "Opera" if "OPR/" in ua else
        "Firefox" if "Firefox/" in ua else
        "Chrome" if "Chrome/" in ua else
        "Safari" if "Safari/" in ua else
        "Przeglądarka"
    )
    system = (
        "Windows" if "Windows" in ua else
        "iPhone" if "iPhone" in ua else
        "iPad" if "iPad" in ua else
        "Android" if "Android" in ua else
        "macOS" if "Mac OS X" in ua or "Macintosh" in ua else
        "Linux" if "Linux" in ua else
        ""
    )
    return f"{browser} na {system}" if system else browser


# ─── Kategorie ──────────────────────────────────────────────────────────────

PALETTE = (
    "emerald", "rose", "amber", "sky", "pink", "violet", "indigo", "teal",
    "lime", "orange", "cyan", "slate",
)
ICONS = (
    "checkmark-circle", "close-circle", "chatbubbles", "help-circle", "flash",
    "star", "flag", "alert-circle", "eye", "hand-left", "walk", "people",
    "megaphone", "timer", "shield-checkmark", "warning", "bulb", "trophy",
    "football", "body", "git-compare", "bookmark", "sparkles", "school",
)
#: Pięć dzisiejszych rodzajów znacznika „Ważne" (`mentor_video_rules.MARKER_CATEGORIES`).
DEFAULT_CATEGORIES: Tuple[Dict[str, str], ...] = (
    {"key": "dobra", "name": "Dobra decyzja", "color": "emerald", "icon": "checkmark-circle",
     "description": "Decyzja zgodna z przepisami i duchem gry."},
    {"key": "zla", "name": "Zła decyzja", "color": "rose", "icon": "close-circle",
     "description": "Decyzja do poprawy - przepis albo interpretacja."},
    {"key": "dyskusja", "name": "Do dyskusji", "color": "amber", "icon": "chatbubbles",
     "description": "Sytuacja graniczna, warta omówienia."},
    {"key": "pytanie", "name": "Pytanie do mentora", "color": "sky", "icon": "help-circle",
     "description": "Para prosi mentora o zdanie."},
    {"key": "kluczowa", "name": "Kluczowa akcja meczu", "color": "pink", "icon": "flash",
     "description": "Moment, który ustawił mecz."},
)
MAX_CATEGORY_NAME = 40
MAX_CATEGORY_DESCRIPTION = 160
MAX_CATEGORIES = 40


def default_category_rows(pair_id: str, actor_id: str = "", now: Optional[datetime] = None, make_id=new_id) -> List[Dict[str, Any]]:
    stamp = now or datetime.now(timezone.utc)
    return [
        {"id": make_id(), "pair_id": pair_id, "key": d["key"], "name": d["name"], "color": d["color"],
         "icon": d["icon"], "description": d["description"], "sort": i, "archived": False,
         "created_by": actor_id or None, "created_at": stamp}
        for i, d in enumerate(DEFAULT_CATEGORIES)
    ]


def clean_category(raw: Mapping[str, Any], *, partial: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not partial or raw.get("name") is not None:
        name = plain(raw.get("name"), MAX_CATEGORY_NAME)
        if not name:
            raise RuleError(422, "CATEGORY_NAME", "Podaj nazwę kategorii.")
        out["name"] = name
    if not partial or raw.get("color") is not None:
        color = s(raw.get("color")) or ("" if partial else PALETTE[0])
        if color not in PALETTE:
            raise RuleError(422, "CATEGORY_COLOR", "Wybierz kolor z palety.")
        out["color"] = color
    if not partial or raw.get("icon") is not None:
        icon = s(raw.get("icon")) or ("" if partial else ICONS[0])
        if icon not in ICONS:
            raise RuleError(422, "CATEGORY_ICON", "Wybierz ikonę z biblioteki.")
        out["icon"] = icon
    if not partial or raw.get("description") is not None:
        out["description"] = plain(raw.get("description"), MAX_CATEGORY_DESCRIPTION) or None
    if raw.get("sort") is not None:
        try:
            out["sort"] = max(0, min(999, int(raw.get("sort"))))
        except (TypeError, ValueError):
            pass
    return out


def reset_plan(existing: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """„Przywróć domyślne": domyślne wracają do wzoru (i z archiwum), własne idą do archiwum.

    Zwraca: `restore` [(id, wzór)], `archive` [id], `create` [wzór] - brakujące domyślne.
    Kategorie globalne admina (pair_id NULL) nie są tu ruszane.
    """
    by_key = {}
    archive: List[str] = []
    for row in existing:
        if row.get("pair_id") is None:
            continue
        key = s(row.get("key"))
        if key and key in {d["key"] for d in DEFAULT_CATEGORIES} and key not in by_key:
            by_key[key] = row
        elif not row.get("archived"):
            archive.append(row["id"])
    restore = []
    create = []
    for i, d in enumerate(DEFAULT_CATEGORIES):
        found = by_key.get(d["key"])
        patch = {"name": d["name"], "color": d["color"], "icon": d["icon"], "description": d["description"], "sort": i, "archived": False}
        if found:
            restore.append((found["id"], patch))
        else:
            create.append({**d, "sort": i})
    return {"restore": restore, "archive": archive, "create": create}


def clean_category_ids(raw: Any, allowed: Iterable[str]) -> List[str]:
    allowed_set = {s(a) for a in allowed}
    out: List[str] = []
    for item in raw if isinstance(raw, list) else []:
        value = s(item)
        if value and value in allowed_set and value not in out:
            out.append(value)
    return out[:8]


# ─── Klipy ──────────────────────────────────────────────────────────────────

MAX_CLIP_S = 600
MAX_VIDEO_S = 6 * 3600
CLIP_SOURCES = ("manual", "proel", "sheet", "marker")
MAX_CLIP_TITLE = 80
MAX_CLIP_NOTE = 1000
#: Do tej długości klip MP4 przekodowujemy (cięcie co do klatki), dłuższy
#: kopiujemy strumieniem (`-c copy`, cięcie na najbliższej klatce kluczowej).
PRECISE_CUT_MAX_S = 180


def validate_clip(start_s: Any, end_s: Any, video_duration: Any = None) -> Tuple[float, float]:
    try:
        start = float(start_s)
        end = float(end_s)
    except (TypeError, ValueError):
        raise RuleError(422, "CLIP_RANGE", "Podaj początek i koniec klipu w sekundach.")
    if start != start or end != end or start < 0 or end > MAX_VIDEO_S:
        raise RuleError(422, "CLIP_RANGE", "Zakres klipu wychodzi poza nagranie.")
    if not start < end:
        raise RuleError(422, "CLIP_ORDER", "Koniec klipu musi być po jego początku.")
    if end - start > MAX_CLIP_S:
        raise RuleError(422, "CLIP_TOO_LONG", "Klip może trwać najwyżej 10 minut.")
    try:
        duration = float(video_duration) if video_duration not in (None, "") else None
    except (TypeError, ValueError):
        duration = None
    if duration and duration > 0 and end > duration + 1:
        raise RuleError(422, "CLIP_RANGE", "Koniec klipu wychodzi poza długość nagrania.")
    return round(start, 2), round(end, 2)


def clip_cut_mode(start_s: float, end_s: float) -> str:
    return "reencode" if end_s - start_s <= PRECISE_CUT_MAX_S else "copy"


def safe_filename(text: Any, ext: str, fallback: str = "plik") -> str:
    """Nazwa pliku do nagłówka `Content-Disposition` - ASCII, bez znaków zakazanych."""
    import unicodedata

    base = unicodedata.normalize("NFKD", plain(text, 200).replace("ł", "l").replace("Ł", "L")).encode("ascii", "ignore").decode()
    base = re.sub(r"[^A-Za-z0-9 ._-]+", "-", base).strip(" .-_")[:60] or fallback
    return f"{base}.{ext}"


def clip_filename(title: Any, match_code: Any, start_s: float) -> str:
    """Nazwa pliku MP4 klipu: numer meczu, tytuł i minuta początku."""
    base = " ".join(p for p in (s(match_code), s(title)) if p) or "klip"
    minute = int(start_s // 60)
    second = int(start_s % 60)
    return safe_filename(f"{base} {minute:02d}-{second:02d}", "mp4", "klip")


def markers_as_clips(video: Mapping[str, Any], markers: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Znaczniki z zakresem z aplikacji (REC) jako klipy tylko do odczytu („z aplikacji")."""
    out = []
    for m in markers or ():
        start, end = m.get("video_s"), m.get("end_s")
        if start is None or end is None:
            continue
        out.append({
            "id": f"marker:{video.get('id')}:{m.get('id')}",
            "match_id": video.get("match_id"),
            "video_id": video.get("id"),
            "start_s": float(start),
            "end_s": float(end),
            "title": m.get("label") or "Znacznik",
            "note": m.get("comment"),
            "category_ids": [],
            "category_key": m.get("category"),
            "source": "marker",
            "source_key": m.get("id"),
            "match_ms": m.get("match_ms"),
            "half": m.get("half"),
            "read_only": True,
        })
    return out


# ─── Zestawienia ────────────────────────────────────────────────────────────

COMPILATION_MODES = ("contrast", "similar", "free")
MAX_COMPILATION_ITEMS = 120


def order_items(items: Sequence[Mapping[str, Any]], mode: str) -> List[Dict[str, Any]]:
    """Pozycje zestawienia w podanej kolejności: bez powtórzeń, kolumna a/b tylko dla „kontrastu"."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for item in items or ():
        clip_id = s(item.get("clip_id"))
        if not clip_id or clip_id in seen:
            continue
        seen.add(clip_id)
        column = s(item.get("column")).lower() if mode == "contrast" else ""
        out.append({
            "clip_id": clip_id,
            "column": (column if column in ("a", "b") else "a") if mode == "contrast" else None,
            "note": plain(item.get("note"), 280) or None,
            "position": len(out),
        })
        if len(out) >= MAX_COMPILATION_ITEMS:
            break
    return out


def append_item(existing: Sequence[Mapping[str, Any]], clip_id: str, column: Any, mode: str) -> List[Dict[str, Any]]:
    ordered = sorted(existing, key=lambda r: int(r.get("position") or 0))
    if any(s(r.get("clip_id")) == s(clip_id) for r in ordered):
        return order_items(ordered, mode)
    return order_items([*ordered, {"clip_id": clip_id, "column": column}], mode)


# ─── Wątki ──────────────────────────────────────────────────────────────────

THREAD_TARGETS = ("match", "clip", "compilation", "pair")
THREAD_KINDS = ("question", "note", "task")
THREAD_STATUSES = ("open", "resolved")
MAX_BODY = 4000
MAX_SHAPES = 20
SHAPE_KINDS = ("arrow", "circle", "line", "rect", "free")


def clean_drawing(raw: Any) -> Optional[List[Dict[str, Any]]]:
    """Strzałki i kółka na stopklatce: do 20 kształtów, współrzędne 0..1."""
    if raw in (None, "", []):
        return None
    shapes = raw.get("shapes") if isinstance(raw, Mapping) else raw
    if not isinstance(shapes, list):
        return None
    out = []
    for shape in shapes[:MAX_SHAPES]:
        if not isinstance(shape, Mapping):
            continue
        kind = s(shape.get("kind") or shape.get("type"))
        if kind not in SHAPE_KINDS:
            continue
        points = []
        for p in (shape.get("points") if isinstance(shape.get("points"), list) else [])[:64]:
            if isinstance(p, (list, tuple)) and len(p) == 2:
                try:
                    x, y = float(p[0]), float(p[1])
                except (TypeError, ValueError):
                    continue
                points.append([round(min(max(x, 0.0), 1.0), 4), round(min(max(y, 0.0), 1.0), 4)])
        if not points:
            continue
        color = s(shape.get("color"))
        out.append({"kind": kind, "points": points, "color": color if color in PALETTE else "amber"})
    return out or None


def clean_mentions(raw: Any, allowed: Iterable[str]) -> List[str]:
    allowed_set = {s(a) for a in allowed}
    out: List[str] = []
    for item in raw if isinstance(raw, list) else []:
        value = s(item)
        if value in allowed_set and value not in out:
            out.append(value)
    return out


def clean_video_anchor(video_s: Any) -> Optional[float]:
    if video_s in (None, ""):
        return None
    try:
        value = float(video_s)
    except (TypeError, ValueError):
        return None
    return round(value, 2) if 0 <= value <= MAX_VIDEO_S else None


# ─── Flagi meczu ────────────────────────────────────────────────────────────

REVIEW_STATUSES = ("open", "discussed", "closed")


def apply_flag(current: Optional[Mapping[str, Any]], patch: Mapping[str, Any], actor_id: str, now: datetime) -> Tuple[Dict[str, Any], bool]:
    """Nowy stan flag meczu + czy to ŚWIEŻE zgłoszenie (do powiadomienia)."""
    row: Dict[str, Any] = dict(current or {})
    row.setdefault("starred", False)
    row.setdefault("submitted", False)
    newly_submitted = False
    if patch.get("starred") is not None:
        row["starred"] = bool(patch["starred"])
        row["starred_by"] = actor_id if row["starred"] else None
        if not row["starred"]:
            row["star_reason"] = None
    if patch.get("star_reason") is not None:
        row["star_reason"] = plain(patch["star_reason"], 120) or None
    if patch.get("submitted") is not None:
        wanted = bool(patch["submitted"])
        if wanted and not row.get("submitted"):
            newly_submitted = True
            row["submitted_by"] = actor_id
            row["submitted_at"] = now
            row["review_status"] = "open"
        if not wanted:
            row["submitted_by"] = None
            row["submitted_at"] = None
            row["review_status"] = None
            row["due_at"] = None
        row["submitted"] = wanted
    if "due_at" in patch and patch.get("due_at") is not None:
        row["due_at"] = aware(patch["due_at"]) if isinstance(patch["due_at"], datetime) else _parse_dt(patch["due_at"])
    if patch.get("review_status") is not None:
        status = s(patch["review_status"])
        if status not in REVIEW_STATUSES:
            raise RuleError(422, "REVIEW_STATUS", "Nieznany stan omówienia.")
        row["review_status"] = status
    if patch.get("note") is not None:
        row["note"] = plain(patch["note"], 500) or None
    row["updated_at"] = now
    return row, newly_submitted


def _parse_dt(value: Any) -> Optional[datetime]:
    text = s(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise RuleError(422, "DUE_AT", "Termin omówienia ma zły format daty.")
    return aware(parsed)


# ─── Mecze: sezony, scalanie źródeł ─────────────────────────────────────────

WARSAW = None


def _warsaw():
    global WARSAW
    if WARSAW is None:
        from zoneinfo import ZoneInfo

        WARSAW = ZoneInfo("Europe/Warsaw")
    return WARSAW


def season_key(when: Any) -> str:
    """„2025/2026" - sezon zaczyna się 1 września (jak monitor i giełda)."""
    dt = when if isinstance(when, datetime) else None
    if dt is None:
        return ""
    local = dt.astimezone(_warsaw()) if dt.tzinfo else dt
    start = local.year if local.month >= 9 else local.year - 1
    return f"{start}/{start + 1}"


def season_label(key: str) -> str:
    return f"Sezon {key}" if key else "Bez daty"


def pair_refs_match(judge_ids: Iterable[Any], first: Any, second: Any) -> bool:
    judges = {s(j) for j in judge_ids or () if s(j)}
    refs = {s(first), s(second)}
    return len(judges) == 2 and "" not in refs and refs == judges


def _dt_from_ms(value: Any) -> Optional[datetime]:
    try:
        ms = float(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


def _local_naive_to_utc(value: Any) -> Optional[datetime]:
    """Hurtownia trzyma godzinę meczu bez strefy - czas polski."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo:
        return value.astimezone(timezone.utc)
    return value.replace(tzinfo=_warsaw()).astimezone(timezone.utc)


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def base_card(match_id: str) -> Dict[str, Any]:
    return {
        "match_id": s(match_id), "season": "", "scheduled_at": None, "competition_name": None, "category": None,
        "round_name": None, "home": {"name": None, "logo_url": None, "score": None},
        "away": {"name": None, "logo_url": None, "score": None}, "halftime": None, "venue_city": None,
        "match_code": None, "delegate_name": None, "stream_url": None, "source": None,
    }


def card_from_public(row: Mapping[str, Any], logos: Optional[Mapping[str, Any]] = None, category: Any = None) -> Dict[str, Any]:
    logos = logos or {}
    card = base_card(row.get("match_id"))
    when = _local_naive_to_utc(row.get("played_at") or row.get("scheduled_at"))
    ht = (row.get("halftime_home"), row.get("halftime_away"))
    card.update({
        "scheduled_at": when, "season": season_key(when), "competition_name": row.get("competition_name"),
        "category": category, "round_name": row.get("round_name") or row.get("matchday_name"),
        "home": {"name": row.get("home_team_name"), "logo_url": logos.get(s(row.get("home_club_id"))), "score": _int_or_none(row.get("score_home"))},
        "away": {"name": row.get("away_team_name"), "logo_url": logos.get(s(row.get("away_club_id"))), "score": _int_or_none(row.get("score_away"))},
        "halftime": f"{ht[0]}:{ht[1]}" if ht[0] is not None and ht[1] is not None else None,
        "venue_city": row.get("venue_city"), "match_code": row.get("match_code"),
        "delegate_name": row.get("delegate_1_name"), "stream_url": row.get("stream_url"), "source": "public",
    })
    return card


def card_from_state(match_id: Any, state: Mapping[str, Any], match_at: Any = None) -> Dict[str, Any]:
    """Mecz z monitora okręgu (`province_matches.state_json`)."""
    card = base_card(match_id)
    when = aware(match_at)
    ht_h, ht_a = _int_or_none(state.get("wynik_gosp_pol")), _int_or_none(state.get("wynik_gosc_pol"))
    card.update({
        "scheduled_at": when, "season": season_key(when),
        "competition_name": state.get("Nazwa") or state.get("RozgrywkiNazwa"),
        "round_name": state.get("kolejka") or state.get("runda"),
        "home": {"name": state.get("ID_zespoly_gosp_ZespolNazwa"), "logo_url": None,
                 "score": _int_or_none(state.get("wynik_bramki_gosp") or state.get("wynik_gosp_full"))},
        "away": {"name": state.get("ID_zespoly_gosc_ZespolNazwa"), "logo_url": None,
                 "score": _int_or_none(state.get("wynik_bramki_gosc") or state.get("wynik_gosc_full"))},
        "halftime": f"{ht_h}:{ht_a}" if ht_h is not None and ht_a is not None else None,
        "venue_city": state.get("Hala_miasto"), "match_code": state.get("RozgrywkiCode"),
        "delegate_name": None if is_blank_name(state.get("NrSedzia_delegat_nazwisko")) else state.get("NrSedzia_delegat_nazwisko"),
        "stream_url": state.get("transmisja") or None,
        "source": "province",
    })
    return card


def card_from_archive(row: Mapping[str, Any]) -> Dict[str, Any]:
    slim = json_value(row.get("slim_json"), {})
    card = base_card(row.get("match_id") or slim.get("id"))
    when = aware(row.get("match_at")) or _dt_from_ms(slim.get("ts"))
    names = slim.get("refNames") if isinstance(slim.get("refNames"), dict) else {}
    card.update({
        "scheduled_at": when, "season": season_key(when),
        "competition_name": slim.get("compName") or slim.get("comp"), "category": slim.get("cat"),
        "round_name": slim.get("round"),
        "home": {"name": slim.get("home"), "logo_url": None, "score": _int_or_none(slim.get("gH"))},
        "away": {"name": slim.get("away"), "logo_url": None, "score": _int_or_none(slim.get("gA"))},
        "halftime": f"{_int_or_none(slim.get('htH'))}:{_int_or_none(slim.get('htA'))}"
        if _int_or_none(slim.get("htH")) is not None and _int_or_none(slim.get("htA")) is not None else None,
        "venue_city": slim.get("city"), "match_code": slim.get("code") or row.get("code"),
        "delegate_name": names.get("delegate"), "source": "archive",
    })
    return card


def _fill(target: Dict[str, Any], other: Mapping[str, Any]) -> None:
    for key, value in other.items():
        if key in ("home", "away"):
            side = target.setdefault(key, {})
            for sub, sub_value in (value or {}).items():
                if side.get(sub) in (None, "") and sub_value not in (None, ""):
                    side[sub] = sub_value
        elif target.get(key) in (None, "") and value not in (None, ""):
            target[key] = value


def merge_matches(*sources: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Mecze pary z kilku źródeł w kolejności pierwszeństwa (hurtownia, monitor, archiwum).

    Jeden mecz = jeden `match_id`; pola puste w źródle ważniejszym uzupełnia
    słabsze. Wynik od najnowszego meczu.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    for source in sources:
        for card in source or ():
            match_id = s(card.get("match_id"))
            if not match_id:
                continue
            if match_id not in merged:
                merged[match_id] = {**card, "home": dict(card.get("home") or {}), "away": dict(card.get("away") or {})}
            else:
                _fill(merged[match_id], card)
    for card in merged.values():
        if not card.get("season") and card.get("scheduled_at"):
            card["season"] = season_key(card["scheduled_at"])
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return sorted(merged.values(), key=lambda c: aware(c.get("scheduled_at")) or epoch, reverse=True)


def seasons_of(cards: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for card in cards:
        key = s(card.get("season"))
        entry = out.setdefault(key, {"season": key, "label": season_label(key), "matches": 0, "starred": 0, "clips": 0})
        entry["matches"] += 1
        entry["starred"] += 1 if card.get("starred") else 0
        entry["clips"] += int(((card.get("clips") or {}).get("count")) or 0)
    return sorted(out.values(), key=lambda e: e["season"], reverse=True)


def next_and_last(cards: Sequence[Mapping[str, Any]], now: datetime) -> Tuple[Optional[Mapping[str, Any]], Optional[Mapping[str, Any]]]:
    upcoming = [c for c in cards if aware(c.get("scheduled_at")) and aware(c["scheduled_at"]) >= now - timedelta(hours=2)
                and (c.get("home") or {}).get("score") is None]
    past = [c for c in cards if aware(c.get("scheduled_at")) and aware(c["scheduled_at"]) < now and c not in upcoming]
    nxt = min(upcoming, key=lambda c: aware(c["scheduled_at"])) if upcoming else None
    last = max(past, key=lambda c: aware(c["scheduled_at"])) if past else None
    return nxt, last


def filter_cards(cards: Sequence[Mapping[str, Any]], *, season: str = "", starred: Optional[bool] = None,
                 submitted: Optional[bool] = None, q: str = "") -> List[Mapping[str, Any]]:
    needle = s(q).casefold()
    out = []
    for c in cards:
        if season and s(c.get("season")) != season:
            continue
        if starred is not None and bool(c.get("starred")) != starred:
            continue
        if submitted is not None and bool(c.get("submitted")) != submitted:
            continue
        if needle:
            hay = " ".join(s(v) for v in (c.get("competition_name"), c.get("match_code"), (c.get("home") or {}).get("name"),
                                          (c.get("away") or {}).get("name"), c.get("venue_city"), c.get("round_name"))).casefold()
            if needle not in hay:
                continue
        out.append(c)
    return out


YOUTH_WORDS = ("junior", "młodzik", "mlodzik", "dzieci", "kadet", "żak", "zak ", "dziecię", "szkół", "szkol", "u1", "u-1", "u2", "u-2", "minipiłk", "minipilk")


def is_youth(category: Any, competition_name: Any = "") -> bool:
    """Mecz młodzieżowy - przy publikacji klipu ostrzegamy (nie blokujemy)."""
    hay = f"{s(category)} {s(competition_name)} ".casefold()
    return any(word in hay for word in YOUTH_WORDS)


# ─── Arkusze i trendy ───────────────────────────────────────────────────────

SECTION_KEYS = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X")
SECTION_TITLES = {
    "I": "Zarządzanie widowiskiem", "II": "Rozumienie gry", "III": "Poruszanie i współpraca",
    "IV": "Mowa ciała i komunikacja", "V": "Linia karania", "VI": "Obszar kołowego", "VII": "Rzuty karne",
    "VIII": "Faul ataku", "IX": "Błędy techniczne", "X": "Umiejętności mentalne",
}
GRADE_POINTS = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7}


def _section_key(section: Mapping[str, Any]) -> str:
    key = s(section.get("key")).upper()
    if key in SECTION_KEYS:
        return key
    match = re.match(r"^\s*([IVX]+)\s*\.", s(section.get("title")))
    return match.group(1) if match and match.group(1) in SECTION_KEYS else ""


def section_values(evaluation: Mapping[str, Any]) -> Dict[str, int]:
    """Litera główna każdej sekcji I-X jako punkty (A=1 … G=7)."""
    out: Dict[str, int] = {}
    for section in (evaluation or {}).get("sections") or []:
        if not isinstance(section, Mapping):
            continue
        key = _section_key(section)
        point = GRADE_POINTS.get(s(section.get("mainGrade")).upper())
        if key and point is not None:
            out[key] = point
    return out


def sheet_points(evaluation: Mapping[str, Any]) -> Optional[float]:
    values = list(section_values(evaluation).values())
    return round(sum(values) / len(values), 2) if values else None


def priority_texts(evaluation: Mapping[str, Any]) -> List[str]:
    out = []
    for item in (evaluation or {}).get("priorities") or []:
        if isinstance(item, Mapping):
            text = s(item.get("body") or item.get("title"))
        else:
            text = s(item)
        if text and not re.fullmatch(r"Priorytet \d+", text):
            out.append(text)
    return out


def _norm_priority(text: str) -> str:
    return re.sub(r"[^\w ]+", "", re.sub(r"\s+", " ", text.casefold())).strip()


def trends(delegate_sheets: Sequence[Mapping[str, Any]], mentor_sheets: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Sekcje I-X w czasie, powtarzające się priorytety i delegat vs mentor (na mecz).

    Wiersz arkusza: `{match_id, date, evaluation}` (`date` - napis ISO / datetime).
    """
    sections = {key: [] for key in SECTION_KEYS}
    priorities: Dict[str, Dict[str, Any]] = {}
    by_match: Dict[str, Dict[str, Any]] = {}
    for source, rows in (("delegate", delegate_sheets), ("mentor", mentor_sheets)):
        for row in rows:
            evaluation = row.get("evaluation") or {}
            date = _date_text(row.get("date"))
            for key, value in section_values(evaluation).items():
                sections[key].append({"date": date, "value": value, "source": source})
            for text in priority_texts(evaluation):
                norm = _norm_priority(text)
                if not norm:
                    continue
                entry = priorities.setdefault(norm, {"text": text, "count": 0, "last": date})
                entry["count"] += 1
                if date and (not entry["last"] or date > entry["last"]):
                    entry["last"] = date
                    entry["text"] = text
            match_id = s(row.get("match_id"))
            if match_id:
                pair = by_match.setdefault(match_id, {"match_id": match_id, "delegate": None, "mentor": None, "date": date})
                points = sheet_points(evaluation) if row.get("points") is None else row.get("points")
                if points is not None:
                    current = pair[source]
                    pair[source] = points if current is None else round((current + points) / 2, 2)
    for key in sections:
        sections[key].sort(key=lambda p: p["date"] or "")
    compare = [
        {"match_id": v["match_id"], "delegate": v["delegate"], "mentor": v["mentor"]}
        for v in sorted(by_match.values(), key=lambda v: v["date"] or "")
        if v["delegate"] is not None and v["mentor"] is not None
    ]
    return {
        "sections": [{"key": key, "label": f"{key}. {SECTION_TITLES[key]}", "points": sections[key]} for key in SECTION_KEYS],
        "priorities": sorted(priorities.values(), key=lambda p: (-p["count"], p["text"]))[:20],
        "delegate_vs_mentor": compare,
    }


def _date_text(value: Any) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    text = s(value)
    match = re.match(r"(\d{4}-\d{2}-\d{2})", text)
    if match:
        return match.group(1)
    match = re.match(r"(\d{2})\.(\d{2})\.(\d{4})", text)
    return f"{match.group(3)}-{match.group(2)}-{match.group(1)}" if match else text[:10]


def points_trend(rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        points = row.get("points")
        if points is None:
            points = sheet_points(row.get("evaluation") or {})
        if points is not None:
            out.append({"date": _date_text(row.get("date")), "points": points})
    return sorted(out, key=lambda p: p["date"])[-12:]


def situations_from_sheet(evaluation: Mapping[str, Any], source: str, author: Any) -> List[Dict[str, Any]]:
    """Kluczowe sytuacje arkusza jako znaczniki osi wideo (czas „12:34" -> ms meczu)."""
    out = []
    for item in (evaluation or {}).get("keySituations") or []:
        if not isinstance(item, Mapping):
            continue
        time_text = s(item.get("time"))
        out.append({
            "source": source,
            "author": author,
            "category": item.get("category"),
            "description": item.get("description"),
            "time": time_text or None,
            "match_ms": clock_to_ms(time_text),
        })
    return out


def clock_to_ms(text: Any) -> Optional[int]:
    match = re.match(r"^\s*(\d{1,3})\s*[:.']\s*(\d{1,2})", s(text))
    if match:
        minutes, seconds = int(match.group(1)), int(match.group(2))
    else:
        only = re.match(r"^\s*(\d{1,3})\s*'?\s*$", s(text))
        if not only:
            return None
        minutes, seconds = int(only.group(1)), 0
    if seconds >= 60 or minutes > 180:
        return None
    return (minutes * 60 + seconds) * 1000


# ─── Raport ─────────────────────────────────────────────────────────────────

REPORT_SECTIONS = ("summary", "matches", "clips", "compilations", "threads", "sheets", "trends", "priorities", "goals")
PUBLIC_REPORT_SECTIONS = ("summary", "matches", "clips", "compilations", "threads", "priorities", "goals")


def clean_report_config(raw: Mapping[str, Any]) -> Dict[str, Any]:
    scope_in = raw.get("scope") if isinstance(raw.get("scope"), Mapping) else {}
    kind = s(scope_in.get("kind")) or "season"
    if kind not in ("match", "range", "season"):
        raise RuleError(422, "REPORT_SCOPE", "Zakres raportu: mecz, okres albo sezon.")
    scope: Dict[str, Any] = {"kind": kind}
    if kind == "match":
        scope["match_id"] = s(scope_in.get("match_id"))
        if not scope["match_id"]:
            raise RuleError(422, "REPORT_SCOPE", "Wybierz mecz raportu.")
    elif kind == "range":
        scope["from"] = _date_text(scope_in.get("from"))
        scope["to"] = _date_text(scope_in.get("to"))
        if not scope["from"] or not scope["to"] or scope["from"] > scope["to"]:
            raise RuleError(422, "REPORT_SCOPE", "Podaj poprawny okres raportu (od - do).")
    else:
        scope["season"] = s(scope_in.get("season"))
    sections = [x for x in (raw.get("sections") or []) if x in REPORT_SECTIONS]
    sections = list(dict.fromkeys(sections)) or ["summary", "matches", "clips"]
    return {"scope": scope, "sections": sections, "title": plain(raw.get("title"), 120),
            "goals": plain(raw.get("goals"), 2000)}


def in_scope(card: Mapping[str, Any], scope: Mapping[str, Any]) -> bool:
    kind = scope.get("kind")
    if kind == "match":
        return s(card.get("match_id")) == s(scope.get("match_id"))
    if kind == "range":
        date = _date_text(card.get("scheduled_at"))
        return bool(date) and scope["from"] <= date <= scope["to"]
    season = s(scope.get("season"))
    return not season or s(card.get("season")) == season


def form_direction(points: Sequence[float]) -> Optional[str]:
    """Forma z ocen w kolejności dat (A = 1 … G = 7, WIĘCEJ = LEPIEJ - jak
    `delegate_evaluation_utils.GRADE_POINTS`): `up` | `steady` | `down` | None.
    Porównuje średnią drugiej połowy ocen z pierwszą (próg 0,25)."""
    values = [p for p in points if p is not None]
    if len(values) < 2:
        return None
    half = len(values) // 2
    first = sum(values[:half]) / half
    second = sum(values[half:]) / (len(values) - half)
    if second >= first + 0.25:
        return "up"
    if second <= first - 0.25:
        return "down"
    return "steady"


FORM_LABELS = {"up": "forma rośnie", "steady": "forma stabilna", "down": "forma spada"}


def report_summary(matches: Sequence[Mapping[str, Any]], clips: Sequence[Mapping[str, Any]],
                   threads: Sequence[Mapping[str, Any]], delegate_sheets: Sequence[Mapping[str, Any]],
                   mentor_sheets: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    d_points = [r.get("points") for r in sorted(delegate_sheets, key=lambda r: _date_text(r.get("date"))) if r.get("points") is not None]
    m_points = [r.get("points") for r in sorted(mentor_sheets, key=lambda r: _date_text(r.get("date"))) if r.get("points") is not None]
    form = form_direction(d_points + m_points if not d_points or not m_points else d_points)
    summary = {
        "matches": len(matches),
        "starred": sum(1 for m in matches if m.get("starred")),
        "clips": len(clips),
        "threads_open": sum(1 for t in threads if t.get("status") == "open"),
        "threads_resolved": sum(1 for t in threads if t.get("status") == "resolved"),
        "delegate_avg": round(sum(d_points) / len(d_points), 2) if d_points else None,
        "mentor_avg": round(sum(m_points) / len(m_points), 2) if m_points else None,
        "form": form,
    }
    story = [f"{summary['matches']} {plural(summary['matches'], 'mecz', 'mecze', 'meczów')} w zakresie raportu"
             + (f", w tym {summary['starred']} {plural(summary['starred'], 'istotny', 'istotne', 'istotnych')}." if summary["starred"] else ".")]
    if summary["clips"]:
        story.append(f"{summary['clips']} {plural(summary['clips'], 'klip', 'klipy', 'klipów')} do omówienia.")
    if summary["delegate_avg"] is not None:
        story.append(f"Średnia z arkuszy delegatów: {fmt_points(summary['delegate_avg'])}.")
    if summary["mentor_avg"] is not None:
        story.append(f"Średnia z ocen mentorów: {fmt_points(summary['mentor_avg'])}.")
    if form:
        story.append(FORM_LABELS[form].capitalize() + ".")
    if summary["threads_open"]:
        story.append(f"Otwarte wątki: {summary['threads_open']}.")
    summary["story"] = story
    return summary


def plural(n: int, one: str, few: str, many: str) -> str:
    n = abs(int(n))
    if n == 1:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def fmt_points(value: Any) -> str:
    return f"{float(value):.2f}".replace(".", ",") if value is not None else "-"


# ─── Projekcja publiczna ────────────────────────────────────────────────────

_PLAYER = re.compile(r"\b(nr\s*\d{1,3})\s+[A-ZĄĆĘŁŃÓŚŹŻ][\wąćęłńóśźżĄĆĘŁŃÓŚŹŻ'-]*")


def strip_player_names(text: Any) -> str:
    """„Kara 2 min - nr 7 Kowalski (Team)" -> „Kara 2 min - nr 7 (Team)"."""
    return _PLAYER.sub(r"\1", s(text))


def public_match(card: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if not card:
        return None
    return {
        "match_id": card.get("match_id"),
        "scheduled_at": card.get("scheduled_at"),
        "competition_name": card.get("competition_name"),
        "category": card.get("category"),
        "round_name": card.get("round_name"),
        "home": {k: (card.get("home") or {}).get(k) for k in ("name", "logo_url", "score")},
        "away": {k: (card.get("away") or {}).get(k) for k in ("name", "logo_url", "score")},
        "venue_city": card.get("venue_city"),
        "match_code": card.get("match_code"),
    }


def public_clip(clip: Mapping[str, Any], *, video: Optional[Mapping[str, Any]], match: Optional[Mapping[str, Any]],
                categories: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Klip publicznie: źródło + zakres + kategoria + opis - bez autorów, wątków, arkuszy i nazwisk zawodników."""
    cats = {s(c.get("id")): c for c in categories}
    source = None
    if video:
        source = {
            "kind": video.get("kind") or "link",
            "provider": video.get("provider"),
            "url": video.get("url") if (video.get("kind") or "link") == "link" else None,
            "play_url": video.get("play_url"),
            "poster_url": video.get("poster_url"),
            "thumbnail_url": video.get("thumbnail_url"),
            "duration_s": video.get("duration_s"),
            "sync": video.get("sync"),
        }
    return {
        "id": clip.get("id"),
        "title": strip_player_names(clip.get("title")) or None,
        "note": strip_player_names(clip.get("note")) or None,
        "start_s": clip.get("start_s"),
        "end_s": clip.get("end_s"),
        "half": clip.get("half"),
        "match_ms": clip.get("match_ms"),
        "categories": [
            {k: cats[c].get(k) for k in ("name", "color", "icon")}
            for c in json_value(clip.get("category_ids"), []) if c in cats
        ],
        "source": source,
        "match": public_match(match),
        "youth": bool(match and is_youth(match.get("category"), match.get("competition_name"))),
    }


def public_report(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """Raport publicznie: bez arkuszy, trendów z arkuszy i nazwisk zawodników w klipach."""
    sections = [x for x in snapshot.get("sections") or [] if x in PUBLIC_REPORT_SECTIONS]
    out = {
        "title": snapshot.get("title"),
        "pair": snapshot.get("pair"),
        "scope": snapshot.get("scope"),
        "scope_label": snapshot.get("scope_label"),
        "sections": sections,
        "generated_at": snapshot.get("generated_at"),
    }
    if "summary" in sections:
        summary = dict(snapshot.get("summary") or {})
        summary.pop("delegate_avg", None)
        summary.pop("mentor_avg", None)
        summary["story"] = [line for line in summary.get("story") or [] if "arkusz" not in line and "ocen" not in line]
        out["summary"] = summary
    if "matches" in sections:
        out["matches"] = [public_match(m) for m in snapshot.get("matches") or []]
    if "clips" in sections:
        out["clips"] = [
            {**{k: c.get(k) for k in ("id", "match_id", "start_s", "end_s", "categories", "public_url", "thumbnail_url")},
             "title": strip_player_names(c.get("title")) or None, "note": strip_player_names(c.get("note")) or None}
            for c in snapshot.get("clips") or []
        ]
    if "compilations" in sections:
        out["compilations"] = [{k: c.get(k) for k in ("id", "name", "mode", "description", "items_count", "public_url")}
                               for c in snapshot.get("compilations") or []]
    if "threads" in sections:
        out["threads"] = [
            {"title": t.get("title"), "status": t.get("status"),
             "comments": [{"body": strip_player_names(c.get("body")), "role": c.get("role")} for c in t.get("comments") or []]}
            for t in snapshot.get("threads") or []
        ]
    if "priorities" in sections:
        out["priorities"] = snapshot.get("priorities") or []
    if "goals" in sections:
        out["goals"] = snapshot.get("goals") or ""
    return out


def public_token() -> str:
    return secrets.token_urlsafe(16)


PUBLIC_WEB = "https://www.bazapodreka.app/mentor"


def public_url(kind: str, token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    letter = {"clip": "k", "compilation": "z", "report": "r"}[kind]
    return f"{PUBLIC_WEB}/{letter}/{token}"


# ─── Retencja nagrań ────────────────────────────────────────────────────────

RETENTION_MONTHS = 12


def add_months(when: datetime, months: int) -> datetime:
    month = when.month - 1 + months
    year = when.year + month // 12
    month = month % 12 + 1
    import calendar

    day = min(when.day, calendar.monthrange(year, month)[1])
    return when.replace(year=year, month=month, day=day)


def upload_expires_at(match_at: Any, created_at: datetime) -> datetime:
    """Pełne wgrane nagranie żyje 12 miesięcy od meczu (bez daty meczu - od wgrania)."""
    base = aware(match_at) or aware(created_at) or datetime.now(timezone.utc)
    return add_months(base, RETENTION_MONTHS)


def retention_actions(upload: Mapping[str, Any], now: datetime) -> Dict[str, bool]:
    """Co dzienne sprzątanie robi z nagraniem: kasuje oryginał po udanym
    transkodowaniu, a po `expires_at` całe nagranie. Porzucone wgrywanie
    (ponad dobę bez ukończenia) przerywa."""
    status = s(upload.get("status"))
    expires = aware(upload.get("expires_at"))
    created = aware(upload.get("created_at"))
    expire = bool(expires and expires <= now and status not in ("expired",))
    return {
        "expire": expire,
        "delete_original": bool(not expire and status == "ready" and upload.get("r2_key") and upload.get("play_key")
                                and upload.get("r2_key") != upload.get("play_key")),
        "abort": bool(not expire and status == "uploading" and created and created <= now - timedelta(days=1)),
    }


# ─── Wgrywanie ──────────────────────────────────────────────────────────────

MAX_UPLOAD_BYTES = 20 * 1024 ** 3
PART_SIZE = 64 * 1024 ** 2
PARTS_PER_BATCH = 40
VIDEO_TYPES = ("video/mp4", "video/quicktime", "video/x-matroska", "video/webm", "video/x-msvideo", "video/mpeg",
               "video/3gpp", "application/octet-stream", "")


def upload_parts(size: int, part_size: int = PART_SIZE) -> int:
    return max(1, -(-int(size) // part_size))


def validate_upload(filename: Any, size: Any, content_type: Any) -> Tuple[str, int, str]:
    name = re.sub(r"[\\/\x00-\x1f]+", "_", s(filename))[:160] or "nagranie.mp4"
    try:
        total = int(size)
    except (TypeError, ValueError):
        raise RuleError(422, "UPLOAD_SIZE", "Podaj rozmiar pliku.")
    if total <= 0:
        raise RuleError(422, "UPLOAD_SIZE", "Plik jest pusty.")
    if total > MAX_UPLOAD_BYTES:
        raise RuleError(422, "UPLOAD_TOO_BIG", "Nagranie może mieć najwyżej 20 GB.")
    kind = s(content_type).lower()
    if kind not in VIDEO_TYPES and not kind.startswith("video/"):
        raise RuleError(422, "UPLOAD_TYPE", "To nie wygląda na plik wideo.")
    return name, total, kind or "application/octet-stream"


def part_batch(total_parts: int, start: int, batch: int = PARTS_PER_BATCH) -> List[int]:
    start = max(1, int(start or 1))
    return list(range(start, min(total_parts, start + batch - 1) + 1)) if start <= total_parts else []


def clean_parts(raw: Any, total_parts: int) -> List[Dict[str, Any]]:
    parts = {}
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, Mapping):
            continue
        try:
            n = int(item.get("n") or item.get("PartNumber"))
        except (TypeError, ValueError):
            continue
        etag = s(item.get("etag") or item.get("ETag"))
        if 1 <= n <= total_parts and etag:
            parts[n] = etag
    if sorted(parts) != list(range(1, total_parts + 1)):
        raise RuleError(422, "UPLOAD_PARTS", "Brakuje części pliku - wyślij wszystkie części jeszcze raz.")
    return [{"PartNumber": n, "ETag": parts[n]} for n in sorted(parts)]


def ffmpeg_progress(line: str, duration_s: Optional[float]) -> Optional[float]:
    """Postęp transkodowania z `-progress pipe:1` (out_time_ms w mikrosekundach)."""
    match = re.match(r"^out_time_(?:ms|us)=(\d+)", s(line))
    if not match or not duration_s:
        return None
    return round(min(0.99, max(0.0, int(match.group(1)) / 1_000_000 / float(duration_s))), 3)


def transcode_args(source: str, target: str, height: Optional[int]) -> List[str]:
    scale = ["-vf", "scale=-2:1080"] if height and height > 1080 else []
    return [
        "ffmpeg", "-hide_banner", "-nostdin", "-y", "-i", source, *scale,
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart", "-progress", "pipe:1", "-nostats", target,
    ]


def cut_args(source: str, target: str, start_s: float, end_s: float) -> List[str]:
    mode = clip_cut_mode(start_s, end_s)
    codec = ["-c", "copy"] if mode == "copy" else [
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "21", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k"]
    return ["ffmpeg", "-hide_banner", "-nostdin", "-y", "-ss", f"{start_s:.2f}", "-i", source,
            "-t", f"{end_s - start_s:.2f}", *codec, "-movflags", "+faststart", target]


# ─── Obecność ───────────────────────────────────────────────────────────────

PRESENCE_TTL_S = 60


def clean_where(value: Any) -> str:
    where = s(value)[:80]
    if where == "dashboard" or re.fullmatch(r"(match|clip|compilation):[A-Za-z0-9_:-]{1,60}", where):
        return where
    return "dashboard"


def unread_count(items: Iterable[Mapping[str, Any]], me: str, seen_at: Optional[datetime]) -> int:
    """Nowe od ostatniej wizyty rzeczy innych osób (klipy, komentarze, wątki)."""
    seen = aware(seen_at)
    total = 0
    for item in items:
        if s(item.get("author_id")) == s(me):
            continue
        created = aware(item.get("created_at"))
        if created and (seen is None or created > seen):
            total += 1
    return min(total, 99)
