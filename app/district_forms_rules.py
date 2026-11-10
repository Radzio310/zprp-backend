"""
Formularze okręgowe - reguły bez bazy i bez sieci.

Kontrakt (źródło prawdy): `docs/formularze-okregowe.md`. Tu leży wszystko, co da
się policzyć bez bazy i co musi być pod testem (`tests/test_district_forms_rules.py`):

  - odbiorcy: trzy kręgi (uczestnicy, obserwatorzy, zarządzający) liczone na żywo
    z listy sędziów okręgu, jak zaproszeni na wydarzenia (`province_event_rules`),
    z jedną różnicą - pusty krąg NIE znaczy „wszyscy",
  - widoczność kolumn wg roli i dla anonimowego webu (§7),
  - maszyna stanów kolumny `confirm` i blokady zapisu (§9): twarda 423 na wierszu
    potwierdzonym w aplikacji, miękka 409 na wierszu zaznaczonym z innego
    urządzenia, 409 po terminie,
  - „wypełnione", sloty przypomnień z presetami i ciszą nocną 21-8 (Europe/Warsaw),
  - statystyki listy z kwotami, filtry wierszy, spięcie statusu z RSVP wydarzenia.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.exam_public_rules import CODE_ALPHABET
from app.board_rules import has_committee_badge
from app.match_market_access import badge_names
from app.province_event_rules import WARSAW, Viewer, can_manage

# ---------------------------------------------------------------------------
# Słowniki i stałe
# ---------------------------------------------------------------------------

KINDS = ("list", "form")
SOURCES = ("app", "web_qr", "web", "manager")
SELF_SOURCES = ("app", "web_qr", "web")
ROLES = ("manager", "observer", "participant")
STATUSES = ("draft", "open", "closed", "archived", "trash")
SCOPES = ("todo", "active", "manage", "drafts", "closed", "archived", "trash")
COVER_TONES = ("gold", "red", "blue", "green", "violet", "slate")
RESULTS_VISIBILITY = ("managers", "observers", "participants")
FILL_MODES = ("steps", "scroll")
NOTIFY_KINDS = ("published", "reminder", "manual", "web_review", "deadline_today")

TITLE_MAX = 160
DESCRIPTION_MAX = 4000
CONFIRMATION_MAX = 300
EMOJI_MAX = 16
GUEST_NAME_MAX = 120
TRASH_DAYS = 30

#: Kod linku `/f/<kod>` i kod parowania QR: 8 znaków bez 0/O/1/l/i (jak strona wyników egzaminu).
CODE_LENGTH = 8
CODE_RE = re.compile(rf"^[{CODE_ALPHABET}]{{{CODE_LENGTH}}}$")
WEB_HOST = "https://www.bazapodreka.app"
FORM_ID_RE = re.compile(r"^[a-f0-9]{16}$")

#: Logowanie QR na webie (wzór: exam_web).
PAIR_TTL = timedelta(minutes=5)
WEB_TOKEN_HOURS = 12
#: „To Ty?" najwyżej raz na 30 minut na wiersz.
WEB_REVIEW_DEDUP = timedelta(minutes=30)
#: Ręczny push komisji: najwyżej raz na 10 minut na formularz.
MANUAL_REMIND_EVERY = timedelta(minutes=10)
#: Plik eksportu do pobrania.
EXPORT_TTL = timedelta(minutes=15)

QUIET_FROM = time(21, 0)
QUIET_UNTIL = time(8, 0)
EVENING_FALLBACK = time(20, 30)

#: Offsety przypomnień przed terminem (`settings.reminders`).
REMINDER_PRESETS: Dict[str, Tuple[Tuple[str, timedelta], ...]] = {
    "off": (),
    "gentle": (("1d", timedelta(days=1)),),
    "standard": (("3d", timedelta(days=3)), ("1d", timedelta(days=1)), ("3h", timedelta(hours=3))),
    "intense": (
        ("7d", timedelta(days=7)),
        ("3d", timedelta(days=3)),
        ("1d", timedelta(days=1)),
        ("6h", timedelta(hours=6)),
        ("2h", timedelta(hours=2)),
    ),
}
DEFAULT_REMINDERS = "standard"

SOURCE_LABELS = {"app": "Aplikacja", "web_qr": "Web QR", "web": "Web", "manager": "Komisja"}


class FormError(Exception):
    """Odmowa z kodem i zdaniem po polsku: `{"error": code, "message": ...}`."""

    def __init__(self, code: str, message: str, status: int = 400, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.extra = extra

    def body(self) -> Dict[str, Any]:
        return {"error": self.code, "message": self.message, **self.extra}


NOT_FOUND_MESSAGE = "Nie ma takiego formularza albo nie jest skierowany do Ciebie."


def not_found() -> FormError:
    return FormError("not_found", NOT_FOUND_MESSAGE, 404)


# ---------------------------------------------------------------------------
# Drobne
# ---------------------------------------------------------------------------


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _ids(values: Any) -> List[str]:
    out: List[str] = []
    for value in values or []:
        text = _s(value)
        if text and text not in out:
            out.append(text)
    return out


def aware(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def iso(value: Any) -> Optional[str]:
    moment = aware(value)
    return moment.isoformat() if moment else None


def parse_iso(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return aware(value)
    text = _s(value)
    if not text:
        return None
    try:
        return aware(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError as error:
        raise FormError("bad_date", "Niepoprawna data.", 400) from error


def loads(raw: Any, default: Any) -> Any:
    """Kolumna JSON potrafi wrócić z bazy napisem (asyncpg bez kodeka) - oddajemy obiekt."""
    if raw is None:
        return default
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    if isinstance(raw, str):
        if not raw.strip():
            return default
        try:
            raw = json.loads(raw)
        except ValueError:
            return default
    if isinstance(default, dict):
        return dict(raw) if isinstance(raw, Mapping) else default
    if isinstance(default, list):
        return list(raw) if isinstance(raw, list) else default
    return raw


def new_form_id() -> str:
    return secrets.token_hex(8)


def new_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def normalize_code(raw: Any) -> Optional[str]:
    """Kod z adresu: wielkość liter, spacje i myślnik bez znaczenia. Zły kształt = None (404 bez bazy)."""
    code = re.sub(r"[\s-]", "", str(raw or "")).lower()
    return code if CODE_RE.match(code) else None


def web_url(code: Optional[str]) -> Optional[str]:
    return f"{WEB_HOST}/f/{code}" if code else None


def pair_url(code: str) -> str:
    return f"{WEB_HOST}/f/p/{code}"


def province_label(display_name: str) -> str:
    """„ŚLĄSKIE" -> „Śląskie", „KUJAWSKO-POMORSKIE" -> „Kujawsko-pomorskie"."""
    text = _s(display_name)
    return text[:1].upper() + text[1:].lower() if text else ""


# ---------------------------------------------------------------------------
# Odbiorcy (§2)
# ---------------------------------------------------------------------------


def clean_target(raw: Any, *, allow_open: bool = False) -> Dict[str, Any]:
    data = raw if isinstance(raw, Mapping) else {}
    out = {
        "include_all": bool(data.get("include_all")),
        "include_badges": _ids(data.get("include_badges")),
        "exclude_badges": _ids(data.get("exclude_badges")),
        "include_ids": _ids(data.get("include_ids")),
        "exclude_ids": _ids(data.get("exclude_ids")),
    }
    if allow_open:
        out["open"] = bool(data.get("open"))
    return out


def has_criteria(target: Mapping[str, Any]) -> bool:
    return bool(target.get("include_all") or _ids(target.get("include_badges")) or _ids(target.get("include_ids")))


def clean_audience(raw: Any, *, kind: str) -> Dict[str, Any]:
    """Trzy kręgi. Pusty krąg uczestników jest błędem (edytor wymaga wyboru)."""
    data = raw if isinstance(raw, Mapping) else {}
    participants = clean_target(data.get("participants"), allow_open=True)
    if participants["open"] and kind != "form":
        raise FormError("bad_audience", "Otwarty formularz (każdy z linkiem) jest tylko w trybie formularza, nie listy.", 400)
    if not has_criteria(participants) and not participants["open"]:
        raise FormError("bad_audience", "Wybierz, kto jest na liście: wszyscy, odznaki albo konkretne osoby.", 400)
    return {
        "participants": participants,
        "observers": clean_target(data.get("observers")),
        "managers": clean_target(data.get("managers")),
    }


def target_ids(judges: Iterable[Mapping[str, Any]], target: Mapping[str, Any], inactive: Iterable[Any] = ()) -> List[str]:
    """Kto pasuje do kręgu. Kolejność jak w wydarzeniach: wyłączenie osoby, dopisanie
    osoby, nieaktywny w okręgu, wykluczona odznaka, potem „wszyscy" albo odznaki.
    Krąg bez kryteriów = NIKT (inaczej niż stare wydarzenia)."""
    data = target if isinstance(target, Mapping) else {}
    skipped = {_s(x) for x in inactive or () if _s(x)}
    include_all = bool(data.get("include_all"))
    include_badges = set(_ids(data.get("include_badges")))
    exclude_badges = set(_ids(data.get("exclude_badges")))
    include_people = set(_ids(data.get("include_ids")))
    exclude_people = set(_ids(data.get("exclude_ids")))
    out: List[str] = []
    for judge in judges:
        jid = _s(judge.get("judge_id"))
        if not jid or jid in exclude_people:
            continue
        if jid in include_people:
            out.append(jid)
            continue
        if jid in skipped:
            continue
        names = set(badge_names(judge.get("badges")))
        if names & exclude_badges:
            continue
        if include_all or (names & include_badges):
            out.append(jid)
    return sorted(set(out))


@dataclass
class Circles:
    participants: List[str] = field(default_factory=list)
    observers: List[str] = field(default_factory=list)
    managers: List[str] = field(default_factory=list)
    open: bool = False


def resolve_audience(
    judges: Sequence[Mapping[str, Any]],
    audience: Mapping[str, Any],
    *,
    author: str,
    inactive: Iterable[Any] = (),
) -> Circles:
    """Kręgi na żywo. Zarządzający: autor, komisja okręgu i `audience.managers` (admin - przy pytającym)."""
    gone = list(inactive or ())
    data = audience if isinstance(audience, Mapping) else {}
    participants_target = data.get("participants") if isinstance(data.get("participants"), Mapping) else {}
    managers = set(target_ids(judges, data.get("managers") or {}, gone))
    managers |= {_s(j.get("judge_id")) for j in judges if _s(j.get("judge_id")) and has_committee_badge(j.get("badges"))}
    if _s(author):
        managers.add(_s(author))
    return Circles(
        participants=target_ids(judges, participants_target, gone),
        observers=target_ids(judges, data.get("observers") or {}, gone),
        managers=sorted(managers),
        open=bool(participants_target.get("open")),
    )


def roles_for(who: Viewer, *, province: str, author: str, circles: Circles) -> List[str]:
    """Moje role w formularzu, w stałej kolejności manager, observer, participant."""
    out: List[str] = []
    jid = who.judge_id
    if who.is_admin or (jid and jid == _s(author)) or can_manage(who, province) or (jid and jid in circles.managers):
        out.append("manager")
    if jid and jid in circles.observers:
        out.append("observer")
    if jid and jid in circles.participants:
        out.append("participant")
    return out


def can_create(who: Viewer, province: str) -> bool:
    """Tworzą admin i komisja okręgu (ta sama reguła co wydarzenia).

    Komisja = odznaka „Komisja sędziowska” albo „Komisja” we własnym okręgu
    (domyślnie, bez nadawania). Ręczny wpis w Tablicy Komisji nie wystarcza
    (decyzja właściciela 10.11.2026).
    """
    return can_manage(who, province)


def scope_counts(items: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    """Liczniki zakładek listy: ile pozycji w każdej (`items`: roles, status, me)."""
    out = {scope: 0 for scope in SCOPES}
    for item in items:
        me = item.get("me") or {}
        for scope in SCOPES:
            if in_scope(scope, roles=item.get("roles") or (), status=_s(item.get("status")),
                        participant=bool(me.get("participant")), filled=bool(me.get("filled")),
                        web_review=bool(me.get("web_review"))):
                out[scope] += 1
    return out


# ---------------------------------------------------------------------------
# Stan formularza
# ---------------------------------------------------------------------------


def is_closed(form: Mapping[str, Any], now: datetime) -> bool:
    if form.get("closed_at") is not None:
        return True
    closes = aware(form.get("closes_at"))
    return closes is not None and now >= closes


def form_status(form: Mapping[str, Any], now: datetime) -> str:
    if form.get("deleted_at") is not None:
        return "trash"
    if form.get("archived_at") is not None:
        return "archived"
    if form.get("published_at") is None:
        return "draft"
    return "closed" if is_closed(form, now) else "open"


def check_access(roles: Sequence[str], status: str) -> None:
    """404 dla obcych; szkic i kosz widzi tylko zarządzający."""
    if not roles:
        raise not_found()
    if status in ("draft", "trash") and "manager" not in roles:
        raise not_found()


#: Źródła, które piszą już w szkicu: komisja i strona www (decyzja 10.11.2026 -
#: link działa przed publikacją). Aplikacja uczestnika czeka na publikację.
DRAFT_WRITABLE_SOURCES = ("manager", "web", "web_qr")


def draft_writable(source: str) -> bool:
    return source in DRAFT_WRITABLE_SOURCES


def pushes_muted(form: Mapping[str, Any]) -> bool:
    """Bez pushy i przypomnień: szkic (odbiorcy go nie widzą) albo tryb cichy (testy na żywo).

    Jedyna bramka wysyłki modułu - sprawdza ją `notify`, przez który idą wszystkie pushe list
    (publikacja, przypomnienia z harmonogramu, ręczne, „To Ty?”). Wyciszony push NIE trafia
    do dziennika, więc po włączeniu powiadomień publikacja może pójść naprawdę.
    """
    return form.get("published_at") is None or bool(form.get("silent"))


#: Wyłączenie trybu cichego: reset = cofnij do szkicu i wyczyść testowe odpowiedzi,
#: send = zostaw i wyślij powiadomienie o publikacji teraz, later = tylko przyszłe przypomnienia.
SILENT_OFF_MODES = ("reset", "send", "later")


def silent_off_refusal(status: str, mode: str) -> Optional["FormError"]:
    if mode not in SILENT_OFF_MODES:
        return FormError("bad_mode", "Wybierz, co zrobić z testowymi odpowiedziami.", 400)
    if status == "trash":
        return FormError("trash", "Formularz jest w koszu.", 409)
    if mode == "reset" and status == "draft":
        return FormError("not_published", "Szkic nie ma jeszcze odpowiedzi do wyczyszczenia.", 409)
    if mode == "send" and status != "open":
        return FormError("not_open", "Powiadomienie o publikacji wyślesz tylko przy otwartej liście.", 409)
    return None


def event_image_url(data_json: Any) -> Optional[str]:
    """Grafika tytułowa spiętego wydarzenia (`data_json.title_image.url`) - tło bohatera formularza."""
    data = loads(data_json, {})
    image = data.get("title_image") if isinstance(data, Mapping) else None
    url = _s(image.get("url")) if isinstance(image, Mapping) else ""
    return url or None


def silent_publish_slot(moment: datetime) -> str:
    """Slot powiadomienia o publikacji po trybie cichym - inny niż „1”, żeby dziennik go nie zdublował."""
    return f"loud-{moment.strftime('%Y%m%dT%H%M%S')}"


def in_scope(scope: str, *, roles: Sequence[str], status: str, participant: bool, filled: bool, web_review: bool) -> bool:
    """Zakładki listy formularzy (`GET /district-forms?scope=`)."""
    manager = "manager" in roles
    if scope == "todo":
        return participant and status == "open" and (not filled or web_review)
    if scope == "active":
        return status == "open"
    if scope == "manage":
        return manager and status in ("draft", "open", "closed")
    if scope == "drafts":
        return manager and status == "draft"
    if scope == "closed":
        return status == "closed"
    if scope == "archived":
        return status == "archived"
    if scope == "trash":
        return manager and status == "trash"
    return False


def restorable(deleted_at: Any, now: datetime) -> bool:
    moment = aware(deleted_at)
    return moment is not None and moment >= now - timedelta(days=TRASH_DAYS)


# ---------------------------------------------------------------------------
# Ustawienia, okładka, tytuł
# ---------------------------------------------------------------------------


def clean_title(value: Any) -> str:
    text = _s(value)
    if not text:
        raise FormError("bad_title", "Podaj tytuł formularza.", 400)
    if len(text) > TITLE_MAX:
        raise FormError("bad_title", f"Tytuł ma najwyżej {TITLE_MAX} znaków.", 400)
    return text


def clean_description(value: Any) -> Optional[str]:
    text = str(value if value is not None else "").strip()
    if len(text) > DESCRIPTION_MAX:
        raise FormError("bad_description", f"Opis ma najwyżej {DESCRIPTION_MAX} znaków.", 400)
    return text or None


def clean_cover(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping) or not value:
        return None
    tone = _s(value.get("tone")) or "gold"
    if tone not in COVER_TONES:
        raise FormError("bad_cover", "Nieznany kolor okładki.", 400)
    out: Dict[str, Any] = {"tone": tone}
    emoji = _s(value.get("emoji"))
    if emoji:
        if len(emoji) > EMOJI_MAX:
            raise FormError("bad_cover", "Okładka przyjmuje jedno emoji.", 400)
        out["emoji"] = emoji
    return out


def clean_settings(raw: Any, *, kind: str) -> Dict[str, Any]:
    data = raw if isinstance(raw, Mapping) else {}
    reminders = _s(data.get("reminders")) or DEFAULT_REMINDERS
    if reminders not in REMINDER_PRESETS:
        raise FormError("bad_settings", "Przypomnienia: wyłączone, łagodne, standardowe albo intensywne.", 400)
    confirmation = _s(data.get("confirmation"))
    if len(confirmation) > CONFIRMATION_MAX:
        raise FormError("bad_settings", f"Komunikat po wysłaniu ma najwyżej {CONFIRMATION_MAX} znaków.", 400)
    out: Dict[str, Any] = {
        "roster_visible": bool(data.get("roster_visible", False)),
        "reminders": reminders,
        "home_prompt": bool(data.get("home_prompt", True)),
        "confirmation": confirmation or None,
    }
    if kind == "form":
        results = _s(data.get("results_visibility")) or "managers"
        if results not in RESULTS_VISIBILITY:
            raise FormError("bad_settings", "Wyniki widzą: zarządzający, obserwatorzy albo uczestnicy.", 400)
        fill_mode = _s(data.get("fill_mode")) or "steps"
        if fill_mode not in FILL_MODES:
            raise FormError("bad_settings", "Tryb wypełniania: krokami albo jedna strona.", 400)
        out.update(
            {
                "anonymous": bool(data.get("anonymous", False)),
                "allow_edit": bool(data.get("allow_edit", True)),
                "results_visibility": results,
                "fill_mode": fill_mode,
            }
        )
    return out


def anonymous_web_refusal(*, kind: str, settings: Mapping[str, Any], audience: Mapping[str, Any], web_enabled: bool) -> Optional[FormError]:
    """Anonimowy formularz nie może mieć webu z listą imion (wybór siebie z listy zdradza osobę)."""
    if kind != "form" or not web_enabled or not settings.get("anonymous"):
        return None
    participants = audience.get("participants") if isinstance(audience.get("participants"), Mapping) else {}
    if participants.get("open"):
        return None
    return FormError(
        "anonymous_web",
        "Formularz anonimowy na stronie www działa tylko jako otwarty (każdy wpisuje imię i nazwisko).",
        400,
    )


# ---------------------------------------------------------------------------
# Kolumny i widoczność (§4, §7)
# ---------------------------------------------------------------------------


def columns_of(schema: Any) -> List[Dict[str, Any]]:
    raw = schema.get("columns") if isinstance(schema, Mapping) else None
    return [dict(c) for c in raw or [] if isinstance(c, Mapping) and _s(c.get("id"))]


def status_column(columns: Sequence[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    for column in columns:
        if column.get("type") == "status":
            return dict(column)
    return None


def self_editable(column: Mapping[str, Any]) -> bool:
    return column.get("editor") in ("self", "self_confirm")


def my_fields(kind: str, schema: Any, columns: Sequence[Mapping[str, Any]]) -> List[str]:
    """Tytuły pól, które uczestnik wypełnia sam (karta „Czeka na Ciebie": „Obecność, wpłata, menu")."""
    if kind == "list":
        titles = [_s(c.get("title")) for c in columns if self_editable(c)]
    else:
        sections = schema.get("sections") if isinstance(schema, Mapping) else None
        titles = [
            _s(q.get("title"))
            for section in sections or []
            if isinstance(section, Mapping)
            for q in section.get("questions") or []
            if isinstance(q, Mapping)
        ]
    return [t for t in titles if t]


#: Tryby widoczności komórek: zarządzający, obserwator, mój wiersz, cudzy wiersz przy
#: `roster_visible`, anonimowy web.
VIEW_MODES = ("manager", "observer", "own", "roster", "web")


def column_visible(column: Mapping[str, Any], mode: str) -> bool:
    visibility = column.get("visibility") or "all"
    if mode == "manager":
        return True
    if mode == "observer":
        return visibility in ("all", "self")
    if mode == "own":
        return visibility != "managers"
    if mode == "roster":
        return visibility == "all"
    if mode == "web":
        return visibility == "all" or self_editable(column)
    return False


def visible_columns(columns: Sequence[Mapping[str, Any]], mode: str) -> List[Dict[str, Any]]:
    return [dict(c) for c in columns if column_visible(c, mode)]


def web_masked(column: Mapping[str, Any]) -> bool:
    """Na anonimowym webie widać tylko „jest wartość", chyba że kolumna jest jawna albo to status."""
    return column.get("type") != "status" and (column.get("visibility") or "all") != "all"


def filter_cells(columns: Sequence[Mapping[str, Any]], cells: Mapping[str, Any], mode: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for column in columns:
        cid = column["id"]
        cell = cells.get(cid) if isinstance(cells, Mapping) else None
        if not isinstance(cell, Mapping) or not column_visible(column, mode):
            continue
        if not has_value(column, cell.get("v")):
            continue
        if mode == "web":
            out[cid] = {"set": True} if web_masked(column) else {"v": cell.get("v"), "src": cell.get("src"), "at": cell.get("at")}
        else:
            out[cid] = dict(cell)
    return out


# ---------------------------------------------------------------------------
# Wartości komórek
# ---------------------------------------------------------------------------


def has_value(column: Mapping[str, Any], value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    if isinstance(value, list) and not value:
        return False
    return True


def clean_value(column: Mapping[str, Any], value: Any) -> Any:
    """Wartość komórki po normalizacji; None = brak. Zła wartość = 400 `bad_value`."""
    title = _s(column.get("title")) or _s(column.get("id"))

    def bad(message: str) -> FormError:
        return FormError("bad_value", f"„{title}”: {message}", 400, column_id=column.get("id"))

    ctype = column.get("type")
    if value is None or (isinstance(value, str) and not value.strip() and ctype != "text"):
        return None
    if ctype == "status":
        options = {o["id"] for o in column.get("options") or []}
        if not isinstance(value, str) or value not in options:
            raise bad("wybierz jedną z opcji.")
        return value
    if ctype == "check":
        if value is True:
            return True
        if value is False:
            return None
        raise bad("to pole zaznacza się albo nie.")
    if ctype == "confirm":
        if value in ("declared", "confirmed"):
            return value
        raise bad("dozwolone: zgłoszone albo potwierdzone.")
    if ctype == "choice":
        options = {o["id"] for o in column.get("options") or []}
        if column.get("multi"):
            if isinstance(value, str):
                value = [value]
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise bad("zaznacz opcje z listy.")
            picked = [o["id"] for o in column.get("options") or [] if o["id"] in set(value)]
            if len(picked) != len(set(value)):
                raise bad("takiej opcji nie ma.")
            return picked or None
        if not isinstance(value, str) or value not in options:
            raise bad("wybierz jedną z opcji.")
        return value
    if ctype == "number":
        if isinstance(value, str):
            try:
                value = float(value.replace(",", ".").strip())
            except ValueError as error:
                raise bad("tu wpisuje się liczbę.") from error
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or value in (float("inf"), float("-inf")):
            raise bad("tu wpisuje się liczbę.")
        if column.get("integer") and int(value) != value:
            raise bad("tu wpisuje się liczbę całkowitą.")
        low, high = column.get("min"), column.get("max")
        if low is not None and value < low:
            raise bad(f"najmniej {low}.")
        if high is not None and value > high:
            raise bad(f"najwięcej {high}.")
        return int(value) if int(value) == value else float(value)
    if ctype == "text":
        if not isinstance(value, str):
            raise bad("tu wpisuje się tekst.")
        text = value.strip()
        limit = int(column.get("max_length") or 500)
        if len(text) > limit:
            raise bad(f"najwyżej {limit} znaków.")
        return text or None
    raise bad("nieznany rodzaj kolumny.")


def make_cell(value: Any, *, source: str, by: Optional[str], now: datetime) -> Dict[str, Any]:
    return {"v": value, "src": source, "by": by or None, "at": now.isoformat()}


def cell_refusal(
    column: Mapping[str, Any],
    *,
    source: str,
    current: Any,
    new: Any,
    closed: bool,
) -> Optional[FormError]:
    """Czy wolno zapisać tę komórkę. None = wolno. Zapis bez zmiany wartości nie trafia tutaj."""
    if source == "manager":
        return None
    editor = column.get("editor") or "self"
    title = _s(column.get("title")) or _s(column.get("id"))
    if editor == "managers":
        return FormError("column_forbidden", f"„{title}” wpisuje komisja.", 403, column_id=column.get("id"))
    if column.get("type") == "confirm" and editor == "self_confirm":
        if current == "confirmed":
            return FormError(
                "confirmed_locked",
                f"„{title}”: komisja już potwierdziła - zmianę zgłoś komisji.",
                403,
                column_id=column.get("id"),
            )
        if new == "confirmed":
            return FormError("column_forbidden", f"„{title}” potwierdza komisja.", 403, column_id=column.get("id"))
    if closed and column.get("lock_after_deadline", column.get("type") != "confirm"):
        return FormError("closed", "Termin minął - tej odpowiedzi nie można już zmienić.", 409, column_id=column.get("id"))
    return None


def web_row_refusal(entry: Optional[Mapping[str, Any]], *, device_id: str, force: bool) -> Optional[FormError]:
    """Blokady wiersza dla anonimowego webu: twarda (zweryfikowany) i miękka (inne urządzenie)."""
    if not entry:
        return None
    if entry.get("verified"):
        return FormError("verified_lock", "Ten sędzia potwierdził wybór w aplikacji.", 423)
    other = _s(entry.get("web_device"))
    if other and other != _s(device_id) and not force:
        at = iso(entry.get("web_at"))
        return FormError(
            "soft_claimed",
            "To już zaznaczono z innego urządzenia. Na pewno to Ty?",
            409,
            at=at,
        )
    return None


# ---------------------------------------------------------------------------
# Wypełnienie
# ---------------------------------------------------------------------------


def _cell_value(cells: Mapping[str, Any], cid: str) -> Any:
    cell = cells.get(cid) if isinstance(cells, Mapping) else None
    return cell.get("v") if isinstance(cell, Mapping) else None


def list_filled(columns: Sequence[Mapping[str, Any]], cells: Mapping[str, Any]) -> bool:
    """Ma status, jeśli jest kolumna statusu. Bez niej: każda wymagana kolumna, którą
    sędzia może wypełnić. Bez wymaganych: cokolwiek w kolumnach sędziego."""
    status = status_column(columns)
    if status:
        return has_value(status, _cell_value(cells, status["id"]))
    own = [c for c in columns if self_editable(c)]
    required = [c for c in own if c.get("required")]
    if required:
        return all(has_value(c, _cell_value(cells, c["id"])) for c in required)
    return any(has_value(c, _cell_value(cells, c["id"])) for c in own)


def entry_filled(kind: str, schema: Any, entry: Optional[Mapping[str, Any]]) -> bool:
    if not entry:
        return False
    if kind == "list":
        return list_filled(columns_of(schema), loads(entry.get("cells_json"), {}))
    return entry.get("submitted_at") is not None and bool(loads(entry.get("answers_json"), {}))


# ---------------------------------------------------------------------------
# Wydarzenie (§8)
# ---------------------------------------------------------------------------


def rsvp_from_status(value: Any) -> Optional[str]:
    """`yes` -> „yes", `no` -> „no", reszta (np. „może") -> brak odpowiedzi RSVP."""
    return value if value in ("yes", "no") else None


def status_from_rsvp(column: Mapping[str, Any], rsvp: str) -> str:
    options = {o["id"] for o in column.get("options") or []}
    if rsvp not in ("yes", "no") or rsvp not in options:
        raise FormError("bad_value", "Ta lista nie ma odpowiedzi „Będę” / „Nie będę”.", 400)
    return rsvp


def event_target(participants: Mapping[str, Any]) -> Dict[str, Any]:
    """Uczestnicy formularza w kształcie zaproszonych wydarzenia (`data_json`)."""
    target = clean_target(participants)
    return {
        "target": {
            "include_all": target["include_all"],
            "include_badges": target["include_badges"],
            "exclude_badges": target["exclude_badges"],
        },
        "include_ids": target["include_ids"],
        "exclude_ids": target["exclude_ids"],
    }


def status_counts(column: Optional[Mapping[str, Any]], participants: Iterable[str], cells_by_judge: Mapping[str, Mapping[str, Any]]) -> Dict[str, int]:
    """{option_id: n, ..., "none": n} wśród obecnych uczestników."""
    if not column:
        return {}
    counts = {o["id"]: 0 for o in column.get("options") or []}
    counts["none"] = 0
    for jid in participants:
        value = _cell_value(cells_by_judge.get(jid) or {}, column["id"])
        if value in counts and value != "none":
            counts[value] += 1
        else:
            counts["none"] += 1
    return counts


# ---------------------------------------------------------------------------
# Przypomnienia (§6)
# ---------------------------------------------------------------------------


def _local(moment: datetime) -> datetime:
    return aware(moment).astimezone(WARSAW)


def _at_local(day, clock: time) -> datetime:
    return datetime.combine(day, clock).replace(tzinfo=WARSAW).astimezone(timezone.utc)


def in_quiet_hours(moment: datetime) -> bool:
    clock = _local(moment).time()
    return clock >= QUIET_FROM or clock < QUIET_UNTIL


def quiet_shift(fire_at: datetime, closes_at: datetime) -> datetime:
    """Slot w nocy (21-8) idzie na 8:00. Gdy termin minie przed 8:00 - na 20:30 poprzedniego wieczoru."""
    if not in_quiet_hours(fire_at):
        return fire_at
    local = _local(fire_at)
    morning_day = local.date() + timedelta(days=1) if local.time() >= QUIET_FROM else local.date()
    morning = _at_local(morning_day, QUIET_UNTIL)
    if morning < aware(closes_at):
        return morning
    return _at_local(morning_day - timedelta(days=1), EVENING_FALLBACK)


def slot_key(name: str, closes_at: datetime) -> str:
    """Klucz slotu niesie termin - przesunięty termin daje nowe przypomnienia."""
    return f"{name}@{int(aware(closes_at).timestamp())}"


def reminder_slots(preset: str, closes_at: Optional[datetime]) -> List[Tuple[str, datetime]]:
    if closes_at is None:
        return []
    deadline = aware(closes_at)
    out: List[Tuple[str, datetime]] = []
    for name, offset in REMINDER_PRESETS.get(preset or DEFAULT_REMINDERS, ()):
        out.append((slot_key(name, deadline), quiet_shift(deadline - offset, deadline)))
    return sorted(out, key=lambda item: item[1])


def due_slot(
    preset: str,
    *,
    closes_at: Optional[datetime],
    published_at: Optional[datetime],
    now: datetime,
) -> Optional[Tuple[str, datetime]]:
    """Najpóźniejszy slot, którego czas już minął, a termin jeszcze nie.

    Sloty sprzed publikacji przepadają (start i tak wysłał „published"); gdy przejście
    spóźniło się o kilka slotów, wychodzi tylko ostatni - bez serii pushy naraz.
    """
    deadline = aware(closes_at)
    published = aware(published_at)
    if deadline is None or published is None or now >= deadline:
        return None
    due = [(key, at) for key, at in reminder_slots(preset, deadline) if at <= now and at >= published]
    return due[-1] if due else None


# ---------------------------------------------------------------------------
# Filtry wierszy
# ---------------------------------------------------------------------------

SPECIAL_FILTERS = ("_filled", "_web_review", "_verified")


def clean_filter(raw: Any) -> Dict[str, Any]:
    """`filter` z adresu (JSON) albo z ciała. Zły JSON = 400."""
    if raw in (None, "", {}):
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as error:
            raise FormError("bad_filter", "Filtr ma zły kształt.", 400) from error
    if not isinstance(raw, Mapping):
        raise FormError("bad_filter", "Filtr ma zły kształt.", 400)
    return {str(k): v for k, v in raw.items()}


def matches_filter(
    columns: Sequence[Mapping[str, Any]],
    *,
    cells: Mapping[str, Any],
    filled: bool,
    web_review: bool,
    verified: bool,
    flt: Mapping[str, Any],
) -> bool:
    """`{colId: v | "none"}` - wszystkie warunki naraz. Dodatkowo `_filled`, `_web_review`, `_verified` (true/false)."""
    by_id = {c["id"]: c for c in columns}
    for key, wanted in (flt or {}).items():
        if key in SPECIAL_FILTERS:
            actual = {"_filled": filled, "_web_review": web_review, "_verified": verified}[key]
            if bool(wanted) != actual:
                return False
            continue
        column = by_id.get(key)
        if column is None:
            continue
        value = _cell_value(cells, key)
        present = has_value(column, value)
        if wanted == "none":
            if present:
                return False
            continue
        if not present:
            return False
        if isinstance(value, list):
            wanted_list = wanted if isinstance(wanted, list) else [wanted]
            if not set(wanted_list) & set(value):
                return False
        elif isinstance(wanted, list):
            if value not in wanted:
                return False
        elif column.get("type") == "check":
            if bool(wanted) is not True:
                return False
        elif str(value) != str(wanted):
            return False
    return True


# ---------------------------------------------------------------------------
# Statystyki listy (§11)
# ---------------------------------------------------------------------------


def _latest_source(cells: Mapping[str, Any]) -> Optional[str]:
    best: Optional[Tuple[str, str]] = None
    for cell in (cells or {}).values():
        if not isinstance(cell, Mapping) or cell.get("src") not in SOURCES:
            continue
        stamp = _s(cell.get("at"))
        if best is None or stamp >= best[0]:
            best = (stamp, cell["src"])
    return best[1] if best else None


def _day(value: Any) -> Optional[str]:
    moment = aware(value) if isinstance(value, datetime) else None
    if moment is None and value:
        try:
            moment = parse_iso(value)
        except FormError:
            moment = None
    return _local(moment).date().isoformat() if moment else None


def timeline(days: Iterable[Optional[str]]) -> List[Dict[str, Any]]:
    """Narastająco, dziennie (data polska)."""
    counts: Dict[str, int] = {}
    for day in days:
        if day:
            counts[day] = counts.get(day, 0) + 1
    out: List[Dict[str, Any]] = []
    running = 0
    for day in sorted(counts):
        running += counts[day]
        out.append({"date": day, "filled": running})
    return out


def _money(amount: Optional[float], count: int) -> Optional[float]:
    if amount is None:
        return None
    total = amount * count
    return int(total) if int(total) == total else round(total, 2)


def list_stats(
    columns: Sequence[Mapping[str, Any]],
    participants: Sequence[str],
    entries: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    """Statystyki listy. `entries`: judge_id -> wiersz (cells_json, verified, web_review, submitted_at)."""
    people = list(dict.fromkeys(participants))
    cells_by: Dict[str, Dict[str, Any]] = {jid: loads((entries.get(jid) or {}).get("cells_json"), {}) for jid in people}
    filled_ids = [jid for jid in people if list_filled(columns, cells_by[jid])]
    sources = {source: 0 for source in SOURCES}
    for jid in people:
        source = _latest_source(cells_by[jid])
        if source:
            sources[source] += 1
    status = status_column(columns)
    positive = {o["id"] for o in (status or {}).get("options") or [] if o.get("tone") == "positive"}
    expected_base = (
        sum(1 for jid in people if _cell_value(cells_by[jid], status["id"]) in positive) if status else len(people)
    )
    stats_columns: List[Dict[str, Any]] = []
    for column in columns:
        cid, ctype = column["id"], column.get("type")
        values = [_cell_value(cells_by[jid], cid) for jid in people]
        present = [v for v in values if has_value(column, v)]
        if ctype in ("status", "choice"):
            counts = {o["id"]: 0 for o in column.get("options") or []}
            for value in present:
                for picked in value if isinstance(value, list) else [value]:
                    if picked in counts:
                        counts[picked] += 1
            stats_columns.append({"id": cid, "type": ctype, "counts": counts, "none": len(values) - len(present)})
        elif ctype == "check":
            stats_columns.append({"id": cid, "type": "check", "yes": len(present), "no": len(values) - len(present)})
        elif ctype == "confirm":
            declared = sum(1 for v in present if v == "declared")
            confirmed = sum(1 for v in present if v == "confirmed")
            amount = column.get("amount")
            stats_columns.append(
                {
                    "id": cid,
                    "type": "confirm",
                    "none": len(values) - declared - confirmed,
                    "declared": declared,
                    "confirmed": confirmed,
                    "amount": amount,
                    "expected_total": _money(amount, expected_base),
                    "declared_total": _money(amount, declared + confirmed),
                    "confirmed_total": _money(amount, confirmed),
                }
            )
        elif ctype == "number":
            numbers = [float(v) for v in present if isinstance(v, (int, float)) and not isinstance(v, bool)]
            total = sum(numbers)
            stats_columns.append(
                {
                    "id": cid,
                    "type": "number",
                    "count": len(numbers),
                    "sum": int(total) if int(total) == total else total,
                    "avg": (total / len(numbers)) if numbers else None,
                    "min": min(numbers) if numbers else None,
                    "max": max(numbers) if numbers else None,
                }
            )
        else:
            stats_columns.append({"id": cid, "type": "text", "count": len(present)})
    return {
        "kind": "list",
        "participants": len(people),
        "filled": len(filled_ids),
        "sources": sources,
        "web_review": sum(1 for jid in people if (entries.get(jid) or {}).get("web_review")),
        "timeline": timeline(_day((entries.get(jid) or {}).get("submitted_at")) for jid in filled_ids),
        "columns": stats_columns,
    }


# ---------------------------------------------------------------------------
# Opisy dla ludzi (push „To Ty?", log)
# ---------------------------------------------------------------------------

CONFIRM_LABELS = {"declared": "Zgłoszone", "confirmed": "Potwierdzone"}


def value_label(column: Mapping[str, Any], value: Any) -> str:
    if not has_value(column, value):
        return "brak"
    ctype = column.get("type")
    labels = {o["id"]: o["label"] for o in column.get("options") or []}
    if ctype in ("status", "choice"):
        items = value if isinstance(value, list) else [value]
        return ", ".join(labels.get(x, str(x)) for x in items)
    if ctype == "check":
        return "tak"
    if ctype == "confirm":
        return CONFIRM_LABELS.get(value, str(value))
    if isinstance(value, float):
        return str(value).replace(".", ",")
    return str(value)


def describe_change(columns: Sequence[Mapping[str, Any]], changes: Mapping[str, Any]) -> str:
    """„Będę" albo „Wpłata: Zgłoszone, Menu: Wegetariańskie" - do treści pusha."""
    by_id = {c["id"]: c for c in columns}
    parts: List[str] = []
    for cid, value in changes.items():
        column = by_id.get(cid)
        if column is None:
            continue
        label = value_label(column, value)
        parts.append(label if column.get("type") == "status" else f"{column.get('title')}: {label}")
    return ", ".join(parts) or "zmiana odpowiedzi"


def deadline_label(closes_at: Any) -> str:
    moment = aware(closes_at)
    if moment is None:
        return ""
    local = _local(moment)
    return f"{local:%d.%m} o {local:%H:%M}"


def notification_action(kind: str) -> str:
    return {"published": "open", "web_review": "review_web"}.get(kind, "fill")


def ip_from(forwarded_for: str, peer: str) -> str:
    """Pierwszy hop z X-Forwarded-For (Railway), inaczej adres połączenia."""
    first = (forwarded_for or "").split(",")[0].strip()
    return first or peer or ""


def clean_geo(raw: Any) -> Optional[Dict[str, Any]]:
    """`{lat, lon, acc}` albo `{denied: true}`; reszta = None."""
    if not isinstance(raw, Mapping):
        return None
    if raw.get("denied") is True:
        return {"denied": True}
    try:
        lat, lon = float(raw.get("lat")), float(raw.get("lon"))
    except (TypeError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    out: Dict[str, Any] = {"lat": round(lat, 6), "lon": round(lon, 6)}
    try:
        acc = float(raw.get("acc"))
        if acc >= 0:
            out["acc"] = round(acc, 1)
    except (TypeError, ValueError):
        pass
    return out


def clean_guest_name(value: Any) -> str:
    text = re.sub(r"\s+", " ", _s(value))
    if len(text) < 3 or " " not in text:
        raise FormError("bad_guest_name", "Wpisz imię i nazwisko.", 400)
    if len(text) > GUEST_NAME_MAX:
        raise FormError("bad_guest_name", f"Imię i nazwisko ma najwyżej {GUEST_NAME_MAX} znaków.", 400)
    return text


def clean_device_id(value: Any) -> str:
    text = _s(value)
    if not 4 <= len(text) <= 200:
        raise FormError("bad_device", "Brakuje identyfikatora przeglądarki - odśwież stronę.", 400)
    return text


def fill_seconds(value: Any) -> Optional[int]:
    """Czas wypełniania z telefonu; wartość bez sensu po prostu pomijamy (nie blokuje zapisu)."""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds != seconds or seconds < 1 or seconds > 6 * 3600:
        return None
    return int(round(seconds))


def name_matches(name: str, query: str) -> bool:
    """Szukanie po imieniu i nazwisku bez polskich znaków i wielkości liter."""
    table = str.maketrans("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ", "acelnoszzACELNOSZZ")
    needle = _s(query).translate(table).casefold()
    return not needle or needle in _s(name).translate(table).casefold()


def badge_catalog(judges: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for judge in judges:
        for name in set(badge_names(judge.get("badges"))):
            counts[name] = counts.get(name, 0) + 1
    return [{"name": name, "count": counts[name]} for name in sorted(counts, key=lambda n: n.casefold())]

