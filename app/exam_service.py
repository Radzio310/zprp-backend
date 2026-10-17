"""
Egzamin z przepisów - logika z dostępem do bazy (etap 1, 16.10.2026).

Trasy (`app/exams.py`) są cienkie; wszystko, co decyduje, leży tu i w `exam_rules.py`.
Baza, tabele, lista sędziów i push przychodzą w obiekcie `Store`, więc moduł
nie importuje `app.db` (który łączy się z Postgresem przy imporcie) i da się go
uruchomić w testach na SQLite.

Daty w bazie są zawsze UTC. SQLite oddaje daty bez strefy, dlatego każdy odczyt
przechodzi przez `_dt`.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from sqlalchemy import and_, case, delete, func, insert, select, update

from app import exam_rules as X
from app import province_event_rules as R
from app.exam_rules import ExamError
from app.settlement_province import DISPLAY, display

logger = logging.getLogger(__name__)

SEED_PATH = Path(__file__).resolve().parent / "data" / "exam_questions_default.json"
#: Zaległe podejścia domyka przejście w tle dopiero po tej zwłoce (bufor z telefonu).
SWEEP_GRACE = timedelta(seconds=120)
RESULTS_PUSH_DAYS = 14
MAX_EVENTS_PER_ATTEMPT = 300

ALL_PROVINCES: List[str] = sorted(DISPLAY.values())


# ---------------------------------------------------------------------------
# Przekazywane z zewnątrz
# ---------------------------------------------------------------------------


@dataclass
class Tables:
    banks: Any
    bank_questions: Any
    definitions: Any
    attempts: Any
    answers: Any
    events: Any
    reminders: Any
    province_events: Any


@dataclass
class Store:
    database: Any
    t: Tables
    #: Sędziowie okręgu: lista słowników {judge_id, full_name, badges}.
    judges: Callable[[str], Awaitable[List[Dict[str, Any]]]]
    #: push(judge_ids, tytuł, treść, dane)
    push: Callable[[List[str], str, str, Dict[str, Any]], Awaitable[None]]
    secret: str = "exam-secret"


@dataclass
class Who:
    judge_id: str
    name: str
    province: str
    is_admin: bool
    badges: Any
    #: async (okręg) -> czy Teach Master tego okręgu
    teach_check: Optional[Callable[[str], Awaitable[bool]]] = None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: Any) -> Optional[str]:
    value = _dt(value)
    return value.isoformat() if value else None


def _row(row: Any) -> Dict[str, Any]:
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row or {})


def _loads(text: Any, default: Any) -> Any:
    if isinstance(text, (dict, list)):
        return text
    if not text:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# Bank pytań
# ---------------------------------------------------------------------------

_BANK_CACHE: Dict[str, Dict[str, Dict[str, Any]]] = {}


def _bank_hash(data: Mapping[str, Any]) -> str:
    return hashlib.sha256(_dumps({"meta": data.get("meta"), "questions": data.get("questions")}).encode()).hexdigest()


def _clean_bank_question(raw: Mapping[str, Any]) -> Dict[str, Any]:
    answers = [{"key": _s(a.get("key")), "text": _s(a.get("text")), "correct": bool(a.get("correct"))}
               for a in raw.get("answers") or []]
    if not _s(raw.get("id")) or not _s(raw.get("number")) or not _s(raw.get("text")):
        raise ExamError("BAD_BANK", f"Pytanie bez id, numeru albo treści: {raw.get('number')!r}.")
    if len(answers) < 2 or not any(a["correct"] for a in answers) or any(not a["key"] for a in answers):
        raise ExamError("BAD_BANK", f"Pytanie {raw.get('number')} nie ma poprawnie opisanych odpowiedzi.")
    return {
        "qid": _s(raw["id"]), "number": _s(raw["number"]), "rule": raw.get("rule"), "kind": raw.get("kind"),
        "multi": sum(1 for a in answers if a["correct"]) > 1 or bool(raw.get("multi")),
        "topics": list(raw.get("topics") or []), "text": _s(raw["text"]), "answers": answers,
        "refs": list(raw.get("refs") or []), "curiosity": X.CURIOSITIES.get(_s(raw["number"])),
    }


async def import_bank(st: Store, data: Mapping[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Wgrywa katalog pytań jako nową wersję (po hashu zawartości). Ten sam katalog
    drugi raz nic nie dubluje - tylko ustawia go jako bieżący i odświeża ciekawostki."""
    if not isinstance(data.get("questions"), list) or not data["questions"]:
        raise ExamError("BAD_BANK", "Plik nie zawiera listy pytań (pole „questions”).")
    questions = [_clean_bank_question(q) for q in data["questions"]]
    if len({q["qid"] for q in questions}) != len(questions):
        raise ExamError("BAD_BANK", "W katalogu powtarzają się identyfikatory pytań.")
    digest = _bank_hash(data)
    db, t = st.database, st.t
    existing = await db.fetch_one(select(t.banks).where(t.banks.c.content_hash == digest))
    meta = data.get("meta") or {}
    if existing:
        version, created = existing["version"], False
    else:
        version = f"{_s(meta.get('published')) or 'bank'}-{digest[:8]}"
        created = True
        async with db.transaction():
            await db.execute(insert(t.banks).values(
                version=version, content_hash=digest, meta_json=_dumps(meta), question_count=len(questions),
                is_current=False, created_at=now or utcnow()))
            await db.execute_many(insert(t.bank_questions), [
                {"bank_version": version, "qid": q["qid"], "number": q["number"], "rule": q["rule"], "kind": q["kind"],
                 "multi": q["multi"], "topics_json": _dumps(q["topics"]), "text": q["text"],
                 "answers_json": _dumps(q["answers"]), "refs_json": _dumps(q["refs"]), "curiosity": q["curiosity"]}
                for q in questions])
    async with db.transaction():
        await db.execute(update(t.banks).values(is_current=False))
        await db.execute(update(t.banks).where(t.banks.c.version == version).values(is_current=True))
        for number, text in X.CURIOSITIES.items():
            await db.execute(update(t.bank_questions)
                             .where(and_(t.bank_questions.c.bank_version == version, t.bank_questions.c.number == number))
                             .values(curiosity=text))
    _BANK_CACHE.pop(version, None)
    return {"version": version, "created": created, "count": len(questions)}


async def ensure_bank(st: Store) -> str:
    """Wersja bieżącego banku. Pusta baza = zaczyn z pliku w repozytorium (raz)."""
    row = await st.database.fetch_one(select(st.t.banks).where(st.t.banks.c.is_current.is_(True)))
    if row:
        return row["version"]
    if not SEED_PATH.exists():
        raise ExamError("BANK_MISSING", "Bank pytań nie został jeszcze zaimportowany. Administrator: POST /exams/bank/import.", 503)
    data = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    return (await import_bank(st, data))["version"]


async def load_bank(st: Store, version: str) -> Dict[str, Dict[str, Any]]:
    if version in _BANK_CACHE:
        return _BANK_CACHE[version]
    rows = await st.database.fetch_all(select(st.t.bank_questions).where(st.t.bank_questions.c.bank_version == version))
    if not rows:
        raise ExamError("BANK_MISSING", f"Wersja banku {version} nie istnieje.", 503)
    bank: Dict[str, Dict[str, Any]] = {}
    for raw in rows:
        r = _row(raw)
        bank[r["qid"]] = {
            "qid": r["qid"], "number": r["number"], "rule": r["rule"], "kind": r["kind"], "multi": bool(r["multi"]),
            "topics": _loads(r["topics_json"], []), "text": r["text"], "answers": _loads(r["answers_json"], []),
            "refs": _loads(r["refs_json"], []), "curiosity": r.get("curiosity"),
        }
    _BANK_CACHE[version] = bank
    return bank


async def bank_public(st: Store, *, since: Optional[str] = None, rule: Optional[int] = None,
                      topic: Optional[str] = None) -> Dict[str, Any]:
    """Pytania dla zalogowanych BEZ kluczy poprawności i bez ciekawostek."""
    version = await ensure_bank(st)
    if since and since == version:
        return {"version": version, "unchanged": True, "questions": []}
    bank = await load_bank(st, version)
    items = sorted(bank.values(), key=lambda q: X.number_key(q["number"]))
    out = []
    for q in items:
        if rule is not None and q.get("rule") != rule:
            continue
        if topic and topic not in (q.get("topics") or []):
            continue
        out.append({**X.public_question(q), "topics": q.get("topics") or []})
    return {"version": version, "unchanged": False, "count": len(out), "questions": out}


# ---------------------------------------------------------------------------
# Uprawnienia
# ---------------------------------------------------------------------------


async def manage_refusal(who: Who, scope: str, province: Any) -> Optional[str]:
    teach = False
    needs_teach = scope == "province" and not who.is_admin and not (
        X.has_committee_badge(who.badges) and R.same_province(who.province, province))
    if needs_teach and who.teach_check:
        try:
            teach = bool(await who.teach_check(province))
        except Exception:  # noqa: BLE001
            logger.warning("egzamin: sprawdzenie Teach Mastera nie powiodło się", exc_info=True)
    return X.manage_refusal(scope=scope, province=province, is_admin=who.is_admin, own_province=who.province,
                            badges=who.badges, is_teach_master=teach)


async def require_manage(who: Who, scope: str, province: Any) -> None:
    reason = await manage_refusal(who, scope, province)
    if reason:
        raise ExamError("EXAM_FORBIDDEN", reason, 403)


async def require_any_manage(who: Who, province: Any = None) -> None:
    """Kreator i prowadzący na żywo: wystarczy prawo zarządzania którymkolwiek okręgiem (albo admin).
    Zwykły zdający nie ma tu czego szukać (szablony i podgląd puli są dla autorów)."""
    if who.is_admin or X.has_committee_badge(who.badges):
        return
    for prov in dict.fromkeys(p for p in (_s(province), _s(who.province)) if p):
        if who.teach_check:
            try:
                if await who.teach_check(prov):
                    return
            except Exception:  # noqa: BLE001
                logger.warning("egzamin: sprawdzenie Teach Mastera nie powiodło się", exc_info=True)
    raise ExamError("EXAM_FORBIDDEN", "Szablony i podgląd puli są dla osób, które zarządzają egzaminami: komisji sędziowskiej, "
                    "Teach Mastera okręgu albo administratora aplikacji.", 403)


# ---------------------------------------------------------------------------
# Wczytywanie egzaminów
# ---------------------------------------------------------------------------


async def _exam(st: Store, exam_id: str, *, deleted_ok: bool = False) -> Dict[str, Any]:
    row = await st.database.fetch_one(select(st.t.definitions).where(st.t.definitions.c.id == exam_id))
    if not row:
        raise ExamError("EXAM_NOT_FOUND", "Nie znaleziono takiego egzaminu.", 404)
    exam = _row(row)
    if exam.get("deleted_at") is not None and not deleted_ok:
        raise ExamError("EXAM_NOT_FOUND", "Ten egzamin został usunięty.", 404)
    exam["config"] = _loads(exam["config_json"], {})
    exam["question_ids"] = _loads(exam["question_ids_json"], [])
    exam["voided"] = _loads(exam["voided_json"], {})
    exam["event_ids"] = _loads(exam["event_ids_json"], {})
    return exam


def _exam_provinces(exam: Mapping[str, Any]) -> List[str]:
    return list(ALL_PROVINCES) if exam["scope"] == "national" else [display(exam["province"])]


def _window_state(config: Mapping[str, Any], now: datetime) -> str:
    start, end = X.parse_time(config["window_start"]), X.parse_time(config["window_end"])
    return "upcoming" if now < start else "closed" if now >= end else "open"


async def _history(st: Store) -> Dict[str, Tuple[int, float]]:
    """qid -> (liczba odpowiedzi, odsetek poprawnych) ze zakończonych podejść - do „trudności z historii”."""
    t = st.t
    rows = await st.database.fetch_all(
        select(t.answers.c.qid, t.answers.c.selected_json, t.attempts.c.exam_id)
        .select_from(t.answers.join(t.attempts, t.attempts.c.id == t.answers.c.attempt_id))
        .where(t.attempts.c.status != "in_progress"))
    counts: Dict[str, List[float]] = {}
    version = await ensure_bank(st)
    bank = await load_bank(st, version)
    for r in rows:
        q = bank.get(r["qid"])
        if not q:
            continue
        score = X.score_question(q, _loads(r["selected_json"], []), "all_or_nothing")
        bucket = counts.setdefault(r["qid"], [0, 0.0])
        bucket[0] += 1
        bucket[1] += score
    return {qid: (int(n), tot / n) for qid, (n, tot) in counts.items() if n}


async def _build_pool(st: Store, config: Mapping[str, Any], bank: Mapping[str, Mapping[str, Any]], exam_id: str) -> List[str]:
    history = await _history(st) if config["scope"]["difficulty"] != "any" else None
    pool = X.resolve_pool(config["scope"], bank.values(), history)
    if config["scope"]["difficulty"] != "any" and len(pool) < config["question_count"]:
        raise ExamError("POOL_TOO_SMALL",
                        f"Do kryterium trudności z historii pasuje tylko {len(pool)} pytań (potrzeba co najmniej 5 odpowiedzi "
                        f"na pytanie). Wybierz „dowolna” albo zmniejsz liczbę pytań.")
    return X.pick_set(pool, config["question_count"], config["set_mode"], exam_id)


async def pool_preview(st: Store, scope: Mapping[str, Any]) -> Dict[str, Any]:
    version = await ensure_bank(st)
    bank = await load_bank(st, version)
    clean = X.clean_config({"scope": scope, "window_start": "2000-01-01T00:00:00+00:00",
                            "window_end": "2000-01-02T00:00:00+00:00"})["scope"]
    history = await _history(st) if clean["difficulty"] != "any" else None
    pool = X.resolve_pool(clean, bank.values(), history)
    return {"bank_version": version, "count": len(pool), "qids": pool}


# ---------------------------------------------------------------------------
# Wydarzenia okręgowe
# ---------------------------------------------------------------------------


async def _publish_events(st: Store, exam: Dict[str, Any], who: Who, now: datetime) -> List[Dict[str, Any]]:
    fields = X.exam_event_fields(exam["name"], exam.get("description"), exam["config"], exam["id"])
    published, ids = [], {}
    for prov in _exam_provinces(exam):
        row = await st.database.fetch_one(insert(st.t.province_events).values(
            province=prov, created_by=who.judge_id, created_by_name=who.name or None,
            created_at=now, updated_at=now, **fields).returning(st.t.province_events.c.id))
        ids[prov] = int(row["id"])
        published.append({"id": ids[prov], "province": prov, "name": exam["name"], "event_date": fields["event_date"],
                          "data_json": fields["data_json"]})
    await st.database.execute(update(st.t.definitions).where(st.t.definitions.c.id == exam["id"])
                              .values(event_ids_json=_dumps(ids)))
    exam["event_ids"] = ids
    return published


async def _sync_events(st: Store, exam: Dict[str, Any], now: datetime) -> bool:
    """Edycja egzaminu przepisuje jego wydarzenia. True, gdy zmienił się termin (warto powiadomić)."""
    fields = X.exam_event_fields(exam["name"], exam.get("description"), exam["config"], exam["id"])
    moved = False
    for prov, event_id in (exam["event_ids"] or {}).items():
        cur = await st.database.fetch_one(select(st.t.province_events).where(st.t.province_events.c.id == int(event_id)))
        if not cur:
            continue
        cur = _row(cur)
        if _dt(cur["event_date"]) != fields["event_date"] or _dt(cur.get("end_date")) != fields["end_date"]:
            moved = True
        data = _loads(cur.get("data_json"), {})
        data.update(fields["data_json"])
        await st.database.execute(update(st.t.province_events).where(st.t.province_events.c.id == int(event_id)).values(
            name=fields["name"], description=fields["description"], event_date=fields["event_date"],
            end_date=fields["end_date"], data_json=data, updated_at=now))
    return moved


async def _trash_events(st: Store, exam: Mapping[str, Any], now: datetime) -> None:
    for event_id in (exam["event_ids"] or {}).values():
        await st.database.execute(update(st.t.province_events).where(st.t.province_events.c.id == int(event_id))
                                  .values(deleted_at=now, updated_at=now))


# ---------------------------------------------------------------------------
# Definicje egzaminów
# ---------------------------------------------------------------------------


def _scope_and_province(body: Mapping[str, Any], who: Who) -> Tuple[str, Optional[str]]:
    scope = _s(body.get("scope")) or "province"
    if scope not in X.SCOPES:
        raise ExamError("BAD_CONFIG", f"Zakres egzaminu: dozwolone wartości to {', '.join(X.SCOPES)}.")
    if scope == "national":
        return scope, None
    raw = _s(body.get("province")) or who.province
    if not raw or display(raw) not in DISPLAY.values():
        raise ExamError("BAD_CONFIG", "Podaj okręg egzaminu (nie znam takiego województwa).")
    return scope, display(raw)


def exam_view(exam: Mapping[str, Any], now: datetime, *, full: bool) -> Dict[str, Any]:
    config = exam["config"]
    base = {
        "id": exam["id"], "name": exam["name"], "description": exam.get("description"), "scope": exam["scope"],
        "province": exam.get("province"), "template": exam.get("template"),
        "window_start": config["window_start"], "window_end": config["window_end"],
        "state": _window_state(config, now), "mandatory": config["mandatory"],
        "question_count": config["question_count"], "time_total_min": config["time_total_min"],
        "time_per_question_s": config["time_per_question_s"], "max_attempts": config["max_attempts"], "retake": config.get("retake", "any"),
        "allow_back": config["allow_back"], "pass_percent": config["pass_percent"],
        "result_release": config["result_release"],
        # Zasady jawne dla zdającego: przedsionek opisuje je wprost (zero cichych blokad).
        "anti": {k: v for k, v in config["anti"].items() if k != "integrity"}, "multi_scoring": config["multi_scoring"],
    }
    if full:
        base.update(config=config, bank_version=exam["bank_version"], voided=exam["voided"], event_ids=exam["event_ids"],
                    pool_size=len(exam["question_ids"]), created_by=exam.get("created_by"),
                    created_by_name=exam.get("created_by_name"), created_at=_iso(exam.get("created_at")),
                    updated_at=_iso(exam.get("updated_at")), can_manage=True)
    return base


async def create_exam(st: Store, who: Who, body: Mapping[str, Any], now: Optional[datetime] = None) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    now = now or utcnow()
    scope, province = _scope_and_province(body, who)
    await require_manage(who, scope, province)
    client_key = _s(body.get("client_key"))[:80] or None
    if client_key:
        # Ponowienie tego samego szkicu (zerwana sieć, podwójne dotknięcie) oddaje ten sam egzamin.
        t = st.t.definitions
        again = await st.database.fetch_one(select(t.c.id).where(and_(
            t.c.created_by == who.judge_id, t.c.client_key == client_key, t.c.deleted_at.is_(None))))
        if again:
            existing = await _exam(st, again["id"])
            return {**exam_view(existing, now, full=True), "existing": True}, []
    name, description = X.clean_text(body.get("name"), body.get("description"))
    template = _s(body.get("template")) or None
    config = X.clean_config(body.get("config") or {}, template=template)
    version = await ensure_bank(st)
    bank = await load_bank(st, version)
    exam_id = uuid.uuid4().hex
    pool = await _build_pool(st, config, bank, exam_id)
    opens, closes = X.parse_time(config["window_start"]), X.parse_time(config["window_end"])
    async with st.database.transaction():
        await st.database.execute(insert(st.t.definitions).values(
            id=exam_id, scope=scope, province=province, name=name, description=description, template=template,
            config_json=_dumps(config), bank_version=version, question_ids_json=_dumps(pool), voided_json="{}",
            event_ids_json="{}", opens_at=opens, closes_at=closes, created_by=who.judge_id,
            created_by_name=who.name or None, client_key=client_key, created_at=now, updated_at=now))
        exam = await _exam(st, exam_id)
        published = await _publish_events(st, exam, who, now)
    return exam_view(exam, now, full=True), published


async def update_exam(st: Store, who: Who, exam_id: str, body: Mapping[str, Any], now: Optional[datetime] = None) -> Tuple[Dict[str, Any], bool]:
    now = now or utcnow()
    exam = await _exam(st, exam_id)
    await require_manage(who, exam["scope"], exam.get("province"))
    name, description = X.clean_text(body.get("name", exam["name"]), body.get("description", exam.get("description")))
    patch = body.get("config") or {}
    config = X.clean_config(X._merge(copy.deepcopy(exam["config"]), patch))
    started = await st.database.fetch_val(select(func.count()).select_from(st.t.attempts).where(st.t.attempts.c.exam_id == exam_id))
    locked = X.locked_changes(exam["config"], config)
    if started and locked:
        raise ExamError("EXAM_LOCKED", "Ktoś już zaczął ten egzamin, więc nie można zmienić: " + ", ".join(X.LOCKED_LABELS.get(k, k) for k in locked) +
                        ". Zmienić można nazwę, opis, termin zamknięcia okna, adresatów i przypomnienia.", 409, {"locked": locked})
    pool = exam["question_ids"]
    if locked and not started:
        version = await ensure_bank(st)
        bank = await load_bank(st, version)
        pool = await _build_pool(st, config, bank, exam_id)
        exam["bank_version"] = version
    exam.update(name=name, description=description, config=config, question_ids=pool)
    await st.database.execute(update(st.t.definitions).where(st.t.definitions.c.id == exam_id).values(
        name=name, description=description, config_json=_dumps(config), question_ids_json=_dumps(pool),
        bank_version=exam["bank_version"], opens_at=X.parse_time(config["window_start"]),
        closes_at=X.parse_time(config["window_end"]), updated_at=now))
    moved = await _sync_events(st, exam, now)
    return exam_view(exam, now, full=True), moved


async def delete_exam(st: Store, who: Who, exam_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    exam = await _exam(st, exam_id)
    await require_manage(who, exam["scope"], exam.get("province"))
    await st.database.execute(update(st.t.definitions).where(st.t.definitions.c.id == exam_id).values(deleted_at=now, updated_at=now))
    await _trash_events(st, exam, now)
    return {"id": exam_id, "deleted": True, "note": "Podejścia i wyniki zostają w bazie; wydarzenia trafiły do kosza okręgu."}


async def _invited_ids(st: Store, exam: Mapping[str, Any], province: str, judges: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    judges = judges if judges is not None else await st.judges(province)
    data = {"target": exam["config"]["target"], "include_ids": exam["config"]["include_ids"],
            "exclude_ids": exam["config"]["exclude_ids"]}
    return R.invited_ids(judges, data)


async def list_for_judge(st: Store, who: Who, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    if not who.province and not who.is_admin:
        raise ExamError("NOT_IN_ROSTER", "Nie ma Cię na liście sędziów okręgu - zgłoś to administratorowi okręgu.", 403)
    t = st.t
    rows = await st.database.fetch_all(select(t.definitions).where(t.definitions.c.deleted_at.is_(None))
                                       .order_by(t.definitions.c.closes_at.desc()).limit(300))
    mine = await st.database.fetch_all(select(t.attempts).where(t.attempts.c.judge_id == who.judge_id))
    attempts: Dict[str, List[Dict[str, Any]]] = {}
    for raw in mine:
        a = _row(raw)
        attempts.setdefault(a["exam_id"], []).append(a)
    judges = await st.judges(display(who.province)) if who.province else []
    items = []
    for raw in rows:
        exam = _row(raw)
        exam["config"] = _loads(exam["config_json"], {})
        exam["voided"] = _loads(exam["voided_json"], {})
        if exam["scope"] == "province" and not R.same_province(who.province, exam["province"]) and not who.is_admin:
            continue
        if not who.is_admin and who.judge_id not in await _invited_ids(st, exam, display(who.province), judges):
            continue
        view = exam_view(exam, now, full=False)
        mine_list = sorted(attempts.get(exam["id"], []), key=lambda a: a["attempt_no"])
        view["my_attempts"] = [_attempt_summary(exam["config"], a, now) for a in mine_list]
        view["attempts_left"] = max(0, exam["config"]["max_attempts"] - len(mine_list))
        items.append(view)
    return {"exams": items, "server_now": now.isoformat()}


def _attempt_summary(config: Mapping[str, Any], attempt: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    score = _loads(attempt.get("score_json"), None)
    shaped = {"status": attempt["status"], "score": score}
    return {"id": attempt["id"], "attempt_no": attempt["attempt_no"], "status": attempt["status"],
            "started_at": _iso(attempt["started_at"]), "finished_at": _iso(attempt.get("finished_at")),
            "result": X.result_view(config, shaped, now)}


async def get_exam(st: Store, who: Who, exam_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    exam = await _exam(st, exam_id)
    refusal = await manage_refusal(who, exam["scope"], exam.get("province"))
    if not refusal:
        return exam_view(exam, now, full=True)
    await _eligibility(st, who, exam)
    return exam_view(exam, now, full=False)


_FINISHED = ("submitted", "expired")


async def _attempt_counts(st: Store, exam_ids: List[str]) -> Dict[str, Dict[str, int]]:
    """Podejścia wg statusu dla całej teczki jednym zapytaniem."""
    if not exam_ids:
        return {}
    a = st.t.attempts
    rows = await st.database.fetch_all(select(a.c.exam_id, a.c.status, func.count()).where(a.c.exam_id.in_(exam_ids))
                                       .group_by(a.c.exam_id, a.c.status))
    out: Dict[str, Dict[str, int]] = {}
    for r in rows:
        out.setdefault(r[0], {})[r[1]] = int(r[2])
    return out


async def _people_summary(st: Store, exam_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Miniatura wyników teczki - jedno zapytanie agregujące dla wszystkich egzaminów.

    Osoba liczy się RAZ, jak w raporcie komisji (`exam_report_rules.summary`):
    najlepsze zakończone podejście. Baza grupuje (egzamin, sędzia) i oddaje
    najlepszy procent i to, czy osoba zdała - wiersz na osobę, nie na podejście
    i nie na odpowiedź. `passed` rośnie razem z procentem (jeden próg
    egzaminu), więc „zdał którekolwiek zakończone” = „zdał najlepszym”.
    """
    if not exam_ids:
        return {}
    a = st.t.attempts
    done = a.c.status.in_(_FINISHED)
    rows = await st.database.fetch_all(
        select(
            a.c.exam_id.label("exam_id"),
            a.c.judge_id.label("judge_id"),
            func.max(case((done, a.c.percent), else_=None)).label("best"),
            func.max(case((and_(done, a.c.passed.is_(True)), 1), else_=0)).label("ok"),
        )
        .where(a.c.exam_id.in_(exam_ids))
        .group_by(a.c.exam_id, a.c.judge_id)
    )
    out: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        m = _row(r)
        agg = out.setdefault(m["exam_id"], {"judges": set(), "best": [], "passed": 0})
        agg["judges"].add(_s(m["judge_id"]))
        if m["best"] is not None:
            agg["best"].append(float(m["best"]))
            agg["passed"] += int(m["ok"] or 0)
    return out


def summary_view(people: Optional[Mapping[str, Any]], invited_ids: Sequence[str]) -> Dict[str, Any]:
    """Liczby miniatury na karcie teczki (te same definicje co raport komisji).

    `attempted` = osoby z jakimkolwiek podejściem, `finished` = z zakończonym,
    `pass_rate` = zdali / zakończyli (None, gdy nikt nie skończył),
    `not_started` = zaproszeni bez żadnego podejścia, `invited` = przystąpili +
    nie przystąpili (jak `summary.invited` w raporcie).
    """
    p = people or {}
    judges = p.get("judges") or set()
    best = p.get("best") or []
    passed = int(p.get("passed") or 0)
    not_started = len({_s(j) for j in invited_ids} - set(judges))
    return {
        "attempted": len(judges),
        "finished": len(best),
        "passed": passed,
        "avg_percent": round(sum(best) / len(best), 2) if best else None,
        "pass_rate": round(passed / len(best), 4) if best else None,
        "not_started": not_started,
        "invited": len(judges) + not_started,
    }


async def list_manage(st: Store, who: Who, province: Optional[str], now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    scope = "province" if province or not who.is_admin else "national"
    prov = display(province or who.province) if scope == "province" else None
    if scope == "province" and (not prov or prov not in DISPLAY.values()):
        raise ExamError("BAD_CONFIG", "Podaj okręg, którego egzaminy chcesz zobaczyć.")
    await require_manage(who, scope, prov)
    t = st.t
    q = select(t.definitions).where(t.definitions.c.deleted_at.is_(None))
    q = q.where(t.definitions.c.scope == "national") if scope == "national" else q.where(t.definitions.c.province == prov)
    rows = await st.database.fetch_all(q.order_by(t.definitions.c.closes_at.desc()))
    exams = []
    for raw in rows:
        exam = _row(raw)
        exam["config"] = _loads(exam["config_json"], {})
        exam["voided"] = _loads(exam["voided_json"], {})
        exam["event_ids"] = _loads(exam["event_ids_json"], {})
        exam["question_ids"] = _loads(exam["question_ids_json"], [])
        exams.append(exam)
    ids = [e["id"] for e in exams]
    counts = await _attempt_counts(st, ids)
    people = await _people_summary(st, ids)
    roster: Dict[str, List[Dict[str, Any]]] = {}
    items = []
    for exam in exams:
        view = exam_view(exam, now, full=True)
        view["attempt_counts"] = counts.get(exam["id"], {})
        invited: List[str] = []
        for p in _exam_provinces(exam):
            if p not in roster:
                roster[p] = await st.judges(p)  # raz na okręg dla całej teczki
            invited += await _invited_ids(st, exam, p, roster[p])
        view["summary"] = summary_view(people.get(exam["id"]), invited)
        items.append(view)
    return {"scope": scope, "province": prov, "exams": items, "templates": X.templates_view()}


# ---------------------------------------------------------------------------
# Sesja zdającego
# ---------------------------------------------------------------------------


async def _eligibility(st: Store, who: Who, exam: Mapping[str, Any]) -> None:
    if who.is_admin:
        return
    if not who.province:
        raise ExamError("NOT_IN_ROSTER", "Nie ma Cię na liście sędziów okręgu - zgłoś to administratorowi okręgu.", 403)
    if exam["scope"] == "province" and not R.same_province(who.province, exam["province"]):
        raise ExamError("EXAM_OTHER_PROVINCE", f"To egzamin okręgu {exam['province']}. Egzaminy innych okręgów widzi tylko administrator.", 403)
    if who.judge_id not in await _invited_ids(st, exam, display(who.province)):
        raise ExamError("EXAM_NOT_INVITED", "Ten egzamin jest skierowany do innej grupy sędziów (ustawiono adresatów po odznakach).", 403)


async def _my_attempts(st: Store, exam_id: str, judge_id: str) -> List[Dict[str, Any]]:
    t = st.t
    rows = await st.database.fetch_all(select(t.attempts).where(and_(t.attempts.c.exam_id == exam_id, t.attempts.c.judge_id == judge_id))
                                       .order_by(t.attempts.c.attempt_no))
    out = []
    for raw in rows:
        out.append(_attempt(raw))
    return out


def _attempt(raw: Any) -> Dict[str, Any]:
    a = _row(raw)
    for key in ("started_at", "deadline_at", "finished_at"):
        a[key] = _dt(a.get(key))
    a["paper"] = _loads(a.get("paper_json"), [])
    a["score"] = _loads(a.get("score_json"), None)
    a["dirty"] = False
    return a


async def _attempt_row(st: Store, attempt_id: str) -> Dict[str, Any]:
    raw = await st.database.fetch_one(select(st.t.attempts).where(st.t.attempts.c.id == attempt_id))
    if not raw:
        raise ExamError("ATTEMPT_NOT_FOUND", "Nie znaleziono takiego podejścia.", 404)
    return _attempt(raw)


async def _own_attempt(st: Store, who: Who, attempt_id: str) -> Dict[str, Any]:
    attempt = await _attempt_row(st, attempt_id)
    if attempt["judge_id"] != who.judge_id:
        raise ExamError("ATTEMPT_NOT_FOUND", "Nie znaleziono takiego podejścia na twoim koncie.", 404)
    return attempt


async def _load_answers(st: Store, attempt_id: str) -> Dict[str, Dict[str, Any]]:
    rows = await st.database.fetch_all(select(st.t.answers).where(st.t.answers.c.attempt_id == attempt_id))
    out = {}
    for raw in rows:
        r = _row(raw)
        out[r["qid"]] = {"qid": r["qid"], "position": r["position"], "shown_at": _dt(r["shown_at"]),
                         "answered_at": _dt(r["answered_at"]), "selected": _loads(r["selected_json"], None),
                         "timed_out": bool(r["timed_out"]), "elapsed_ms": r["elapsed_ms"], "changes": r["changes"] or 0,
                         "flags": _loads(r["flags_json"], []), "dirty": False}
    return out


async def _save(st: Store, attempt: Dict[str, Any], answers: Dict[str, Dict[str, Any]]) -> None:
    t, db = st.t, st.database
    for qid, row in answers.items():
        if not row.get("dirty"):
            continue
        values = dict(position=row["position"], shown_at=row["shown_at"], answered_at=row["answered_at"],
                      selected_json=None if row["selected"] is None else _dumps(row["selected"]),
                      timed_out=bool(row["timed_out"]), elapsed_ms=row.get("elapsed_ms"), changes=row.get("changes") or 0,
                      flags_json=_dumps(row.get("flags") or []))
        exists = await db.fetch_val(select(func.count()).select_from(t.answers).where(
            and_(t.answers.c.attempt_id == attempt["id"], t.answers.c.qid == qid)))
        if exists:
            await db.execute(update(t.answers).where(and_(t.answers.c.attempt_id == attempt["id"], t.answers.c.qid == qid)).values(**values))
        else:
            await db.execute(insert(t.answers).values(attempt_id=attempt["id"], qid=qid, **values))
        row["dirty"] = False
    if attempt.get("dirty"):
        await db.execute(update(t.attempts).where(t.attempts.c.id == attempt["id"]).values(
            status=attempt["status"], finish_reason=attempt.get("finish_reason"), finished_at=attempt.get("finished_at"),
            current_index=attempt["current_index"], device_id=attempt.get("device_id")))
        attempt["dirty"] = False


async def _finalize_score(st: Store, exam: Mapping[str, Any], attempt: Dict[str, Any], answers: Dict[str, Dict[str, Any]]) -> None:
    """Ocena na serwerze, raz po zakończeniu (i po unieważnieniu pytania)."""
    if attempt["status"] == "in_progress":
        return
    bank = await load_bank(st, exam["bank_version"])
    score = X.score_attempt(exam["config"], attempt["paper"], answers, bank, exam["voided"])
    attempt["score"] = score
    await st.database.execute(update(st.t.attempts).where(st.t.attempts.c.id == attempt["id"]).values(
        score_json=_dumps(score), percent=score["percent"], passed=score["passed"]))


async def _record_event(st: Store, exam_id: str, attempt: Mapping[str, Any], kind: str, detail: Mapping[str, Any],
                        client_ts_ms: Optional[float] = None, now: Optional[datetime] = None) -> None:
    await st.database.execute(insert(st.t.events).values(
        exam_id=exam_id, attempt_id=attempt["id"], judge_id=attempt["judge_id"], kind=kind, detail_json=_dumps(detail),
        client_ts_ms=client_ts_ms, created_at=now or utcnow()))


async def _check_device(st: Store, exam: Mapping[str, Any], attempt: Dict[str, Any], device_id: Any, now: datetime) -> None:
    if not exam["config"]["anti"]["single_device"]:
        return
    device = _s(device_id)
    if not device:
        raise ExamError("EXAM_DEVICE_REQUIRED", "Ten egzamin pilnuje urządzenia - aplikacja musi przesłać identyfikator telefonu (device_id).", 400)
    if not attempt.get("device_id"):
        attempt["device_id"] = device
        attempt["dirty"] = True
    elif attempt["device_id"] != device:
        recent = await st.database.fetch_all(select(st.t.events).where(and_(
            st.t.events.c.attempt_id == attempt["id"], st.t.events.c.kind == "device_change")))
        if not any(_loads(r["detail_json"], {}).get("device_id") == device for r in recent):
            await _record_event(st, exam["id"], attempt, "device_change", {"device_id": device, "expected": attempt["device_id"]}, now=now)
        raise ExamError("EXAM_OTHER_DEVICE", "Egzamin trwa na innym urządzeniu. Wznowienie tutaj wymaga zgody komisji - zgłoś się do niej.", 409)


def _question_view(exam: Mapping[str, Any], attempt: Mapping[str, Any], answers: Mapping[str, Mapping[str, Any]],
                   bank: Mapping[str, Mapping[str, Any]], index: int, now: datetime) -> Dict[str, Any]:
    item = attempt["paper"][index]
    row = answers.get(item["qid"]) or {}
    view = X.public_question(bank[item["qid"]], item["keys"])
    view.update(index=index, selected=row.get("selected"), answered=row.get("answered_at") is not None,
                seconds_left=X.question_seconds_left(exam["config"], row, now))
    return view


def _state(exam: Mapping[str, Any], attempt: Mapping[str, Any], answers: Mapping[str, Mapping[str, Any]],
           bank: Mapping[str, Mapping[str, Any]], index: Optional[int], now: datetime) -> Dict[str, Any]:
    config = exam["config"]
    total = len(attempt["paper"])
    state = {
        "attempt": {
            "id": attempt["id"], "exam_id": exam["id"], "attempt_no": attempt["attempt_no"], "status": attempt["status"],
            "finish_reason": attempt.get("finish_reason"), "started_at": _iso(attempt["started_at"]),
            "deadline_at": _iso(attempt["deadline_at"]), "finished_at": _iso(attempt.get("finished_at")),
            "current_index": attempt["current_index"], "total": total, "answered": sum(1 for r in answers.values() if r.get("answered_at")),
            "allow_back": config["allow_back"], "time_per_question_s": config["time_per_question_s"],
            "room_code_required": config["anti"]["room_code"],
        },
        "server_now": now.isoformat(),
        "question": None,
        "result": X.result_view(config, attempt, now) if attempt["status"] != "in_progress" else None,
    }
    if attempt["status"] == "in_progress" and index is not None:
        state["question"] = _question_view(exam, attempt, answers, bank, index, now)
    return state


async def _settle_and_save(st: Store, exam: Mapping[str, Any], attempt: Dict[str, Any], answers: Dict[str, Dict[str, Any]],
                           now: datetime, index: Optional[int] = None, want_question: bool = True) -> Optional[int]:
    served = X.serve_question(exam["config"], attempt, answers, now, index) if want_question else None
    if not want_question:
        X.settle(exam["config"], attempt, answers, now)
    await _save(st, attempt, answers)
    if attempt["status"] != "in_progress" and attempt.get("score") is None:
        await _finalize_score(st, exam, attempt, answers)
    return served


async def start_attempt(st: Store, who: Who, exam_id: str, body: Mapping[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    exam = await _exam(st, exam_id)
    await _eligibility(st, who, exam)
    config = exam["config"]
    attempts = await _my_attempts(st, exam_id, who.judge_id)
    running = next((a for a in attempts if a["status"] == "in_progress"), None)
    if running is None:
        refusal = X.start_refusal(config, now, attempts)
        if refusal:
            raise refusal
        if config["anti"]["room_code"] and not X.room_code_ok(st.secret, exam_id, body.get("room_code"), now):
            raise ExamError("EXAM_ROOM_CODE", "Podaj aktualny kod sali (6 cyfr z ekranu prowadzącego, zmienia się co 30 s).", 403)
        bank = await load_bank(st, exam["bank_version"])
        attempt_no = len(attempts) + 1
        paper = X.build_paper(config, exam["question_ids"], bank, exam_id=exam_id, judge_id=who.judge_id, attempt_no=attempt_no)
        attempt_id = uuid.uuid4().hex
        device = _s(body.get("device_id")) or None
        if config["anti"]["single_device"] and not device:
            raise ExamError("EXAM_DEVICE_REQUIRED", "Ten egzamin pilnuje urządzenia - aplikacja musi przesłać identyfikator telefonu (device_id).", 400)
        try:
            await st.database.execute(insert(st.t.attempts).values(
                id=attempt_id, exam_id=exam_id, judge_id=who.judge_id, judge_name=who.name or None,
                province=display(who.province) if who.province else None, attempt_no=attempt_no, status="in_progress",
                started_at=now, deadline_at=X.attempt_deadline(config, now), current_index=0, paper_json=_dumps(paper),
                device_id=device, created_at=now))
        except Exception:  # noqa: BLE001 - podwójne dotknięcie: drugie żądanie dostaje to samo podejście
            attempts = await _my_attempts(st, exam_id, who.judge_id)
            running = next((a for a in attempts if a["status"] == "in_progress"), None)
            if running is None:
                raise
        else:
            running = await _attempt_row(st, attempt_id)
    attempt = running
    await _check_device(st, exam, attempt, body.get("device_id"), now)
    flushed = None
    pending = body.get("buffered")
    if isinstance(pending, list) and pending and len(pending) <= 200:
        # Kolejka offline z zabitej aplikacji: przyjmujemy ją PRZED settle, żeby termin pytania
        # liczony zegarem serwera nie zamknął odpowiedzi udzielonych w czasie.
        answers = await _load_answers(st, attempt["id"])
        flushed = await _apply_batch(st, exam, attempt, answers, pending, body.get("client_now_ms"), True, now)
    state = await _serve(st, exam, attempt, None, now, resumed=bool(attempts and running in attempts))
    if flushed is not None:
        state["buffered_results"] = flushed
    return state


async def _serve(st: Store, exam: Mapping[str, Any], attempt: Dict[str, Any], index: Optional[int], now: datetime,
                 resumed: bool = False) -> Dict[str, Any]:
    bank = await load_bank(st, exam["bank_version"])
    answers = await _load_answers(st, attempt["id"])
    served = await _settle_and_save(st, exam, attempt, answers, now, index)
    state = _state(exam, attempt, answers, bank, served, now)
    state["resumed"] = resumed
    return state


async def attempt_state(st: Store, who: Who, attempt_id: str, index: Optional[int], device_id: Any, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    attempt = await _own_attempt(st, who, attempt_id)
    exam = await _exam(st, attempt["exam_id"], deleted_ok=True)
    if attempt["status"] == "in_progress":
        await _check_device(st, exam, attempt, device_id, now)
    return await _serve(st, exam, attempt, index, now)


#: Flagi, które są tylko opisem trasy odpowiedzi (nie sygnałem dla komisji) - nie trafiają do dziennika zdarzeń.
_QUIET_FLAGS = ("buffered", "buffered_revived")


async def _apply_batch(st: Store, exam: Mapping[str, Any], attempt: Dict[str, Any], answers: Dict[str, Dict[str, Any]],
                       items: List[Any], client_now_ms: Any, buffered: bool, now: datetime) -> List[Dict[str, Any]]:
    """Przyjmuje paczkę odpowiedzi i zapisuje jej ślady. Zamknięte przez czas podejście dostaje nową ocenę."""
    bank = await load_bank(st, exam["bank_version"])
    was_closed = attempt["status"] != "in_progress"
    items = [i for i in items if isinstance(i, Mapping)]
    results = X.apply_answers(exam["config"], attempt, answers, items, bank, now, client_now_ms, buffered)
    for res in results:
        for flag in res.get("flags") or []:
            if flag not in _QUIET_FLAGS:
                await _record_event(st, exam["id"], attempt, "time_flag", {"flag": flag, "qid": res.get("qid")}, now=now)
    await _save(st, attempt, answers)
    if attempt["status"] != "in_progress" and (attempt.get("score") is None or (
            was_closed and any(r.get("status") == "accepted" for r in results))):
        await _finalize_score(st, exam, attempt, answers)
    return results


async def post_answers(st: Store, who: Who, attempt_id: str, body: Mapping[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    attempt = await _own_attempt(st, who, attempt_id)
    exam = await _exam(st, attempt["exam_id"], deleted_ok=True)
    items = body.get("answers") or []
    if not isinstance(items, list) or not items:
        raise ExamError("EXAM_EMPTY_BATCH", "Brak odpowiedzi do zapisania (pole „answers”).")
    if len(items) > 200:
        raise ExamError("EXAM_BATCH_TOO_BIG", "Za dużo odpowiedzi w jednej paczce (maksimum 200).")
    if attempt["status"] == "in_progress":
        await _check_device(st, exam, attempt, body.get("device_id"), now)
    bank = await load_bank(st, exam["bank_version"])
    answers = await _load_answers(st, attempt_id)
    results = await _apply_batch(st, exam, attempt, answers, items, body.get("client_now_ms"), bool(body.get("buffered")), now)
    served = None
    if attempt["status"] == "in_progress":
        served = X.serve_question(exam["config"], attempt, answers, now, None)
        await _save(st, attempt, answers)
    state = _state(exam, attempt, answers, bank, served, now)
    return {"results": results, "state": state}


async def post_events(st: Store, who: Who, attempt_id: str, body: Mapping[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    attempt = await _own_attempt(st, who, attempt_id)
    exam = await _exam(st, attempt["exam_id"], deleted_ok=True)
    items = body.get("events") or []
    if not isinstance(items, list) or not items:
        raise ExamError("EXAM_EMPTY_BATCH", "Brak zdarzeń do zapisania (pole „events”).")
    if any(not isinstance(i, Mapping) for i in items[:50]):
        raise ExamError("EXAM_BAD_EVENT", "Każde zdarzenie w polu „events” musi być obiektem {kind, detail?, client_ts_ms?}.", 400)
    if attempt["status"] == "in_progress":
        await _check_device(st, exam, attempt, body.get("device_id"), now)
    count = await st.database.fetch_val(select(func.count()).select_from(st.t.events).where(st.t.events.c.attempt_id == attempt_id))
    anti = exam["config"]["anti"]
    recorded, ignored, policy = 0, [], None
    answers = await _load_answers(st, attempt_id)
    for item in items[:50]:
        kind = _s(item.get("kind"))
        if kind not in X.CLIENT_EVENT_KINDS:
            ignored.append({"kind": kind, "reason": f"Nieznany rodzaj zdarzenia. Dozwolone: {', '.join(X.CLIENT_EVENT_KINDS)}."})
            continue
        if kind == "screenshot" and not anti["screenshots"]:
            ignored.append({"kind": kind, "reason": "Wykrywanie zrzutów jest wyłączone dla tego egzaminu."})
            continue
        if kind != "app_background" and count + recorded >= MAX_EVENTS_PER_ATTEMPT:
            ignored.append({"kind": kind, "reason": "Limit zdarzeń na jedno podejście został wyczerpany."})
            continue
        detail = item.get("detail") if isinstance(item.get("detail"), Mapping) else {}
        if count + recorded < MAX_EVENTS_PER_ATTEMPT:
            await _record_event(st, exam["id"], attempt, kind, dict(detail), item.get("client_ts_ms"), now)
            recorded += 1
        else:
            ignored.append({"kind": kind, "reason": "Limit zdarzeń wyczerpany - to zdarzenie nie trafiło do dziennika, ale polityka wyjścia zadziałała."})
        if kind == "app_background" and attempt["status"] == "in_progress":
            policy = X.apply_leave_policy(exam["config"], attempt, answers, now)
    await _save(st, attempt, answers)
    if attempt["status"] != "in_progress" and attempt.get("score") is None:
        await _finalize_score(st, exam, attempt, answers)
    bank = await load_bank(st, exam["bank_version"])
    served = X.serve_question(exam["config"], attempt, answers, now, None) if attempt["status"] == "in_progress" else None
    await _save(st, attempt, answers)
    return {"recorded": recorded, "ignored": ignored, "policy": policy, "state": _state(exam, attempt, answers, bank, served, now)}


async def finish_attempt(st: Store, who: Who, attempt_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    attempt = await _own_attempt(st, who, attempt_id)
    exam = await _exam(st, attempt["exam_id"], deleted_ok=True)
    answers = await _load_answers(st, attempt_id)
    if attempt["status"] == "in_progress":
        X.settle(exam["config"], attempt, answers, now)
    if attempt["status"] == "in_progress":
        refusal = X.finish_refusal(exam["config"], attempt)
        if refusal:
            raise refusal
        X.finish_attempt(attempt, now, "manual")
    await _save(st, attempt, answers)
    if attempt.get("score") is None:
        await _finalize_score(st, exam, attempt, answers)
    return {"attempt_id": attempt_id, "status": attempt["status"], "result": X.result_view(exam["config"], attempt, now)}


async def attempt_result(st: Store, who: Who, attempt_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    attempt = await _own_attempt(st, who, attempt_id)
    exam = await _exam(st, attempt["exam_id"], deleted_ok=True)
    if attempt["status"] == "in_progress":
        answers = await _load_answers(st, attempt_id)
        X.settle(exam["config"], attempt, answers, now)
        await _save(st, attempt, answers)
        if attempt["status"] != "in_progress" and attempt.get("score") is None:
            await _finalize_score(st, exam, attempt, answers)
    return {"attempt_id": attempt_id, "status": attempt["status"], "attempt_no": attempt["attempt_no"],
            "result": X.result_view(exam["config"], attempt, now),
            "review_available": X.review_refusal(exam["config"], attempt["status"], now) is None,
            "review_opens_at": exam["config"]["window_end"], "server_now": now.isoformat()}


async def attempt_review(st: Store, who: Who, attempt_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utcnow()
    attempt = await _own_attempt(st, who, attempt_id)
    exam = await _exam(st, attempt["exam_id"], deleted_ok=True)
    refusal = X.review_refusal(exam["config"], attempt["status"], now)
    if refusal:
        raise ExamError("EXAM_REVIEW_LOCKED", refusal, 403, {"opens_at": exam["config"]["window_end"]})
    answers = await _load_answers(st, attempt_id)
    if attempt.get("score") is None:
        await _finalize_score(st, exam, attempt, answers)
    bank = await load_bank(st, exam["bank_version"])
    return {"attempt_id": attempt_id, "result": X.result_view(exam["config"], attempt, now),
            "questions": X.review_view(exam["config"], attempt["paper"], answers, bank, attempt["score"])}


# ---------------------------------------------------------------------------
# Komisja
# ---------------------------------------------------------------------------


async def _managed_exam(st: Store, who: Who, exam_id: str) -> Dict[str, Any]:
    exam = await _exam(st, exam_id)
    await require_manage(who, exam["scope"], exam.get("province"))
    return exam


async def _events_by_attempt(st: Store, exam_id: str) -> Dict[str, List[Dict[str, Any]]]:
    rows = await st.database.fetch_all(select(st.t.events).where(st.t.events.c.exam_id == exam_id).order_by(st.t.events.c.id))
    out: Dict[str, List[Dict[str, Any]]] = {}
    for raw in rows:
        r = _row(raw)
        out.setdefault(r["attempt_id"], []).append({"id": r["id"], "kind": r["kind"], "detail": _loads(r["detail_json"], {}),
                                                    "client_ts_ms": r.get("client_ts_ms"), "at": _iso(r["created_at"])})
    return out


async def attempts_list(st: Store, who: Who, exam_id: str) -> Dict[str, Any]:
    exam = await _managed_exam(st, who, exam_id)
    rows = await st.database.fetch_all(select(st.t.attempts).where(st.t.attempts.c.exam_id == exam_id)
                                       .order_by(st.t.attempts.c.judge_name, st.t.attempts.c.attempt_no))
    events = await _events_by_attempt(st, exam_id)
    items = []
    for raw in rows:
        a = _attempt(raw)
        score = a["score"] or {}
        items.append({"attempt_id": a["id"], "judge_id": a["judge_id"], "judge_name": a.get("judge_name"),
                      "province": a.get("province"), "attempt_no": a["attempt_no"], "status": a["status"],
                      "started_at": _iso(a["started_at"]), "finished_at": _iso(a.get("finished_at")),
                      "points": score.get("points"), "max": score.get("max"), "percent": score.get("percent"),
                      "passed": score.get("passed"), "integrity": X.integrity_report(events.get(a["id"], []), exam["config"]["anti"].get("integrity"))})
    return {"exam_id": exam_id, "pass_percent": exam["config"]["pass_percent"], "attempts": items}


async def attempt_card(st: Store, who: Who, exam_id: str, attempt_id: str) -> Dict[str, Any]:
    exam = await _managed_exam(st, who, exam_id)
    attempt = await _attempt_row(st, attempt_id)
    if attempt["exam_id"] != exam_id:
        raise ExamError("ATTEMPT_NOT_FOUND", "To podejście nie należy do tego egzaminu.", 404)
    answers = await _load_answers(st, attempt_id)
    bank = await load_bank(st, exam["bank_version"])
    events = (await _events_by_attempt(st, exam_id)).get(attempt_id, [])
    timeline = []
    for item in attempt["paper"]:
        row = answers.get(item["qid"]) or {}
        timeline.append({"position": row.get("position"), "qid": item["qid"], "number": bank[item["qid"]]["number"],
                         "selected": row.get("selected"), "shown_at": _iso(row.get("shown_at")),
                         "answered_at": _iso(row.get("answered_at")), "elapsed_ms": row.get("elapsed_ms"),
                         "timed_out": bool(row.get("timed_out")), "changes": row.get("changes"), "flags": row.get("flags")})
    return {"attempt_id": attempt_id, "judge_id": attempt["judge_id"], "judge_name": attempt.get("judge_name"),
            "status": attempt["status"], "finish_reason": attempt.get("finish_reason"), "score": attempt["score"],
            "device_id": attempt.get("device_id"), "integrity": X.integrity_report(events, exam["config"]["anti"].get("integrity")), "events": events,
            "timeline": timeline}


async def exam_stats(st: Store, who: Who, exam_id: str) -> Dict[str, Any]:
    exam = await _managed_exam(st, who, exam_id)
    t = st.t
    done = [_attempt(r) for r in await st.database.fetch_all(select(t.attempts).where(and_(
        t.attempts.c.exam_id == exam_id, t.attempts.c.status != "in_progress")))]
    ids = [a["id"] for a in done]
    rows = []
    if ids:
        for raw in await st.database.fetch_all(select(t.answers).where(t.answers.c.attempt_id.in_(ids))):
            r = _row(raw)
            rows.append({"qid": r["qid"], "selected": _loads(r["selected_json"], []), "timed_out": bool(r["timed_out"]),
                         "elapsed_ms": r["elapsed_ms"]})
    bank = await load_bank(st, exam["bank_version"])
    percents = [a["score"]["percent"] for a in done if a.get("score")]
    histogram = [0] * 10
    for p in percents:
        histogram[min(9, int(p // 10))] += 1
    passed = sum(1 for a in done if (a.get("score") or {}).get("passed"))
    return {
        "exam_id": exam_id, "pass_percent": exam["config"]["pass_percent"],
        "summary": {"finished": len(done), "passed": passed, "pass_rate": round(passed / len(done), 4) if done else None,
                    "avg_percent": round(sum(percents) / len(percents), 2) if percents else None, "histogram_10pct": histogram},
        "questions": X.question_stats(rows, bank, exam["voided"], exam["config"]["multi_scoring"]),
    }


async def missing(st: Store, who: Who, exam_id: str) -> Dict[str, Any]:
    exam = await _managed_exam(st, who, exam_id)
    rows = await st.database.fetch_all(select(st.t.attempts.c.judge_id).where(st.t.attempts.c.exam_id == exam_id))
    attended = {r["judge_id"] for r in rows}
    out = []
    for prov in _exam_provinces(exam):
        judges = await st.judges(prov)
        by_id = {_s(j["judge_id"]): j for j in judges}
        for jid in await _invited_ids(st, exam, prov, judges):
            if jid not in attended:
                out.append({"judge_id": jid, "name": _s(by_id[jid].get("full_name")) or jid, "province": prov})
    out.sort(key=lambda r: (r["province"], r["name"]))
    return {"exam_id": exam_id, "count": len(out), "missing": out}


async def void_question(st: Store, who: Who, exam_id: str, qid: str, mode: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Unieważnia pytanie i przelicza wyniki zakończonych podejść. `drop` wyłącza pytanie
    z puli punktów, `credit` zalicza je wszystkim."""
    exam = await _managed_exam(st, who, exam_id)
    if mode not in X.VOID_MODES:
        raise ExamError("BAD_CONFIG", f"Tryb unieważnienia: dozwolone wartości to {', '.join(X.VOID_MODES)}.")
    if qid not in exam["question_ids"]:
        raise ExamError("EXAM_UNKNOWN_QUESTION", "Tego pytania nie ma w puli egzaminu.", 404)
    exam["voided"][qid] = mode
    await st.database.execute(update(st.t.definitions).where(st.t.definitions.c.id == exam_id)
                              .values(voided_json=_dumps(exam["voided"]), updated_at=now or utcnow()))
    return {"exam_id": exam_id, "voided": exam["voided"], "recomputed": await _recompute(st, exam)}


async def unvoid_question(st: Store, who: Who, exam_id: str, qid: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    exam = await _managed_exam(st, who, exam_id)
    if qid not in exam["voided"]:
        raise ExamError("EXAM_NOT_VOIDED", "To pytanie nie jest unieważnione.", 409)
    exam["voided"].pop(qid)
    await st.database.execute(update(st.t.definitions).where(st.t.definitions.c.id == exam_id)
                              .values(voided_json=_dumps(exam["voided"]), updated_at=now or utcnow()))
    return {"exam_id": exam_id, "voided": exam["voided"], "recomputed": await _recompute(st, exam)}


async def _recompute(st: Store, exam: Mapping[str, Any]) -> int:
    rows = await st.database.fetch_all(select(st.t.attempts).where(and_(
        st.t.attempts.c.exam_id == exam["id"], st.t.attempts.c.status != "in_progress")))
    for raw in rows:
        attempt = _attempt(raw)
        await _finalize_score(st, exam, attempt, await _load_answers(st, attempt["id"]))
    return len(rows)


async def allow_device(st: Store, who: Who, exam_id: str, attempt_id: str, device_id: str) -> Dict[str, Any]:
    await _managed_exam(st, who, exam_id)
    attempt = await _attempt_row(st, attempt_id)
    if attempt["exam_id"] != exam_id:
        raise ExamError("ATTEMPT_NOT_FOUND", "To podejście nie należy do tego egzaminu.", 404)
    if not _s(device_id):
        raise ExamError("EXAM_DEVICE_REQUIRED", "Podaj identyfikator urządzenia (device_id), które komisja dopuszcza.")
    await st.database.execute(update(st.t.attempts).where(st.t.attempts.c.id == attempt_id).values(device_id=_s(device_id)))
    return {"attempt_id": attempt_id, "device_id": _s(device_id)}


async def room_code_for(st: Store, who: Who, exam_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    exam = await _managed_exam(st, who, exam_id)
    if not exam["config"]["anti"]["room_code"]:
        raise ExamError("EXAM_FEATURE_OFF", "Tryb sali (kod zmienny co 30 s) jest wyłączony dla tego egzaminu.", 409)
    return X.room_code(st.secret, exam_id, now or utcnow())


async def similarity_scan(st: Store, who: Who, exam_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    exam = await _managed_exam(st, who, exam_id)
    if not exam["config"]["anti"]["similarity"]:
        raise ExamError("EXAM_FEATURE_OFF", "Wykrywanie podobieństwa par jest wyłączone dla tego egzaminu.", 409)
    rows = await st.database.fetch_all(select(st.t.attempts).where(and_(
        st.t.attempts.c.exam_id == exam_id, st.t.attempts.c.status != "in_progress")))
    packs = []
    for raw in rows:
        a = _attempt(raw)
        answers = await _load_answers(st, a["id"])
        correct = {r["qid"]: r.get("correct") for r in (a["score"] or {}).get("questions", [])}
        packs.append({"attempt_id": a["id"], "judge_id": a["judge_id"], "answers": {
            qid: {"selected": r.get("selected"), "correct": bool(correct.get(qid)), "answered_at": r.get("answered_at")}
            for qid, r in answers.items()}})
    pairs = X.similarity_pairs(packs, thresholds=exam["config"]["anti"].get("integrity"))
    await st.database.execute(delete(st.t.events).where(and_(st.t.events.c.exam_id == exam_id, st.t.events.c.kind == "similarity")))
    by_id = {p["attempt_id"]: p for p in packs}
    for pair in pairs:
        for i, aid in enumerate(pair["attempt_ids"]):
            other = pair["judge_ids"][1 - i]
            await _record_event(st, exam_id, {"id": aid, "judge_id": by_id[aid]["judge_id"]}, "similarity",
                                {"with_judge_id": other, "common_wrong": pair["common_wrong"],
                                 "close_in_time": pair["close_in_time"]}, now=now)
    return {"exam_id": exam_id, "pairs": pairs, "note": "To sygnał do oceny przez komisję, nie wyrok."}


# ---------------------------------------------------------------------------
# Przejście w tle: domknięcie spóźnionych podejść, przypomnienia, „wyniki dostępne”
# ---------------------------------------------------------------------------


async def _safe_push(st: Store, ids: List[str], title: str, body: str, data: Dict[str, Any]) -> None:
    try:
        await st.push(ids, title, body, data)
    except Exception:  # noqa: BLE001
        logger.warning("egzamin: powiadomienie nieudane", exc_info=True)


def _push_data(exam: Mapping[str, Any], province: str, notice: str) -> Dict[str, Any]:
    return {"kind": "province_event", "type": "province_event", "eventId": str((exam["event_ids"] or {}).get(province, "")),
            "examId": exam["id"], "province": province, "notice": notice}


async def _finalize_overdue(st: Store, now: datetime) -> int:
    rows = await st.database.fetch_all(select(st.t.attempts).where(and_(
        st.t.attempts.c.status == "in_progress", st.t.attempts.c.deadline_at <= now - SWEEP_GRACE)))
    done = 0
    for raw in rows:
        attempt = _attempt(raw)
        exam = await _exam(st, attempt["exam_id"], deleted_ok=True)
        answers = await _load_answers(st, attempt["id"])
        X.settle(exam["config"], attempt, answers, now)
        await _save(st, attempt, answers)
        if attempt["status"] != "in_progress":
            await _finalize_score(st, exam, attempt, answers)
            done += 1
    return done


async def _mark_sent(st: Store, exam_id: str, ids: Sequence[str], kind: str, now: datetime) -> None:
    for jid in ids:
        try:
            await st.database.execute(insert(st.t.reminders).values(exam_id=exam_id, judge_id=jid, kind=kind, sent_at=now))
        except Exception:  # noqa: BLE001 - już wpisane (równoległe przejście)
            pass


async def sweep_exam_reminders(st: Store, now: Optional[datetime] = None) -> int:
    """Wzorzec `sweep_event_reminders`: wpis do dziennika PRZED wysyłką, więc powtórzone
    przejście nie wyśle drugi raz. Zwraca liczbę wysłanych powiadomień."""
    now = now or utcnow()
    t = st.t
    total = 0
    await _finalize_overdue(st, now)

    # 1) „X przed końcem okna" do tych, którzy jeszcze nie przystąpili
    rows = await st.database.fetch_all(select(t.definitions).where(and_(
        t.definitions.c.deleted_at.is_(None), t.definitions.c.opens_at <= now, t.definitions.c.closes_at > now)).limit(200))
    for raw in rows:
        exam = _row(raw)
        exam["config"] = _loads(exam["config_json"], {})
        exam["event_ids"] = _loads(exam["event_ids_json"], {})
        thresholds = exam["config"].get("reminders_hours") or []
        if not thresholds:
            continue
        attended = {r["judge_id"] for r in await st.database.fetch_all(
            select(t.attempts.c.judge_id).where(t.attempts.c.exam_id == exam["id"]))}
        sent = {(r["judge_id"], r["kind"]) for r in await st.database.fetch_all(
            select(t.reminders).where(t.reminders.c.exam_id == exam["id"]))}
        for prov in _exam_provinces(exam):
            pending = [j for j in await _invited_ids(st, exam, prov) if j not in attended]
            for kind, people in X.due_exam_reminders(
                now=now, window_start=_dt(exam["opens_at"]), window_end=_dt(exam["closes_at"]),
                created_at=_dt(exam.get("created_at")), thresholds_hours=thresholds, pending=pending, sent=sent):
                hours = int(kind.split("_")[1].rstrip("h"))
                await _mark_sent(st, exam["id"], people, kind, now)
                left = "mniej niż godzina" if hours <= 1 else f"{hours} h"
                await _safe_push(st, people, f"⏳ Egzamin: {exam['name']}",
                                 f"Okno zamyka się za ok. {left}. Nie przystąpiłeś jeszcze - zrób to w aplikacji.",
                                 _push_data(exam, prov, "exam_reminder"))
                total += len(people)

    # 2) „wyniki dostępne" po zamknięciu okna, do tych, którzy skończyli podejście
    rows = await st.database.fetch_all(select(t.definitions).where(and_(
        t.definitions.c.deleted_at.is_(None), t.definitions.c.closes_at <= now,
        t.definitions.c.closes_at > now - timedelta(days=RESULTS_PUSH_DAYS))).limit(200))
    for raw in rows:
        exam = _row(raw)
        exam["config"] = _loads(exam["config_json"], {})
        exam["event_ids"] = _loads(exam["event_ids_json"], {})
        if not exam["config"].get("results_push"):
            continue
        if await st.database.fetch_val(select(func.count()).select_from(t.attempts).where(and_(
                t.attempts.c.exam_id == exam["id"], t.attempts.c.status == "in_progress"))):
            continue  # najpierw domknij trwające podejścia
        done = await st.database.fetch_all(select(t.attempts.c.judge_id, t.attempts.c.province).where(and_(
            t.attempts.c.exam_id == exam["id"], t.attempts.c.status != "in_progress")))
        sent = {r["judge_id"] for r in await st.database.fetch_all(
            select(t.reminders).where(and_(t.reminders.c.exam_id == exam["id"], t.reminders.c.kind == "results")))}
        by_prov: Dict[str, List[str]] = {}
        for r in done:
            if r["judge_id"] not in sent:
                by_prov.setdefault(r["province"] or "", []).append(r["judge_id"])
        for prov, people in by_prov.items():
            people = sorted(set(people))
            await _mark_sent(st, exam["id"], people, "results", now)
            await _safe_push(st, people, f"📋 Wyniki egzaminu: {exam['name']}",
                             "Wynik i przegląd odpowiedzi z kluczem są już dostępne.", _push_data(exam, prov, "exam_results"))
            total += len(people)
    return total
