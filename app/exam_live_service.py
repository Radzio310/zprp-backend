"""
Egzamin na żywo - logika z dostępem do bazy (etap 5, 16.10.2026).

Tak jak `exam_service.py`: baza, tabele i uprawnienia przychodzą w obiekcie `LiveStore`,
więc moduł nie importuje `app.db` (łączy się z Postgresem przy imporcie) i da się go uruchomić
w testach na SQLite. Reguły (fazy, punkty, widoki) są w `exam_live_rules.py`.

Serwer trzyma stan w BAZIE (faza, termin pytania, odpowiedzi, wyniki), a gniazda WebSocket tylko
rozgłaszają to, co z bazy wynika (`exam_live_hub.py`). Dzięki temu:
  - restart procesu niczego nie gubi - klienci wracają przez GET migawki,
  - każde zdarzenie (odpowiedź, zmiana fazy) przechodzi przez jedną blokadę sesji,
  - termin pytania egzekwujemy też „leniwie" (`tick`): kto zapyta po terminie, ten zobaczy reveal,
    nawet jeśli zegar w tle nie zdążył zadziałać.

Ocena i punkty za szybkość: wyłącznie tu. Czas odpowiedzi to różnica zegara SERWERA (chwila
przyjęcia odpowiedzi minus chwila wydania pytania), więc opóźnienie sieci liczy się wszystkim po równo
i nie da się go podrobić. Klucz poprawnych odpowiedzi opuszcza ten moduł dopiero w widoku reveal.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional

from sqlalchemy import delete, insert, select, update

from app import exam_live_rules as L
from app import exam_rules as X
from app import exam_service as S
from app.exam_rules import ExamError

MAX_ACTIVE_PER_HOST = 5


@dataclass
class LiveTables:
    sessions: Any
    participants: Any
    answers: Any


@dataclass
class LiveStore:
    exam: S.Store
    t: LiveTables

    @property
    def database(self) -> Any:
        return self.exam.database


# Blokady sesji: jeden proces Railway (patrz exam_live_hub.py), więc słownik w pamięci wystarcza.
_LOCKS: Dict[str, asyncio.Lock] = {}


def lock_for(session_id: str) -> asyncio.Lock:
    lock = _LOCKS.get(session_id)
    if lock is None:
        lock = _LOCKS[session_id] = asyncio.Lock()
    return lock


def _row(raw: Any) -> Dict[str, Any]:
    return S._row(raw)


# ---------------------------------------------------------------------------
# Wczytywanie
# ---------------------------------------------------------------------------


def _session(raw: Any) -> Dict[str, Any]:
    s = _row(raw)
    s["config"] = S._loads(s["config_json"], {})
    s["question_ids"] = S._loads(s["question_ids_json"], [])
    s["q_total"] = len(s["question_ids"])
    for key in ("phase_started_at", "deadline_at", "created_at", "updated_at", "ended_at"):
        s[key] = S._dt(s.get(key))
    return s


async def session_row(ls: LiveStore, session_id: str) -> Dict[str, Any]:
    raw = await ls.database.fetch_one(select(ls.t.sessions).where(ls.t.sessions.c.id == session_id))
    if not raw:
        raise ExamError("LIVE_NOT_FOUND", "Nie znaleziono takiej sesji na żywo (mogła zostać usunięta).", 404)
    return _session(raw)


async def session_by_token(ls: LiveStore, token: str) -> Dict[str, Any]:
    raw = await ls.database.fetch_one(select(ls.t.sessions).where(ls.t.sessions.c.token == str(token or "")))
    if not raw:
        raise ExamError("LIVE_NOT_FOUND", "Nie znaleziono takiej sesji. Sprawdź kod albo link.", 404)
    return _session(raw)


async def session_by_projector(ls: LiveStore, token: str) -> Dict[str, Any]:
    """Rzutnik wchodzi WYŁĄCZNIE tokenem rzutnika (token dołączania z QR tu nie działa)."""
    value = str(token or "")
    raw = await ls.database.fetch_one(select(ls.t.sessions).where(ls.t.sessions.c.projector_token == value)) if value else None
    if not raw:
        raise ExamError("LIVE_NOT_FOUND", "Nie znaleziono takiej sesji. Sprawdź kod albo link.", 404)
    return _session(raw)


async def _ensure_projector_token(ls: LiveStore, s: Dict[str, Any]) -> None:
    """Sesje założone przed wprowadzeniem tokenu rzutnika dostają go przy pierwszym odczycie."""
    if s.get("projector_token"):
        return
    value = secrets.token_urlsafe(16)
    await ls.database.execute(update(ls.t.sessions).where(ls.t.sessions.c.id == s["id"]).values(projector_token=value))
    s["projector_token"] = value


async def _active_pins(ls: LiveStore, now: datetime) -> Dict[str, Dict[str, Any]]:
    rows = await ls.database.fetch_all(select(ls.t.sessions).where(ls.t.sessions.c.phase != "end"))
    out: Dict[str, Dict[str, Any]] = {}
    for raw in rows:
        s = _session(raw)
        if L.session_active(s["phase"], s["updated_at"], now):
            out[s["pin"]] = s
    return out


async def session_by_ref(ls: LiveStore, ref: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    """Sesja po PIN-ie (tylko aktywna) albo po tokenie z kodu QR."""
    token = str(ref.get("token") or "").strip()
    if token:
        s = await session_by_token(ls, token)
    else:
        pin = L.clean_pin(ref.get("pin"))
        if len(pin) != 6:
            raise ExamError("LIVE_BAD_PIN", "Kod PIN ma 6 cyfr.")
        s = (await _active_pins(ls, now)).get(pin)
        if not s:
            raise ExamError("LIVE_PIN_UNKNOWN", "Nie ma aktywnej sesji z takim kodem PIN. Sprawdź kod na ekranie prowadzącego.", 404)
    if s["phase"] == "end":
        raise ExamError("LIVE_ENDED", "Ta sesja jest już zakończona.", 409)
    if not L.session_active(s["phase"], s["updated_at"], now):
        raise ExamError("LIVE_ENDED", "Ta sesja wygasła z powodu bezczynności.", 409)
    return s


async def _participants(ls: LiveStore, session_id: str) -> List[Dict[str, Any]]:
    t = ls.t.participants
    rows = await ls.database.fetch_all(select(t).where(t.c.session_id == session_id).order_by(t.c.joined_at, t.c.id))
    return [_row(r) for r in rows]


async def _answers_for(ls: LiveStore, session_id: str, q_index: int) -> Dict[str, Dict[str, Any]]:
    t = ls.t.answers
    rows = await ls.database.fetch_all(select(t).where((t.c.session_id == session_id) & (t.c.q_index == q_index)))
    out: Dict[str, Dict[str, Any]] = {}
    for raw in rows:
        r = _row(raw)
        r["selected"] = S._loads(r["selected_json"], [])
        out[r["participant_id"]] = r
    return out


async def _all_answers(ls: LiveStore, session_id: str) -> List[Dict[str, Any]]:
    t = ls.t.answers
    rows = await ls.database.fetch_all(select(t).where(t.c.session_id == session_id))
    out = []
    for raw in rows:
        r = _row(raw)
        r["selected"] = S._loads(r["selected_json"], [])
        out.append(r)
    return out


def links_for(token: str, projector_token: Optional[str] = None) -> Dict[str, str]:
    """Adresy WZGLĘDNE (rzutnik i QR składają z nich pełny adres z bieżącego hosta).
    Rzutnik i jego QR mają własny token; `join_url` niesie token dołączania."""
    ptoken = projector_token or token
    return {"join_url": f"/exam-live/join/{token}", "qr_url": f"/exam-live/projector/{ptoken}/qr.svg",
            "projector_url": f"/exam-live/projector/{ptoken}", "join_page": "/exam-live/join",
            # 17.10.2026: krótki adres z markowego kodu i macierz kodu dla animowanego rysowania
            "join_short": f"/exam-live/j/{token}", "qr_json": f"/exam-live/projector/{ptoken}/qr.json",
            "qr_brand": f"/exam-live/projector/{ptoken}/qr.svg?style=brand",
            "qr_json_url": f"/exam-live/projector/{ptoken}/qr.json", "poster_url": f"/exam-live/projector/{ptoken}/poster.pdf",
            "story_url": f"/exam-live/projector/{ptoken}/story.png"}


async def load_state(ls: LiveStore, session_id: str, now: datetime) -> Dict[str, Any]:
    """Wszystko, z czego buduje się widoki. Zawiera klucze pytania - nie wychodzi poza serwer."""
    s = await session_row(ls, session_id)
    await _ensure_projector_token(ls, s)
    parts = await _participants(ls, session_id)
    answers: Dict[str, Dict[str, Any]] = {}
    question = None
    next_question = None
    if s["phase"] in ("question", "reveal") and 0 <= s["q_index"] < s["q_total"]:
        answers = await _answers_for(ls, session_id, s["q_index"])
        bank = await S.load_bank(ls.exam, s["bank_version"])
        question = bank.get(s["question_ids"][s["q_index"]])
    if s["phase"] != "end" and s["q_index"] + 1 < s["q_total"]:
        # Zapowiedź dla prowadzącego (`session.next`); bank siedzi w pamięci podręcznej.
        next_question = (await S.load_bank(ls.exam, s["bank_version"])).get(s["question_ids"][s["q_index"] + 1])
    return {
        "session": s, "participants": parts, "answers": answers, "question": question, "next_question": next_question,
        "result": S._loads(s.get("result_json"), None) if s["phase"] == "end" else None,
        "links": links_for(s["token"], s.get("projector_token")), "server_now": now,
    }


# ---------------------------------------------------------------------------
# Zapisy
# ---------------------------------------------------------------------------


async def _bump(ls: LiveStore, session_id: str, now: datetime, **values: Any) -> None:
    t = ls.t.sessions
    await ls.database.execute(update(t).where(t.c.id == session_id).values(rev=t.c.rev + 1, updated_at=now, **values))


async def create_session(ls: LiveStore, who: S.Who, body: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    est = ls.exam
    character = L.clean_choice(body.get("character"), L.CHARACTERS, "quiz", "Charakter sesji")
    phone_view = L.clean_choice(body.get("phone_view"), L.PHONE_VIEWS, "full", "Widok telefonu")
    raw_config = dict(body.get("config") or {})
    session_id = str(uuid.uuid4())
    exam: Optional[Dict[str, Any]] = None
    title_default = body.get("title")

    if S._s(body.get("exam_id")):
        exam = await S._exam(est, S._s(body["exam_id"]))
        await S.require_manage(who, exam["scope"], exam.get("province"))
        scope, province = exam["scope"], exam.get("province")
        bank_version = exam["bank_version"]
        ecfg = exam["config"]
        qids = X.pick_set(exam["question_ids"], int(ecfg.get("question_count") or len(exam["question_ids"])), "shared", session_id)
        raw_config.setdefault("pass_percent", ecfg.get("pass_percent"))
        if ecfg.get("time_per_question_s"):
            raw_config.setdefault("question_time_s", min(600, int(ecfg["time_per_question_s"])))
        raw_config.setdefault("multi_scoring", ecfg.get("multi_scoring") or "all_or_nothing")
        title_default = title_default or exam["name"]
    else:
        scope, province = S._scope_and_province(body, who)
        await S.require_manage(who, scope, province)
        bank_version = await S.ensure_bank(est)
        bank = await S.load_bank(est, bank_version)
        if body.get("question_ids"):
            qids = [S._s(q) for q in body["question_ids"] if S._s(q)]
            qids = list(dict.fromkeys(qids))
            unknown = [q for q in qids if q not in bank]
            if unknown:
                raise ExamError("BAD_SCOPE", f"Tych pytań nie ma w banku: {', '.join(unknown[:5])}.")
        elif isinstance(body.get("pool"), Mapping):
            pool_cfg = body["pool"]
            clean_scope = X.clean_config({"scope": pool_cfg.get("scope") or {}, "window_start": "2000-01-01T00:00:00+00:00",
                                          "window_end": "2000-01-02T00:00:00+00:00"})["scope"]
            pool = X.resolve_pool(clean_scope, bank.values(), None)
            count = X._int(pool_cfg.get("count", min(10, len(pool))), "Liczba pytań", 1, L.MAX_QUESTIONS)
            qids = X.pick_set(pool, count, "shared", session_id)
        else:
            raise ExamError("LIVE_NO_QUESTIONS", "Wybierz pytania (question_ids), zakres z liczbą (pool) albo podaj egzamin (exam_id).")
    if not qids:
        raise ExamError("LIVE_NO_QUESTIONS", "Sesja musi mieć co najmniej jedno pytanie.")
    if len(qids) > L.MAX_QUESTIONS:
        raise ExamError("BAD_CONFIG", f"Sesja może mieć najwyżej {L.MAX_QUESTIONS} pytań.")
    if body.get("shuffle"):
        import random

        random.Random(session_id).shuffle(qids)
    cfg = L.clean_live_config(raw_config, character)
    title = L.clean_title(title_default, character)

    active = await _active_pins(ls, now)
    mine = [s for s in active.values() if s["host_id"] == who.judge_id]
    if len(mine) >= MAX_ACTIVE_PER_HOST:
        raise ExamError("LIVE_TOO_MANY", f"Masz już {len(mine)} aktywnych sesji. Zakończ którąś, zanim założysz następną.", 409)
    pin = L.generate_pin(set(active))
    await ls.database.execute(insert(ls.t.sessions).values(
        id=session_id, pin=pin, token=secrets.token_urlsafe(16), projector_token=secrets.token_urlsafe(16), host_id=who.judge_id, host_name=who.name,
        scope=scope, province=province, exam_id=exam["id"] if exam else None, title=title, character=character,
        phone_view=phone_view, guests_allowed=bool(body.get("guests_allowed", False)),
        config_json=S._dumps(cfg), bank_version=bank_version, question_ids_json=S._dumps(qids),
        phase="lobby", q_index=-1, rev=1, created_at=now, updated_at=now))
    return await load_state(ls, session_id, now)


async def _commit_scores(ls: LiveStore, session_id: str) -> None:
    """Przy reveal sumujemy punkty z odpowiedzi do uczestników (ranking żywy dopiero po odsłonięciu)."""
    answers = await _all_answers(ls, session_id)
    totals: Dict[str, List[float]] = {}
    for a in answers:
        bucket = totals.setdefault(a["participant_id"], [0, 0, 0])
        bucket[0] += int(a.get("points") or 0)
        bucket[1] += 1 if float(a.get("fraction") or 0) >= 1.0 else 0
        bucket[2] += 1
    t = ls.t.participants
    for pid, (score, correct, answered) in totals.items():
        await ls.database.execute(update(t).where(t.c.id == pid).values(
            score=int(score), correct_count=int(correct), answered_count=int(answered)))


async def _reveal(ls: LiveStore, s: Mapping[str, Any], now: datetime) -> None:
    await _commit_scores(ls, s["id"])
    await _bump(ls, s["id"], now, phase="reveal", phase_started_at=now)


async def _finish(ls: LiveStore, s: Mapping[str, Any], now: datetime) -> None:
    await _commit_scores(ls, s["id"])
    bank = await S.load_bank(ls.exam, s["bank_version"])
    parts = await _participants(ls, s["id"])
    answers = await _all_answers(ls, s["id"])
    skipped = set(s["config"].get("skipped") or [])
    result = L.build_result(character=s["character"], pass_percent=s["config"].get("pass_percent"),
                            question_ids=[q for q in s["question_ids"] if q not in skipped] or s["question_ids"],
                            bank=bank, participants=parts, answers=[a for a in answers if a["qid"] not in skipped])
    await _bump(ls, s["id"], now, phase="end", phase_started_at=now, deadline_at=None, ended_at=now,
                result_json=S._dumps(result))


async def tick(ls: LiveStore, session_id: str, now: datetime) -> bool:
    """Leniwy upływ czasu: po terminie pytania (gdy auto_reveal) przechodzimy do reveal."""
    async with lock_for(session_id):
        s = await session_row(ls, session_id)
        if s["phase"] == "question" and s["config"]["auto_reveal"] and s["deadline_at"] and now >= s["deadline_at"]:
            await _reveal(ls, s, now)
            return True
    return False


async def control(ls: LiveStore, who: S.Who, session_id: str, action: str, now: datetime,
                  expect: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Sterowanie fazami. Tylko prowadzący (admin może dodatkowo zakończyć cudzą sesję)."""
    async with lock_for(session_id):
        s = await session_row(ls, session_id)
        if s["host_id"] != who.judge_id and not (who.is_admin and action == "end"):
            raise ExamError("LIVE_NOT_HOST", "Fazami tej sesji steruje tylko jej prowadzący.", 403)
        if s["phase"] == "question" and s["config"]["auto_reveal"] and s["deadline_at"] and now >= s["deadline_at"]:
            await _reveal(ls, s, now)
            s = await session_row(ls, session_id)
        expect = expect or {}
        if (expect.get("from_phase") and expect["from_phase"] != s["phase"]) or (
                expect.get("from_index") is not None and expect["from_index"] != s["q_index"]):
            raise ExamError("LIVE_STALE", "Faza zdążyła się już zmienić (np. skończył się czas). Odśwież widok i spróbuj ponownie.",
                            409, {"phase": s["phase"], "q_index": s["q_index"]})
        if action in L.PILOT_ACTIONS:
            await _pilot(ls, s, action, now, expect)
            return await load_state(ls, session_id, now)
        action = L.control_action(action, s["phase"])
        if action == "end":
            if s["phase"] == "question":
                await _commit_scores(ls, s["id"])
            await _finish(ls, s, now)
            return await load_state(ls, session_id, now)
        phase, index = L.next_phase(s["phase"], s["q_index"], s["q_total"], s["config"]["ranking"]["leaderboard_each"])
        if phase == "question":
            deadline = now + timedelta(seconds=s["config"]["question_time_s"])
            await _bump(ls, session_id, now, phase="question", q_index=index, phase_started_at=now, deadline_at=deadline)
        elif phase == "reveal":
            await _reveal(ls, s, now)
        elif phase == "end":
            await _finish(ls, s, now)
        else:
            await _bump(ls, session_id, now, phase=phase, phase_started_at=now, deadline_at=None)
    return await load_state(ls, session_id, now)


async def _pilot(ls: LiveStore, s: Mapping[str, Any], action: str, now: datetime, extra: Mapping[str, Any]) -> None:
    """Pauza, wznowienie, dodatkowy czas, pominięcie pytania, zamknięcie sali (17.10.2026).
    Stan w `config_json` (bez migracji tabel): `paused_left`, `locked`, `skipped`, `kicked`."""
    cfg = dict(s["config"])
    paused = cfg.get("paused_left") is not None
    refusal = L.pilot_refusal(action, s["phase"], paused)
    if refusal:
        raise refusal
    sid = s["id"]
    if action in ("lock", "unlock"):
        cfg["locked"] = action == "lock"
        await _bump(ls, sid, now, config_json=S._dumps(cfg))
        return
    total = float(cfg["question_time_s"])
    if action == "pause":
        left = max(0.0, (s["deadline_at"] - now).total_seconds()) if s["deadline_at"] else total
        cfg["paused_left"] = round(left, 3)
        await _bump(ls, sid, now, config_json=S._dumps(cfg), deadline_at=None)
    elif action == "resume":
        left = float(cfg.pop("paused_left") or 0)
        # Start pytania przesunięty o pauzę: punkty za szybkość liczą tylko czas, gdy zegar szedł.
        await _bump(ls, sid, now, config_json=S._dumps(cfg), deadline_at=now + timedelta(seconds=left),
                    phase_started_at=now - timedelta(seconds=max(0.0, total - left)))
    elif action == "extend":
        raw = extra.get("seconds")
        seconds = X._int(raw if raw is not None else L.EXTEND_DEFAULT_S, "Dodatkowy czas (s)", 5, 120)
        if paused:
            cfg["paused_left"] = float(cfg["paused_left"]) + seconds
            await _bump(ls, sid, now, config_json=S._dumps(cfg))
        else:
            base = s["deadline_at"] if s["deadline_at"] and s["deadline_at"] > now else now
            await _bump(ls, sid, now, deadline_at=base + timedelta(seconds=seconds))
    elif action == "skip":
        # Pytanie wypada z sesji: odpowiedzi kasujemy, nie liczy się do wyniku ani do progu.
        qid = s["question_ids"][s["q_index"]]
        cfg.pop("paused_left", None)
        cfg["skipped"] = list(dict.fromkeys(list(cfg.get("skipped") or []) + [qid]))
        t = ls.t.answers
        await ls.database.execute(delete(t).where((t.c.session_id == sid) & (t.c.q_index == s["q_index"])))
        await _commit_scores(ls, sid)
        if s["q_index"] + 1 < s["q_total"]:
            await _bump(ls, sid, now, config_json=S._dumps(cfg), q_index=s["q_index"] + 1, phase_started_at=now,
                        deadline_at=now + timedelta(seconds=total))
        else:
            await _bump(ls, sid, now, config_json=S._dumps(cfg))
            await _finish(ls, await session_row(ls, sid), now)


async def kick(ls: LiveStore, who: S.Who, session_id: str, participant_id: str, now: datetime) -> Dict[str, Any]:
    """Prowadzący usuwa osobę z sali: znika z listy i rankingu, nie wraca tym samym kontem ani biletem gościa."""
    async with lock_for(session_id):
        s = await session_row(ls, session_id)
        if s["host_id"] != who.judge_id:
            raise ExamError("LIVE_NOT_HOST", "Z sali usuwa tylko prowadzący.", 403)
        if s["phase"] == "end":
            raise ExamError("LIVE_ENDED", "Ta sesja jest już zakończona.", 409)
        t = ls.t.participants
        raw = await ls.database.fetch_one(select(t).where((t.c.session_id == session_id) & (t.c.id == participant_id)))
        if not raw:
            raise ExamError("LIVE_NO_PARTICIPANT", "Tej osoby już nie ma w sali.", 404)
        p = _row(raw)
        cfg = dict(s["config"])
        kicked = list(cfg.get("kicked") or [])
        kicked.append(f"j:{p['judge_id']}" if p.get("judge_id") else f"g:{p.get('guest_token')}")
        cfg["kicked"] = kicked[-500:]
        a = ls.t.answers
        await ls.database.execute(delete(a).where((a.c.session_id == session_id) & (a.c.participant_id == participant_id)))
        await ls.database.execute(delete(t).where(t.c.id == participant_id))
        await _bump(ls, session_id, now, config_json=S._dumps(cfg))
    return await load_state(ls, session_id, now)


def was_kicked(s: Mapping[str, Any], *, judge_id: Optional[str] = None, guest_token: Optional[str] = None) -> bool:
    kicked = s["config"].get("kicked") or []
    return (judge_id is not None and f"j:{judge_id}" in kicked) or (guest_token is not None and f"g:{guest_token}" in kicked)


async def patch_session(ls: LiveStore, who: S.Who, session_id: str, body: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    async with lock_for(session_id):
        s = await session_row(ls, session_id)
        if s["host_id"] != who.judge_id:
            raise ExamError("LIVE_NOT_HOST", "Ustawienia tej sesji zmienia tylko jej prowadzący.", 403)
        if s["phase"] == "end":
            raise ExamError("LIVE_ENDED", "Ta sesja jest już zakończona.", 409)
        values: Dict[str, Any] = {}
        cfg = dict(s["config"])
        cfg["ranking"] = dict(cfg["ranking"])
        if "guests_allowed" in body:
            values["guests_allowed"] = bool(body["guests_allowed"])
        if "phone_view" in body:
            values["phone_view"] = L.clean_choice(body["phone_view"], L.PHONE_VIEWS, "full", "Widok telefonu")
        if "auto_reveal" in body:
            cfg["auto_reveal"] = bool(body["auto_reveal"])
        ranking = body.get("ranking")
        if isinstance(ranking, Mapping):
            if "mode" in ranking and ranking["mode"] != cfg["ranking"]["mode"]:
                if s["phase"] != "lobby":
                    raise ExamError("LIVE_LOCKED", "Sposób liczenia punktów można zmienić tylko w lobby, przed pierwszym pytaniem.", 409)
                cfg["ranking"]["mode"] = X._choice(ranking["mode"], L.RANK_MODES, "Tryb rankingu")
            if "top_n" in ranking:
                cfg["ranking"]["top_n"] = X._int(ranking["top_n"], "Ile miejsc w rankingu", 1, 20)
            for key in ("show_own_rank", "leaderboard_each"):
                if key in ranking:
                    cfg["ranking"][key] = bool(ranking[key])
        if "question_time_s" in body:
            cfg["question_time_s"] = X._int(body["question_time_s"], "Czas na pytanie (s)", 5, 600)
        if not values and cfg == s["config"]:
            return await load_state(ls, session_id, now)
        await _bump(ls, session_id, now, config_json=S._dumps(cfg), **values)
    return await load_state(ls, session_id, now)


# ---------------------------------------------------------------------------
# Uczestnicy i odpowiedzi
# ---------------------------------------------------------------------------


async def participant_by_judge(ls: LiveStore, session_id: str, judge_id: str) -> Optional[Dict[str, Any]]:
    t = ls.t.participants
    raw = await ls.database.fetch_one(select(t).where((t.c.session_id == session_id) & (t.c.judge_id == str(judge_id))))
    return _row(raw) if raw else None


async def participant_by_guest(ls: LiveStore, session_id: str, guest_token: str) -> Optional[Dict[str, Any]]:
    if not guest_token:
        return None
    t = ls.t.participants
    raw = await ls.database.fetch_one(select(t).where((t.c.session_id == session_id) & (t.c.guest_token == str(guest_token))))
    return _row(raw) if raw else None


async def _admit(ls: LiveStore, s: Mapping[str, Any], now: datetime, *, kind: str, name: str,
                 judge_id: Optional[str] = None, guest_token: Optional[str] = None) -> Dict[str, Any]:
    pid = str(uuid.uuid4())
    async with lock_for(s["id"]):
        fresh = await session_row(ls, s["id"])
        if fresh["phase"] == "end":
            raise ExamError("LIVE_ENDED", "Ta sesja jest już zakończona.", 409)
        if judge_id and was_kicked(fresh, judge_id=judge_id):
            raise ExamError("LIVE_KICKED", "Prowadzący usunął Cię z tej sesji.", 403)
        if fresh["config"].get("locked"):
            raise ExamError("LIVE_LOCKED", "Prowadzący zamknął salę - nowe osoby nie mogą już dołączyć.", 409)
        if fresh["phase"] != "lobby" and not fresh["config"]["late_join"]:
            raise ExamError("LIVE_STARTED", "Ta sesja już wystartowała, a prowadzący nie pozwala dołączać po starcie.", 409)
        parts = await _participants(ls, s["id"])
        if len(parts) >= L.MAX_PARTICIPANTS:
            raise ExamError("LIVE_FULL", f"Sesja ma już komplet uczestników ({L.MAX_PARTICIPANTS}).", 409)
        if kind == "guest" and any(p["name"].casefold() == name.casefold() for p in parts):
            raise ExamError("LIVE_NICK_TAKEN", f"Nick „{name}” jest już zajęty w tej sesji. Wybierz inny.", 409)
        await ls.database.execute(insert(ls.t.participants).values(
            id=pid, session_id=s["id"], kind=kind, judge_id=judge_id, name=name, guest_token=guest_token, score=0,
            correct_count=0, answered_count=0, joined_at=now))
        await _bump(ls, s["id"], now)
    t = ls.t.participants
    return _row(await ls.database.fetch_one(select(t).where(t.c.id == pid)))


async def join_user(ls: LiveStore, who: S.Who, ref: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    s = await session_by_ref(ls, ref, now)
    existing = await participant_by_judge(ls, s["id"], who.judge_id)
    if existing:
        return {"session": s, "participant": existing, "rejoined": True}
    name = who.name or f"Sędzia {who.judge_id}"
    return {"session": s, "participant": await _admit(ls, s, now, kind="user", name=name, judge_id=who.judge_id), "rejoined": False}


async def join_guest(ls: LiveStore, ref: Mapping[str, Any], nick: Any, now: datetime) -> Dict[str, Any]:
    s = await session_by_ref(ls, ref, now)
    if not s["guests_allowed"]:
        raise ExamError("LIVE_GUESTS_OFF", "Prowadzący nie włączył dołączania z przeglądarki. "
                        "Zaloguj się w aplikacji BAZA albo poproś prowadzącego o włączenie gości.", 403)
    participant = await _admit(ls, s, now, kind="guest", name=L.clean_nick(nick), guest_token=secrets.token_urlsafe(18))
    return {"session": s, "participant": participant, "rejoined": False}


async def submit_answer(ls: LiveStore, session_id: str, participant_id: str, selected: Any, now: datetime) -> Dict[str, Any]:
    """Przyjmuje odpowiedź, ocenia i liczy punkty. Wynik NIE zdradza poprawności (to dopiero reveal)."""
    async with lock_for(session_id):
        s = await session_row(ls, session_id)
        if s["phase"] == "question" and s["config"]["auto_reveal"] and s["deadline_at"] and now >= s["deadline_at"] + timedelta(seconds=L.ANSWER_GRACE_S):
            await _reveal(ls, s, now)
            s = await session_row(ls, session_id)
        refusal = L.answer_refusal(s["phase"], s["deadline_at"], now, s["config"].get("paused_left") is not None)
        if refusal:
            raise refusal
        t = ls.t.answers
        qid = s["question_ids"][s["q_index"]]
        taken = await ls.database.fetch_one(select(t.c.qid).where(
            (t.c.session_id == session_id) & (t.c.participant_id == participant_id) & (t.c.qid == qid)))
        if taken:
            raise ExamError("LIVE_ALREADY_ANSWERED", "Odpowiedź na to pytanie już wysłałeś(-aś) - nie można jej zmienić.", 409)
        bank = await S.load_bank(ls.exam, s["bank_version"])
        question = bank[qid]
        keys = L.clean_selection(question, selected)
        cfg = s["config"]
        fraction = X.score_question(question, keys, cfg["multi_scoring"])
        elapsed = max(0.0, (now - s["phase_started_at"]).total_seconds() * 1000.0) if s["phase_started_at"] else None
        points = L.speed_points(cfg["ranking"]["mode"], fraction, elapsed, cfg["question_time_s"])
        await ls.database.execute(insert(t).values(
            session_id=session_id, participant_id=participant_id, qid=qid, q_index=s["q_index"],
            selected_json=S._dumps(keys), fraction=float(fraction), points=int(points),
            elapsed_ms=int(elapsed) if elapsed is not None else None, answered_at=now))
        await _bump(ls, session_id, now)
        answered = len(await _answers_for(ls, session_id, s["q_index"]))
        total = len(await _participants(ls, session_id))
        everyone = bool(cfg["auto_reveal"]) and total > 0 and answered >= total
        if everyone:
            await _reveal(ls, await session_row(ls, session_id), now)
    return {"accepted": True, "qid": qid, "answered": answered, "everyone_answered": everyone}


# ---------------------------------------------------------------------------
# Listy i wyniki
# ---------------------------------------------------------------------------


async def hosted_list(ls: LiveStore, who: S.Who, now: datetime) -> Dict[str, Any]:
    t = ls.t.sessions
    rows = await ls.database.fetch_all(select(t).where(t.c.host_id == who.judge_id).order_by(t.c.created_at.desc()).limit(50))
    out = []
    for raw in rows:
        s = _session(raw)
        out.append({"id": s["id"], "title": s["title"], "character": s["character"], "phase": s["phase"],
                    "pin": s["pin"] if L.session_active(s["phase"], s["updated_at"], now) else None,
                    "active": L.session_active(s["phase"], s["updated_at"], now), "q_total": s["q_total"],
                    "created_at": S._iso(s["created_at"]), "ended_at": S._iso(s["ended_at"])})
    return {"sessions": out, "server_now": now.isoformat()}


async def results(ls: LiveStore, who: S.Who, session_id: str, now: datetime) -> Dict[str, Any]:
    s = await session_row(ls, session_id)
    if s["host_id"] != who.judge_id:
        await S.require_manage(who, s["scope"], s.get("province"))
    if s["phase"] != "end":
        raise ExamError("LIVE_NOT_ENDED", "Wyniki będą dostępne po zakończeniu sesji.", 409)
    result = S._loads(s.get("result_json"), {})
    return {"session": {"id": s["id"], "title": s["title"], "character": s["character"], "exam_id": s["exam_id"],
                        "ended_at": S._iso(s["ended_at"])}, "result": result, "server_now": now.isoformat()}
