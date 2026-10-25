"""
Egzamin na żywo (Kahoot-owy) - reguły bez bazy i bez sieci (etap 5, 16.10.2026).

Plan: BAZA/docs/egzamin-z-przepisow-plan.md (sekcja „Na żywo”), kontrakt: BAZA/docs/egzamin-api.md.

Tu leży wszystko, co decyduje, i da się to sprawdzić bez Postgresa i bez gniazd:
  - czyszczenie konfiguracji sesji (quiz szkoleniowy / egzamin na sali),
  - PIN 6 cyfr unikalny wśród aktywnych sesji, nick gościa,
  - maszyna faz: lobby -> question -> reveal -> leaderboard -> end (sterują tylko prowadzący),
  - punkty za szybkość liczone przez serwer, ranking z remisami ex aequo (1, 2, 2, 4),
  - ZAWSZE osobny widok per rola (prowadzący / uczestnik / rzutnik): klucz poprawnych
    odpowiedzi wychodzi dopiero w fazie reveal i później, nigdy w fazie question.

Zasada jak w całym module: ZERO CICHYCH BLOKAD - każda odmowa to `ExamError` z kodem
i zdaniem po polsku.
"""

from __future__ import annotations

import hashlib
import os
import random
import re
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from app import exam_rules as X
from app.exam_rules import ExamError

# ---------------------------------------------------------------------------
# Stałe
# ---------------------------------------------------------------------------

CHARACTERS = ("quiz", "exam")
PHONE_VIEWS = ("full", "tiles")
RANK_MODES = ("speed", "correct")
PHASES = ("lobby", "question", "reveal", "leaderboard", "end")
ROLES = ("host", "player", "projector")

POINTS_MAX = 1000
#: Odpowiedź po terminie przyjmujemy jeszcze tyle sekund (opóźnienie sieci).
ANSWER_GRACE_S = 1.5
MAX_PARTICIPANTS = 400
MAX_QUESTIONS = 100
NICK_MIN, NICK_MAX = 2, 24
#: Sesja bez żadnej zmiany tak długo przestaje być aktywna (PIN wraca do puli).
ACTIVE_TTL_S = 8 * 3600
#: Ile osób wypisujemy w lobby na rzutniku / ile wierszy pełnego rankingu dostaje prowadzący.
LOBBY_NAMES_MAX = 80
FULL_RANKING_MAX = 400
TOP_ROWS_MAX = 25

#: Ekran sali i strona uczestnika żyją w BAZA_web (25.10.2026, styl „Hala nocą”). Tylko www:
#: domena bez www przekierowuje (308), a App Links / Universal Links nie znoszą przekierowań.
WEB_BASE = os.getenv("EXAM_LIVE_WEB_BASE", "https://www.bazapodreka.app").rstrip("/")
#: Krótki adres do przepisania z ekranu (bez https i www).
WEB_SHORT = "bazapodreka.app/sala"


def web_join_url(pin: Optional[str]) -> str:
    """Adres z kodu QR i z linku: `https://www.bazapodreka.app/sala/482913` (bez PIN-u - strona wpisywania)."""
    digits = clean_pin(pin)
    return f"{WEB_BASE}/sala/{digits}" if digits else f"{WEB_BASE}/sala"


def web_projector_url(projector_token: str) -> str:
    """Ekran sali (rzutnik) w BAZA_web. Token rzutnika, nie PIN: PIN widzi cała sala."""
    return f"{WEB_BASE}/sala/ekran/{projector_token}"


def public_key(participant_id: Any) -> str:
    """Stały, jawny klucz osoby dla rzutnika (animacje wbiegania i wyścigu w rankingu).
    Skrót zamiast numeru uczestnika: z klucza nie da się odpowiadać ani podszyć."""
    return hashlib.sha1(f"live:{participant_id}".encode("utf-8")).hexdigest()[:12]


DEFAULT_LIVE_CONFIG: Dict[str, Any] = {
    "question_time_s": 20,
    "multi_scoring": "all_or_nothing",
    "ranking": {"mode": "speed", "top_n": 5, "show_own_rank": True, "leaderboard_each": True},
    "auto_reveal": True,
    "late_join": True,
    "pass_percent": None,
}


# ---------------------------------------------------------------------------
# Konfiguracja
# ---------------------------------------------------------------------------


def clean_live_config(raw: Optional[Mapping[str, Any]], character: str) -> Dict[str, Any]:
    """Pełna, sprawdzona konfiguracja. Egzamin na sali: punkty za poprawność (bez szybkości),
    próg zaliczenia (domyślnie 75%), bez dołączania po starcie."""
    raw = dict(raw or {})
    exam = character == "exam"
    cfg: Dict[str, Any] = {
        "question_time_s": X._int(raw.get("question_time_s", 30 if exam else 20), "Czas na pytanie (s)", 5, 600),
        "multi_scoring": X._choice(raw.get("multi_scoring", "all_or_nothing"), X.MULTI_SCORING, "Punktacja wielokrotnego wyboru"),
        "auto_reveal": bool(raw.get("auto_reveal", True)),
        "late_join": bool(raw.get("late_join", not exam)),
        # Ta sama opcja co w egzaminie indywidualnym: domyślnie wolno zaznaczyć kilka, z podpowiedzią = jedna.
        "single_hint_all": bool(raw.get("single_hint_all")),
        "single_hint_ids": X._strings(raw.get("single_hint_ids")),
    }
    rank = raw.get("ranking") if isinstance(raw.get("ranking"), Mapping) else {}
    cfg["ranking"] = {
        "mode": X._choice(rank.get("mode", "correct" if exam else "speed"), RANK_MODES, "Tryb rankingu"),
        "top_n": X._int(rank.get("top_n", 5), "Ile miejsc w rankingu", 1, 20),
        "show_own_rank": bool(rank.get("show_own_rank", True)),
        "leaderboard_each": bool(rank.get("leaderboard_each", True)),
    }
    if exam:
        cfg["pass_percent"] = float(X._int(raw.get("pass_percent", 75), "Próg zaliczenia (%)", 0, 100))
    else:
        cfg["pass_percent"] = None
    return cfg


def clean_choice(raw: Any, allowed: Sequence[str], default: str, label: str) -> str:
    return X._choice(raw if raw not in (None, "") else default, allowed, label)


def clean_title(raw: Any, character: str) -> str:
    text = re.sub(r"\s+", " ", str(raw or "")).strip()
    if not text:
        return "Egzamin na sali" if character == "exam" else "Quiz szkoleniowy"
    if len(text) > 120:
        raise ExamError("BAD_CONFIG", "Tytuł sesji może mieć najwyżej 120 znaków.")
    return text


# ---------------------------------------------------------------------------
# PIN i nick
# ---------------------------------------------------------------------------


def generate_pin(taken: Set[str], rng: Optional[random.Random] = None) -> str:
    """6 cyfr (bez zera na początku), nieużywany przez żadną AKTYWNĄ sesję."""
    rng = rng or random.SystemRandom()
    for _ in range(200):
        pin = str(rng.randrange(100000, 1000000))
        if pin not in taken:
            return pin
    raise ExamError("LIVE_PIN_EXHAUSTED", "Nie udało się wylosować wolnego kodu PIN. Spróbuj za chwilę.", 503)


def clean_pin(raw: Any) -> str:
    return re.sub(r"\D", "", str(raw or ""))


def clean_nick(raw: Any) -> str:
    text = re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f<>]", "", str(raw or ""))).strip()
    if len(text) < NICK_MIN:
        raise ExamError("LIVE_BAD_NICK", f"Wpisz nick (co najmniej {NICK_MIN} znaki).")
    if len(text) > NICK_MAX:
        raise ExamError("LIVE_BAD_NICK", f"Nick może mieć najwyżej {NICK_MAX} znaków.")
    return text


def session_active(phase: str, updated_at: Optional[datetime], now: datetime) -> bool:
    if phase == "end":
        return False
    if updated_at is None:
        return True
    return (now - X._aware(updated_at)).total_seconds() < ACTIVE_TTL_S


# ---------------------------------------------------------------------------
# Maszyna faz
# ---------------------------------------------------------------------------


def next_phase(phase: str, q_index: int, q_total: int, leaderboard_each: bool) -> Tuple[str, int]:
    """Następna faza po „dalej" prowadzącego. Błąd z wyjaśnieniem, gdy to niemożliwe.

    lobby -> question(0) -> reveal -> leaderboard -> question(1) ... -> leaderboard -> end.
    Z `leaderboard_each=False` ranking pokazujemy tylko po ostatnim pytaniu."""
    if phase == "lobby":
        if q_total < 1:
            raise ExamError("LIVE_NO_QUESTIONS", "Sesja nie ma żadnych pytań, więc nie ma czego zaczynać.", 409)
        return "question", 0
    if phase == "question":
        return "reveal", q_index
    if phase == "reveal":
        last = q_index >= q_total - 1
        if last or leaderboard_each:
            return "leaderboard", q_index
        return "question", q_index + 1
    if phase == "leaderboard":
        if q_index >= q_total - 1:
            return "end", q_index
        return "question", q_index + 1
    raise ExamError("LIVE_ENDED", "Ta sesja jest już zakończona.", 409)


#: Polecenia pilota prowadzącego poza fazami (17.10.2026); lista idzie w `session.controls`.
PILOT_ACTIONS = ("pause", "resume", "extend", "skip", "lock", "unlock", "unveil", "unveil_all")
CONTROLS = ("pause", "resume", "extend", "skip", "lock", "unlock", "kick", "unveil")
EXTEND_DEFAULT_S = 15
#: Ceremonia wyników po zakończeniu (25.10.2026): prowadzący odsłania kolejne etapy na rzutniku
#: (dalsze miejsca od końca, 3., 2., 1., pełna tabela). Serwer trzyma sam numer kroku w `config_json`;
#: etapy liczy ekran z rankingu. `unveil_all` = od razu pełna tabela.
UNVEIL_ACTIONS = ("unveil", "unveil_all")
UNVEIL_MAX = 9


def pilot_refusal(action: str, phase: str, paused: bool) -> Optional[ExamError]:
    """Czemu polecenie pilota nie działa teraz (zero cichych blokad) albo None."""
    if action in UNVEIL_ACTIONS:
        if phase != "end":
            return ExamError("LIVE_BAD_PHASE", "Wyniki odsłania się po zakończeniu sesji.", 409)
        return None
    if phase == "end":
        return ExamError("LIVE_ENDED", "Ta sesja jest już zakończona.", 409)
    if action in ("lock", "unlock"):
        return None
    if phase != "question":
        return ExamError("LIVE_BAD_PHASE", "To polecenie działa w trakcie pytania.", 409)
    if action == "pause" and paused:
        return ExamError("LIVE_PAUSED", "Pytanie jest już wstrzymane.", 409)
    if action == "resume" and not paused:
        return ExamError("LIVE_NOT_PAUSED", "Pytanie nie jest wstrzymane.", 409)
    return None


def control_action(action: str, phase: str) -> str:
    """Normalizacja akcji prowadzącego: next | reveal | end."""
    if action not in ("next", "reveal", "end"):
        raise ExamError("LIVE_BAD_ACTION", "Nieznana akcja. Dozwolone: next, reveal, end, pause, resume, extend, skip, lock, unlock, unveil, unveil_all.")
    if phase == "end":
        raise ExamError("LIVE_ENDED", "Ta sesja jest już zakończona.", 409)
    if action == "reveal" and phase != "question":
        raise ExamError("LIVE_BAD_PHASE", "Odpowiedzi można odsłonić tylko w trakcie pytania.", 409)
    return action


# ---------------------------------------------------------------------------
# Ocena i punkty
# ---------------------------------------------------------------------------


def speed_points(mode: str, fraction: float, elapsed_ms: Optional[float], limit_s: float) -> int:
    """Punkty za pytanie. `speed`: od 1000 (natychmiast) do 500 (ostatnia chwila), razy ułamek
    poprawności. `correct`: 1000 razy ułamek, bez względu na czas. Zła odpowiedź = 0."""
    if fraction <= 0:
        return 0
    if mode == "correct" or elapsed_ms is None or limit_s <= 0:
        return int(round(POINTS_MAX * fraction))
    ratio = min(1.0, max(0.0, elapsed_ms / (limit_s * 1000.0)))
    return int(round(POINTS_MAX * fraction * (1.0 - 0.5 * ratio)))


def clean_selection(question: Mapping[str, Any], selected: Any, config: Optional[Mapping[str, Any]] = None) -> List[str]:
    keys = [str(k).strip() for k in (selected or []) if str(k).strip()]
    keys = list(dict.fromkeys(keys))
    if not keys:
        raise ExamError("LIVE_EMPTY_ANSWER", "Zaznacz odpowiedź, zanim ją wyślesz.")
    valid = {a["key"] for a in question.get("answers") or []}
    bad = [k for k in keys if k not in valid]
    if bad:
        raise ExamError("LIVE_BAD_KEY", f"Nie ma takiej odpowiedzi: {', '.join(bad)}.")
    if len(keys) > 1 and X.single_hint(config or {}, question):
        raise ExamError("LIVE_SINGLE_ONLY", "To pytanie ma jedną poprawną odpowiedź - zaznacz tylko jedną.")
    return keys


def answer_refusal(phase: str, deadline: Optional[datetime], now: datetime, paused: bool = False) -> Optional[ExamError]:
    if phase == "question" and paused:
        return ExamError("LIVE_PAUSED", "Prowadzący wstrzymał pytanie. Odpowiesz, gdy czas ruszy.", 409)
    if phase != "question":
        return ExamError("LIVE_NOT_ACCEPTING", "Teraz nie przyjmujemy odpowiedzi - poczekaj na następne pytanie.", 409)
    if deadline is not None and (now - X._aware(deadline)).total_seconds() > ANSWER_GRACE_S:
        return ExamError("LIVE_TIME_UP", "Czas na to pytanie minął.", 409)
    return None


# ---------------------------------------------------------------------------
# Ranking (remisy ex aequo gęsto: 1, 2, 2, 3 - decyzja 25.10.2026 dla egzaminów z przepisów)
# ---------------------------------------------------------------------------


def rank_participants(participants: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Równe punkty = wspólne miejsce, następne bez przeskoku (1, 2, 2, 3), jak w rankingach
    egzaminów (`exam_report_rules.place_ex_aequo`). W remisie kolejność wierszy: nazwisko."""
    ordered = sorted(participants, key=lambda p: (-int(p.get("score") or 0), str(p.get("name") or "").lower()))
    out: List[Dict[str, Any]] = []
    prev_score: Optional[int] = None
    place = 0
    for p in ordered:
        score = int(p.get("score") or 0)
        if score != prev_score:
            place += 1
            prev_score = score
        out.append({"participant_id": p["id"], "place": place, "name": p.get("name"), "kind": p.get("kind"),
                    "score": score, "correct": int(p.get("correct_count") or 0)})
    return out


def distribution(question: Mapping[str, Any], answers: Mapping[str, Mapping[str, Any]], participants_n: int) -> Dict[str, Any]:
    """Rozkład odpowiedzi do fazy reveal: ile osób wybrało każdy klawisz i ile nie odpowiedziało."""
    counts = {a["key"]: 0 for a in question.get("answers") or []}
    correct = 0
    for row in answers.values():
        for key in row.get("selected") or []:
            if key in counts:
                counts[key] += 1
        if float(row.get("fraction") or 0) >= 1.0:
            correct += 1
    return {"distribution": counts, "answered": len(answers), "skipped": max(0, participants_n - len(answers)),
            "correct_count": correct}


# ---------------------------------------------------------------------------
# Wynik trwały (zapisywany przy zakończeniu sesji)
# ---------------------------------------------------------------------------


def build_result(
    *, character: str, pass_percent: Optional[float], question_ids: Sequence[str],
    bank: Mapping[str, Mapping[str, Any]], participants: Sequence[Mapping[str, Any]],
    answers: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    total_q = len(question_ids)
    by_pid: Dict[str, List[Mapping[str, Any]]] = {}
    by_q: Dict[str, List[Mapping[str, Any]]] = {}
    for row in answers:
        by_pid.setdefault(row["participant_id"], []).append(row)
        by_q.setdefault(row["qid"], []).append(row)
    ranked = {r["participant_id"]: r for r in rank_participants(participants)}
    ranking = []
    for p in participants:
        rows = by_pid.get(p["id"], [])
        fraction_sum = sum(float(r.get("fraction") or 0) for r in rows)
        percent = round(100.0 * fraction_sum / total_q, 1) if total_q else 0.0
        timed = [int(r["elapsed_ms"]) for r in rows if r.get("elapsed_ms") is not None]
        ranking.append({
            "participant_id": p["id"], "judge_id": p.get("judge_id"), "name": p.get("name"), "kind": p.get("kind"),
            "place": ranked[p["id"]]["place"], "score": int(p.get("score") or 0),
            "correct": sum(1 for r in rows if float(r.get("fraction") or 0) >= 1.0),
            "answered": len(rows), "percent": percent,
            #: Łączny czas namysłu nad oddanymi odpowiedziami (ms); None = serwer nie zmierzył żadnej.
            "time_ms": sum(timed) if timed else None,
            "passed": (percent >= float(pass_percent)) if (character == "exam" and pass_percent is not None) else None,
        })
    # W remisie szybszy wyżej (sam wiersz; miejsce zostaje wspólne).
    ranking.sort(key=lambda e: (e["place"], e["time_ms"] if e["time_ms"] is not None else 1 << 62, str(e["name"] or "").lower()))
    questions = []
    n = len(participants)
    for qid in question_ids:
        q = bank.get(qid) or {}
        rows = by_q.get(qid, [])
        counts = {a["key"]: 0 for a in q.get("answers") or []}
        for r in rows:
            for key in r.get("selected") or []:
                if key in counts:
                    counts[key] += 1
        questions.append({
            "qid": qid, "number": q.get("number"), "answered": len(rows), "skipped": max(0, n - len(rows)),
            "correct_rate": round(sum(1 for r in rows if float(r.get("fraction") or 0) >= 1.0) / n, 3) if n else None,
            "distribution": counts, "correct_keys": sorted(X.correct_keys(q)) if q else [],
        })
    return {
        "character": character, "pass_percent": pass_percent, "question_count": total_q, "participants": n,
        "passed": sum(1 for e in ranking if e["passed"]) if character == "exam" else None,
        "ranking": ranking, "questions": questions,
    }


# ---------------------------------------------------------------------------
# Widoki per rola
# ---------------------------------------------------------------------------


def _iso(value: Any) -> Optional[str]:
    value = X._aware(value) if value else None
    return value.isoformat() if value else None


def _seconds_left(deadline: Any, now: datetime) -> Optional[float]:
    if not deadline:
        return None
    return round(max(0.0, (X._aware(deadline) - now).total_seconds()), 2)


def _session_block(state: Mapping[str, Any], role: str) -> Dict[str, Any]:
    s = state["session"]
    cfg = s["config"]
    block = {
        "id": s["id"], "title": s["title"], "character": s["character"], "phase": s["phase"],
        "q_index": s["q_index"], "q_total": s["q_total"], "phone_view": s["phone_view"],
        "guests_allowed": bool(s["guests_allowed"]), "pass_percent": cfg.get("pass_percent"),
        "question_time_s": cfg["question_time_s"], "ranking": dict(cfg["ranking"]),
        "auto_reveal": cfg["auto_reveal"], "late_join": cfg["late_join"],
        "joined": len(state["participants"]), "scope": s.get("scope"), "province": s.get("province"),
        "started_at": _iso(s.get("phase_started_at")),
        "paused": s["phase"] == "question" and cfg.get("paused_left") is not None,
        "locked": bool(cfg.get("locked")),
    }
    if s["phase"] == "end":
        block["unveil"] = int(cfg.get("unveil") or 0)
    if role == "host":
        block["controls"] = list(CONTROLS)
        nq = state.get("next_question")
        block["next"] = ({"index": s["q_index"] + 1, "number": nq.get("number"), "rule": nq.get("rule"), "kind": nq.get("kind"),
                          "multi": not X.single_hint(cfg, nq), "text": nq.get("text")} if nq else None)
    if role in ("host", "projector"):
        block["pin"] = s["pin"]
        block["links"] = dict(state.get("links") or {})
    return block


def _public_question(q: Mapping[str, Any], *, tiles: bool, cfg: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    pub = X.exam_question(cfg or {}, q)
    if tiles:
        # Same kafle: telefon nie dostaje treści pytania ani odpowiedzi, tylko klucze (kolor/kształt).
        return {"qid": pub["qid"], "multi": pub["multi"], "single_hint": pub["single_hint"], "tiles_only": True,
                "answers": [{"key": a["key"]} for a in pub["answers"]]}
    return pub


def _question_block(state: Mapping[str, Any], role: str, now: datetime) -> Optional[Dict[str, Any]]:
    s = state["session"]
    q = state.get("question")
    if not q or s["phase"] not in ("question", "reveal"):
        return None
    tiles = role == "player" and s["phone_view"] == "tiles" and s["phase"] == "question"
    block = _public_question(q, tiles=tiles, cfg=s["config"])
    block["index"] = s["q_index"]
    block["total"] = s["q_total"]
    block["time_s"] = s["config"]["question_time_s"]
    block["deadline_at"] = _iso(s.get("deadline_at"))
    block["seconds_left"] = _seconds_left(s.get("deadline_at"), now) if s["phase"] == "question" else 0.0
    paused_left = s["config"].get("paused_left")
    if s["phase"] == "question" and paused_left is not None:
        # Pauza: zegar zamrożony, termin pusty (przesuwa się przy wznowieniu).
        block["paused"] = True
        block["seconds_left"] = round(float(paused_left), 2)
    return block


def _reveal_block(state: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    s = state["session"]
    q = state.get("question")
    if s["phase"] != "reveal" or not q:
        return None
    dist = distribution(q, state["answers"], len(state["participants"]))
    block: Dict[str, Any] = {"correct_keys": sorted(X.correct_keys(q)), **dist}
    if q.get("curiosity"):
        block["curiosity"] = q["curiosity"]
    return block


def _previous_places(state: Mapping[str, Any]) -> Dict[str, Dict[str, int]]:
    """Miejsca i punkty sprzed bieżącego pytania (wyścig pasków na rzutniku: kto kogo wyprzedził).
    `last_points` = punkty za pytanie, po którym stoi ranking; bez nich wszyscy stoją w miejscu."""
    gained = state.get("last_points") or {}
    before = [{**p, "score": int(p.get("score") or 0) - int(gained.get(p["id"]) or 0)} for p in state["participants"]]
    return {r["participant_id"]: {"place": r["place"], "score": r["score"], "gained": int(gained.get(r["participant_id"]) or 0)}
            for r in rank_participants(before)}


def streaks_of(answers: Sequence[Mapping[str, Any]], q_index: int) -> Dict[str, int]:
    """Seria pełnych trafień każdego uczestnika: kolejne pytania (q_index, q_index-1, ...) z ułamkiem 1.
    Brak odpowiedzi albo odpowiedź niepełna przerywa serię."""
    hit: Dict[str, Set[int]] = {}
    for a in answers:
        if float(a.get("fraction") or 0) >= 1.0:
            hit.setdefault(str(a["participant_id"]), set()).add(int(a.get("q_index") or 0))
    out: Dict[str, int] = {}
    for pid, idx in hit.items():
        n = 0
        while (q_index - n) in idx:
            n += 1
        if n:
            out[pid] = n
    return out


def _board(state: Mapping[str, Any], role: str, viewer: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    ranked = rank_participants(state["participants"])
    cfg = state["session"]["config"]["ranking"]
    top = [dict(r) for r in ranked if r["place"] <= cfg["top_n"]][:TOP_ROWS_MAX]
    prev = _previous_places(state)
    streaks = state.get("streaks") or {}
    for row in top:
        before = prev.get(row["participant_id"]) or {}
        row["key"] = public_key(row["participant_id"])
        row["prev_place"] = before.get("place", row["place"])
        row["prev_score"] = before.get("score", row["score"])
        row["gained"] = before.get("gained", 0)
        row["streak"] = int(streaks.get(row["participant_id"]) or 0)
    board: Dict[str, Any] = {"mode": cfg["mode"], "top": top, "total_players": len(ranked)}
    if role == "host":
        board["full"] = [{**r, "key": public_key(r["participant_id"]), "streak": int(streaks.get(r["participant_id"]) or 0)}
                         for r in ranked[:FULL_RANKING_MAX]]
    if viewer is not None:
        mine = next((r for r in ranked if r["participant_id"] == viewer["id"]), None)
        board["you"] = ({"place": mine["place"], "score": mine["score"], "name": mine["name"]}
                        if mine and cfg["show_own_rank"] else None)
        for row in top:
            row["you"] = row["participant_id"] == viewer["id"]
    if role != "host":
        for row in top:
            row.pop("participant_id", None)
    return board


def _me_block(state: Mapping[str, Any], viewer: Mapping[str, Any]) -> Dict[str, Any]:
    s = state["session"]
    phase = s["phase"]
    mine = state["answers"].get(viewer["id"])
    block: Dict[str, Any] = {
        "participant_id": viewer["id"], "key": public_key(viewer["id"]), "name": viewer["name"], "kind": viewer["kind"],
        "answered": mine is not None and phase in ("question", "reveal"),
    }
    if mine is not None and phase in ("question", "reveal"):
        block["selected"] = list(mine.get("selected") or [])
    if phase in ("reveal", "leaderboard", "end"):
        ranked = next((r for r in rank_participants(state["participants"]) if r["participant_id"] == viewer["id"]), None)
        block["total"] = int(viewer.get("score") or 0)
        if ranked and s["config"]["ranking"]["show_own_rank"]:
            block["place"] = ranked["place"]
        if phase == "reveal":
            fraction = float(mine.get("fraction") or 0) if mine is not None else 0.0
            block["correct"] = (fraction >= 1.0) if mine is not None else None
            block["partial"] = 0 < fraction < 1.0
            block["points"] = int(mine.get("points") or 0) if mine is not None else 0
    return block


def _final_for(state: Mapping[str, Any], viewer: Optional[Mapping[str, Any]], role: str) -> Optional[Dict[str, Any]]:
    result = state.get("result")
    if state["session"]["phase"] != "end" or not result:
        return None
    out: Dict[str, Any] = {"character": result["character"], "pass_percent": result["pass_percent"],
                           "question_count": result["question_count"], "participants": result["participants"],
                           "passed": result.get("passed")}
    if viewer is not None:
        mine = next((e for e in result["ranking"] if e["participant_id"] == viewer["id"]), None)
        if mine:
            out["you"] = {k: mine[k] for k in ("place", "score", "correct", "answered", "percent", "passed")}
    if role == "host":
        out["ranking"] = result["ranking"][:FULL_RANKING_MAX]
        out["questions"] = result["questions"]
    if role == "projector":
        # Pełna tabela ceremonii: wszyscy, bez numerów uczestników i sędziów (barwa koszulki z `key`).
        out["board"] = [{"key": public_key(e["participant_id"]), "place": e["place"], "name": e["name"], "kind": e["kind"],
                         "score": e["score"], "correct": e["correct"], "answered": e["answered"], "percent": e["percent"],
                         "passed": e["passed"], "time_ms": e.get("time_ms")}
                        for e in result["ranking"][:FULL_RANKING_MAX]]
    return out


def view_for(role: str, state: Mapping[str, Any], viewer: Optional[Mapping[str, Any]], now: datetime) -> Dict[str, Any]:
    """Migawka dla jednej roli. `state` = wynik `load_state` (z pełnym pytaniem i kluczami),
    ale do widoku trafia wyłącznie to, co dana rola i faza mają prawo zobaczyć."""
    if role not in ROLES:
        raise ExamError("LIVE_BAD_ROLE", "Nieznana rola widoku.")
    s = state["session"]
    phase = s["phase"]
    view: Dict[str, Any] = {
        "v": 1, "rev": s["rev"], "server_now": now.isoformat(), "role": role,
        "session": _session_block(state, role),
        "question": _question_block(state, role, now),
        "reveal": _reveal_block(state),
        "leaderboard": None, "final": None, "me": None,
    }
    if phase in ("question", "reveal"):
        view["session"]["answered"] = len(state["answers"])
    if phase in ("leaderboard", "end"):
        view["leaderboard"] = _board(state, role, viewer if role == "player" else None)
    if phase == "end":
        view["final"] = _final_for(state, viewer if role == "player" else None, role)
    if role == "player" and viewer is not None:
        view["me"] = _me_block(state, viewer)
    parts = state["participants"]
    if role == "host":
        answered_ids = set(state["answers"]) if phase in ("question", "reveal") else set()
        ranked = {r["participant_id"]: r for r in rank_participants(parts)}
        view["participants"] = [
            {"id": p["id"], "key": public_key(p["id"]), "name": p["name"], "kind": p["kind"], "answered": p["id"] in answered_ids,
             "score": int(p.get("score") or 0),
             "place": ranked[p["id"]]["place"] if phase not in ("lobby", "question") else None}
            for p in parts[:FULL_RANKING_MAX]]
    elif role == "projector" and phase == "lobby":
        # Najnowsi na końcu listy: przy tłumie rzutnik pokazuje tych, którzy właśnie wbiegli.
        view["participants"] = [{"key": public_key(p["id"]), "name": p["name"], "kind": p["kind"]}
                                for p in parts[-LOBBY_NAMES_MAX:]]
    elif role == "projector" and phase == "question":
        # Pas żetonów „kto oddał” pod pytaniem: sama obecność odpowiedzi, bez treści i bez poprawności.
        answered_ids = set(state["answers"])
        view["participants"] = [{"key": public_key(p["id"]), "name": p["name"], "kind": p["kind"], "answered": p["id"] in answered_ids}
                                for p in parts[:LOBBY_NAMES_MAX]]
    return view
