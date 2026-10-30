"""
Egzamin na komputerze (BAZA_web /egzamin, 24.10.2026) - reguły bez bazy (moduł-liść).

Strona w przeglądarce pisze ZWYKŁE podejście egzaminu (`exam_attempts`), tylko z innego
urządzenia (`device_id = "web:<przeglądarka>"`). Tu jest to, czego telefon nie miał:

  - sygnały ochrony z przeglądarki i telefonu-strażnika -> zapis w `exam_events`,
  - liczenie naruszeń i reakcja egzaminu (`anti.web`: zapis / ostrzeżenie / oddanie po N),
  - flagi rytmu (czasy na pytanie nienaturalne) i mapy kliknięć poza pytaniem,
  - oś zdarzeń karty podejścia dla komisji: `events:[{t_ms, kind, label, detail, ...}]`, `flags:[str]`.

Zapis zdarzeń (bez nowych rodzajów w progach rzetelności):
  - wyjście z pełnego ekranu / zmiana karty / utrata fokusu -> `app_background` z `detail.source="web"`
    (liczy się do rzetelności jak wyjście z aplikacji),
  - PrtScn -> `screenshot` z `detail.source="web"`,
  - reszta -> `web_signal` z `detail.signal` (devtools, druga sesja, strażnik, blokady, kliknięcia).
Naruszenie liczone do reakcji ma `detail.counted = true`.
"""
from __future__ import annotations

import statistics
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from app.exam_rules import DEFAULT_WEB, clean_web

#: Sygnały przeglądarki, które są naruszeniem (liczą się do reakcji egzaminu).
LEAVE_SIGNALS = ("fullscreen_exit", "tab_hidden", "window_blur")
VIOLATION_SIGNALS = LEAVE_SIGNALS + ("printscreen", "devtools", "second_session", "guard_left", "guard_lost")
#: Sygnały tylko do zapisu (próby zablokowane w przeglądarce, mapa kliknięć).
QUIET_SIGNALS = ("copy", "paste", "cut", "context_menu", "print", "select_all", "click_outside", "guard_back", "resume")
CLIENT_SIGNALS = VIOLATION_SIGNALS + QUIET_SIGNALS

LABELS: Dict[str, str] = {
    "fullscreen_exit": "Wyjście z pełnego ekranu",
    "tab_hidden": "Zmiana karty albo zminimalizowanie okna",
    "window_blur": "Przejście do innego okna",
    "printscreen": "Klawisz Print Screen",
    "devtools": "Narzędzia deweloperskie przeglądarki",
    "second_session": "Druga sesja egzaminu na tym koncie",
    "guard_left": "Telefon-strażnik wyszedł z aplikacji",
    "guard_lost": "Telefon-strażnik przestał się odzywać",
    "guard_back": "Telefon-strażnik wrócił",
    "copy": "Próba kopiowania (zablokowana)",
    "cut": "Próba wycięcia (zablokowana)",
    "paste": "Próba wklejenia (zablokowana)",
    "context_menu": "Prawy przycisk myszy (zablokowany)",
    "print": "Próba wydruku (zablokowana)",
    "select_all": "Zaznacz wszystko (zablokowane)",
    "click_outside": "Kliknięcia poza pytaniem",
    "resume": "Powrót do egzaminu",
    "app_background": "Wyjście z aplikacji",
    "screenshot": "Zrzut ekranu",
    "time_flag": "Flaga czasu odpowiedzi",
    "device_change": "Próba wznowienia na innym urządzeniu",
    "similarity": "Podobne błędy u innej osoby",
    "room_code": "Kod sali",
    "forced_submit": "Arkusz oddany po naruszeniach",
}

#: Flagi podejścia (lista napisów dla komisji). Kolejność = waga.
FLAG_LABELS: Dict[str, str] = {
    "auto_submitted": "Oddany automatycznie po naruszeniach",
    "second_session": "Druga sesja na tym koncie",
    "devtools": "Otwarte narzędzia deweloperskie",
    "printscreen": "Print Screen w trakcie",
    "guard_left": "Telefon-strażnik opuścił aplikację",
    "guard_lost": "Telefon-strażnik zamilkł",
    "left_often": "Częste wyjścia z egzaminu (3+)",
    "long_absence": "Długa nieobecność (30 s+)",
    "rhythm_uniform": "Nienaturalnie równy rytm odpowiedzi",
    "rhythm_rapid": "Większość odpowiedzi szybciej niż w 3 s",
    "rhythm_spike": "Nagłe długie zawieszenia przed odpowiedzią",
    "clicks_outside": "Dużo kliknięć poza pytaniem",
    "blocked_attempts": "Wiele prób kopiowania/wklejania",
}

GUARD_SILENCE_S = 25.0
SESSION_STALE_S = 25.0
CLICKS_FLAG_MIN = 25
BLOCKED_FLAG_MIN = 5
LONG_ABSENCE_S = 30.0
MAX_CLIENT_EVENTS = 40


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def web_policy(config: Mapping[str, Any]) -> Dict[str, Any]:
    """`anti.web` egzaminu; stary egzamin bez pola albo z błędną wartością = domyślne."""
    raw = (config.get("anti") or {}).get("web") if isinstance(config, Mapping) else None
    try:
        return clean_web(raw)
    except Exception:  # noqa: BLE001 - zapisany zły kształt nie może zablokować egzaminu
        return dict(DEFAULT_WEB)


def record_shape(signal: str, detail: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Sygnał z przeglądarki/strażnika -> `{kind, detail, counted}`; nieznany = None.

    Do `exam_events` trafiają WYŁĄCZNIE naruszenia (oś komisji liczy każde zdarzenie poza
    `resume/room_code/time_flag/similarity/device_change` jako naruszenie). Sygnały ciche
    (`counted: False`) zbiera sesja w `quiet_json` i wracają do komisji jako flagi."""
    signal = _s(signal)
    if signal not in CLIENT_SIGNALS:
        return None
    clean: Dict[str, Any] = {}
    for key, value in (detail or {}).items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            clean[str(key)[:40]] = value if not isinstance(value, str) else value[:200]
        elif isinstance(value, Mapping) and key == "zones":
            clean["zones"] = {str(k)[:20]: int(v) for k, v in list(value.items())[:12] if isinstance(v, (int, float))}
    if signal not in VIOLATION_SIGNALS:
        return {"kind": None, "detail": clean, "counted": False, "signal": signal}
    clean.update(source="web", signal=signal, counted=True)
    if signal in LEAVE_SIGNALS:
        clean["reason"] = signal
        return {"kind": "app_background", "detail": clean, "counted": True, "signal": signal}
    if signal == "printscreen":
        return {"kind": "screenshot", "detail": clean, "counted": True, "signal": signal}
    return {"kind": "web_signal", "detail": clean, "counted": True, "signal": signal}


def merge_quiet(quiet: Mapping[str, Any], signal: str, detail: Mapping[str, Any]) -> Dict[str, Any]:
    """Licznik sygnałów cichych sesji: `{counts:{copy:n,...}, clicks:n, zones:{strefa:n}}`."""
    out = {"counts": dict(quiet.get("counts") or {}), "clicks": int(quiet.get("clicks") or 0), "zones": dict(quiet.get("zones") or {}),
           "longest_s": float(quiet.get("longest_s") or 0)}
    if signal == "resume":
        # Powrót niesie czas nieobecności - najdłuższa przerwa daje flagę „długa nieobecność".
        try:
            out["longest_s"] = max(out["longest_s"], float(detail.get("seconds") or 0))
        except (TypeError, ValueError):
            pass
    if signal == "click_outside":
        try:
            n = max(1, min(500, int(detail.get("count") or 1)))
        except (TypeError, ValueError):
            n = 1
        out["clicks"] += n
        for zone, value in (detail.get("zones") or {}).items():
            if isinstance(value, (int, float)):
                out["zones"][str(zone)[:20]] = int(out["zones"].get(str(zone)[:20], 0)) + int(value)
    else:
        out["counts"][signal] = int(out["counts"].get(signal, 0)) + 1
    return out


def decide(policy: Mapping[str, Any], violations: int, new: int) -> Dict[str, Any]:
    """Reakcja po `new` nowych naruszeniach (razem `violations`). Zwraca opis dla strony."""
    reaction = policy.get("reaction") or DEFAULT_WEB["reaction"]
    after = int(policy.get("submit_after") or DEFAULT_WEB["submit_after"])
    left = max(0, after - violations) if reaction == "submit" else None
    out: Dict[str, Any] = {"reaction": reaction, "violations": violations, "submit_after": after if reaction == "submit" else None,
                           "left": left, "action": "none", "message": None}
    if new <= 0:
        return out
    if reaction == "log":
        out.update(action="logged")
    elif reaction == "submit" and violations >= after:
        out.update(action="submitted", message=f"Egzamin został oddany: {violations} naruszeń przy limicie {after}. "
                                               "Odpowiedzi udzielone do tej chwili się liczą, komisja widzi przebieg.")
    else:
        tail = (f" Zostało {left} - przy {after}. arkusz odda się sam." if reaction == "submit" and left is not None else "")
        out.update(action="warned", message="To naruszenie zapisało się w przebiegu egzaminu i zobaczy je komisja." + tail)
    return out


def is_counted(event: Mapping[str, Any]) -> bool:
    """Naruszenie widoczne dla zdającego (liczba): wyjścia, zrzuty, zmiana urządzenia i liczone sygnały WWW."""
    kind = _s(event.get("kind"))
    detail = event.get("detail") if isinstance(event.get("detail"), Mapping) else {}
    if kind in ("app_background", "screenshot", "device_change"):
        return True
    return kind == "web_signal" and bool(detail.get("counted"))


def violation_count(events: Iterable[Mapping[str, Any]]) -> int:
    return sum(1 for e in events if is_counted(e))


def _event_name(event: Mapping[str, Any]) -> str:
    kind = _s(event.get("kind"))
    detail = event.get("detail") if isinstance(event.get("detail"), Mapping) else {}
    if detail.get("source") == "web" and detail.get("signal"):
        return _s(detail.get("signal"))
    if kind == "web_signal":
        return _s(detail.get("signal")) or kind
    return kind


def _at(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    text = _s(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def timeline_events(events: Sequence[Mapping[str, Any]], started_at: Any) -> List[Dict[str, Any]]:
    """Zdarzenia karty z `t_ms` (od startu podejścia), `label` po polsku i `counted`. Pola dawne zostają."""
    start = _at(started_at)
    out = []
    for e in label_events(events):
        at = _at(e.get("at"))
        t_ms = int((at - start).total_seconds() * 1000) if at and start else None
        out.append({**e, "t_ms": max(0, t_ms) if t_ms is not None else None, "counted": is_counted(e)})
    return out


def rhythm_flags(elapsed_ms: Sequence[Optional[float]]) -> List[str]:
    """Rytm odpowiedzi: zbyt równy (współczynnik zmienności < 0,12), zbyt szybki (połowa < 3 s),
    nagłe zawieszenia (odpowiedź > 6x mediana i > 45 s co najmniej dwa razy). Min. 6 odpowiedzi."""
    values = [float(v) for v in elapsed_ms if isinstance(v, (int, float)) and v >= 0]
    if len(values) < 6:
        return []
    flags = []
    mean = statistics.fmean(values)
    if mean > 0 and statistics.pstdev(values) / mean < 0.12:
        flags.append("rhythm_uniform")
    if sum(1 for v in values if v < 3000) * 2 >= len(values):
        flags.append("rhythm_rapid")
    median = statistics.median(values)
    if median > 0 and sum(1 for v in values if v > 6 * median and v > 45000) >= 2:
        flags.append("rhythm_spike")
    return flags


def attempt_flags(events: Sequence[Mapping[str, Any]], elapsed_ms: Sequence[Optional[float]],
                  quiet: Optional[Mapping[str, Any]] = None, finish_reason: Any = None) -> List[str]:
    """Flagi podejścia dla komisji (napisy z `FLAG_LABELS`), w kolejności wagi."""
    found = set()
    leaves = 0
    if _s(finish_reason) == "web_violations":
        found.add("auto_submitted")
    for e in events:
        name = _event_name(e)
        kind = _s(e.get("kind"))
        detail = e.get("detail") if isinstance(e.get("detail"), Mapping) else {}
        if name in ("second_session", "devtools", "printscreen", "guard_left", "guard_lost"):
            found.add(name)
        if kind == "time_flag" and detail.get("source") == "web" and detail.get("flag") in FLAG_LABELS:
            found.add(_s(detail.get("flag")))
        if kind == "app_background":
            leaves += 1
            try:
                if float(detail.get("seconds") or 0) >= LONG_ABSENCE_S:
                    found.add("long_absence")
            except (TypeError, ValueError):
                pass
    if leaves >= 3:
        found.add("left_often")
    q = quiet or {}
    if float(q.get("longest_s") or 0) >= LONG_ABSENCE_S:
        found.add("long_absence")
    if int(q.get("clicks") or 0) >= CLICKS_FLAG_MIN:
        found.add("clicks_outside")
    if sum(int(v or 0) for k, v in (q.get("counts") or {}).items() if k in ("copy", "cut", "paste", "context_menu", "print", "select_all")) >= BLOCKED_FLAG_MIN:
        found.add("blocked_attempts")
    found.update(rhythm_flags(elapsed_ms))
    order = list(FLAG_LABELS)
    return sorted(found, key=lambda f: order.index(f) if f in order else len(order))


def label_events(events: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Dokleja `label` (po polsku) i `signal` do osi zdarzeń - pola dawne zostają."""
    out = []
    for e in events:
        name = _event_name(e)
        detail = e.get("detail") if isinstance(e.get("detail"), Mapping) else {}
        label = LABELS.get(name, LABELS.get(_s(e.get("kind")), name))
        if _s(e.get("kind")) == "time_flag" and detail.get("flag"):
            label = _s(detail.get("label")) or FLAG_LABELS.get(_s(detail.get("flag"))) or f"{LABELS['time_flag']}: {detail.get('flag')}"
        out.append({**dict(e), "signal": name, "label": label, "source": detail.get("source") or "app"})
    return out


def guard_heard_since(link: Optional[Mapping[str, Any]], started_at: Any) -> bool:
    """Czy strażnik odezwał się w tej sesji. Stare sparowanie (np. telefon z logowania kodem), które milczy od
    początku egzaminu, to brak strażnika, a nie naruszenie - zamilknąć może tylko ten, który działał."""
    seen = _at(link.get("guard_seen_at")) if link else None
    start = _at(started_at)
    return bool(seen and start and seen >= start)


def guard_state(link: Optional[Mapping[str, Any]], now: datetime) -> Dict[str, Any]:
    """Stan telefonu-strażnika dla strony: `none` (nie sparowany) | `ok` | `away` (w tle) | `silent`."""
    if not link or not _s(link.get("guard_device_id")):
        return {"state": "none", "label": None, "seen_s": None}
    seen = _at(link.get("guard_seen_at"))
    seen_s = (now - seen).total_seconds() if seen else None
    state = _s(link.get("guard_state")) or "ok"
    if seen_s is None or seen_s > GUARD_SILENCE_S:
        state = "silent"
    elif state not in ("ok", "away"):
        state = "ok"
    return {"state": state, "label": link.get("guard_label"), "seen_s": round(seen_s, 1) if seen_s is not None else None}
