# app/training_spk_slides.py
#
# Oś czasu meczu zamieniona na POLECENIA - po kolei, tak jak się działy.
#
# Jedno źródło, trzy wyjścia: slajdy w aplikacji, pasek poleceń nad ekranem
# meczu i PDF do wyświetlenia grupie. Gdyby każde z nich składało zdania samo,
# ta sama akcja brzmiałaby w trzech miejscach inaczej - a sędzia porównuje to,
# co widzi na rzutniku, z tym, co ma na telefonie.
#
# ZDARZENIA RÓWNOCZESNE IDĄ NA JEDEN SLAJD. W protokole bramka i kara potrafią
# mieć ten sam czas, bo padły w jednej akcji („bramka gospodarzy nr 16 i kara
# dwóch minut dla gości nr 7"). Rozbicie ich na dwa slajdy kazałoby sędziemu
# ustawić ten sam czas dwa razy i sugerowało, że to dwie osobne sytuacje.
#
# CZAS JEST NA KAŻDYM SLAJDZIE, także w trybie prezentacji, gdzie nie jest ostro
# oceniany. Bez niego sędzia nie ma jak ustawić zegara nawet wtedy, gdy chce -
# a właśnie ustawianie zegara jest częścią ćwiczenia.

from __future__ import annotations

from typing import Any, Dict, List

#: Ile milisekund różnicy uznajemy jeszcze za „w tej samej akcji".
SAME_ACTION_MS = 1_000

#: Dopełniacz - „bramka GOSPODARZY", „kara dla GOŚCI".
TEAM_OF = {"host": "gospodarzy", "guest": "gości"}

#: Mianownik - „czas dla drużyny: GOSPODARZE".
TEAM_IS = {"host": "gospodarze", "guest": "goście"}


def format_clock(ms: Any) -> str:
    """MM:SS liczone od początku meczu, tak jak pokazuje je zegar w hali."""
    try:
        total = max(0, int(ms)) // 1000
    except (TypeError, ValueError):
        total = 0
    return f"{total // 60:02d}:{total % 60:02d}"


def _who(event: Dict[str, Any]) -> str:
    """Numer zawodnika albo osoba z ławki - po ludzku.

    Protokół zapisuje osoby towarzyszące jako „Tr" i „Os", a nie jako numery.
    Wypisanie ich jako „nr Tr" byłoby zdaniem, którego nikt nie wypowiada.
    """
    raw = str(event.get("player") if event.get("player") is not None else "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if lowered.startswith("tr"):
        return "trener"
    if lowered.startswith("os"):
        return "osoba towarzysząca"
    return f"nr {raw}"


def action_text(event: Dict[str, Any]) -> str:
    """Jedno zdanie o jednym zdarzeniu. Pusty napis = nie umiemy tego nazwać."""
    kind = str(event.get("type") or "").strip()
    team = str(event.get("team") or "").strip()
    of = TEAM_OF.get(team, "")
    who = _who(event)
    tail = f" {who}" if who else ""

    if kind == "goal":
        return f"Bramka {of}{tail}".strip()
    if kind == "goalRemoved":
        return f"Anulowana bramka {of}{tail}".strip()
    if kind == "penaltyKickScored":
        return f"Rzut karny wykorzystany, {of}{tail}".strip()
    if kind == "penaltyKickMissed":
        return f"Rzut karny niewykorzystany, {of}{tail}".strip()
    if kind == "warning":
        return f"Upomnienie dla {of}{tail}".strip()
    if kind in ("penalty1", "penalty2", "penalty3"):
        which = {"penalty1": "", "penalty2": " (druga)", "penalty3": " (trzecia)"}[kind]
        return f"Kara 2 minut dla {of}{tail}{which}".strip()
    if kind == "disqualification":
        return f"Dyskwalifikacja, {of}{tail}".strip()
    if kind == "disqualificationBlue":
        return f"Dyskwalifikacja z raportem, {of}{tail}".strip()
    if kind == "teamTime":
        extra = str(event.get("extra") or "").strip()
        mark = f" ({extra})" if extra else ""
        return f"Czas dla drużyny: {TEAM_IS.get(team, '')}{mark}".strip()
    return ""


def _join_actions(actions: List[str]) -> str:
    """„Bramka gospodarzy nr 16 i kara 2 minut dla gości nr 7".

    Kolejne człony schodzą małą literą, bo to jedno zdanie o jednej akcji, a nie
    lista. Wielka litera w środku wyglądała jak sklejone dwa polecenia - czyli
    dokładnie jak to, czego scalanie miało uniknąć.
    """
    if not actions:
        return ""
    head, rest = actions[0], actions[1:]
    return " i ".join([head] + [r[:1].lower() + r[1:] for r in rest])


def _slide_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Akcja slajdu jako dane - do wykrywania wykonania, nie do pokazywania."""
    player = str(event.get("player") if event.get("player") is not None else "").strip()
    if player.endswith(".0"):
        player = player[:-2]
    return {
        "type": str(event.get("type") or "").strip(),
        "team": str(event.get("team") or "").strip(),
        "player": player,
    }


def shootout_slide(shot: Dict[str, Any]) -> Dict[str, Any]:
    """Jeden rzut serii jako slajd - „trafienie" albo „pudło", po nazwisku.

    Kształt jest ten sam, co slajdu z osi czasu, więc prezentacja, PDF i
    prowadzenie w aplikacji nie muszą wiedzieć, że seria przyszła z innego
    pola dokumentu. W miejscu zegara stoi NUMER SERII: rzuty po meczu nie mają
    czasu gry, a pusty duży zegar zostawiał na stronie dziurę.
    """
    team = str(shot.get("team") or "").strip()
    player = str(shot.get("player") or "").strip()
    scored = bool(shot.get("scored"))
    round_no = int(shot.get("round") or 0)
    who = f" nr {player}" if player else ""
    text = (
        f"Seria karnych, rzut {round_no}: {TEAM_IS.get(team, '')}{who} - "
        f"{'trafienie' if scored else 'pudło'}"
    ).strip()
    return {
        "n": 0,
        "half": 2,
        "timeMs": 0,
        "clock": str(round_no or ""),
        "shootout": True,
        "actions": [text],
        "events": [
            {
                "type": "penaltyKickScored" if scored else "penaltyKickMissed",
                "team": team,
                "player": player,
                # Który to rzut tej drużyny - po tym paruje je telefon.
                "shot": int(shot.get("shotIndex") or 0),
            }
        ],
        "text": text,
    }


def slides_from_timeline(
    timeline: Any,
    meta: Dict[str, Any] | None = None,
    shootout: Any = None,
) -> List[Dict[str, Any]]:
    """Lista slajdów w kolejności meczu.

    Kształt slajdu jest CELOWO płaski: numer, połowa, czas w milisekundach i
    gotowy tekst. Aplikacja ma go tylko pokazać i - w trybie prezentacji -
    ustawić z niego zegar; nie ma niczego doliczać, bo wtedy PDF i ekran
    zaczęłyby się różnić.

    Obok tekstu slajd niesie te same akcje JAKO DANE (`events`): rodzaj,
    drużynę i numer. Tryb prowadzenia w aplikacji sprawdza po nich, czy sędzia
    wykonał akcję ze slajdu - z samego zdania nie dałoby się tego odczytać bez
    parsowania własnych tekstów, a to jest prosta droga do rozjazdu przy
    pierwszej zmianie sformułowania.

    SERIA RZUTÓW KARNYCH DOCHODZI NA KOŃCU, z osobnego pola dokumentu
    (`shootout`, patrz `training_spk_shootout.py`) - w osi czasu jej nie ma.
    Bez niej materiał kończył się ostatnią akcją drugiej połowy i zostawiał
    ćwiczącego z remisem, jakby mecz na tym się skończył.
    """
    events = [e for e in (timeline or []) if isinstance(e, dict)]
    events = [e for e in events if action_text(e)]
    events.sort(key=lambda e: (bool(e.get("shootout")), int(e.get("time") or 0)))

    slides: List[Dict[str, Any]] = []
    for event in events:
        text = action_text(event)
        time_ms = int(event.get("time") or 0)
        in_shootout = bool(event.get("shootout"))
        last = slides[-1] if slides else None
        same_action = (
            last is not None
            and last["shootout"] == in_shootout
            and abs(last["timeMs"] - time_ms) <= SAME_ACTION_MS
        )
        if same_action:
            last["actions"].append(text)
            last["events"].append(_slide_event(event))
            last["text"] = _join_actions(last["actions"])
            continue
        slides.append(
            {
                "n": len(slides) + 1,
                "half": int(event.get("half") or 1),
                "timeMs": time_ms,
                "clock": format_clock(time_ms),
                "shootout": in_shootout,
                "actions": [text],
                "events": [_slide_event(event)],
                "text": text,
            }
        )

    for shot in shootout or []:
        if isinstance(shot, dict):
            slides.append(shootout_slide(shot))

    # Numerację nadajemy PO scaleniu - inaczej slajdy miałyby dziury tam, gdzie
    # dwie akcje trafiły na jeden ekran.
    for index, slide in enumerate(slides, start=1):
        slide["n"] = index
    return slides


def slides_header(meta: Dict[str, Any] | None) -> Dict[str, str]:
    """Nagłówek materiału - to samo w aplikacji i na pierwszej stronie PDF."""
    data = meta or {}
    host = str(data.get("hostTeamName") or "").strip()
    guest = str(data.get("guestTeamName") or "").strip()
    return {
        "matchNumber": str(data.get("matchNumber") or "").strip(),
        "teams": f"{host} - {guest}".strip(" -"),
        "date": str(data.get("date") or "").strip(),
        "result": f"{data.get('finalHost', '')}:{data.get('finalGuest', '')}".strip(":"),
        "halfResult": f"{data.get('halfHost', '')}:{data.get('halfGuest', '')}".strip(":"),
    }
