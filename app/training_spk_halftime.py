# app/training_spk_halftime.py
#
# Wzorzec odcięty na przerwie - stan meczu, od którego zaczyna sędzia
# ćwiczący przy skróconym nagraniu.
#
# PO CO. Skrót oficjalnego materiału pokazuje drugą połowę i rzuty karne.
# Sędzia nie ma czego prowadzić w pierwszej połowie, a bez niej nie da się
# poprawnie prowadzić drugiej: kary trzeciej rozstrzygają o dyskwalifikacji,
# druga żółta zależy od pierwszej, a wynik musi startować z 10:14, nie z 0:0.
# Dostaje więc pierwszą połowę WCZYTANĄ, dokładnie tak jak stołowy przejmujący
# mecz po przerwie.
#
# CZEGO TO NIE ROBI. Odcięta pierwsza połowa NIE wchodzi do oceny - ani po
# stronie wzorca, ani po stronie podejścia (`training_spk_score.py`, tryb
# „condensed"). Inaczej każde podejście zaczynałoby od kilkudziesięciu zdarzeń
# trafionych bez jednego naciśnięcia.
#
# SKĄD REGUŁY. Kształt stanu meczu bierze się z `getFullState` w
# `BAZA/components/MatchScreen.tsx`. Każde pole niesie czas w innej postaci i
# dlatego każde ma tu własną regułę, a nie jedno wspólne sito:
#
#   protocol      - zdarzenia z `half` i `time` w milisekundach,
#   penaltyTiles  - `assignedAt` w milisekundach czasu gry,
#   warningTiles  - `minute` jako TEKST z numerem minuty,
#   teamTimeouts  - trzy gniazda (first/second/third) z czasem w milisekundach,
#   goalHistory   - wpisy z `half` albo z `time`, zależnie od wydania.
#
# CZEGO ŚWIADOMIE NIE PRZELICZAMY. Bramek przy nazwiskach - aplikacja wylicza
# je z protokołu sama (`resolvePlayerGoalsFromProtocol`), więc przeliczanie ich
# tutaj byłoby drugim źródłem prawdy i pierwszą okazją do rozjazdu.
#
# CO NATOMIAST MUSIMY PRZYCIĄĆ W SKŁADACH: rubryki kar przy nazwiskach
# (`penalty1..3`, `disqualification`, `penaltyExtra` z czasem „MM:SS" i
# `warning` z minutą „9'") oraz sankcje osób towarzyszących. Aplikacja
# odbudowuje z tych rubryk kafelki kar na boisku (`buildTilesFromStats`),
# więc kara z 49. minuty przepuszczona w kolumnie wracała jako AKTYWNA kara
# na przerwie, a trzecie wykluczenie z drugiej połowy stawało się
# dyskwalifikacją, zanim sędzia zaczął ćwiczyć.

from __future__ import annotations

from typing import Any, Dict, List, Optional

#: Ile trwa połowa, gdy konfiguracja meczu nie mówi inaczej.
DEFAULT_HALF_MINUTES = 30

#: Rzuty karne z serii po meczu - nigdy nie należą do pierwszej połowy.
_SHOOTOUT_KEY = "shootout"


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def half_length_ms(blob: Dict[str, Any]) -> int:
    """Długość połowy w milisekundach - z konfiguracji meczu, nie z założenia."""
    cfg = blob.get("matchConfig")
    minutes = _int((cfg or {}).get("halfTime"), 0) if isinstance(cfg, dict) else 0
    if minutes <= 0:
        minutes = DEFAULT_HALF_MINUTES
    return minutes * 60_000


def first_half_events(protocol: Any, half_ms: int) -> List[Dict[str, Any]]:
    """Zdarzenia pierwszej połowy.

    Rozstrzyga `half`, a gdy go nie ma - czas. Zdarzenie bez obu pól zostaje:
    brak znacznika znaczy zwykle „coś, co nie ma czasu", a takich rzeczy nie
    wolno gubić przy przenoszeniu stanu.
    """
    out: List[Dict[str, Any]] = []
    if not isinstance(protocol, list):
        return out
    for item in protocol:
        if not isinstance(item, dict):
            continue
        if item.get(_SHOOTOUT_KEY):
            continue
        half = item.get("half")
        if half is not None:
            if _int(half, 1) == 1:
                out.append(item)
            continue
        if "time" in item:
            if _int(item.get("time")) < half_ms:
                out.append(item)
            continue
        out.append(item)
    return out


def _first_half_tiles(tiles: Any, half_ms: int) -> List[Dict[str, Any]]:
    """Kafelki kar - `assignedAt` liczy czas gry w milisekundach."""
    if not isinstance(tiles, list):
        return []
    return [
        t
        for t in tiles
        if isinstance(t, dict) and _int(t.get("assignedAt"), 0) < half_ms
    ]


def _first_half_warnings(tiles: Any, half_ms: int) -> List[Dict[str, Any]]:
    """Upomnienia - `minute` jest TEKSTEM, np. „23"."""
    if not isinstance(tiles, list):
        return []
    limit = half_ms // 60_000
    out: List[Dict[str, Any]] = []
    for t in tiles:
        if not isinstance(t, dict):
            continue
        raw = str(t.get("minute") or "").strip()
        # Minuta „23" znaczy 23. minutę meczu, więc przy połowie 30-minutowej
        # graniczna wartość to 29. Nierozpoznana minuta zostaje - upomnienie
        # zgubione po cichu byłoby gorsze niż upomnienie o minutę za daleko.
        digits = "".join(ch for ch in raw if ch.isdigit())
        if digits and int(digits) >= limit:
            continue
        out.append(t)
    return out


def _time_text_ms(raw: Any) -> Optional[int]:
    """Czas z rubryki protokołu w milisekundach.

    Rubryki kar niosą „MM:SS", upomnienia „9'", a starsze zapisy samą minutę.
    Nierozpoznany zapis daje ``None`` - wołający decyduje, co z nim zrobić.
    """
    text = str(raw or "").strip()
    if not text:
        return None
    if ":" in text:
        mm, _, ss = text.partition(":")
        mm_digits = "".join(ch for ch in mm if ch.isdigit())
        ss_digits = "".join(ch for ch in ss if ch.isdigit())
        if not mm_digits:
            return None
        return (int(mm_digits) * 60 + (int(ss_digits) if ss_digits else 0)) * 1000
    digits = "".join(ch for ch in text if ch.isdigit())
    return int(digits) * 60_000 if digits else None


def _keep_time(raw: Any, half_ms: int) -> bool:
    """Czy rubryka z czasem należy do pierwszej połowy.

    Rubryka bez rozpoznawalnego czasu ZOSTAJE - to ten sam wybór, co przy
    upomnieniach: sankcja zgubiona po cichu jest gorsza niż sankcja o minutę
    za daleko.
    """
    ms = _time_text_ms(raw)
    return ms is None or ms < half_ms


#: Rubryki zawodnika z czasem sankcji.
_PLAYER_TIME_FIELDS = (
    "warning",
    "penalty1",
    "penalty2",
    "penalty3",
    "disqualification",
    "disqualificationDesc",
    "penaltyExtra",
)


def _first_half_player_stats(stats: Any, half_ms: int) -> List[Any]:
    """Składy z rubrykami kar przyciętymi do pierwszej połowy.

    Wykluczenia są numerowane KOLEJNOŚCIĄ, nie czasem: po odcięciu drugiego
    trzecie nie może zostać „trzecim", bo aplikacja czyta z tego numeru
    dyskwalifikację. Zachowane wykluczenia dosuwamy więc do początku.
    """
    if not isinstance(stats, list):
        return []
    out: List[Any] = []
    for p in stats:
        if not isinstance(p, dict):
            continue
        q = dict(p)
        for key in _PLAYER_TIME_FIELDS:
            if key in q and not _keep_time(q.get(key), half_ms):
                q[key] = ""
        kept = [q.get(k) for k in ("penalty1", "penalty2", "penalty3") if q.get(k)]
        for idx, key in enumerate(("penalty1", "penalty2", "penalty3")):
            if key in q or idx < len(kept):
                q[key] = kept[idx] if idx < len(kept) else ""
        if "hasRedCard" in q:
            q["hasRedCard"] = bool(q.get("disqualification") or q.get("disqualificationDesc"))
        out.append(q)
    return out


def _first_half_companions(companions: Any, half_ms: int) -> Any:
    """Osoby towarzyszące: flagi sankcji zostają tylko z czasem z pierwszej połowy.

    Flaga bez czasu (starszy zapis) zostaje - jak wszędzie tu, brak znacznika
    nie jest dowodem na drugą połowę.
    """
    if not isinstance(companions, list):
        return companions
    out: List[Any] = []
    for c in companions:
        if not isinstance(c, dict):
            continue
        q = dict(c)
        if "warningTime" in q and not _keep_time(q.get("warningTime"), half_ms):
            q["warningTime"] = ""
            q["warned"] = False
        if "redTime" in q and not _keep_time(q.get("redTime"), half_ms):
            q["redTime"] = ""
            q["red"] = False
        if "redBlueTime" in q and not _keep_time(q.get("redBlueTime"), half_ms):
            q["redBlueTime"] = ""
            q["redBlue"] = False
        times = q.get("penaltyTimes")
        if isinstance(times, list):
            kept = [t for t in times if _keep_time(t, half_ms)]
            q["penaltyTimes"] = kept
            if not kept and len(times) > 0:
                q["twoMinutes"] = False
        out.append(q)
    return out


def _first_half_timeouts(timeouts: Any, half_ms: int) -> Dict[str, Any]:
    """Czasy dla drużyny: trzy gniazda, każde z czasem gry albo puste.

    Trzeci czas w piłce ręcznej i tak nie należy do pierwszej połowy, ale nie
    zakładamy tego z reguł - patrzymy na zapisany czas, bo to on jest prawdą
    o tym konkretnym meczu.
    """
    empty = {"first": None, "second": None, "third": None}
    if not isinstance(timeouts, dict):
        return {"host": dict(empty), "guest": dict(empty)}

    out: Dict[str, Any] = {}
    for side in ("host", "guest"):
        slots = timeouts.get(side)
        kept = dict(empty)
        if isinstance(slots, dict):
            for key in ("first", "second", "third"):
                value = slots.get(key)
                if value is None:
                    continue
                if _int(value, -1) >= 0 and _int(value, -1) < half_ms:
                    kept[key] = value
        out[side] = kept
    return out


def _first_half_goal_history(history: Any, half_ms: int) -> List[Any]:
    """Historia bramek - wpisy niosą `half` albo `time`, zależnie od wydania."""
    if not isinstance(history, list):
        return []
    out: List[Any] = []
    for item in history:
        if not isinstance(item, dict):
            continue
        if item.get(_SHOOTOUT_KEY):
            continue
        half = item.get("half")
        if half is not None:
            if _int(half, 1) == 1:
                out.append(item)
            continue
        if "time" in item and _int(item.get("time")) >= half_ms:
            continue
        out.append(item)
    return out


def penalty_stats_from(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Rzuty karne (siódemki) policzone z podanych zdarzeń.

    Liczymy je TUTAJ, bo `penaltyStats` w zapisie meczu jest sumą z całego
    spotkania i przeniesiona bez zmiany pokazywałaby na przerwie siódemki,
    których jeszcze nie było.
    """
    out = {
        "host": {"total": 0, "goals": 0},
        "guest": {"total": 0, "goals": 0},
    }
    for event in events:
        kind = str(event.get("type") or "")
        team = str(event.get("team") or "")
        if team not in out or kind not in ("penaltyKickScored", "penaltyKickMissed"):
            continue
        out[team]["total"] += 1
        if kind == "penaltyKickScored":
            out[team]["goals"] += 1
    return out


def config_without_signatures(config: Any) -> Dict[str, Any]:
    """Konfiguracja meczu z wyczyszczonymi podpisami.

    Sędzia ćwiczący przejmuje mecz po przerwie razem z całą pierwszą połową -
    ale NIE razem z podpisami ludzi, którzy ten mecz naprawdę prowadzili.
    Podpis jest potwierdzeniem obecności złożonym przez konkretnego człowieka;
    przeniesiony do cudzego ćwiczenia byłby cudzym podpisem pod protokołem,
    którego ten człowiek nigdy nie widział.

    Nazwisko, rola i numer licencji medyka ZOSTAJĄ - to dane meczu, nie
    potwierdzenie. Tak samo nazwiska sędziów w obsadzie.
    """
    if not isinstance(config, dict):
        return {}

    out = dict(config)
    extras = out.get("extras")
    if not isinstance(extras, dict):
        return out

    extras = dict(extras)
    extras.pop("hostTeamSignature", None)
    extras.pop("guestTeamSignature", None)

    medic = extras.get("medic")
    if isinstance(medic, dict):
        medic = dict(medic)
        medic.pop("signature", None)
        extras["medic"] = medic

    officials = extras.get("officials")
    if isinstance(officials, dict):
        cleaned: Dict[str, Any] = {}
        for role, person in officials.items():
            if isinstance(person, dict):
                person = dict(person)
                # `PersonWithSign` - nazwisko zostaje, podpis nie.
                person.pop("signature", None)
                person.pop("sign", None)
            cleaned[role] = person
        extras["officials"] = cleaned

    out["extras"] = extras
    return out


def state_after_first_half(
    blob: Dict[str, Any],
    *,
    saved_at_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Stan meczu na przerwie, gotowy do wczytania jako autozapis.

    ZEGAR STOI NA KOŃCU PIERWSZEJ POŁOWY, a nie w trakcie przerwy. Sędzia ma
    przed sobą to samo, co po naciśnięciu „koniec pierwszej połowy": zegar na
    30:00, gra zatrzymana, druga połowa do rozpoczęcia. Odliczanie przerwy
    byłoby tu udawaniem czasu, który nigdy nie płynął.
    """
    if not isinstance(blob, dict):
        blob = {}

    half_ms = half_length_ms(blob)
    protocol = first_half_events(blob.get("protocol"), half_ms)

    raw_half = blob.get("halfScore")
    half_score = (
        {"host": _int(raw_half.get("host")), "guest": _int(raw_half.get("guest"))}
        if isinstance(raw_half, dict)
        else {"host": 0, "guest": 0}
    )

    config = config_without_signatures(blob.get("matchConfig"))
    for key in ("hostCompanions", "guestCompanions"):
        if key in config:
            config[key] = _first_half_companions(config.get(key), half_ms)

    state: Dict[str, Any] = {
        "matchConfig": config,
        # ── zegar ──
        "mainTime": half_ms,
        "breakTime": 0,
        "isFirstHalf": False,
        "isGameRunning": False,
        "isHalfBreak": False,
        "isBreakRunning": False,
        "breakRemainingMs": 0,
        "halfBreakRemainingMs": 0,
        # ── wynik ──
        # Aplikacja i tak przeliczy go z protokołu; podajemy go, żeby ekran miał
        # z czego rysować, zanim to zrobi.
        "scoreHost": half_score["host"],
        "scoreGuest": half_score["guest"],
        "halfScore": half_score,
        # ── przebieg ──
        "protocol": protocol,
        "penaltyStats": penalty_stats_from(protocol),
        "teamTimeouts": _first_half_timeouts(blob.get("teamTimeouts"), half_ms),
        "penaltyTiles": _first_half_tiles(blob.get("penaltyTiles"), half_ms),
        "warningTiles": _first_half_warnings(blob.get("warningTiles"), half_ms),
        "goalHistory": _first_half_goal_history(blob.get("goalHistory"), half_ms),
        # ── składy ──
        # Bramki przy nazwiskach wylicza aplikacja z protokołu; rubryki kar
        # przycinamy tutaj, bo z nich aplikacja odbudowuje kary na boisku.
        "hostPlayerStats": _first_half_player_stats(blob.get("hostPlayerStats"), half_ms),
        "guestPlayerStats": _first_half_player_stats(blob.get("guestPlayerStats"), half_ms),
        # ── rzeczy, których na przerwie nie ma ──
        # STAN POCZĄTKOWY, NIE ``None``. Ekran meczu wznawia te kontenery
        # wprost (``setPenaltyShots(saved.penaltyShots)``) i pierwszy render
        # czyta ``penaltyShots.host``. ``None`` w tym miejscu wywracał cały
        # moduł stolikowy przy wejściu w skrót nagrania. Kształty są dokładnie
        # takie, z jakimi ekran startuje sam.
        "penaltyScores": {"host": 0, "guest": 0},
        "penaltyResults": {"host": [None] * 5, "guest": [None] * 5},
        "currentPenaltyRound": 0,
        "penaltyShots": {"host": [], "guest": []},
        "penaltyStarterTeam": None,
        "penaltyShootoutActive": False,
        "penaltyShootoutFinished": False,
        "penaltyShootoutScoreLabel": None,
        "activeTeamTimeout": {"host": False, "guest": False},
        "activeTimeoutTeam": None,
        # Cofanie zaczyna się od zera: sędzia nie ma prawa cofać cudzych
        # zdarzeń z pierwszej połowy, bo ich nie wpisywał.
        "undoStack": [],
        "savedAtMs": saved_at_ms,
    }

    starter = blob.get("firstHalfStarterTeam")
    if starter:
        # Rozstrzyga, kto rozpoczyna DRUGĄ połowę - drużyny się zamieniają.
        state["firstHalfStarterTeam"] = starter

    return state
