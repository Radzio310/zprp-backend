# app/training_spk_score.py
#
# Ocena przebiegu szkoleniowego: ile z meczu SPK/1 sędzia zapisał tak, jak było.
#
# CZYSTA DECYZJA, bez bazy i bez sieci. To jest jedyne miejsce, które mówi
# komuś „poszło ci tak a tak" - i po szkoleniu ktoś na pewno zapyta „dlaczego
# akurat tyle". Musi dać się pokazać w teście, a nie w planie zapytania.
#
# CO PORÓWNUJEMY. Dwie listy `ProtocolEvent` (`BAZA/components/types/
# MatchTypes.ts`): wzorcową z oficjalnego protokołu i tę z przebiegu sędziego.
# Każde zdarzenie ma czas w milisekundach, połowę, rodzaj, drużynę i numer
# zawodnika.
#
# JAK DOPASOWUJEMY. Zdarzenie po zdarzeniu, a nie sumami. Sumy nie odróżniają
# sędziego, który nadążał za meczem, od tego, który wpisał wszystko po fakcie -
# a to jest dokładnie ta różnica, której szkolenie ma uczyć. Dla każdego
# zdarzenia wzorca szukamy najbliższego w czasie zdarzenia sędziego TEGO SAMEGO
# RODZAJU i TEJ SAMEJ DRUŻYNY, w oknie dopasowania. Numer zawodnika NIE wchodzi
# do dopasowania, tylko do oceny - inaczej bramka zapisana pod złym numerem
# liczyłaby się podwójnie: raz jako pominięta, raz jako nadmiarowa, i sędzia
# dostałby za jedną pomyłkę dwie kary.
#
# DWA OKNA, ŚWIADOMIE RÓŻNE:
#   * OKNO DOPASOWANIA (szerokie) - do którego momentu uznajemy, że chodzi o to
#     samo zdarzenie. Za wąskie rozbija jedną pomyłkę na dwie.
#   * TOLERANCJA CZASU (wąska) - do którego momentu czas uznajemy za trafiony.
#     Dla bramek 10 sekund, bo tyle wynosi rozjazd między transmisją a zegarem
#     w hali. Dla kar i wykluczeń dwie sekundy: kara ma w protokole konkretny
#     czas, od którego liczy się jej koniec, więc tu przybliżenie jest błędem.
#
# TRYB PREZENTACJI NIE OCENIA CZASU. Slajdy przewija sędzia własnym tempem, więc
# zegar mówi o tym, jak szybko klikał, a nie o tym, czy prowadzi mecz poprawnie.
# Ocena czasu wtedy nie powstaje i nie wchodzi do wyniku - zamiast być liczona i
# po cichu zaniżana.

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.training_spk_slides import action_text, format_clock

#: Do którego momentu uznajemy, że dwa zdarzenia to to samo zdarzenie.
MATCH_WINDOW_MS = 90_000

#: Czas trafiony: bramki.
GOAL_TOLERANCE_MS = 10_000

#: Czas trafiony: kary, wykluczenia, czasy dla drużyny.
STRICT_TOLERANCE_MS = 2_000

#: Rodzaje zdarzeń, którym wolno mieć luźniejszy zegar.
GOAL_TYPES = frozenset({"goal", "penaltyKickScored", "penaltyKickMissed"})

#: Rodzaje, przy których czas jest CZĘŚCIĄ ZDARZENIA, a nie jego okolicznością.
#:
#: Kara ma w protokole moment, od którego liczy się jej koniec; czas dla drużyny
#: ma minutę, w której go przyznano. Bramka takiego zobowiązania nie niesie -
#: ważne jest, że padła i kto ją zdobył. Ten podział rozstrzyga, co jest
#: oceniane po czasie w trybie skróconego nagrania.
TIMED_TYPES = frozenset(
    {
        "warning",
        "penalty1",
        "penalty2",
        "penalty3",
        "disqualification",
        "disqualificationBlue",
        "teamTime",
    }
)

#: Tolerancja czasu w trybie skróconego nagrania - luźna z rozmysłu.
#:
#: Materiał jest cięty, więc zegar hali pojawia się na ekranie nierówno i nie
#: zawsze przy samej akcji. Dwie sekundy karałyby tu za montaż, nie za pracę
#: sędziego; dziesięć sekund nadal wyłapuje karę wpisaną „gdzieś w tej połowie".
CONDENSED_TOLERANCE_MS = 10_000

#: Rodzaje, które w ogóle rozpoznajemy. Cokolwiek innego pomijamy po obu
#: stronach - nieznany rodzaj po jednej stronie zamieniłby się w karę dla
#: sędziego za coś, czego ocena nawet nie rozumie.
KNOWN_TYPES = frozenset(
    {
        "goal",
        "goalRemoved",
        "penaltyKickScored",
        "penaltyKickMissed",
        "warning",
        "penalty1",
        "penalty2",
        "penalty3",
        "disqualification",
        "disqualificationBlue",
        "teamTime",
    }
)

#: Wagi składowych wyniku końcowego. Suma 100.
#:
#: Zdarzenia ważą najwięcej, bo protokół bez zdarzenia jest protokołem
#: nieprawdziwym. Numer zawodnika drugi - myli się rzadziej i łatwiej poprawić.
#: Czas najmniej, bo jest jedyną składową, którą psuje rzecz niezależna od
#: sędziego: opóźnienie transmisji.
WEIGHTS: Dict[str, int] = {
    "events": 55,
    "players": 25,
    "timing": 20,
}

#: Waga czasu rozdzielona na pozostałe, gdy czasu nie oceniamy (prezentacja).
WEIGHTS_NO_TIMING: Dict[str, int] = {
    "events": 70,
    "players": 30,
}

#: Skrócone nagranie: czas zostaje, ale jako kryterium LUŹNE.
#:
#: Ocenia się w nim wyłącznie czas kar, wykluczeń i czasów dla drużyny - przy
#: bramkach materiał jest pocięty i zegar nic nie mówi. Dziesięć punktów na sto
#: to dokładnie tyle, żeby wpisanie kary w przypadkowej minucie było widoczne w
#: wyniku, a nie żeby o nim decydowało.
WEIGHTS_CONDENSED: Dict[str, int] = {
    "events": 60,
    "players": 30,
    "timing": 10,
}

#: Od której połowy liczymy przy skróconym nagraniu.
CONDENSED_FROM_HALF = 2


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _player_key(value: Any) -> str:
    """Numer zawodnika jako tekst - „7" i 7 to ten sam zawodnik.

    Puste zostaje puste: część zdarzeń (czas dla drużyny) numeru nie ma i nie
    wolno traktować braku jako pomyłki.
    """
    text = str(value if value is not None else "").strip()
    if text.endswith(".0"):
        text = text[:-2]
    return text


def normalize_events(raw: Any) -> List[Dict[str, Any]]:
    """Lista zdarzeń sprowadzona do postaci, którą da się porównywać.

    Odsiewamy zdarzenia nieznanego rodzaju i te bez drużyny - po obu stronach
    tak samo. Zdarzenia z serii rzutów karnych ZOSTAJĄ, ale z własnym
    znacznikiem: nie mają czasu gry, więc do oceny czasu nie wchodzą.
    """
    out: List[Dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "").strip()
        team = str(item.get("team") or "").strip()
        if kind not in KNOWN_TYPES or team not in ("host", "guest"):
            continue
        out.append(
            {
                "i": index,
                "type": kind,
                "team": team,
                "time": _int(item.get("time")),
                "half": _int(item.get("half"), 1),
                "player": _player_key(item.get("player")),
                "shootout": bool(item.get("shootout")),
            }
        )
    out.sort(key=lambda e: (e["shootout"], e["time"], e["i"]))
    return out


def tolerance_for(kind: str, *, mode: str = "video") -> int:
    """Ile sekund rozjazdu wolno mieć temu rodzajowi zdarzenia.

    Przy skróconym nagraniu tolerancja jest jedna i luźna dla wszystkiego -
    materiał jest cięty, więc rozróżnianie bramek od kar co do sekundy nie ma
    tam podstawy. To, CO wchodzi do oceny czasu, rozstrzyga `TIMED_TYPES`, a
    nie ta funkcja.
    """
    if mode == "condensed":
        return CONDENSED_TOLERANCE_MS
    return GOAL_TOLERANCE_MS if kind in GOAL_TYPES else STRICT_TOLERANCE_MS


def _pair_events(
    reference: List[Dict[str, Any]],
    attempt: List[Dict[str, Any]],
    *,
    ignore_time: bool = False,
    mode: str = "video",
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(dopasowane, pominięte, nadmiarowe).

    Dopasowanie jest ZACHŁANNE i idzie po wzorcu, od zdarzenia do zdarzenia.
    Algorytm optymalny (węgierski) dałby ten sam wynik przy kilkudziesięciu
    zdarzeniach na mecz, a przestałby dać się wytłumaczyć sędziemu, który
    zapyta „czemu akurat ta bramka jest uznana za tamtą".

    `ignore_time` wyłącza okno dopasowania i zostawia samą KOLEJNOŚĆ. Jest
    potrzebne w trybie prezentacji: sędzia przewija slajdy własnym tempem, więc
    zegar nie mówi nic o meczu. Bez tego przełącznika bramka zapisana dziesięć
    minut „za późno" wypadała jednocześnie jako pominięta i jako nadmiarowa -
    i prezentacja punktowała zero komuś, kto zapisał wszystko poprawnie.
    """
    used: set = set()
    matched: List[Dict[str, Any]] = []
    missed: List[Dict[str, Any]] = []

    for ref in reference:
        best: Optional[Dict[str, Any]] = None
        best_delta = MATCH_WINDOW_MS + 1
        for cand in attempt:
            if cand["i"] in used:
                continue
            if cand["type"] != ref["type"] or cand["team"] != ref["team"]:
                continue
            # Seria rzutów karnych ma własny świat: jej zdarzenia dopasowujemy
            # wyłącznie do zdarzeń z serii, bo czas mają sztuczny.
            if cand["shootout"] != ref["shootout"]:
                continue
            delta = abs(cand["time"] - ref["time"])
            if ref["shootout"] or ignore_time:
                # Czas nic tu nie znaczy - liczy się kolejność, a tę zapewnia
                # sortowanie i „pierwszy wolny". Tak jest w serii rzutów
                # karnych (nie ma własnego zegara) i w trybie prezentacji.
                delta = 0
            if delta < best_delta:
                best, best_delta = cand, delta
            if delta == 0:
                break
        if best is None or best_delta > MATCH_WINDOW_MS:
            missed.append(ref)
            continue
        used.add(best["i"])
        matched.append(
            {
                # Zdanie o zdarzeniu składa TEN SAM moduł, co slajdy i PDF.
                # Aplikacja dostaje gotowy tekst, bo inaczej reguła nazywania
                # akcji istniałaby po obu stronach i przy pierwszej poprawce
                # ekran wyników zacząłby mówić co innego niż prezentacja.
                "text": action_text(ref),
                "clock": format_clock(ref["time"]),
                "type": ref["type"],
                "team": ref["team"],
                "refTime": ref["time"],
                "myTime": best["time"],
                "deltaMs": best["time"] - ref["time"],
                "refPlayer": ref["player"],
                "myPlayer": best["player"],
                "playerOk": ref["player"] == best["player"],
                "shootout": ref["shootout"],
                "timeOk": abs(best["time"] - ref["time"])
                <= tolerance_for(ref["type"], mode=mode),
            }
        )

    extra = [e for e in attempt if e["i"] not in used]
    for event in missed + extra:
        event["text"] = action_text(event)
        event["clock"] = format_clock(event["time"])
    return matched, missed, extra


def _in_condensed_scope(event: Dict[str, Any]) -> bool:
    """Czy to zdarzenie wchodzi do oceny skróconego nagrania.

    Rzuty karne zostają zawsze: seria odbywa się po meczu i jest właśnie tym,
    co skrót pokazuje na końcu.
    """
    return bool(event.get("shootout")) or _int(event.get("half"), 1) >= CONDENSED_FROM_HALF


def _pct(part: float, whole: float) -> float:
    if whole <= 0:
        return 100.0
    return max(0.0, min(100.0, round(100.0 * part / whole, 1)))


def score_run(
    reference_events: Any,
    attempt_events: Any,
    *,
    mode: str = "video",
    reference_meta: Optional[Dict[str, Any]] = None,
    attempt_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Pełna ocena jednego podejścia.

    `mode`:
      * "video"     - pełne nagranie, czas oceniany dla wszystkiego,
      * "slides"    - prezentacja, czas NIE jest oceniany,
      * "condensed" - skrócone nagranie: liczymy DOPIERO OD DRUGIEJ POŁOWY, a
        czas oceniamy wyłącznie przy karach, wykluczeniach i czasach dla
        drużyny, i to luźno.

    DLACZEGO SKRÓT ODCINA PIERWSZĄ POŁOWĘ PO OBU STRONACH. Sędzia dostaje ją
    wczytaną gotową, prosto z wzorca - gdyby weszła do oceny, każde podejście
    zaczynałoby od kilkudziesięciu zdarzeń trafionych bez jednego naciśnięcia.
    Wynik mówiłby wtedy o tym, ile meczu dostał w prezencie, a nie o tym, ile
    poprowadził.

    Zwracany kształt jest jednocześnie tym, co pokazuje ekran wyników - nie ma
    drugiego liczenia po stronie aplikacji. Jedna odpowiedź, jedno źródło.
    """
    reference = normalize_events(reference_events)
    attempt = normalize_events(attempt_events)

    if mode == "condensed":
        reference = [e for e in reference if _in_condensed_scope(e)]
        attempt = [e for e in attempt if _in_condensed_scope(e)]

    matched, missed, extra = _pair_events(
        reference,
        attempt,
        # Przy skrócie kolejność jest pewniejsza niż zegar: materiał jest cięty,
        # więc dopasowanie po czasie rozjeżdżałoby pary tam, gdzie sędzia
        # pracował poprawnie.
        ignore_time=(mode in ("slides", "condensed")),
        mode=mode,
    )

    total_ref = len(reference)
    events_pct = _pct(len(matched), total_ref)

    # Nadmiarowe zdarzenia obniżają ocenę zdarzeń osobno: protokół z dopisaną
    # bramką, której nie było, jest tak samo nieprawdziwy jak ten z bramką
    # pominiętą. Kara jest proporcjonalna do wielkości meczu, a nie stała -
    # trzy zmyślone kary w meczu o siedemdziesięciu zdarzeniach to co innego
    # niż trzy w meczu o dziesięciu.
    if total_ref > 0 and extra:
        events_pct = max(0.0, round(events_pct - 100.0 * len(extra) / total_ref, 1))

    with_player = [m for m in matched if m["refPlayer"] or m["myPlayer"]]
    players_pct = _pct(
        len([m for m in with_player if m["playerOk"]]), len(with_player)
    )

    timed = [m for m in matched if not m["shootout"]]
    if mode == "condensed":
        # Czas bramki w ciętym materiale nie mówi nic o pracy sędziego.
        timed = [m for m in timed if m["type"] in TIMED_TYPES]
    timing_pct = _pct(len([m for m in timed if m["timeOk"]]), len(timed))

    if mode == "slides":
        weights = WEIGHTS_NO_TIMING
        parts = {"events": events_pct, "players": players_pct}
    elif mode == "condensed":
        weights = WEIGHTS_CONDENSED
        parts = {
            "events": events_pct,
            "players": players_pct,
            "timing": timing_pct,
        }
    else:
        weights = WEIGHTS
        parts = {
            "events": events_pct,
            "players": players_pct,
            "timing": timing_pct,
        }

    total = round(
        sum(parts[k] * weights[k] for k in parts) / sum(weights.values()), 1
    )

    return {
        "mode": mode,
        "score": total,
        "parts": parts,
        "weights": weights,
        "counts": {
            "reference": total_ref,
            "mine": len(attempt),
            "matched": len(matched),
            "missed": len(missed),
            "extra": len(extra),
            "wrongPlayer": len([m for m in matched if not m["playerOk"]]),
            "lateOrEarly": len([m for m in timed if not m["timeOk"]]),
        },
        "result": _score_line_report(reference_meta, attempt_meta),
        "matched": matched,
        "missed": missed,
        "extra": extra,
    }


def _score_line_report(
    reference_meta: Optional[Dict[str, Any]],
    attempt_meta: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Wynik meczu i wynik do przerwy - osobno od zdarzeń.

    Osobno, bo to jest jedyna liczba, którą po meczu widzi cały świat. Sędzia
    może zgubić dwie kary i wciąż oddać poprawny wynik - i odwrotnie, co jest
    znacznie gorsze. Zestawienie musi to rozróżniać, zamiast topić w jednym
    procencie.
    """
    ref = reference_meta or {}
    mine = attempt_meta or {}

    def line(src: Dict[str, Any], prefix: str) -> str:
        host = str(src.get(f"{prefix}Host") or "").strip()
        guest = str(src.get(f"{prefix}Guest") or "").strip()
        return f"{host}-{guest}" if host or guest else ""

    final_ref, final_mine = line(ref, "final"), line(mine, "final")
    half_ref, half_mine = line(ref, "half"), line(mine, "half")

    return {
        "final": {"reference": final_ref, "mine": final_mine, "ok": final_ref == final_mine},
        "half": {"reference": half_ref, "mine": half_mine, "ok": half_ref == half_mine},
    }


def grade(score: float) -> str:
    """Jedno słowo do nagłówka ekranu wyników.

    Progi są okrągłe i widoczne w kodzie z rozmysłu: sędzia ma móc usłyszeć,
    gdzie przebiega granica, a nie domyślać się jej z koloru paska.
    """
    if score >= 95:
        return "wzorowo"
    if score >= 85:
        return "bardzo dobrze"
    if score >= 70:
        return "dobrze"
    if score >= 50:
        return "są braki"
    return "do powtórzenia"
