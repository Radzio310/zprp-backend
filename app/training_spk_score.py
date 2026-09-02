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

#: Do którego momentu uznajemy, że dwa zdarzenia to to samo zdarzenie.
MATCH_WINDOW_MS = 90_000

#: Czas trafiony: bramki.
GOAL_TOLERANCE_MS = 10_000

#: Czas trafiony: kary, wykluczenia, czasy dla drużyny.
STRICT_TOLERANCE_MS = 2_000

#: Rodzaje zdarzeń, którym wolno mieć luźniejszy zegar.
GOAL_TYPES = frozenset({"goal", "penaltyKickScored", "penaltyKickMissed"})

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


def tolerance_for(kind: str) -> int:
    """Ile sekund rozjazdu wolno mieć temu rodzajowi zdarzenia."""
    return GOAL_TOLERANCE_MS if kind in GOAL_TYPES else STRICT_TOLERANCE_MS


def _pair_events(
    reference: List[Dict[str, Any]],
    attempt: List[Dict[str, Any]],
    *,
    ignore_time: bool = False,
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
                "type": ref["type"],
                "team": ref["team"],
                "refTime": ref["time"],
                "myTime": best["time"],
                "deltaMs": best["time"] - ref["time"],
                "refPlayer": ref["player"],
                "myPlayer": best["player"],
                "playerOk": ref["player"] == best["player"],
                "shootout": ref["shootout"],
                "timeOk": abs(best["time"] - ref["time"]) <= tolerance_for(ref["type"]),
            }
        )

    extra = [e for e in attempt if e["i"] not in used]
    return matched, missed, extra


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
      * "video"  - sędzia prowadził przy nagraniu, czas jest oceniany,
      * "slides" - sędzia prowadził przy prezentacji, czas NIE jest oceniany.

    Zwracany kształt jest jednocześnie tym, co pokazuje ekran wyników - nie ma
    drugiego liczenia po stronie aplikacji. Jedna odpowiedź, jedno źródło.
    """
    reference = normalize_events(reference_events)
    attempt = normalize_events(attempt_events)
    matched, missed, extra = _pair_events(
        reference, attempt, ignore_time=(mode == "slides")
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
    timing_pct = _pct(len([m for m in timed if m["timeOk"]]), len(timed))

    if mode == "slides":
        weights = WEIGHTS_NO_TIMING
        parts = {"events": events_pct, "players": players_pct}
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
