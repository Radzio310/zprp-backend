"""Czyste reguły portalu publicznego (mapa miast, statystyki, porównania).

Bez bazy i bez sieci - testowalne w izolacji. Wejścia to zwykłe słowniki.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Optional

from app.national_distance_parser import clean_city, normalize_city_key
from app.national_place_rules import province_label, province_slug
from app.zprp_public import match_rules as MR

_PREFIXES = re.compile(r"^(m|gm|msc|miasto|gmina)\.?\s+", re.I)
_LEADING_POSTAL = re.compile(r"^\d{2}\s*-\s*\d{3}[\s,]*")


def _clean(raw: object) -> str:
    return clean_city(_LEADING_POSTAL.sub("", str(raw or "").strip()))


def city_variants(raw: object) -> list[str]:
    """Klucze nazw, od najdokładniejszego: pełna nazwa, potem człon przed
    nawiasem / ` - ` / przecinkiem / ukośnikiem, bez prefiksu „m.", „gm."."""
    text = _clean(raw)
    if not text:
        return []
    out: list[str] = []

    def add(value: str) -> None:
        key = normalize_city_key(value)
        if key and key not in out:
            out.append(key)

    add(text)
    add(_PREFIXES.sub("", text))
    head = re.split(r"\s*[(/,]\s*|\s+-\s+", text, maxsplit=1)[0]
    add(head)
    add(_PREFIXES.sub("", head))
    return out


def display_city(raw: object) -> str:
    """Czytelna nazwa miasta do wyświetlenia (bez kodu pocztowego i prefiksu)."""
    text = _PREFIXES.sub("", _clean(raw))
    head = re.split(r"\s*[(/,]\s*|\s+-\s+", text, maxsplit=1)[0].strip()
    return head or text


def province_hint(association_name: object) -> str:
    """Slug województwa ze związku okręgowego („Śląski ZPRP" -> „slaskie")."""
    return province_slug(association_name)


def pick_best(candidates: list[dict], hint: str = "") -> Optional[dict]:
    """Z kilku miejscowości o tej samej nazwie: zgodne z województwem klubu,
    w ostateczności najliczniejsze / najczęściej obserwowane."""
    if not candidates:
        return None
    pool = [c for c in candidates if hint and c.get("province") == hint] or candidates
    return max(pool, key=lambda c: (c.get("weight") or 0))


def resolve_city(
    raw: object,
    index: dict[str, list[dict]],
    hint: str = "",
    fallback: Optional[Callable[[str], list[dict]]] = None,
    cache: Optional[Callable[[str], Optional[dict]]] = None,
) -> Optional[dict]:
    """Nazwa miasta -> {lat, lon, province, name, source} albo None.

    `index`: name_key -> kandydaci z tabeli odległości (klucze lat, lon,
    province, weight). `fallback`: skorowidz GeoNames (ta sama postać).
    `cache`: klucz nazwy -> punkt z trwałej pamięci geokodera (Nominatim) albo
    None - ostatnia deska, tylko dla nazw, których nie znają dwa pierwsze źródła."""
    for key in city_variants(raw):
        hit = pick_best(index.get(key, []), hint)
        if hit and hit.get("lat") is not None and hit.get("lon") is not None:
            return {**hit, "source": "national_places"}
    if fallback:
        for key in city_variants(raw):
            hit = pick_best(fallback(key) or [], hint)
            if hit and hit.get("lat") is not None:
                return {**hit, "source": "gazetteer"}
    if cache:
        for key in city_variants(raw):
            hit = cache(key)
            if hit and hit.get("lat") is not None and hit.get("lon") is not None:
                return {"key": f"geo:{key}", "name": hit.get("name") or display_city(raw), "province": hit.get("province") or "",
                        "weight": 0, "approximate": False, **hit, "source": "nominatim"}
    return None


def build_index(nodes: Iterable[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    for node in nodes:
        key = node.get("name_key") or normalize_city_key(node.get("name") or "")
        if not key or node.get("lat") is None or node.get("lon") is None:
            continue
        index.setdefault(key, []).append(node)
    return index


def voivodeship(slug: str) -> Optional[str]:
    return province_label(slug or "") or None


# ---------------------------------------------------------------------------
# Statystyki z meczów
# ---------------------------------------------------------------------------


def team_record(matches: Iterable[dict], is_mine: Callable[[str, dict], bool]) -> dict[str, Any]:
    """Bilans z rozegranych meczów. `is_mine(side, match)` mówi, czy strona
    'home'/'away' to badany podmiot (drużyna albo klub).

    Piłka ręczna nie zna remisu: równy wynik rozstrzygają rzuty karne, walkower
    liczy się jak zwycięstwo/porażka. Nowe pola: `record` {w, wk, lk, l},
    płaskie `wins_regular`/`wins_shootout`/`losses_shootout`/`losses_regular`
    (porównywarka) i `form_detail` (W/WK/LK/L, ostatnie 5 rozstrzygniętych).
    Stare pola zostają dla zgodności: `wins`/`losses` liczą też rozstrzygnięcia
    po karnych, `draws` to wyłącznie mecze z równym wynikiem BEZ serii karnych
    w danych (źródło nie podało rozstrzygnięcia, zwykle 0).

    Derby klubu (obie drużyny tego samego klubu, `is_mine` prawdziwe po obu
    stronach) to JEDEN rozegrany mecz klubu: wchodzi do `played` (i do
    `home_played` - klub był gospodarzem), więc liczba w hero zgadza się z listą
    „Rozegrane” (`match_counts.played`). Do bilansu W/WK/LK/L, bramek, formy
    i średnich NIE wchodzi - klub wygrałby i przegrał ten sam mecz. Liczbę takich
    meczów podaje `derbies` (front: „w tym N derbów klubu”); `win_rate` i średnie
    liczone są z meczów bez derbów.
    """
    played = draws = gf = ga = derbies = 0
    home_played = away_played = 0
    form: list[str] = []
    detail: list[str] = []
    rec = MR.empty_record()
    for m in sorted(matches, key=lambda x: (x.get("scheduled_at") is not None, x.get("scheduled_at") or datetime.min)):
        sh, sa = m.get("score_home"), m.get("score_away")
        if sh is None or sa is None:
            continue
        mine_home, mine_away = is_mine("home", m), is_mine("away", m)
        if mine_home and mine_away:  # derby klubu: rozegrany raz, poza bilansem
            played += 1
            home_played += 1
            derbies += 1
            continue
        if not mine_home and not mine_away:  # nie nasz mecz
            continue
        mine, theirs = (sh, sa) if mine_home else (sa, sh)
        played += 1
        home_played += 1 if mine_home else 0
        away_played += 0 if mine_home else 1
        gf += mine
        ga += theirs
        code = MR.side_result(m, "home" if mine_home else "away")
        if code is None:
            draws += 1
            form.append("D")
            continue
        rec[code.lower()] += 1
        detail.append(code)
        form.append(MR.basic_result(code) or "D")
    wins, losses = rec["w"] + rec["wk"], rec["l"] + rec["lk"]
    scored = played - derbies  # mecze z bilansem (bez derbów klubu)
    return {
        "played": played, "wins": wins, "draws": draws, "losses": losses,
        "derbies": derbies,
        "wins_regular": rec["w"], "wins_shootout": rec["wk"],
        "losses_shootout": rec["lk"], "losses_regular": rec["l"],
        "record": rec,
        "goals_for": gf, "goals_against": ga, "goal_difference": gf - ga,
        "avg_goals_for": round(gf / scored, 2) if scored else None,
        "avg_goals_against": round(ga / scored, 2) if scored else None,
        "win_rate": round(wins / scored, 3) if scored else None,
        "home_played": home_played, "away_played": away_played,
        "form": form[-5:],
        "form_detail": detail[-5:],
    }


UPCOMING_GRACE = timedelta(hours=3)


def is_played(card: dict) -> bool:
    """Rozegrany = jest wynik (ta sama reguła co `team_record` i `isPlayed` w kliencie)."""
    return card.get("score_home") is not None and card.get("score_away") is not None


def is_upcoming(card: dict, now: datetime) -> bool:
    """Przed nami = bez wyniku, nie wycofany i nie starszy niż 3 h (mecz w toku też)."""
    if is_played(card) or card.get("withdrawn"):
        return False
    at = card.get("scheduled_at")
    return at is None or not isinstance(at, datetime) or at >= now - UPCOMING_GRACE


def match_counts(cards: Iterable[dict], now: datetime) -> dict[str, int]:
    """Liczniki list meczów liczone na serwerze z PEŁNEJ listy (bez obcięcia do 5).

    `all` = played + upcoming + pending (+ wycofane bez wyniku, liczone w `withdrawn`).
    `pending` = termin minął, a wyniku nie ma (czeka na protokół)."""
    out = {"all": 0, "played": 0, "upcoming": 0, "today": 0, "pending": 0, "withdrawn": 0}
    for card in cards:
        out["all"] += 1
        at = card.get("scheduled_at")
        if isinstance(at, datetime) and at.date() == now.date():
            out["today"] += 1
        if is_played(card):
            out["played"] += 1
        elif card.get("withdrawn"):
            out["withdrawn"] += 1
        elif is_upcoming(card, now):
            out["upcoming"] += 1
        else:
            out["pending"] += 1
    return out


def normalise_for_radar(entities: list[dict], metrics: list[str]) -> dict[str, Any]:
    """Max na metrykę i wartości 0..1 do wykresu radarowego."""
    maxima: dict[str, float] = {}
    for metric in metrics:
        values = [e["metrics"].get(metric) for e in entities if isinstance(e["metrics"].get(metric), (int, float))]
        maxima[metric] = max(values) if values else 0
    for entity in entities:
        entity["radar"] = {
            metric: (round(entity["metrics"][metric] / maxima[metric], 3)
                     if maxima[metric] and isinstance(entity["metrics"].get(metric), (int, float)) else 0.0)
            for metric in metrics
        }
    return {"max": maxima}


# ---------------------------------------------------------------------------
# Tożsamość drużyny przez sezony (bilans bezpośredni)
# ---------------------------------------------------------------------------


def team_key(name: object) -> str:
    """Klucz nazwy drużyny: bez wielkości liter, polskich znaków, interpunkcji i podwójnych spacji.

    team_id zmienia się co sezon, a klub może mieć kilka drużyn w jednej kategorii
    (np. „SMS Enea Gniezno" i „Enea MKS Gniezno"), więc tożsamość = klub + nazwa drużyny.
    """
    import unicodedata

    text = unicodedata.normalize("NFKD", str(name or "").replace("ł", "l").replace("Ł", "L"))
    text = "".join(ch for ch in text if not unicodedata.combining(ch)).casefold()
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text).split())


def h2h_between(rows: Iterable[dict], team_a: dict, team_b: dict) -> list[dict]:
    """Zostawia tylko mecze dokładnie tych dwóch drużyn (w dowolnej kolejności stron).

    `team_a`/`team_b`: {club_id, team_id?, name}. Strona pasuje, gdy ten sam klub i (ta sama
    drużyna po id albo po znormalizowanej nazwie). Mecz klubu z samym sobą odpada zawsze.
    """
    def same(row: dict, side: str, team: dict) -> bool:
        if not team.get("club_id") or row.get(f"{side}_club_id") != team["club_id"]:
            return False
        if team.get("team_id") and row.get(f"{side}_team_id") == team["team_id"]:
            return True
        key = team_key(team.get("name"))
        return bool(key) and team_key(row.get(f"{side}_team_name")) == key

    out = []
    for r in rows:
        if r.get("home_club_id") and r.get("home_club_id") == r.get("away_club_id"):
            continue
        if (same(r, "home", team_a) and same(r, "away", team_b)) or (same(r, "home", team_b) and same(r, "away", team_a)):
            out.append(r)
    return out
