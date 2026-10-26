"""Statystyki ogólnopolskie (ekran „Statystyki" portalu) - czyste reguły, bez bazy i sieci.

Kontrakt: `docs/stats.md`. Tu siedzą:
* klasyfikacja rozgrywek (kategoria jak `category.ts` w BAZA_web, szczebel, województwo),
* zakres jednego paska filtrów (`Scope`) - każda sekcja liczy dokładnie ten zakres,
* migawka sezonu (`Frame`) w zwartej postaci (`slots`), budowana w wątku z wierszy bazy,
* sekcje Sezon / Województwa / Trendy i rekordy oraz ciekawostki z szablonów po polsku.

Identyfikatory (klucze kategorii, `central`/`district`, slugi województw, `kind`)
są stałe i angielskie/ASCII; polskie są wyłącznie etykiety i zdania ciekawostek.
Wynik bez remisów: kod gospodarza `W`/`WK`/`LK`/`L` z `match_rules.side_result`.
"""

from __future__ import annotations

import math
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.national_place_rules import VOIVODESHIPS, province_label, province_slug
from app.zprp_public import match_rules as MR
from app.zprp_public import referee_placeholder as RP

# ---------------------------------------------------------------------------
# Słowniki
# ---------------------------------------------------------------------------

CATEGORY_LABELS: Dict[str, str] = {
    "OS": "Superliga",
    "LC": "Liga Centralna",
    "I": "I liga",
    "II": "II liga",
    "III": "III liga",
    "S": "Seniorzy - inne ligi",
    "J": "Juniorzy",
    "Jm": "Juniorzy mł.",
    "Ml": "Młodzicy",
    "Ml1213": "Dzieci",
    "MP": "Mistrzostwa Polski",
    "PP": "Puchar Polski",
    "SP": "Superpuchar",
    "OTHER": "Pozostałe rozgrywki",
}
CENTRAL_KEYS = frozenset({"OS", "LC", "I", "II", "MP", "PP", "SP"})
AGE_LABELS: Dict[str, str] = {"1": "Seniorzy", "2": "Juniorzy", "3": "Juniorzy młodsi", "4": "Młodzicy", "5": "Dzieci"}
_AGE_FALLBACK = {"1": "S", "2": "J", "3": "Jm", "4": "Ml", "5": "Ml1213"}
GENDER_LABELS: Dict[str, str] = {"M": "Mężczyźni", "K": "Kobiety", "X": "Koedukacyjne"}
LEVEL_LABELS: Dict[str, str] = {"central": "Centralne", "district": "Okręgowe"}
UNKNOWN = "unknown"
NO_MATCH = "_none"
PROVINCES: Tuple[str, ...] = tuple(VOIVODESHIPS)

MIN_MATCHES_AVG = 5
MIN_TEAM_MATCHES = 3
TOP_N = 10
MILESTONES_BASE = (1_000, 5_000, 10_000, 25_000, 50_000, 100_000)
PROJECTION_DAYS = 28


def _fold(text: Any) -> str:
    base = unicodedata.normalize("NFKD", str(text or "").replace("ł", "l").replace("Ł", "l"))
    return "".join(c for c in base if not unicodedata.combining(c)).lower()


_RE_PP = re.compile(r"\bpp\b")
_RE_III = re.compile(r"\b(iii|3)\.? lig")
_RE_II = re.compile(r"\b(ii|2)\.? lig")
_RE_I = re.compile(r"\b(i|1)\.? lig")
_RE_JM = re.compile(r"junior\w* mlodsz|jm[lk]?\b")
_RE_KIDS = re.compile(r"12\s*[-–]\s*13|dzieci")


def league_key(name: Any, age: Any = None) -> str:
    """Klucz kategorii z nazwy rozgrywek (reguły i kolejność jak `categoryOf` w BAZA_web),
    a gdy nazwa nic nie mówi - z kategorii wiekowej ZPRP."""
    s = f" {_fold(name)} "
    if "superpuchar" in s:
        return "SP"
    if "puchar polski" in s or _RE_PP.search(s):
        return "PP"
    if "mistrzostw" in s:
        return "MP"
    if "superlig" in s or "ekstraklas" in s:
        return "OS"
    if "liga centraln" in s:
        return "LC"
    if _RE_III.search(s):
        return "III"
    if _RE_II.search(s):
        return "II"
    if _RE_I.search(s):
        return "I"
    if _RE_JM.search(s):
        return "Jm"
    if "junior" in s:
        return "J"
    if _RE_KIDS.search(s):
        return "Ml1213"
    if "mlodzi" in s or "mlodzik" in s:
        return "Ml"
    return _AGE_FALLBACK.get(str(age or "").strip(), "OTHER")


def level_of(key: str, comp_province: str) -> str:
    return "central" if key in CENTRAL_KEYS or not comp_province else "district"


# ---------------------------------------------------------------------------
# Liczby i tekst
# ---------------------------------------------------------------------------


def pct(part: float, whole: float) -> Optional[float]:
    return round(100.0 * part / whole, 1) if whole else None


def avg(total: float, count: float, nd: int = 2) -> Optional[float]:
    return round(total / count, nd) if count else None


def plural(n: int, one: str, few: str, many: str) -> str:
    n = abs(int(n))
    if n == 1:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def fmt_int(n: Any) -> str:
    return f"{int(n):,}".replace(",", " ")


def fmt_dec(x: Any, nd: int = 1) -> str:
    return f"{float(x):.{nd}f}".replace(".", ",")


_MONTHS = ("stycznia", "lutego", "marca", "kwietnia", "maja", "czerwca", "lipca", "sierpnia",
           "września", "października", "listopada", "grudnia")


def fmt_date(d: Any) -> str:
    if isinstance(d, datetime):
        d = d.date()
    if not isinstance(d, date):
        return ""
    return f"{d.day} {_MONTHS[d.month - 1]}"


def as_datetime(value: Any) -> Optional[datetime]:
    """`scheduled_at` z bazy (Postgres: datetime, SQLite bywa napisem) -> naiwny datetime."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo is None else value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.strip().replace("Z", ""))
        except ValueError:
            return None
    return None


def _s(value: Any) -> Optional[str]:
    """Identyfikatory i nazwy powtarzają się w tysiącach wierszy - jedna kopia w pamięci."""
    return sys.intern(str(value)) if value is not None else None


def _int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Migawka sezonu
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Comp:
    competition_id: str
    name: str
    key: str
    age: Optional[str]
    gender: Optional[str]
    level: str
    province: str


@dataclass(slots=True)
class Club:
    club_id: str
    name: Optional[str]
    logo_url: Optional[str]
    province: str


@dataclass(slots=True)
class Team:
    team_id: str
    name: Optional[str]
    club_id: Optional[str]
    province: str
    competition_name: Optional[str]


@dataclass(slots=True)
class Match:
    match_id: str
    comp: Comp
    province: str
    at: Optional[datetime]
    home_team_id: Optional[str]
    away_team_id: Optional[str]
    home_club_id: Optional[str]
    away_club_id: Optional[str]
    home_team_name: Optional[str]
    away_team_name: Optional[str]
    sh: Optional[int]
    sa: Optional[int]
    hh: Optional[int]
    ha: Optional[int]
    soh: Optional[int]
    soa: Optional[int]
    walkover: bool
    withdrawn: bool
    res: Optional[str]
    spectators: Optional[int]
    refs: Tuple[str, ...]
    code: Optional[str]

    @property
    def played(self) -> bool:
        return self.sh is not None and self.sa is not None

    @property
    def counted(self) -> bool:
        """Do bramek, średnich i rekordów: rozegrany i nie walkower/wycofanie."""
        return self.sh is not None and self.sa is not None and not self.walkover and not self.withdrawn

    @property
    def total(self) -> int:
        return (self.sh or 0) + (self.sa or 0)

    @property
    def margin(self) -> int:
        return abs((self.sh or 0) - (self.sa or 0))


@dataclass(slots=True)
class PlayerAgg:
    player_id: str
    team_id: str
    comp: Comp
    province: str
    apps: int
    goals: int
    pen_g: int
    pen_a: int
    two: int
    red: int
    warn: int


@dataclass(slots=True)
class BigGame:
    match: Match
    player_id: str
    team_id: str
    side: str
    province: str
    goals: int
    pen_g: int


@dataclass
class Frame:
    season_id: Optional[str]
    season_name: Optional[str]
    built_at: datetime
    comps: Dict[str, Comp] = field(default_factory=dict)
    clubs: Dict[str, Club] = field(default_factory=dict)
    teams: Dict[str, Team] = field(default_factory=dict)
    matches: List[Match] = field(default_factory=list)
    by_id: Dict[str, Match] = field(default_factory=dict)
    by_code_day: Dict[Tuple[str, date], Match] = field(default_factory=dict)
    players: List[PlayerAgg] = field(default_factory=list)
    big: List[BigGame] = field(default_factory=list)
    lineup_ids: frozenset = frozenset()
    proel: Dict[str, dict] = field(default_factory=dict)


def comp_from_row(row: dict) -> Comp:
    prov = province_slug(row.get("association_name") or "")
    key = league_key(row.get("name"), row.get("category"))
    gender = str(row.get("gender") or "").strip().upper() or None
    age = str(row.get("category") or "").strip() or None
    return Comp(str(row["competition_id"]), str(row.get("name") or ""), key, age, gender, level_of(key, prov), prov)


def comp_from_name(competition_id: Any, name: Any) -> Comp:
    """Rozgrywki spoza migawki (np. nowe od kwadransa): tylko z nazwy, województwo nieznane."""
    key = league_key(name)
    return Comp(str(competition_id or ""), str(name or ""), key, None, None, level_of(key, ""), "")


def match_province(comp: Comp, home_club_id: Any, clubs: Dict[str, Club]) -> str:
    """Okręgowe - województwo rozgrywek; centralne - województwo klubu gospodarza."""
    if comp.level == "district" and comp.province:
        return comp.province
    club = clubs.get(str(home_club_id or ""))
    if club and club.province:
        return club.province
    return comp.province or UNKNOWN


def _ref_keys(row: dict, memo: Dict[Tuple[Any, Any], Optional[str]]) -> Tuple[str, ...]:
    """Klucze sędziów meczu (bez „brak obsady"). `memo`: sędziów jest setki, meczów dziesiątki tysięcy."""
    out = []
    for idc, nmc in RP.REFEREE_SLOTS:
        pair = (row.get(idc), row.get(nmc))
        if pair not in memo:
            rid, name = RP.clean_official(*pair)
            memo[pair] = sys.intern(rid or f"n:{_fold(name)}") if (rid or name) else None
        key = memo[pair]
        if key and key not in out:
            out.append(key)
    return tuple(out)


def build_frame(
    season: Optional[dict],
    comp_rows: Iterable[dict],
    assoc_rows: Iterable[dict],
    club_rows: Iterable[dict],
    match_rows: Iterable[dict],
    player_rows: Iterable[dict] = (),
    big_rows: Iterable[dict] = (),
    lineup_ids: Iterable[Any] = (),
    built_at: Optional[datetime] = None,
) -> Frame:
    """Wiersze bazy -> zwarta migawka sezonu (CPU, wołane w wątku)."""
    frame = Frame(
        season_id=(season or {}).get("season_id"),
        season_name=(season or {}).get("name"),
        built_at=built_at or datetime.now(timezone.utc),
    )
    assoc_prov: Dict[str, str] = {}
    for a in assoc_rows:
        slug = province_slug(a.get("name") or "") or province_slug(a.get("full_name") or "")
        if a.get("association_id") is not None:
            assoc_prov[str(a["association_id"])] = slug
    for c in club_rows:
        cid = str(c.get("club_id") or "")
        if cid:
            frame.clubs[cid] = Club(cid, c.get("name"), c.get("logo_url"), assoc_prov.get(str(c.get("association_id") or ""), ""))
    for r in comp_rows:
        comp = comp_from_row(r)
        frame.comps[comp.competition_id] = comp

    ref_memo: Dict[Tuple[Any, Any], Optional[str]] = {}
    team_comps: Dict[str, Counter] = defaultdict(Counter)
    team_seen: Dict[str, Tuple[Optional[str], Optional[str], Comp]] = {}
    for r in match_rows:
        cid = str(r.get("competition_id") or "")
        comp = frame.comps.get(cid)
        if comp is None:
            comp = comp_from_name(cid, r.get("competition_name"))
            frame.comps[cid] = comp
        withdrawn = bool(r.get("withdrawn"))
        walkover = bool(r.get("walkover_team_id"))
        res = MR.side_result(r, "home") if r.get("score_home") is not None or walkover else None
        m = Match(
            match_id=str(r["match_id"]),
            comp=comp,
            province=match_province(comp, r.get("home_club_id"), frame.clubs),
            at=as_datetime(r.get("scheduled_at")),
            home_team_id=_s(r.get("home_team_id")), away_team_id=_s(r.get("away_team_id")),
            home_club_id=_s(r.get("home_club_id")), away_club_id=_s(r.get("away_club_id")),
            home_team_name=_s(r.get("home_team_name")), away_team_name=_s(r.get("away_team_name")),
            sh=_int(r.get("score_home")), sa=_int(r.get("score_away")),
            hh=_int(r.get("halftime_home")), ha=_int(r.get("halftime_away")),
            soh=_int(r.get("shootout_home")), soa=_int(r.get("shootout_away")),
            walkover=walkover, withdrawn=withdrawn, res=res,
            spectators=_int(r.get("spectators")) or None,
            refs=_ref_keys(r, ref_memo),
            code=str(r.get("match_code") or "").strip() or None,
        )
        frame.matches.append(m)
        frame.by_id[m.match_id] = m
        if m.code and m.at:
            frame.by_code_day.setdefault((m.code, m.at.date()), m)
        for tid, club, name in ((m.home_team_id, m.home_club_id, m.home_team_name), (m.away_team_id, m.away_club_id, m.away_team_name)):
            if tid:
                team_comps[str(tid)][comp.name] += 1
                team_seen[str(tid)] = (club, name, comp)
    frame.matches.sort(key=lambda m: (m.at or datetime.min, m.match_id))
    for tid, (club, name, comp) in team_seen.items():
        club_obj = frame.clubs.get(str(club or ""))
        prov = (club_obj.province if club_obj else "") or (comp.province if comp.level == "district" else "") or UNKNOWN
        frame.teams[tid] = Team(tid, name, club, prov, team_comps[tid].most_common(1)[0][0] if team_comps[tid] else None)

    def team_prov(tid: Any, comp: Comp) -> str:
        t = frame.teams.get(str(tid or ""))
        if t:
            return t.province
        return comp.province if comp.level == "district" and comp.province else UNKNOWN

    for r in player_rows:
        comp = frame.comps.get(str(r.get("competition_id") or ""))
        if comp is None or not r.get("player_id"):
            continue
        tid = _s(r.get("team_id") or "")
        frame.players.append(PlayerAgg(
            _s(r["player_id"]), tid, comp, team_prov(tid, comp), int(r.get("apps") or 0), int(r.get("goals") or 0),
            int(r.get("penalty_goals") or 0), int(r.get("penalty_attempts") or 0), int(r.get("two_minutes") or 0),
            int(r.get("red_cards") or 0), int(r.get("warnings") or 0),
        ))
    for r in big_rows:
        m = frame.by_id.get(str(r.get("match_id") or ""))
        if m is None or not m.counted:
            continue
        tid = str(r.get("team_id") or "")
        frame.big.append(BigGame(m, str(r["player_id"]), tid, str(r.get("side") or ""), team_prov(tid, m.comp),
                                 int(r.get("goals") or 0), int(r.get("penalty_goals") or 0)))
    frame.lineup_ids = frozenset(str(i) for i in lineup_ids)
    return frame


# ---------------------------------------------------------------------------
# Zakres
# ---------------------------------------------------------------------------


def _list(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    items = value if isinstance(value, (list, tuple)) else str(value).split(",")
    return tuple(sorted({str(v).strip() for v in items if str(v).strip()}))


@dataclass(frozen=True)
class Scope:
    season_id: Optional[str] = None
    gender: Optional[str] = None
    categories: Tuple[str, ...] = ()
    age: Optional[str] = None
    level: Optional[str] = None
    provinces: Tuple[str, ...] = ()

    @classmethod
    def parse(cls, season_id: Any = None, gender: Any = None, category: Any = None, age: Any = None,
              level: Any = None, province: Any = None) -> "Scope":
        g = str(gender or "").strip().upper() or None
        lv = str(level or "").strip().lower() or None
        # Nieznana wartość = pusty wynik (nie błąd), ale jeden wspólny znacznik - klucz pamięci się nie mnoży.
        cats = tuple(sorted({c if c in CATEGORY_LABELS else NO_MATCH for c in _list(category)}))
        provs = tuple(sorted({p if p in VOIVODESHIPS or p == UNKNOWN else NO_MATCH for p in (x.lower() for x in _list(province))}))
        return cls(
            season_id=str(season_id or "").strip() or None,
            gender=g,
            categories=cats,
            age=str(age or "").strip() or None,
            level=lv,
            provinces=provs,
        )

    def with_season(self, season_id: Optional[str]) -> "Scope":
        return Scope(season_id, self.gender, self.categories, self.age, self.level, self.provinces)

    def without_provinces(self) -> "Scope":
        return Scope(self.season_id, self.gender, self.categories, self.age, self.level, ())

    def key(self) -> str:
        return "|".join((self.season_id or "", self.gender or "", ",".join(self.categories), self.age or "",
                         self.level or "", ",".join(self.provinces)))

    def as_dict(self) -> Dict[str, Any]:
        return {"season_id": self.season_id, "gender": self.gender, "category": list(self.categories),
                "age": self.age, "level": self.level, "province": list(self.provinces)}

    def comp_ok(self, c: Comp) -> bool:
        if self.gender and c.gender != self.gender:
            return False
        if self.categories and c.key not in self.categories:
            return False
        if self.age and c.age != self.age:
            return False
        if self.level and c.level != self.level:
            return False
        return True

    def province_ok(self, province: str) -> bool:
        return not self.provinces or province in self.provinces

    def match_ok(self, m: Match) -> bool:
        return self.comp_ok(m.comp) and self.province_ok(m.province)

    def player_ok(self, p: Any) -> bool:
        return self.comp_ok(p.comp) and self.province_ok(p.province)


def scoped(frame: Frame, scope: Scope) -> List[Match]:
    return [m for m in frame.matches if scope.match_ok(m)]


# ---------------------------------------------------------------------------
# Karty wyników (bez nazwisk - te dokłada warstwa bazy)
# ---------------------------------------------------------------------------


def _logo(frame: Frame, club_id: Any) -> Optional[str]:
    c = frame.clubs.get(str(club_id or ""))
    return c.logo_url if c else None


def match_ref(m: Match, frame: Frame, **extra: Any) -> Dict[str, Any]:
    return {
        "match_id": m.match_id,
        "home_team_id": m.home_team_id, "away_team_id": m.away_team_id,
        "home_team_name": m.home_team_name, "away_team_name": m.away_team_name,
        "home_club_id": m.home_club_id, "away_club_id": m.away_club_id,
        "home_logo_url": _logo(frame, m.home_club_id), "away_logo_url": _logo(frame, m.away_club_id),
        "score_home": m.sh, "score_away": m.sa, "shootout_home": m.soh, "shootout_away": m.soa,
        "halftime_home": m.hh, "halftime_away": m.ha,
        "scheduled_at": m.at.isoformat() if m.at else None,
        "competition_id": m.comp.competition_id, "competition_name": m.comp.name,
        "category": m.comp.key, "province": m.province, "score_source": "zprp",
        **extra,
    }


def team_ref(frame: Frame, team_id: Any) -> Dict[str, Any]:
    t = frame.teams.get(str(team_id or ""))
    club_id = t.club_id if t else None
    return {"team_id": team_id, "team_name": t.name if t else None, "club_id": club_id,
            "club_logo_url": _logo(frame, club_id), "province": t.province if t else None}


def player_ref(frame: Frame, player_id: Any, team_id: Any) -> Dict[str, Any]:
    """PlayerRef bez nazwiska - imię, nazwisko i zdjęcie dokłada `stats.fill_players`."""
    t = team_ref(frame, team_id)
    return {"player_id": player_id, "first_name": None, "last_name": None, "photo_url": None,
            "team_id": team_id, "team_name": t["team_name"], "club_id": t["club_id"], "club_logo_url": t["club_logo_url"]}


# ---------------------------------------------------------------------------
# Sezon
# ---------------------------------------------------------------------------


def result_counts(ms: Iterable[Match]) -> Dict[str, Any]:
    rec = {"home_w": 0, "home_wk": 0, "away_wk": 0, "away_w": 0}
    slot = {"W": "home_w", "WK": "home_wk", "LK": "away_wk", "L": "away_w"}
    unresolved = 0
    for m in ms:
        if not m.played and not m.walkover:
            continue
        if m.res in slot:
            rec[slot[m.res]] += 1
        elif m.played:
            unresolved += 1
    decided = sum(rec.values())
    return {"decided": decided, **rec,
            "home_win_pct": pct(rec["home_w"] + rec["home_wk"], decided),
            "away_win_pct": pct(rec["away_w"] + rec["away_wk"], decided),
            "shootout_pct": pct(rec["home_wk"] + rec["away_wk"], decided),
            "unresolved": unresolved}


def _home_won(m: Match) -> Optional[bool]:
    if m.res in ("W", "WK"):
        return True
    if m.res in ("L", "LK"):
        return False
    return None


def halftime_stats(ms: Iterable[Match]) -> Dict[str, Any]:
    n = level = leader = trailer = 0
    for m in ms:
        if not m.counted or m.hh is None or m.ha is None or (m.hh == 0 and m.ha == 0):
            continue
        won = _home_won(m)
        if won is None:
            continue
        n += 1
        if m.hh == m.ha:
            level += 1
        elif (m.hh > m.ha) == won:
            leader += 1
        else:
            trailer += 1
    return {"matches": n, "leader_win_pct": pct(leader, n - level), "trailer_win_pct": pct(trailer, n - level), "level_at_ht": level}


def _histogram(values: Iterable[int], key: str) -> List[Dict[str, int]]:
    counts = Counter(values)
    return [{key: k, "matches": counts[k]} for k in sorted(counts)]


@dataclass
class TeamLine:
    team_id: str
    matches: int = 0
    gf: int = 0
    ga: int = 0
    results: List[Tuple[datetime, str, str]] = field(default_factory=list)


_FLIP = {"W": "L", "L": "W", "WK": "LK", "LK": "WK"}


def team_lines(frame: Frame, scope: Scope) -> Dict[str, TeamLine]:
    """Drużyny zakresu: mecze w zakresie bez województwa, drużyna z województwa zakresu (własny klub)."""
    dims = scope.without_provinces()
    out: Dict[str, TeamLine] = {}
    for m in frame.matches:
        if not dims.comp_ok(m.comp):
            continue
        for tid, mine, theirs, flip in ((m.home_team_id, m.sh, m.sa, False), (m.away_team_id, m.sa, m.sh, True)):
            if not tid:
                continue
            team = frame.teams.get(str(tid))
            if scope.provinces and not scope.province_ok(team.province if team else UNKNOWN):
                continue
            line = out.get(str(tid))
            if line is None:
                line = out[str(tid)] = TeamLine(str(tid))
            if m.counted:
                line.matches += 1
                line.gf += mine or 0
                line.ga += theirs or 0
            code = _FLIP.get(m.res) if flip else m.res
            if code and (m.played or m.walkover):
                line.results.append((m.at or datetime.min, m.match_id, code))
    return out


def longest_win_streak(results: Sequence[Tuple[datetime, str, str]]) -> Optional[Dict[str, Any]]:
    """Najdłuższa seria zwycięstw (W i WK) z chronologicznych wyników drużyny."""
    best: Optional[Tuple[int, int, int]] = None
    run_start = None
    ordered = sorted(results)
    for i, (_, _, code) in enumerate(ordered):
        if code in ("W", "WK"):
            run_start = i if run_start is None else run_start
            length = i - run_start + 1
            if best is None or length > best[0]:
                best = (length, run_start, i)
        else:
            run_start = None
    if not best:
        return None
    length, a, b = best
    return {"length": length, "current": b == len(ordered) - 1,
            "from": ordered[a][0].date().isoformat() if ordered[a][0] != datetime.min else None,
            "to": ordered[b][0].date().isoformat() if ordered[b][0] != datetime.min else None}


def _player_totals(players: Iterable[PlayerAgg]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for p in players:
        t = out.get(p.player_id)
        if t is None:
            t = out[p.player_id] = {"player_id": p.player_id, "apps": 0, "goals": 0, "pen_g": 0, "pen_a": 0, "two": 0,
                                    "red": 0, "warn": 0, "teams": Counter()}
        t["apps"] += p.apps
        t["goals"] += p.goals
        t["pen_g"] += p.pen_g
        t["pen_a"] += p.pen_a
        t["two"] += p.two
        t["red"] += p.red
        t["warn"] += p.warn
        t["teams"][p.team_id] += p.goals * 100 + p.apps
    return out


def _scorer_line(frame: Frame, t: Dict[str, Any]) -> Dict[str, Any]:
    team_id = t["teams"].most_common(1)[0][0] if t["teams"] else None
    return {"player": player_ref(frame, t["player_id"], team_id), "goals": t["goals"], "matches": t["apps"],
            "per_match": avg(t["goals"], t["apps"]), "penalty_goals": t["pen_g"], "penalty_attempts": t["pen_a"],
            "two_minutes": t["two"]}


def season_stats(frame: Frame, scope: Scope) -> Dict[str, Any]:
    ms = scoped(frame, scope)
    counted = [m for m in ms if m.counted]
    goals = sum(m.total for m in counted)
    players = [p for p in frame.players if scope.player_ok(p)]
    totals = _player_totals(players)
    lines = team_lines(frame, scope)
    refs = {r for m in ms for r in m.refs}
    clubs = {frame.teams[t].club_id for t in lines if t in frame.teams and frame.teams[t].club_id}

    scorers = sorted(totals.values(), key=lambda t: (-t["goals"], t["apps"], t["player_id"]))
    by_avg = sorted((t for t in totals.values() if t["apps"] >= MIN_MATCHES_AVG and t["goals"]),
                    key=lambda t: (-t["goals"] / t["apps"], -t["goals"], t["player_id"]))
    by_seven = sorted((t for t in totals.values() if t["pen_g"]), key=lambda t: (-t["pen_g"], t["pen_a"], t["player_id"]))

    def team_row(line: TeamLine) -> Dict[str, Any]:
        team = frame.teams.get(line.team_id)
        return {"team": team_ref(frame, line.team_id), "competition_name": team.competition_name if team else None,
                "matches": line.matches, "goals_for": line.gf, "goals_against": line.ga,
                "gf_pm": avg(line.gf, line.matches), "ga_pm": avg(line.ga, line.matches)}

    eligible = [l for l in lines.values() if l.matches >= MIN_TEAM_MATCHES]
    attack = sorted(eligible, key=lambda l: (-l.gf / l.matches, l.team_id))[:TOP_N]
    defense = sorted(eligible, key=lambda l: (l.ga / l.matches, l.team_id))[:TOP_N]

    streaks = []
    for line in lines.values():
        s = longest_win_streak(line.results)
        if s and s["length"] >= 2:
            streaks.append({"team": team_ref(frame, line.team_id), **s})
    streaks.sort(key=lambda s: (-s["length"], not s["current"], str(s["team"]["team_id"])))

    team_disc: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    for p in players:
        team_disc[p.team_id][0] += p.two
        team_disc[p.team_id][1] += p.red
    two_total = sum(p.two for p in players)
    lineup_matches = sum(1 for m in counted if m.match_id in frame.lineup_ids)

    def disc_row(tid: str, value: int, label: str) -> Dict[str, Any]:
        played = lines[tid].matches if tid in lines else 0
        return {"team": team_ref(frame, tid), label: value, "matches": played, "per_match": avg(value, played)}

    teams_two = sorted(((t, v[0]) for t, v in team_disc.items() if v[0]), key=lambda x: (-x[1], x[0]))[:TOP_N]
    teams_red = sorted(((t, v[1]) for t, v in team_disc.items() if v[1]), key=lambda x: (-x[1], x[0]))[:TOP_N]

    crowd = [m for m in ms if m.spectators]
    attendance = None
    if crowd:
        total_crowd = sum(m.spectators or 0 for m in crowd)
        attendance = {"matches": len(crowd), "total": total_crowd, "avg": round(total_crowd / len(crowd)),
                      "top": [match_ref(m, frame, spectators=m.spectators)
                              for m in sorted(crowd, key=lambda m: (-(m.spectators or 0), m.match_id))[:5]]}

    return {
        "totals": {
            "matches": len(ms),
            "played": sum(1 for m in ms if m.played),
            "remaining": sum(1 for m in ms if not m.played and not m.withdrawn and not m.walkover),
            "walkovers": sum(1 for m in ms if m.played and (m.walkover or m.withdrawn)),
            "goals": goals,
            "avg_goals": avg(goals, len(counted)),
            "avg_home_goals": avg(sum(m.sh or 0 for m in counted), len(counted)),
            "avg_away_goals": avg(sum(m.sa or 0 for m in counted), len(counted)),
            "teams": len(lines), "clubs": len(clubs), "players": len(totals), "referees": len(refs),
        },
        "results": result_counts(ms),
        "halftime": halftime_stats(ms),
        "attendance": attendance,
        "goals_histogram": _histogram((m.total for m in counted), "goals"),
        "margin_histogram": _histogram((m.margin for m in counted), "margin"),
        "top_scorers": [_scorer_line(frame, t) for t in scorers[:15] if t["goals"]],
        "top_scorers_avg": [_scorer_line(frame, t) for t in by_avg[:TOP_N]],
        "top_seven_m": [_scorer_line(frame, t) for t in by_seven[:TOP_N]],
        "teams_attack": [team_row(l) for l in attack],
        "teams_defense": [team_row(l) for l in defense],
        "win_streaks": streaks[:TOP_N],
        "discipline": {
            "two_minutes": two_total,
            "red_cards": sum(p.red for p in players),
            "warnings": sum(p.warn for p in players),
            "two_min_per_match": avg(two_total, lineup_matches),
            "matches_with_lineups": lineup_matches,
            "teams_two_min": [disc_row(t, v, "two_minutes") for t, v in teams_two],
            "teams_red": [disc_row(t, v, "red_cards") for t, v in teams_red],
        },
        "biggest_wins": [match_ref(m, frame, margin=m.margin)
                         for m in sorted(counted, key=lambda m: (-m.margin, -m.total, m.match_id))[:TOP_N] if m.margin],
        "highest_scoring": [match_ref(m, frame, total=m.total)
                            for m in sorted(counted, key=lambda m: (-m.total, -m.margin, m.match_id))[:TOP_N]],
    }


# ---------------------------------------------------------------------------
# Województwa
# ---------------------------------------------------------------------------


def _bucket(ms: Sequence[Match]) -> Dict[str, Any]:
    counted = [m for m in ms if m.counted]
    goals = sum(m.total for m in counted)
    res = result_counts(ms)
    return {"matches": len(ms), "played": sum(1 for m in ms if m.played), "goals": goals,
            "avg_goals": avg(goals, len(counted)), "home_win_pct": res["home_win_pct"], "shootout_pct": res["shootout_pct"]}


def geo_stats(frame: Frame, scope: Scope) -> Dict[str, Any]:
    ms = scoped(frame, scope)
    by_prov: Dict[str, List[Match]] = defaultdict(list)
    for m in ms:
        by_prov[m.province].append(m)
    lines = team_lines(frame, scope)
    teams_by: Dict[str, set] = defaultdict(set)
    clubs_by: Dict[str, set] = defaultdict(set)
    for tid in lines:
        t = frame.teams.get(tid)
        prov = t.province if t else UNKNOWN
        teams_by[prov].add(tid)
        if t and t.club_id:
            clubs_by[prov].add(t.club_id)
    players_by: Dict[str, set] = defaultdict(set)
    level_two: Dict[str, int] = defaultdict(int)
    for p in frame.players:
        if scope.player_ok(p):
            players_by[p.province].add(p.player_id)
            level_two[p.comp.level] += p.two
    wanted = list(scope.provinces) if scope.provinces else list(PROVINCES)
    total = len(ms)

    def row(slug: str) -> Dict[str, Any]:
        part = by_prov.get(slug, [])
        return {"key": slug, "label": province_label(slug) or slug, **_bucket(part),
                "share_pct": pct(len(part), total),
                "clubs": len(clubs_by.get(slug, ())), "teams": len(teams_by.get(slug, ())),
                "players": len(players_by.get(slug, ())),
                "referees": len({r for m in part for r in m.refs})}

    provinces = [row(slug) for slug in wanted if slug in VOIVODESHIPS]
    unknown = row(UNKNOWN) if not scope.provinces and by_prov.get(UNKNOWN) else None

    cats = [k for k in CATEGORY_LABELS if any(m.comp.key == k for m in ms)]
    genders = [g for g in GENDER_LABELS if any(m.comp.gender == g for m in ms)]
    matrix_rows = []
    for slug in [p["key"] for p in provinces]:
        part = by_prov.get(slug, [])
        by_cat: Dict[str, List[Match]] = defaultdict(list)
        by_gen: Dict[str, List[Match]] = defaultdict(list)
        for m in part:
            by_cat[m.comp.key].append(m)
            if m.comp.gender:
                by_gen[m.comp.gender].append(m)

        def cell(group: Sequence[Match]) -> Dict[str, Any]:
            counted = [m for m in group if m.counted]
            g = sum(m.total for m in counted)
            return {"matches": len(group), "goals": g, "avg_goals": avg(g, len(counted))}

        matrix_rows.append({"key": slug, "by_category": {k: cell(v) for k, v in by_cat.items()},
                            "by_gender": {k: cell(v) for k, v in by_gen.items()}})

    levels = {}
    for lv in LEVEL_LABELS:
        part = [m for m in ms if m.comp.level == lv]
        lineup = sum(1 for m in part if m.counted and m.match_id in frame.lineup_ids)
        levels[lv] = {**_bucket(part), "two_min_per_match": avg(level_two.get(lv, 0), lineup)}
    counted = [m for m in ms if m.counted]
    return {
        "provinces": provinces,
        "unknown": unknown,
        "matrix": {"categories": cats, "genders": genders, "rows": matrix_rows},
        "levels": levels,
        "totals": {"matches": total, "played": sum(1 for m in ms if m.played), "goals": sum(m.total for m in counted)},
    }


# ---------------------------------------------------------------------------
# Trendy, kamienie milowe, rekordy
# ---------------------------------------------------------------------------


def _week_start(d: date) -> date:
    return d - timedelta(days=d.weekday())


def weekly_series(ms: Sequence[Match], today: date) -> List[Dict[str, Any]]:
    weeks: Dict[date, List[Match]] = defaultdict(list)
    for m in ms:
        if m.played and m.at and m.at.date() <= today:
            weeks[_week_start(m.at.date())].append(m)
    out = []
    for wk in sorted(weeks):
        part = weeks[wk]
        counted = [m for m in part if m.counted]
        g = sum(m.total for m in counted)
        out.append({"week_start": wk.isoformat(), "matches": len(part), "goals": g, "avg_goals": avg(g, len(counted)),
                    "home_win_pct": result_counts(part)["home_win_pct"]})
    return out


def milestone_steps(limit: int) -> List[int]:
    steps = [s for s in MILESTONES_BASE if s <= limit]
    n = 200_000
    while n <= limit:
        steps.append(n)
        n += 100_000
    return steps


def next_milestone(total: int) -> int:
    for s in MILESTONES_BASE:
        if s > total:
            return s
    return (total // 100_000 + 1) * 100_000


def cumulative(frame: Frame, ms: Sequence[Match], today: date) -> Dict[str, Any]:
    counted = sorted((m for m in ms if m.counted and m.at and m.at.date() <= today), key=lambda m: (m.at, m.match_id))
    daily: Dict[date, int] = defaultdict(int)
    milestones = []
    total = 0
    steps = milestone_steps(sum(m.total for m in counted))
    si = 0
    for m in counted:
        before = total
        total += m.total
        daily[m.at.date()] += m.total
        while si < len(steps) and before < steps[si] <= total:
            milestones.append({"goals": steps[si], "date": m.at.date().isoformat(), "match": match_ref(m, frame)})
            si += 1
    run = 0
    points = []
    for d in sorted(daily):
        run += daily[d]
        points.append({"date": d.isoformat(), "goals": daily[d], "cumulative": run})
    target = next_milestone(total)
    first = counted[0].at.date() if counted else today
    window = max(1, min(PROJECTION_DAYS, (today - first).days + 1))
    recent = sum(v for d, v in daily.items() if today - timedelta(days=window) < d <= today)
    rate = recent / window if window else 0.0
    projected = None
    if rate > 0:
        projected = (today + timedelta(days=math.ceil((target - total) / rate))).isoformat()
    return {"total_goals": total, "daily": points, "milestones": milestones,
            "next_milestone": {"goals": target, "remaining": target - total, "rate_per_day": round(rate, 1),
                               "projected_date": projected}}


def record(kind: str, title: str, value: Any, unit: str, match: Optional[dict] = None, player: Optional[dict] = None,
           side: Optional[str] = None, minute: Optional[int] = None, detail: Optional[str] = None,
           source: str = "zprp") -> Dict[str, Any]:
    return {"kind": kind, "title": title, "value": value, "unit": unit, "match": match, "player": player,
            "side": side, "minute": minute, "detail": detail, "source": source}


def match_records(frame: Frame, scope: Scope) -> List[Dict[str, Any]]:
    ms = scoped(frame, scope)
    counted = [m for m in ms if m.counted]
    out: List[Dict[str, Any]] = []
    if counted:
        top = max(counted, key=lambda m: (m.total, m.margin, m.match_id))
        out.append(record("highest_scoring_match", "Najwięcej bramek w meczu", top.total, plural(top.total, "bramka", "bramki", "bramek"), match_ref(top, frame)))
        win = max(counted, key=lambda m: (m.margin, m.total, m.match_id))
        if win.margin:
            out.append(record("biggest_win", "Najwyższe zwycięstwo", win.margin, plural(win.margin, "bramka", "bramki", "bramek"),
                              match_ref(win, frame), side="home" if (win.sh or 0) > (win.sa or 0) else "away"))
        hi = max(counted, key=lambda m: (max(m.sh or 0, m.sa or 0), m.match_id))
        best = max(hi.sh or 0, hi.sa or 0)
        out.append(record("most_goals_team", "Najwięcej bramek jednej drużyny", best, plural(best, "bramka", "bramki", "bramek"),
                          match_ref(hi, frame), side="home" if (hi.sh or 0) >= (hi.sa or 0) else "away"))
    big = [b for b in frame.big if scope.comp_ok(b.match.comp) and scope.province_ok(b.province)]
    if big:
        b = max(big, key=lambda b: (b.goals, -b.pen_g, b.match.match_id))
        out.append(record("top_individual_game", "Najwięcej bramek zawodnika w meczu", b.goals, plural(b.goals, "bramka", "bramki", "bramek"),
                          match_ref(b.match, frame), player_ref(frame, b.player_id, b.team_id), side=b.side))
        sev = [x for x in big if x.pen_g]
        if sev:
            s = max(sev, key=lambda b: (b.pen_g, b.goals, b.match.match_id))
            out.append(record("most_seven_m_game", "Najwięcej trafionych rzutów karnych w meczu", s.pen_g,
                              plural(s.pen_g, "rzut karny", "rzuty karne", "rzutów karnych"),
                              match_ref(s.match, frame), player_ref(frame, s.player_id, s.team_id), side=s.side))
    crowd = [m for m in ms if m.spectators]
    if crowd:
        m = max(crowd, key=lambda m: (m.spectators or 0, m.match_id))
        out.append(record("highest_attendance", "Najwięcej widzów", m.spectators, plural(m.spectators or 0, "widz", "widzów", "widzów"),
                          match_ref(m, frame)))
    return out


def busiest_day(ms: Sequence[Match], today: date) -> Optional[Tuple[date, int]]:
    days = Counter(m.at.date() for m in ms if m.played and m.at and m.at.date() <= today)
    if not days:
        return None
    d, n = max(days.items(), key=lambda kv: (kv[1], kv[0]))
    return d, n


def province_leader(frame: Frame, scope: Scope, min_matches: int = 20) -> Optional[Tuple[str, float]]:
    sums: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    for m in scoped(frame, scope):
        if m.counted and m.province in VOIVODESHIPS:
            sums[m.province][0] += m.total
            sums[m.province][1] += 1
    eligible = [(p, g / n) for p, (g, n) in sums.items() if n >= min_matches]
    if len(eligible) < 2:
        return None
    return max(eligible, key=lambda x: (x[1], x[0]))


# ---------------------------------------------------------------------------
# Ciekawostki: szablony i składanie
# ---------------------------------------------------------------------------

FACT_TEMPLATES: Dict[str, str] = {
    "goals_per_minute": "W tym zakresie pada średnio {rate} bramki na minutę gry.",
    "avg_goals": "Średnio {avg} bramek w meczu - łącznie {total} w {matches} {matches_noun}.",
    "home_advantage": "Gospodarze wygrywają {home}% meczów, goście {away}%.",
    "shootouts": "Rzuty karne po remisie rozstrzygnęły {count} {noun} ({pct}% rozegranych).",
    "top_scorer": "{name} prowadzi w klasyfikacji strzelców: {goals} {goals_noun} w {matches} {matches_noun}.",
    "busiest_day": "Najwięcej meczów jednego dnia: {count} ({date}).",
    "province_goals": "Najwięcej bramek na mecz pada w województwie {label}: średnio {avg}.",
    "halftime": "Drużyna prowadząca do przerwy wygrywa {pct}% meczów.",
    "one_goal_games": "{pct}% meczów kończy się różnicą jednej bramki.",
    "milestone": "Bramka nr {goals} sezonu padła {date} w meczu {home} - {away}.",
    "next_milestone": "Do bramki nr {goals} brakuje {remaining} - w tym tempie padnie około {date}.",
    "attendance": "Rekord frekwencji: {count} {noun} na meczu {home} - {away}.",
    "teams_clubs": "W rozgrywkach gra {teams} {teams_noun} z {clubs} {clubs_noun}.",
    "streak": "Najdłuższa seria zwycięstw: {team} - {length} z rzędu.",
    "last5": "{pct}% bramek w protokołach elektronicznych pada w ostatnich 5 minutach meczu.",
    "sevens": "Rzuty karne (7 m) wpadają w {pct}% prób.",
    "first_goal": "Drużyna, która rzuca pierwszą bramkę, wygrywa {pct}% meczów.",
    "comeback": "Największy powrót: odrobiona strata {deficit} {noun} w meczu {home} - {away}.",
    "power_play": "Gra w przewadze daje średnio {pp} bramki na mecz, a kara 2 minut kosztuje ukaranych {window} bramki bilansu.",
}


def _fact(kind: str, value: Any, match_id: Optional[str] = None, **fmt: Any) -> Dict[str, Any]:
    return {"kind": kind, "text": FACT_TEMPLATES[kind].format(**fmt), "value": value, "match_id": match_id}


def _person(p: Optional[dict]) -> str:
    if not p:
        return ""
    return f'{p.get("first_name") or ""} {p.get("last_name") or ""}'.strip()


def build_facts(season: Dict[str, Any], trends: Dict[str, Any], proel: Optional[Dict[str, Any]],
                busiest: Optional[Tuple[date, int]], leader: Optional[Tuple[str, float]], limit: int = 12) -> List[Dict[str, Any]]:
    """Ciekawostki z policzonych sekcji (imiona i nazwiska już dołożone). Kolejność = ciekawość."""
    out: List[Dict[str, Any]] = []
    t = season.get("totals") or {}
    res = season.get("results") or {}
    cum = (trends or {}).get("cumulative") or {}
    counted_matches = sum(h["matches"] for h in season.get("goals_histogram") or [])
    if cum.get("milestones"):
        ms = cum["milestones"][-1]
        mt = ms.get("match") or {}
        out.append(_fact("milestone", ms["goals"], mt.get("match_id"), goals=fmt_int(ms["goals"]),
                         date=fmt_date(date.fromisoformat(ms["date"])), home=mt.get("home_team_name") or "?",
                         away=mt.get("away_team_name") or "?"))
    nm = cum.get("next_milestone") or {}
    if nm.get("projected_date") and nm.get("remaining"):
        out.append(_fact("next_milestone", nm["goals"], goals=fmt_int(nm["goals"]), remaining=fmt_int(nm["remaining"]),
                         date=fmt_date(date.fromisoformat(nm["projected_date"]))))
    top = (season.get("top_scorers") or [None])[0]
    if top and top.get("goals") and _person(top.get("player")):
        out.append(_fact("top_scorer", top["goals"], name=_person(top["player"]), goals=top["goals"],
                         goals_noun=plural(top["goals"], "bramka", "bramki", "bramek"), matches=top["matches"],
                         matches_noun="meczu" if top["matches"] == 1 else "meczach"))
    if t.get("avg_goals"):
        out.append(_fact("goals_per_minute", round(t["avg_goals"] / 60, 2), rate=fmt_dec(t["avg_goals"] / 60, 2)))
        out.append(_fact("avg_goals", t["avg_goals"], avg=fmt_dec(t["avg_goals"]), total=fmt_int(t["goals"]),
                         matches=fmt_int(counted_matches), matches_noun="meczu" if counted_matches == 1 else "meczach"))
    if res.get("home_win_pct") is not None and res.get("decided", 0) >= 10:
        out.append(_fact("home_advantage", res["home_win_pct"], home=fmt_dec(res["home_win_pct"]), away=fmt_dec(res["away_win_pct"])))
    so = (res.get("home_wk") or 0) + (res.get("away_wk") or 0)
    if so:
        out.append(_fact("shootouts", so, count=fmt_int(so), noun=plural(so, "mecz", "mecze", "meczów"), pct=fmt_dec(res["shootout_pct"])))
    ht = season.get("halftime") or {}
    if ht.get("leader_win_pct") is not None and ht.get("matches", 0) >= 10:
        out.append(_fact("halftime", ht["leader_win_pct"], pct=fmt_dec(ht["leader_win_pct"])))
    if proel and (proel.get("matches") or 0) >= 5:
        if proel.get("last5_share_pct") is not None:
            out.append(_fact("last5", proel["last5_share_pct"], pct=fmt_dec(proel["last5_share_pct"])))
        if proel.get("first_goal_winner_pct") is not None:
            out.append(_fact("first_goal", proel["first_goal_winner_pct"], pct=fmt_dec(proel["first_goal_winner_pct"])))
        sev = proel.get("sevens") or {}
        if sev.get("pct") is not None:
            out.append(_fact("sevens", sev["pct"], pct=fmt_dec(sev["pct"])))
        big = (proel.get("comebacks") or {}).get("biggest")
        if big and big.get("deficit"):
            mt = big.get("match") or {}
            out.append(_fact("comeback", big["deficit"], mt.get("match_id"), deficit=big["deficit"],
                             noun=plural(big["deficit"], "bramki", "bramek", "bramek"),
                             home=mt.get("home_team_name") or "?", away=mt.get("away_team_name") or "?"))
    margins = {h["margin"]: h["matches"] for h in season.get("margin_histogram") or []}
    if counted_matches >= 10 and margins.get(1):
        p = pct(margins[1], counted_matches)
        out.append(_fact("one_goal_games", p, pct=fmt_dec(p)))
    streak = (season.get("win_streaks") or [None])[0]
    if streak and streak.get("length", 0) >= 3 and (streak.get("team") or {}).get("team_name"):
        out.append(_fact("streak", streak["length"], team=streak["team"]["team_name"], length=streak["length"]))
    if leader:
        out.append(_fact("province_goals", round(leader[1], 2), label=province_label(leader[0]), avg=fmt_dec(leader[1])))
    if busiest and busiest[1] >= 2:
        out.append(_fact("busiest_day", busiest[1], count=fmt_int(busiest[1]), date=fmt_date(busiest[0])))
    att = season.get("attendance") or {}
    if att.get("top"):
        mt = att["top"][0]
        out.append(_fact("attendance", mt.get("spectators"), mt.get("match_id"), count=fmt_int(mt.get("spectators") or 0),
                         noun=plural(mt.get("spectators") or 0, "widza", "widzów", "widzów"),
                         home=mt.get("home_team_name") or "?", away=mt.get("away_team_name") or "?"))
    if t.get("teams") and t.get("clubs"):
        out.append(_fact("teams_clubs", t["teams"], teams=fmt_int(t["teams"]), teams_noun=plural(t["teams"], "drużyna", "drużyny", "drużyn"),
                         clubs=fmt_int(t["clubs"]), clubs_noun="klubu" if t["clubs"] == 1 else "klubów"))
    return out[:limit]


# ---------------------------------------------------------------------------
# Filtry
# ---------------------------------------------------------------------------


def filter_options(frame: Frame) -> Dict[str, Any]:
    genders: Counter = Counter()
    cats: Counter = Counter()
    ages: Counter = Counter()
    levels: Counter = Counter()
    provs: Counter = Counter()
    cat_level: Dict[str, Counter] = defaultdict(Counter)
    for m in frame.matches:
        c = m.comp
        if c.gender:
            genders[c.gender] += 1
        cats[c.key] += 1
        cat_level[c.key][c.level] += 1
        if c.age:
            ages[c.age] += 1
        levels[c.level] += 1
        provs[m.province] += 1
    clubs_by: Dict[str, int] = Counter(c.province for c in frame.clubs.values() if c.province)
    return {
        "genders": [{"key": k, "label": GENDER_LABELS[k], "matches": genders[k]} for k in GENDER_LABELS if genders[k]],
        "categories": [{"key": k, "label": CATEGORY_LABELS[k], "matches": cats[k], "level": cat_level[k].most_common(1)[0][0]}
                       for k in CATEGORY_LABELS if cats[k]],
        "ages": [{"key": k, "label": AGE_LABELS[k], "matches": ages[k]} for k in AGE_LABELS if ages[k]],
        "levels": [{"key": k, "label": LEVEL_LABELS[k], "matches": levels[k]} for k in LEVEL_LABELS if levels[k]],
        "provinces": [{"key": k, "label": VOIVODESHIPS[k], "matches": provs[k], "clubs": clubs_by.get(k, 0)} for k in PROVINCES],
    }


def weekday_average(frame: Frame, scope: Scope, today: date) -> Dict[str, Any]:
    """Średnia z dni sezonu przed dziś o tym samym dniu tygodnia, w których grano (zakres jak dziś)."""
    days: Dict[date, List[int]] = defaultdict(lambda: [0, 0, 0])
    for m in scoped(frame, scope):
        if not m.at or m.at.date() >= today or m.at.weekday() != today.weekday():
            continue
        d = days[m.at.date()]
        d[0] += 1
        if m.counted:
            d[1] += m.total
            d[2] += 1
    n = len(days)
    matches = sum(v[0] for v in days.values())
    goals = sum(v[1] for v in days.values())
    counted = sum(v[2] for v in days.values())
    return {"weekday": today.weekday(), "days": n, "matches": avg(matches, n, 1), "goals": avg(goals, n, 1),
            "avg_goals": avg(goals, counted)}


def day_summary(frame: Frame, scope: Scope, day: date) -> Dict[str, Any]:
    part = [m for m in scoped(frame, scope) if m.at and m.at.date() == day]
    counted = [m for m in part if m.counted]
    g = sum(m.total for m in counted)
    return {"date": day.isoformat(), "matches": len(part), "played": sum(1 for m in part if m.played), "goals": g,
            "avg_goals": avg(g, len(counted))}
