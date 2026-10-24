"""Reguły transmisji - czyste funkcje (bez sieci i bazy). Kontrakt: `docs/streams.md`.

* poziom rozgrywek (`OS` Superliga, `LC` Liga Centralna, `I` I liga, `MP-J`
  Mistrzostwa Polski młodzieży, `PP`, `II`, `other`) i jego waga,
* dopasowanie filmu do meczu: obie drużyny w tytule (nazwy jak
  `proel_live_rules.fold`, z prostą odmianą: wspólne 5 pierwszych liter),
  okno czasu (start transmisji ±3 h od rozpoczęcia meczu albo publikacja
  w oknie -10 dni…+3 dni), brak sprzeczności (junior/kobiety vs mecz),
* pewność: `official` / `confirmed` / `possible` (słabsze nie istnieją),
* plan sprawdzeń kanałów (60 min przed meczem co 5 min, w trakcie co 3 min,
  do 24 h po meczu co godzinę, poza tym raz na dobę) i wybór wyszukiwań,
* kształty odpowiedzi (`Stream`, `Link`, `Channel`).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Optional
from zoneinfo import ZoneInfo

from app.time_pl import has_kickoff_time
from app.protocol_category import classify_match_code
from app.zprp_public.proel_live_rules import fold

WARSAW = ZoneInfo("Europe/Warsaw")

CONFIDENCE_RANK = {"possible": 1, "confirmed": 2, "official": 3}
STATE_RANK = {"live": 0, "upcoming": 1, "vod": 2, "link": 3}
TIER_PRIORITY = {"OS": 5, "LC": 4, "I": 3, "MP-J": 2, "PP": 2, "II": 1, "other": 0}
#: Poziomy, dla których wolno wydać wyszukiwanie YouTube (100 jednostek).
SEARCH_TIERS = ("OS", "LC", "I", "MP-J")

LIVE_SPAN = timedelta(hours=2, minutes=15)
DAILY = timedelta(hours=24)

#: Tytuły, które nie są transmisją meczu (wywiady, skróty, zapowiedzi...).
_NOT_BROADCAST = re.compile(
    r"\b(wywiad\w*|konferencj\w*|zapowied\w*|trening\w*|kulis\w*|vlog\w*|magazyn\w*|podsumowan\w*|"
    r"skrot\w*|highlights?|najlepsze akcje|bramki meczu|interview|press)\b"
)
_YOUTH = re.compile(r"\b(junior\w*|juniork\w*|mlodzik\w*|mlodziczk\w*|kadet\w*|dziec\w*|u1[4-9]|u2[01])\b")
_SENIOR = re.compile(r"\b(superlig\w*|liga centralna|lidze centralnej|senior\w*)\b")
_WOMEN = re.compile(r"\b(kobiet\w*|women)\b")
_MEN = re.compile(r"\b(mezczyzn\w*|men)\b")
#: Data w tytule tylko z rokiem („22.10.2026”) - samo „18.10” bywa godziną.
_DATE = re.compile(r"\b([0-3]?\d)[./-]([01]?\d)[./-](\d{4}|\d{2})\b")

_STOP = {"ks", "mks", "uks", "sms", "kps", "spr", "klub", "sportowy", "ii", "iii", "ssr", "kpr", "azs", "sp", "zo",
         "sa", "zprp", "handball", "team", "pilka", "reczna", "pilki", "recznej", "stowarzyszenie", "sport", "sportu"}


# ---------------------------------------------------------------------------
# Daty
# ---------------------------------------------------------------------------


def aware(value: Any) -> Optional[datetime]:
    """Wartość z bazy (naiwna = UTC) → aware UTC."""
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def kickoff_utc(scheduled_at: Any) -> Optional[datetime]:
    """`scheduled_at` meczu (naiwny czas warszawski) → aware UTC."""
    if not isinstance(scheduled_at, datetime):
        return None
    if scheduled_at.tzinfo is not None:
        return scheduled_at.astimezone(timezone.utc)
    return scheduled_at.replace(tzinfo=WARSAW).astimezone(timezone.utc)


def warsaw_iso(value: Any) -> Optional[str]:
    """Aware/naiwny-UTC → naiwny czas warszawski ISO (jak `scheduled_at` w kartach)."""
    dt = aware(value)
    return dt.astimezone(WARSAW).replace(tzinfo=None).isoformat() if dt else None


def timed_kickoff(match: dict[str, Any]) -> Optional[datetime]:
    """Kickoff do okien czasowych (szukanie, „na żywo", plan sprawdzeń) - None, gdy
    ZPRP nie podał godziny (00:00 = do ustalenia): taki mecz nie „startuje o północy"."""
    return match.get("kickoff") if match.get("kickoff_known", True) else None


def state_kickoff(match: dict[str, Any]) -> Optional[datetime]:
    """Kickoff dla `state_without_api`: bez godziny - koniec doby meczu minus LIVE_SPAN
    (film „upcoming" do północy, potem „vod")."""
    kickoff = match.get("kickoff")
    if kickoff is None or match.get("kickoff_known", True):
        return kickoff
    day_end = kickoff.astimezone(WARSAW).replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    return day_end.replace(tzinfo=WARSAW).astimezone(timezone.utc) - LIVE_SPAN


def pacific_day(now: datetime) -> str:
    """Doba limitu YouTube API (Google liczy ją wg czasu pacyficznego)."""
    return now.astimezone(ZoneInfo("America/Los_Angeles")).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Rozgrywki
# ---------------------------------------------------------------------------

_CODE_TIER = {"superliga": "OS", "superpuchar": "OS", "liga_centralna": "LC", "i_liga": "I", "ii_liga": "II",
              "pp": "PP", "mp": "MP-J"}


def is_youth(*texts: Any) -> bool:
    return any(_YOUTH.search(fold(t)) for t in texts if t)


def competition_tier(name: Any = "", match_code: Any = "", category: Any = "") -> str:
    """Poziom rozgrywek z nazwy (pierwszeństwo), potem z numeru meczu."""
    n = " ".join(fold(name).split())
    youth = is_youth(name, category)
    if "superlig" in n and not youth:
        return "OS"
    if "liga centralna" in n and not youth:
        return "LC"
    if "mistrzostw" in n and youth:
        return "MP-J"
    if "puchar polski" in n and not youth:
        return "PP"
    if re.search(r"(^|\s)ii liga\b", n):
        return "II"
    if re.search(r"(^|\s)i liga\b", n) and not youth:
        return "I"
    kind = classify_match_code(match_code).competition
    if kind in ("junior", "junior_ml", "mlodzik", "mlodzik_ml") or (kind == "mp" and youth):
        return "MP-J" if "mistrzostw" in n or kind == "mp" else "other"
    tier = _CODE_TIER.get(kind, "other")
    return "other" if youth and tier in ("OS", "LC", "I", "PP") else tier


def gender_of(gender: Any = "", match_code: Any = "") -> str:
    g = fold(gender).strip()[:1].upper()
    if g in ("K", "M"):
        return g
    return classify_match_code(match_code).gender or ""


# ---------------------------------------------------------------------------
# Dopasowanie filmu do meczu
# ---------------------------------------------------------------------------


def name_tokens(name: Any) -> set[str]:
    return {w for w in fold(name).split() if len(w) > 2 and w not in _STOP}


def _hit(token: str, words: set[str]) -> bool:
    if token in words:
        return True
    if len(token) < 5:
        return False
    return any(len(w) >= 5 and w[:5] == token[:5] for w in words)


def team_score(team_name: Any, text: Any) -> tuple[float, int]:
    """(pokrycie słów nazwy drużyny w tekście 0..1, liczba trafionych słów)."""
    tokens = name_tokens(team_name)
    if not tokens:
        return 0.0, 0
    words = set(fold(text).split())
    hits = sum(1 for t in tokens if _hit(t, words))
    return hits / len(tokens), hits


def team_level(team_name: Any, text: Any) -> str:
    """`strong` (cała nazwa albo ≥2 słowa), `weak` (≥ połowa nazwy), `none`."""
    cover, hits = team_score(team_name, text)
    if hits and (cover >= 0.999 or hits >= 2):
        return "strong"
    if hits and cover >= 0.5:
        return "weak"
    return "none"


def title_dates(title: Any) -> list[date]:
    out = []
    for d, m, y in _DATE.findall(str(title or "")):
        yy = int(y)
        if yy < 100:
            yy += 2000
        try:
            out.append(date(yy, int(m), int(d)))
        except ValueError:
            continue
    return out


def time_fit(kickoff: Optional[datetime], start: Optional[datetime], *, broadcast: bool, title: Any = "") -> str:
    """`exact` (start transmisji ±3 h / data w tytule), `near` (publikacja w oknie), `none`."""
    if kickoff is None:
        return "none"
    local_day = kickoff.astimezone(WARSAW).date()
    dates = title_dates(title)
    if dates and local_day not in dates:
        return "none"  # tytuł mówi o innym dniu - inny mecz tych samych drużyn
    if start is None:
        return "near" if dates else "none"
    delta = start - kickoff
    if broadcast:
        if abs(delta) <= timedelta(hours=3):
            return "exact"
        return "near" if dates else "none"
    if timedelta(days=-10) <= delta <= timedelta(days=3):
        return "exact" if dates else "near"
    return "none"


def conflicts(title: Any, match: dict[str, Any]) -> bool:
    """Tytuł mówi o innej kategorii/płci niż mecz."""
    t = fold(title)
    if _NOT_BROADCAST.search(t):
        return True
    youth = bool(match.get("youth"))
    if _YOUTH.search(t) and not youth:
        return True
    if youth and _SENIOR.search(t):
        return True
    gender = match.get("gender") or ""
    if gender == "M" and _WOMEN.search(t):
        return True
    if gender == "K" and _MEN.search(t):
        return True
    return False


@dataclass(frozen=True)
class Verdict:
    home: str
    away: str
    time: str

    @property
    def both_strong(self) -> bool:
        return self.home == "strong" and self.away == "strong"

    @property
    def both_hit(self) -> bool:
        return self.home != "none" and self.away != "none"


def judge(video: dict[str, Any], match: dict[str, Any], *, own_club: Optional[str] = None) -> Optional[Verdict]:
    """Film × mecz → `Verdict` albo None (nie ten mecz).

    `own_club` = klub właściciela kanału: jego strona meczu liczy się jako
    trafiona (klub pisze „Mecz z Pogonią”), ale wtedy wymagamy pewnego czasu.
    """
    title = video.get("title") or ""
    if conflicts(title, match):
        return None
    if video.get("duration_s") and video.get("state") == "vod" and int(video["duration_s"]) < 20 * 60:
        return None  # skrót, nie mecz
    home = team_level(match.get("home_team_name"), title)
    away = team_level(match.get("away_team_name"), title)
    if own_club and own_club == match.get("home_club_id") and home == "none":
        home = "own"
    if own_club and own_club == match.get("away_club_id") and away == "none":
        away = "own"
    broadcast = bool(video.get("is_broadcast")) or video.get("state") in ("live", "upcoming")
    start = video.get("starts_at") if broadcast else (video.get("published") or video.get("starts_at"))
    fit = time_fit(match.get("kickoff"), start, broadcast=broadcast, title=title)
    if fit == "none" or home == "none" or away == "none":
        return None
    if "own" in (home, away):
        other = away if home == "own" else home
        if other != "strong" or fit != "exact":
            return None
        home, away = ("strong", away) if home == "own" else (home, "strong")
    return Verdict(home=home, away=away, time=fit)


def confidence(verdict: Verdict, channel: Optional[dict[str, Any]], match: dict[str, Any]) -> Optional[str]:
    """Pewność wpisu dla dopasowania z kanału (`channel` None = wynik wyszukiwania/podpowiedzi)."""
    kind = (channel or {}).get("kind")
    verified = bool((channel or {}).get("verified"))
    clubs = {match.get("home_club_id"), match.get("away_club_id")} - {None, ""}
    own = bool(channel and channel.get("club_id") and channel.get("club_id") in clubs)
    if verdict.both_strong:
        if kind == "official" and verified:
            return "official"
        if kind == "club" and own:
            return "official" if verified else "confirmed"
        if kind in ("club", "producer", "broadcaster", "official"):
            return "confirmed"
        return "confirmed" if verdict.time == "exact" else "possible"
    if verdict.both_hit:
        if kind in ("official", "producer") and verified and verdict.time == "exact":
            return "confirmed"
        return "possible"
    return None


def best_match(video: dict[str, Any], matches: Iterable[dict[str, Any]], channel: Optional[dict[str, Any]] = None
               ) -> Optional[tuple[dict[str, Any], str]]:
    """Najlepszy mecz dla filmu: (mecz, pewność) albo None. Remis dwóch meczów = nic (niepewne)."""
    own = (channel or {}).get("club_id") if (channel or {}).get("kind") == "club" else None
    scored = []
    for match in matches:
        verdict = judge(video, match, own_club=own)
        if verdict is None:
            continue
        level = confidence(verdict, channel, match)
        if level is None:
            continue
        rank = (CONFIDENCE_RANK[level], verdict.time == "exact", verdict.both_strong)
        scored.append((rank, match, level))
    if not scored:
        return None
    scored.sort(key=lambda s: s[0], reverse=True)
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        return None
    return scored[0][1], scored[0][2]


def merge_confidence(old: Optional[str], new: str, *, locked: bool) -> str:
    if locked and old:
        return old
    if not old:
        return new
    return old if CONFIDENCE_RANK.get(old, 0) >= CONFIDENCE_RANK.get(new, 0) else new


def state_without_api(kickoff: Optional[datetime], now: datetime) -> str:
    """Film z RSS bez potwierdzenia API: przed końcem meczu „upcoming”, potem „vod”.
    Nigdy „live” z samego zegara."""
    if kickoff and now < kickoff + LIVE_SPAN:
        return "upcoming"
    return "vod"


# ---------------------------------------------------------------------------
# Plan sprawdzeń
# ---------------------------------------------------------------------------


def window_interval(kickoff: datetime, now: datetime) -> Optional[timedelta]:
    """Interwał sprawdzania kanału ze względu na JEDEN mecz (None = mecz nie wpływa)."""
    if kickoff - timedelta(minutes=60) <= now < kickoff:
        return timedelta(minutes=5)
    if kickoff <= now <= kickoff + LIVE_SPAN:
        return timedelta(minutes=3)
    if kickoff + LIVE_SPAN < now <= kickoff + timedelta(hours=24):
        return timedelta(hours=1)
    return None


def next_check_at(kickoffs: Iterable[datetime], now: datetime) -> datetime:
    """Kiedy następnym razem sprawdzić kanał: najkrótszy interwał z meczów, a gdy
    mecz dopiero będzie - najpóźniej na 60 min przed nim."""
    best = now + DAILY
    for kickoff in kickoffs:
        interval = window_interval(kickoff, now)
        if interval is not None:
            best = min(best, now + interval)
        elif now < kickoff - timedelta(minutes=60):
            best = min(best, kickoff - timedelta(minutes=60))
    return best


def scope_of(channel: dict[str, Any]) -> list[str]:
    raw = channel.get("scope") if "scope" in channel else channel.get("scope_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "[]")
        except ValueError:
            raw = []
    return [str(x) for x in raw] if isinstance(raw, list) else []


def relevant_matches(channel: dict[str, Any], matches: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mecze, które mogą być na tym kanale: kanał klubu - mecze klubu; oficjalny/producent -
    mecze z poziomów `scope`; nadawca bez zakresu - wszystkie; kafelek TV - żadne."""
    kind = channel.get("kind")
    if kind == "tv" or channel.get("platform") != "youtube":
        return []
    if kind == "club":
        club = channel.get("club_id")
        return [m for m in matches if club and club in (m.get("home_club_id"), m.get("away_club_id"))]
    scope = scope_of(channel)
    if not scope:
        return list(matches) if kind == "broadcaster" else []
    return [m for m in matches if m.get("tier") in scope]


def pick_search_targets(matches: Iterable[dict[str, Any]], covered: set[str], searched: dict[str, int],
                        now: datetime, remaining: int, per_cycle: int = 2) -> list[tuple[dict[str, Any], str]]:
    """Mecze do wyszukania w YouTube: ważne poziomy, bez znalezionej transmisji,
    od 30 min przed do 100 min po rozpoczęciu; najwyżej raz „upcoming” i raz „live”."""
    out = []
    for m in sorted(matches, key=lambda m: (-TIER_PRIORITY.get(m.get("tier") or "other", 0), m.get("kickoff") or now)):
        if len(out) >= min(per_cycle, max(0, remaining)):
            break
        kickoff = timed_kickoff(m)
        if m.get("tier") not in SEARCH_TIERS or not kickoff or m["match_id"] in covered:
            continue
        if kickoff - timedelta(minutes=30) <= now < kickoff:
            event = "upcoming"
        elif kickoff <= now <= kickoff + timedelta(minutes=100):
            event = "live"
        else:
            continue
        if searched.get(f"{m['match_id']}:{event}", 0) >= 1:
            continue
        out.append((m, event))
    return out


def search_query(match: dict[str, Any]) -> str:
    def short(name: Any) -> str:
        words = [w for w in str(name or "").split() if fold(w).strip() not in _STOP]
        return " ".join(words[:3])

    return f"{short(match.get('home_team_name'))} {short(match.get('away_team_name'))}".strip()


# ---------------------------------------------------------------------------
# Kształty odpowiedzi
# ---------------------------------------------------------------------------


def embed_url(platform: str, video_id: Optional[str]) -> Optional[str]:
    if platform == "youtube" and video_id:
        return f"https://www.youtube-nocookie.com/embed/{video_id}"
    return None


def channel_view(row: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not row:
        return None
    return {"title": row.get("title"), "url": row.get("url"), "kind": row.get("kind"), "verified": bool(row.get("verified"))}


def stream_view(row: dict[str, Any], channel: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    platform = row.get("platform") or "other"
    ch = channel_view(channel)
    if ch is None and (row.get("channel_title") or row.get("channel_url")):
        ch = {"title": row.get("channel_title"), "url": row.get("channel_url"), "kind": None, "verified": False}
    return {
        "id": row.get("id"),
        "match_id": row.get("match_id"),
        "platform": platform,
        "url": row.get("url"),
        "embed_url": embed_url(platform, row.get("video_id")),
        "video_id": row.get("video_id"),
        "title": row.get("title"),
        "thumbnail_url": row.get("thumbnail_url"),
        "channel": ch,
        "state": row.get("state") or "link",
        "starts_at": warsaw_iso(row.get("starts_at")),
        "duration_s": row.get("duration_s") if row.get("state") == "vod" else None,
        "confidence": row.get("confidence") or "possible",
    }


def sort_streams(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(items, key=lambda s: (STATE_RANK.get(s.get("state"), 9), -CONFIDENCE_RANK.get(s.get("confidence"), 0),
                                        s.get("starts_at") or ""))


def public_channel(row: dict[str, Any]) -> dict[str, Any]:
    return {"id": row.get("id"), "platform": row.get("platform"), "title": row.get("title"), "url": row.get("url"),
            "handle": row.get("handle"), "kind": row.get("kind"), "verified": bool(row.get("verified"))}


def admin_channel(row: dict[str, Any]) -> dict[str, Any]:
    def iso(v: Any) -> Optional[str]:
        dt = aware(v)
        return dt.isoformat() if dt else None

    return {**public_channel(row), "channel_id": row.get("channel_id"), "playlist_id": row.get("playlist_id"),
            "club_id": row.get("club_id"), "association_id": row.get("association_id"), "scope": scope_of(row),
            "active": bool(row.get("active", True)), "discovered_from": row.get("discovered_from"),
            "last_checked_at": iso(row.get("last_checked_at")), "next_check_at": iso(row.get("next_check_at")),
            "error": row.get("error")}


def channel_link(row: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Kanał jako kafelek `Link` („Gdzie oglądać”)."""
    if not row.get("url"):
        return None
    facebook = row.get("platform") == "facebook"
    return {"platform": "facebook" if facebook else "youtube", "title": row.get("title") or ("Facebook" if facebook else "YouTube"),
            "url": row["url"], "kind": "facebook" if facebook else "channel", "note": None}


def where_to_watch(tier: str, tier_channels: list[dict[str, Any]], club_channels: list[dict[str, Any]],
                   tv_links: dict[str, Any]) -> list[dict[str, Any]]:
    """Kafelki: TV/płatne poziomu, kanał oficjalny/producenta poziomu, kanały klubów (YouTube, potem Facebook)."""
    out: list[dict[str, Any]] = [dict(link) for link in tv_links.get(tier, ())]
    rows = list(tier_channels) + sorted(club_channels, key=lambda r: r.get("platform") == "facebook")
    seen = {link["url"] for link in out}
    for row in rows:
        link = channel_link(row)
        if link and link["url"] not in seen:
            seen.add(link["url"])
            out.append(link)
    return out


def match_context(row: dict[str, Any]) -> dict[str, Any]:
    """Wiersz meczu (+ `comp_name`, `comp_category`, `comp_gender`) → kontekst dopasowania."""
    name = row.get("comp_name") or row.get("competition_name")
    category = row.get("comp_category") or ""
    return {
        "match_id": str(row.get("match_id")),
        "competition_id": row.get("competition_id"),
        "home_team_name": row.get("home_team_name"),
        "away_team_name": row.get("away_team_name"),
        "home_club_id": row.get("home_club_id"),
        "away_club_id": row.get("away_club_id"),
        "scheduled_at": row.get("scheduled_at"),
        "kickoff": kickoff_utc(row.get("scheduled_at")),
        "kickoff_known": has_kickoff_time(row.get("scheduled_at")),
        "tier": competition_tier(name, row.get("match_code"), category),
        "gender": gender_of(row.get("comp_gender"), row.get("match_code")),
        "youth": is_youth(name, category),
        "stream_url": row.get("stream_url"),
        "withdrawn": bool(row.get("withdrawn")),
    }
