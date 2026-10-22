"""Nagrania meczu dla mentorów - znaczniki, synchronizacja, oś meczu (liść).

ZNACZNIK to „skocz do 12:34 - kara 2 min". Dwa rodzaje:
  - ręczny: czas W NAGRANIU (`video_s`) wpisany przez sędziego,
  - z protokołu ProEla: czas MECZU (`match_ms`, jak w przebiegu protokołu,
    liczony od pierwszego gwizdka) i połowa. Na czas w nagraniu przelicza go
    aplikacja z synchronizacji nagrania (poniżej) - dzięki temu poprawienie
    „początku meczu w nagraniu" przesuwa od razu wszystkie znaczniki.

SYNCHRONIZACJA (`sync`) - raz na nagranie:
  - `match_start_s`  sekunda nagrania z pierwszym gwizdkiem,
  - `second_half_s`  sekunda nagrania z początkiem II połowy (opcjonalna;
                     bez niej aplikacja dolicza przerwę z konfiguracji meczu
                     i pokazuje czas jako przybliżony),
  - `half_minutes`, `break_minutes` z konfiguracji meczu w ProElu,
  - `stream_start_ms` prawdziwa godzina (UTC, ms) sekundy 0:00 nagrania -
                     dla transmisji YouTube z serwera (`app/link_preview.py`),
  - `kickoff_wall_ms`, `second_half_wall_ms` godzina pierwszego gwizdka
                     i wznowienia II połowy ze śladu zegara ProEla
                     (`app/match_clock_rules.py`) - zapamiętane w nagraniu,
                     bo migawki, z których je liczymy, wygasają.

GODZINA ZDARZENIA. Znacznik z protokołu niesie też `wall_ms` (o której
zegar meczu pokazał ten czas) i `wall_err_s` (deklarowany błąd). Aplikacja
liczy sekundę filmu z godziny: od kotwicy w tej samej połowie, a bez kotwic
od godziny startu transmisji. Przerwy w grze przestają wtedy przesuwać akcje.

STATUS MENTORA w prośbie o ocenę: wysłano -> przeczytane -> ocenił.
„Przeczytane" stawia serwer, gdy mentor otworzy szczegóły meczu (każda
wersja aplikacji pyta wtedy `GET /mentor-evaluations/match/{id}`).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional

MAX_MARKERS = 80
MAX_LABEL = 80
MAX_VIDEO_SECONDS = 6 * 3600
MAX_MATCH_MS = 3 * 3600 * 1000
MARKER_KINDS = ("manual", "goal", "seven", "penalty", "card", "timeout")
#: Rodzaje akcji znacznika „Ważne" (16.10.2026: pięć zamiast ośmiu) - lustro
#: `MARKER_CATEGORIES` w `BAZA/utils/matchVideoLinks.ts`.
MARKER_CATEGORIES = ("dobra", "zla", "dyskusja", "pytanie", "kluczowa")
#: Stare kategorie z zapisanych danych i starszych aplikacji -> nowy rodzaj.
#: Oryginał zostaje w `legacy_category`, gdy niesie więcej niż nowy rodzaj.
LEGACY_CATEGORIES: Dict[str, str] = {
    "trafna": "dobra",
    "bledna": "zla",
    "dyskusja": "dyskusja",
    "ustawienie": "dyskusja",
    "wspolpraca": "dyskusja",
    "kontrola": "dyskusja",
    "gwizdek": "dyskusja",
    "inne": "dyskusja",
}
#: Zakres nagrany przyciskiem REC: najdłużej 10 minut.
MAX_RANGE_S = 600
MAX_COMMENT = 280
#: Godzina ścienna w ms UTC: od 2020 do 2100 - wszystko inne to śmieć.
MIN_WALL_MS = 1_577_836_800_000
MAX_WALL_MS = 4_102_444_800_000

#: Rodzaje zdarzeń przebiegu ProEla -> rodzaj znacznika i opis.
EVENT_KINDS: Dict[str, tuple[str, str]] = {
    "goal": ("goal", "Bramka"),
    "penaltyKickScored": ("seven", "Rzut karny 7 m - bramka"),
    "penaltyKickMissed": ("seven", "Rzut karny 7 m - niewykorzystany"),
    "warning": ("card", "Upomnienie"),
    "penalty1": ("penalty", "Kara 2 min"),
    "penalty2": ("penalty", "II kara 2 min"),
    "penalty3": ("penalty", "III kara 2 min"),
    "penaltyExtra": ("penalty", "Kara dodatkowa 2 min"),
    "disqualification": ("card", "Dyskwalifikacja"),
    "disqualificationBlue": ("card", "Dyskwalifikacja z opisem"),
    "teamTime": ("timeout", "Czas dla drużyny"),
}

_ID = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def _num(value: Any) -> Optional[float]:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return n if n == n else None  # NaN


def _label(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    # Myślniki długie i półpauzy zamieniamy na zwykły dywiz (zasada BAZY).
    text = text.replace("—", "-").replace("–", "-")
    return text[:MAX_LABEL]


def clean_sync(raw: Any) -> Dict[str, Any]:
    src = raw if isinstance(raw, Mapping) else {}
    out: Dict[str, Any] = {}
    for key in ("match_start_s", "second_half_s"):
        n = _num(src.get(key))
        out[key] = int(round(n)) if n is not None and 0 <= n <= MAX_VIDEO_SECONDS else None
    half = _num(src.get("half_minutes"))
    out["half_minutes"] = int(half) if half and 5 <= half <= 60 else None
    brk = _num(src.get("break_minutes"))
    out["break_minutes"] = int(brk) if brk is not None and 0 <= brk <= 60 else None
    for key in ("stream_start_ms", "kickoff_wall_ms", "second_half_wall_ms"):
        out[key] = _wall(src.get(key))
    return out


def _wall(value: Any) -> Optional[int]:
    n = _num(value)
    return int(n) if n is not None and MIN_WALL_MS <= n <= MAX_WALL_MS else None


def normalize_category(raw: Any, legacy: Any = None) -> tuple[Optional[str], Optional[str]]:
    """Rodzaj akcji + stara kategoria, jeśli przy mapowaniu zgubiłaby treść.

    trafna/bledna/dyskusja mają dokładny odpowiednik, reszta starych trafia
    do „dyskusja" i zostaje zapamiętana w `legacy_category`.
    """
    key = str(raw or "")
    old = str(legacy or "")
    old = old if old in LEGACY_CATEGORIES and LEGACY_CATEGORIES[old] != old and old not in ("trafna", "bledna") else None
    if key in MARKER_CATEGORIES:
        return key, old
    if key in LEGACY_CATEGORIES:
        mapped = LEGACY_CATEGORIES[key]
        return mapped, (key if key not in ("trafna", "bledna", "dyskusja") else None)
    return None, None


def clean_markers(raw: Any) -> List[Dict[str, Any]]:
    """Znaczniki od klienta: odrzuca śmieci, przycina opisy, pilnuje limitu."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, Mapping):
            continue
        marker_id = str(item.get("id") or "").strip()
        if not _ID.match(marker_id) or marker_id in seen:
            continue
        label = _label(item.get("label"))
        kind = str(item.get("kind") or "manual")
        if kind not in MARKER_KINDS:
            kind = "manual"
        video_s = _num(item.get("video_s"))
        match_ms = _num(item.get("match_ms"))
        video_s = int(round(video_s)) if video_s is not None and 0 <= video_s <= MAX_VIDEO_SECONDS else None
        match_ms = int(match_ms) if match_ms is not None and 0 <= match_ms <= MAX_MATCH_MS else None
        if video_s is None and match_ms is None:
            continue
        half = item.get("half")
        half = int(half) if half in (1, 2, "1", "2") else None
        if not label:
            label = "Znacznik"
        etype = str(item.get("type") or "")
        wall_ms = _wall(item.get("wall_ms")) if match_ms is not None else None
        wall_err = _num(item.get("wall_err_s"))
        important = item.get("important") is True
        category, legacy = normalize_category(item.get("category"), item.get("legacy_category"))
        if important and category is None:
            category = "dyskusja"
        # Koniec zakresu (REC) - tylko przy znaczniku z czasem nagrania.
        end_s = _num(item.get("end_s"))
        end_s = int(round(end_s)) if end_s is not None and video_s is not None and video_s < end_s <= min(video_s + MAX_RANGE_S, MAX_VIDEO_SECONDS) else None
        comment = re.sub(r"[ 	]+", " ", str(item.get("comment") or "")).replace("—", "-").replace("–", "-").strip()[:MAX_COMMENT] or None
        seen.add(marker_id)
        out.append(
            {
                "id": marker_id,
                "label": label,
                "kind": kind,
                "video_s": video_s,
                "end_s": end_s,
                "match_ms": match_ms,
                "half": half if match_ms is not None else None,
                "source_key": str(item.get("source_key") or "")[:80] or None,
                "type": etype if etype in EVENT_KINDS else None,
                "wall_ms": wall_ms,
                "wall_err_s": int(min(max(wall_err, 0), 3600)) if wall_ms is not None and wall_err is not None else None,
                # „Ważne do oceny" - para wskazuje mentorowi, na co patrzeć.
                "important": important,
                "category": category if important else None,
                "legacy_category": legacy if important and legacy else None,
                "comment": comment if important else None,
            }
        )
        if len(out) >= MAX_MARKERS:
            break
    return out


def _clock(ms: int) -> str:
    s = max(0, int(ms) // 1000)
    return f"{s // 60:02d}:{s % 60:02d}"


def timeline_from_blob(blob: Any) -> Dict[str, Any]:
    """Oś meczu z zapisu ProEla - zdarzenia do zaimportowania jako znaczniki.

    Bez serii rzutów karnych (nie mają własnego zegara) i bez usuniętych bramek.
    """
    data = blob if isinstance(blob, Mapping) else {}
    cfg = data.get("matchConfig") if isinstance(data.get("matchConfig"), Mapping) else {}
    teams = {
        "host": str(cfg.get("hostTeamName") or "Gospodarze").strip(),
        "guest": str(cfg.get("guestTeamName") or "Goście").strip(),
    }
    cards: Dict[str, Dict[str, str]] = {}
    for side in ("host", "guest"):
        source = cfg.get(f"{side}PlayerCards") or data.get(f"{side}PlayerCards") or []
        cards[side] = {
            str(c.get("number")): str(c.get("fullName") or "").strip()
            for c in source
            if isinstance(c, Mapping) and c.get("number") is not None
        }
    half = _num(cfg.get("halfTime"))
    brk = _num(cfg.get("halfBreak"))
    events: List[Dict[str, Any]] = []
    for raw in data.get("protocol") or []:
        if not isinstance(raw, Mapping) or raw.get("shootout"):
            continue
        etype = str(raw.get("type") or "")
        if etype not in EVENT_KINDS:
            continue
        ms = _num(raw.get("time"))
        if ms is None or ms < 0 or ms > MAX_MATCH_MS:
            continue
        kind, title = EVENT_KINDS[etype]
        team = str(raw.get("team") or "")
        player = str(raw.get("player") if raw.get("player") is not None else "").strip()
        who = ""
        if player:
            if player == "Tr":
                who = "trener"
            elif player == "Os":
                who = "osoba towarzysząca"
            elif not player.isdigit():
                who = f"os. tow. {player}"
            else:
                name = cards.get(team, {}).get(player, "")
                surname = name.split(" ")[0] if name else ""
                who = f"nr {player}{' ' + surname if surname else ''}"
        half_no = raw.get("half")
        half_no = int(half_no) if half_no in (1, 2, "1", "2") else None
        score = str(raw.get("score") or "").strip()
        team_short = teams.get(team, "")
        label = title
        if who:
            label += f" - {who}"
        if team_short:
            label += f" ({team_short})"
        events.append(
            {
                "key": f"{etype}:{team}:{player}:{int(ms)}",
                "type": etype,
                "kind": kind,
                "match_ms": int(ms),
                "half": half_no,
                "clock": _clock(int(ms)),
                "team": team if team in teams else None,
                "label": _label(label),
                "score": score[:12] or None,
            }
        )
    events.sort(key=lambda e: e["match_ms"])
    return {
        "available": bool(events),
        "half_minutes": int(half) if half and 5 <= half <= 60 else 30,
        "break_minutes": int(brk) if brk is not None and 0 <= brk <= 60 else 10,
        "teams": teams,
        "colors": {
            side: _hex_color(cfg.get(f"{side}JerseyColor") or data.get(f"{side}JerseyColor"))
            for side in ("host", "guest")
        },
        "events": events,
    }


def _hex_color(value: Any) -> Any:
    """Kolor koszulki z meczu ProEla jako #rrggbb albo None."""
    text = str(value or "").strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", text):
        return text.lower()
    return None


def mentor_states(
    *,
    assigned: Iterable[str],
    requests: Iterable[Mapping[str, Any]],
    published_authors: Iterable[str],
    drafting_authors: Iterable[str] = (),
) -> Dict[str, Dict[str, Any]]:
    """Stan każdego przypisanego mentora: none / sent / read / rated.

    „Ocenił" wygrywa zawsze (opublikowana ocena, także bez prośby).
    """
    published = {str(a) for a in published_authors}
    drafting = {str(a) for a in drafting_authors}
    by_mentor = {str(r.get("mentor_id")): r for r in requests}
    out: Dict[str, Dict[str, Any]] = {}
    for mentor_id in sorted({str(m) for m in assigned}):
        req = by_mentor.get(mentor_id)
        if mentor_id in published:
            state = "rated"
        elif req and req.get("read_at"):
            state = "read"
        elif req:
            state = "sent"
        else:
            state = "none"
        out[mentor_id] = {
            "state": state,
            "drafting": mentor_id in drafting and state != "rated",
            "sent_at": req.get("last_sent_at") if req else None,
            "read_at": req.get("read_at") if req else None,
            "rated_at": req.get("fulfilled_at") if req else None,
        }
    return out


def should_mark_read(*, actor_id: str, request: Mapping[str, Any]) -> bool:
    """Przeczytanie liczy się tylko dla adresata, raz, i nie po wykonaniu prośby."""
    return (
        str(request.get("mentor_id") or "") == str(actor_id)
        and not request.get("read_at")
        and not request.get("fulfilled_at")
    )
