"""Trybuna: jedna lista wyników szukania (Bastion + YouTube + "baza"), trafność wobec ZAPYTANIA i cel dodania.

Kontrakt: `docs/mentor-panel.md` 8.11 ("Przebudowa wyszukiwania"). Zasady:
  - pewność (`sure`) i `confidence` liczy się wobec zapytania i meczu, którego dotyczy wynik (kod meczu co do litery, drużyny,
    dzień) - tym samym `score_game` co dla kaset; "oficjalność" kanału YouTube (`official`) jest OSOBNYM sygnałem i pewności nie daje,
  - kod w zapytaniu ("LCM/32") różny od kodu meczu wyniku zabija wynik (confidence 0), a nie tylko go obniża,
  - `best` tylko przy `sure` albo wyraźnej przewadze; dwa różne pewne mecze naraz = brak `best` (wybiera człowiek),
  - cel dodania (`target`): wynik pasujący do meczu TEJ pary (ID ZPRP albo kod+dzień+drużyny) -> `pair_match` (istniejące
    `POST /pairs/{p}/matches/{m}/videos`, do oceny), inaczej `trybuna`.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from app import mentor_bastion_search as S
from app import mentor_panel_rules as R

CODE_RE = re.compile(r"[A-Za-zĄ-Żą-ż]{1,6}\s*/\s*\d{1,3}[A-Za-z]?")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}\.\d{1,2}\.\d{4}")
QUERY_NOISE = re.compile(r"\bOR\b|[\"()]|(?<!\w)-\w+")
#: Poniżej tej pewności wynik nie trafia do listy `ranked`.
RANK_MIN = 25
#: `best` bez pieczątki: pewność i przewaga nad drugim.
BEST_CONF = 70
BEST_GAP = 25
TITLE_PREFIX = re.compile(r"^\s*[A-ZĄ-Ż0-9]{2,6}\s*:\s*")
TITLE_CODE = re.compile(r"\b([A-Za-z]{1,6}/\d{1,3}[A-Za-z]?)\b")


def parse_query(q: Any, date_hint: Optional[date] = None) -> Dict[str, Any]:
    """Zapytanie -> kody meczów ("LCM/32"), daty, słowa (rdzenie drużyn). `date_hint` = dzień z filtra (od == do)."""
    text = R.s(q)
    codes = [re.sub(r"\s+", "", m) for m in CODE_RE.findall(text)]
    dates = []
    for m in DATE_RE.findall(text):
        d = S.parse_day(m)
        if d:
            dates.append(d)
    if date_hint:
        dates.append(date_hint)
    rest = DATE_RE.sub(" ", CODE_RE.sub(" ", text))
    rest = QUERY_NOISE.sub(" ", rest)
    words = [w for w in S.team_tokens(rest) if len(w) >= 3][:6] if rest.strip() else []
    return {"codes": codes, "dates": dates, "words": words}


def empty_profile(profile: Mapping[str, Any]) -> bool:
    return not (profile.get("codes") or profile.get("dates") or profile.get("words"))


def _team_hit(words: Iterable[str], name: Any) -> bool:
    tokens = set(S.team_tokens(name))
    return any(w in tokens or S.team_similarity(w, name) >= 0.8 for w in words)


def query_score(profile: Mapping[str, Any], card: Mapping[str, Any], extra_names: Iterable[Any] = ()) -> Dict[str, Any]:
    """Pewność wyniku wobec zapytania: kod (co do litery), drużyny (słowa z zapytania w nazwach), dzień. `card` = mecz wyniku
    (`match_code`, `home.name`, `away.name`, `scheduled_at`); `extra_names` = dodatkowe nazwy (np. z tytułu filmu)."""
    codes, words, dates = profile.get("codes") or [], profile.get("words") or [], profile.get("dates") or []
    if empty_profile(profile):
        return {"confidence": 40, "sure": False, "signals": {"code": None, "teams": None, "date": None}}
    code: Any = None
    card_code = S._alnum(card.get("match_code"))
    if codes and card_code:
        mine = [S._alnum(c) for c in codes]
        code = True if card_code in mine else "case" if card_code.casefold() in {c.casefold() for c in mine} else False
    teams: Optional[str] = None
    if words:
        home, away = (card.get("home") or {}).get("name"), (card.get("away") or {}).get("name")
        names = list(extra_names)
        h = _team_hit(words, home) or any(_team_hit(words, n) for n in names)
        a = _team_hit(words, away) or (len(names) > 1 and _team_hit(words, names[-1]))
        teams = "both" if h and a else "one" if h or a else "none"
    day: Optional[str] = None
    if dates:
        cd = S.card_day(card)
        if cd:
            diff = min(abs((d - cd).days) for d in dates)
            day = "same" if diff == 0 else "near" if diff == 1 else "far"
    points = {True: 55, "case": 25, False: -60, None: 0}[code] + {"both": 40, "one": 20, "none": -20, None: 0}[teams] \
        + {"same": 15, "near": 5, "far": -25, None: 0}[day]
    sure = (code is True and teams != "none" and day != "far") or (teams == "both" and day == "same" and code is not False)
    if code is False:
        confidence = 0  # inny kod meczu niż w zapytaniu: to nie jest ten mecz
    else:
        confidence = 100 if sure else max(0, min(99, 30 + points))
    return {"confidence": confidence, "sure": sure and code is not False, "signals": {"code": code, "teams": teams, "date": day}}


def title_game(title: Any, starts_local: Optional[str]) -> Dict[str, Any]:
    """Film z YouTube jako "kaseta": drużyny z tytułu ("LCM: AZS AGH Kraków - ENERGA Gwardia Koszalin"), kod jeśli jest w tytule, data startu."""
    from app import mentor_trybuna_rules as T

    text = TITLE_PREFIX.sub("", R.s(title))
    snap = T.snapshot_from_title(text)
    m = TITLE_CODE.search(R.s(title))
    return {"home": (snap.get("home") or {}).get("name"), "away": (snap.get("away") or {}).get("name"), "date": starts_local,
            "code": m.group(1) if m else None, "competition": None}


def video_consistent(video: Mapping[str, Any], card: Mapping[str, Any]) -> bool:
    """Czy film mówi o meczu, do którego go przypisano (drużyny z tytułu zgodne z kartą; brak drużyn w tytule = brak zastrzeżeń)."""
    if not (video.get("home") or video.get("away")) or not (card.get("home") or card.get("away")):
        return True
    return S.score_game(video, card)["signals"]["teams"] != "none"


def rank_key(item: Mapping[str, Any]) -> Tuple[Any, ...]:
    day = S.parse_day(item.get("date"))
    return (0 if item.get("sure") else 1, -int(item.get("confidence") or 0), -(day.toordinal() if day else 0))


def best_key(ranked: List[Mapping[str, Any]]) -> Optional[str]:
    """`best`: pierwszy pewny (gdy wszystkie pewne dotyczą tego samego meczu - ten sam kod), albo wyraźny lider (>= 70 i +25)."""
    if not ranked:
        return None
    top = ranked[0]
    if top.get("sure"):
        others = {R.s(r.get("code")) for r in ranked[1:] if r.get("sure") and R.s(r.get("code"))}
        if others - {R.s(top.get("code"))}:
            return None
        return top["key"]
    second = int(ranked[1]["confidence"]) if len(ranked) > 1 else 0
    return top["key"] if int(top["confidence"]) >= BEST_CONF and int(top["confidence"]) - second >= BEST_GAP else None


def pair_target(game_like: Mapping[str, Any], pair_cards: Iterable[Mapping[str, Any]], zprp_id: Any = None) -> Dict[str, Any]:
    """Cel dodania: mecz tej pary (ID ZPRP albo kod+dzień+drużyny) albo Trybuna."""
    cards = list(pair_cards)
    hit = next((c for c in cards if zprp_id and R.s(c.get("match_id")) == R.s(zprp_id)), None)
    if hit is None:
        best, best_conf = None, 0
        for c in cards:
            scored = S.score_game(game_like, c)
            if scored["confidence"] >= 75 and scored["signals"].get("code") is not False and scored["signals"].get("category") != "diff" \
                    and scored["confidence"] > best_conf:
                best, best_conf = c, scored["confidence"]
        hit = best
    if hit is not None:
        name = " - ".join(x for x in ((hit.get("home") or {}).get("name"), (hit.get("away") or {}).get("name")) if x)
        return {"kind": "pair_match", "match_id": hit["match_id"], "label": f"Mecz pary: {name}".strip(": ")}
    return {"kind": "trybuna", "match_id": None, "label": "Trybuna (cudzy mecz)"}


def fold_baza(ranked: List[Dict[str, Any]], best: Optional[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Wpis "baza" nie dubluje `best`: gdy `best` to ten sam mecz co wpis "baza" (wspólny `target.match_id`), wpis "baza" znika z listy,
    a odpowiedź dostaje `best_in_baza: true` i `best_match_id`. Zwraca (lista, {best_in_baza, best_match_id})."""
    info: Dict[str, Any] = {"best_in_baza": False, "best_match_id": None}
    top = next((r for r in ranked if r["key"] == best), None) if best else None
    if top is None:
        return ranked, info
    mid = (top.get("target") or {}).get("match_id") or (top.get("ref") or {}).get("match_id")
    if not mid:
        return ranked, info
    kept = [r for r in ranked if not (r["source"] == "baza" and r is not top and (r.get("ref") or {}).get("match_id") == mid)]
    info["best_in_baza"] = len(kept) != len(ranked) or top["source"] == "baza"
    info["best_match_id"] = mid
    return kept, info


def identity(entry: Mapping[str, Any]) -> str:
    """Tożsamość meczu wyniku: kod meczu + dzień (czas polski), inaczej drużyny + dzień, inaczej sam klucz wpisu. Dzień meczu bierze się
    z `match_day` (film z YouTube: dzień MECZU, nie transmisji), inaczej z `date`."""
    day = S.parse_day(entry.get("match_day")) or S.parse_day(entry.get("date"))
    code = S._alnum(entry.get("code")).casefold()
    if code and day:
        return f"c:{code}|{day.isoformat()}"
    teams = sorted(S.fold(x) for x in (entry.get("home"), entry.get("away")) if x)
    if teams and day:
        return f"t:{'|'.join(teams)}|{day.isoformat()}"
    return f"k:{entry.get('key')}"


def _has_video(entry: Mapping[str, Any]) -> bool:
    return entry.get("source") == "bastion" and entry.get("state") == "video" and bool((entry.get("ref") or {}).get("bunny_item_id"))


def source_info(entry: Mapping[str, Any]) -> Dict[str, Any]:
    ref = entry.get("ref") or {}
    out: Dict[str, Any] = {"source": entry["source"], "key": entry["key"], "confidence": entry.get("confidence"), "sure": bool(entry.get("sure"))}
    if entry["source"] == "bastion":
        out.update(bunny_item_id=ref.get("bunny_item_id"), game_id=ref.get("game_id"), video_state=entry.get("video_state") or entry.get("state"),
                   url=entry.get("url"))
    elif entry["source"] == "youtube":
        out.update(video_id=ref.get("video_id"), url=ref.get("url"), official=bool(entry.get("official")))
    else:
        out.update(match_id=ref.get("match_id"))
    return out


def merge_ranked(ranked: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ten sam mecz z kilku źródeł (kaseta z nagraniem, ta sama bez nagrania, film YouTube, wpis z "bazy") = JEDEN wpis z listą
    `sources`. Wersja główna: kaseta Bastionu Z NAGRANIEM, inaczej pierwsza w kolejności trafności. Wpis ma `in_baza` / `baza_match_id`,
    gdy któryś ze źródeł to mecz pary albo Trybuny pary; `target` bierze najlepszy z grupy (mecz pary > mecz z Trybuny > nowy)."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    for e in ranked:
        gid = identity(e)
        if gid not in groups:
            groups[gid] = []
            order.append(gid)
        groups[gid].append(e)
    merged: List[Dict[str, Any]] = []
    for gid in order:
        members = groups[gid]
        primary = next((m for m in members if _has_video(m)), members[0])
        out = dict(primary)
        out["sources"] = [source_info(m) for m in sorted(members, key=lambda m: (m is not primary, rank_key(m)))]
        out["confidence"] = max(int(m.get("confidence") or 0) for m in members)
        out["sure"] = any(m.get("sure") for m in members)
        baza = next((m for m in members if m["source"] == "baza"), None)
        out["in_baza"] = baza is not None
        out["baza_match_id"] = (baza.get("ref") or {}).get("match_id") if baza else None
        rank = {"pair_match": 0, "trybuna": 1}
        targets = [m.get("target") for m in members if m.get("target")]
        with_id = [x for x in targets if x.get("match_id")]
        out["target"] = (sorted(with_id, key=lambda x: rank.get(x.get("kind"), 2)) or targets or [None])[0]
        merged.append(out)
    merged.sort(key=rank_key)
    return merged


def best_info(ranked: List[Mapping[str, Any]], best: Optional[str]) -> Dict[str, Any]:
    """`best_in_baza` / `best_match_id` dla wybranego `best` (wpis jest już scalony z wpisem "baza")."""
    top = next((r for r in ranked if r["key"] == best), None) if best else None
    if top is None:
        return {"best_in_baza": False, "best_match_id": None}
    return {"best_in_baza": bool(top.get("in_baza")), "best_match_id": top.get("baza_match_id") or (top.get("target") or {}).get("match_id")}


def counts(ranked: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    """Liczniki spójne z `ranked`: ile wpisów ma dane źródło wśród `sources`."""
    out = {"ranked": 0, "bastion": 0, "youtube": 0, "baza": 0}
    for r in ranked:
        out["ranked"] += 1
        for s in {x["source"] for x in r.get("sources") or [{"source": r["source"]}]}:
            out[s] = out.get(s, 0) + 1
    return out
