"""Kanał YouTube pary -> mecze pary (18.11.2026): czysta logika rozpoznawania tytułów i dopasowania. Bez bazy i sieci.

Tytuł filmu na kanale sędziego („28.02.2026 - KS Otmęt Krapkowice vs MKS MOS Śląsk Wrocław (II połowa)”,
„29.03.2025 IMC_MKS Wieluń - Enea Orlęta Zwoleń”, „21.10.2023 SUMKS Jedynka Myślenice   KS VIVE II KIELCE”) rozkładamy
na datę, gospodarza, gościa, połowę i przedrostek numeru meczu. Dopasowanie szuka TYLKO wśród meczów pary (kart z
`pair_match_cards`), więc obsada jest z założenia Wasza - liczą się data, drużyny i numer:
  - `sure`     pewne:   ta sama data i obie drużyny (silnie albo jedna silnie, druga słabo),
  - `likely`   prawdopodobne: data ±1 dzień i obie drużyny, albo ta sama data i jedna drużyna, albo brak daty w tytule
               i obie drużyny silnie (jedyny taki mecz pary),
  - `possible` możliwe: obie drużyny bez zgodnej daty (np. rewanż) - do ręcznego sprawdzenia,
  - brak      film nie pasuje do żadnego meczu pary.
Powody (`reasons`) idą wprost do przeglądu: „data”, „gospodarz”, „gość”, „numer IMC”, „druga połowa”.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.streams.rules import fold, team_level

CONFIDENCES = ("sure", "likely", "possible")
RANK = {"sure": 3, "likely": 2, "possible": 1, None: 0}

_DATE = re.compile(r"(?<!\d)(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{4}|\d{2})(?!\d)")
_ISO = re.compile(r"(?<!\d)(20\d{2})-(\d{2})-(\d{2})(?!\d)")
_HALF = re.compile(r"\(?\s*\b(II|I|2|1)\s*\.?\s*(?:po[łl]owa|po[łl]\.?|half)\b\s*\)?", re.I)
_CODE = re.compile(r"^\s*([A-Z]{2,5}\d?)\s*[_/]\s*")
_SEP = re.compile(r"\s+(?:vs\.?|v\.?|–|—|-|:)\s+|\s{3,}", re.I)
_NOISE = re.compile(r"\b(?:mecz|transmisja|live|na żywo|full match|cały mecz|skrót|highlights)\b", re.I)


def _year(y: str) -> int:
    return 2000 + int(y) if len(y) == 2 else int(y)


def parse_title(title: Any) -> Dict[str, Any]:
    """{date: 'yyyy-mm-dd'|None, home, away, half: 1|2|None, code: 'IMC'|None, rest} - drużyny jako tekst z tytułu."""
    text = str(title or "").strip()
    found: Optional[date] = None
    m = _DATE.search(text)
    if m:
        try:
            found = date(_year(m.group(3)), int(m.group(2)), int(m.group(1)))
        except ValueError:
            found = None
        text = (text[:m.start()] + " " + text[m.end():]).strip()
    else:
        m = _ISO.search(text)
        if m:
            try:
                found = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                found = None
            text = (text[:m.start()] + " " + text[m.end():]).strip()
    half: Optional[int] = None
    h = _HALF.search(text)
    if h:
        half = 2 if h.group(1).upper() in ("II", "2") else 1
        text = (text[:h.start()] + " " + text[h.end():]).strip()
    text = re.sub(r"^[\s\-–—|:]+|[\s\-–—|:]+$", "", text)
    code = None
    c = _CODE.match(text)
    if c:
        code = c.group(1)
        text = text[c.end():]
    clean = _NOISE.sub(" ", text)
    parts = [p.strip(" -–—|") for p in _SEP.split(clean) if p and p.strip(" -–—|")]
    home, away = (parts + ["", ""])[:2] if len(parts) >= 2 else ("", "")
    return {"date": found.isoformat() if found else None, "home": home, "away": away, "half": half, "code": code, "rest": clean.strip()}


def card_day(card: Mapping[str, Any]) -> Optional[str]:
    """Dzień meczu (Europa/Warszawa) karty jako 'yyyy-mm-dd'."""
    raw = card.get("scheduled_at")
    if isinstance(raw, datetime):
        when = raw
    else:
        text = str(raw or "")
        if not text:
            return None
        try:
            when = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return text[:10] or None
    if when.tzinfo is not None:
        from zoneinfo import ZoneInfo

        when = when.astimezone(ZoneInfo("Europe/Warsaw"))
    return when.date().isoformat()


def _sides(parsed: Mapping[str, Any], title: str, card: Mapping[str, Any]) -> Tuple[str, str, bool]:
    """Poziomy dopasowania gospodarza i gościa karty (z kolejnością z tytułu albo odwróconą); bez rozbicia - cały tytuł."""
    home = str((card.get("home") or {}).get("name") or "")
    away = str((card.get("away") or {}).get("name") or "")
    if parsed.get("home") and parsed.get("away"):
        straight = (team_level(home, parsed["home"]), team_level(away, parsed["away"]))
        swapped = (team_level(home, parsed["away"]), team_level(away, parsed["home"]))
        value = {"strong": 2, "weak": 1, "none": 0}
        if sum(value[x] for x in swapped) > sum(value[x] for x in straight):
            return swapped[0], swapped[1], True
        return straight[0], straight[1], False
    return team_level(home, title), team_level(away, title), False


def score(parsed: Mapping[str, Any], title: str, card: Mapping[str, Any]) -> Dict[str, Any]:
    """Ocena jednej pary film - mecz: {confidence|None, points, reasons, swapped}."""
    h, a, swapped = _sides(parsed, title, card)
    both = h != "none" and a != "none"
    one = h != "none" or a != "none"
    strong_both = h == "strong" and a == "strong"
    day = card_day(card)
    vid_day = parsed.get("date")
    gap: Optional[int] = None
    if day and vid_day:
        try:
            gap = abs((date.fromisoformat(day) - date.fromisoformat(vid_day)).days)
        except ValueError:
            gap = None
    reasons: List[str] = []
    if gap == 0:
        reasons.append("data")
    elif gap == 1:
        reasons.append("data ±1 dzień")
    if h != "none":
        reasons.append("gospodarz" if h == "strong" else "gospodarz (część nazwy)")
    if a != "none":
        reasons.append("gość" if a == "strong" else "gość (część nazwy)")
    code = parsed.get("code")
    code_ok = bool(code and str(card.get("match_code") or "").upper().startswith(str(code).upper()))
    if code_ok:
        reasons.append(f"numer {code}")
    if swapped:
        reasons.append("drużyny odwrotnie")
    points = {"strong": 2, "weak": 1, "none": 0}[h] + {"strong": 2, "weak": 1, "none": 0}[a]
    points += 6 if gap == 0 else 3 if gap == 1 else 0
    points += 1 if code_ok else 0
    confidence: Optional[str] = None
    if gap == 0 and both and (h == "strong" or a == "strong"):
        confidence = "sure"
    elif (gap == 1 and both) or (gap == 0 and one) or (vid_day is None and strong_both):
        confidence = "likely"
    elif both and (strong_both or code_ok):
        confidence = "possible"
    return {"confidence": confidence, "points": points, "reasons": reasons, "swapped": swapped}


def propose(title: str, cards: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Najlepszy mecz pary dla tytułu i do dwóch alternatyw: {parsed, match_id, confidence, points, reasons, alternatives}."""
    parsed = parse_title(title)
    ranked = []
    for card in cards:
        s = score(parsed, title, card)
        if s["confidence"]:
            ranked.append((RANK[s["confidence"]], s["points"], str(card.get("match_id") or ""), s))
    ranked.sort(key=lambda x: (-x[0], -x[1], x[2]))
    if not ranked:
        return {"parsed": parsed, "match_id": None, "confidence": None, "points": 0, "reasons": [], "alternatives": []}
    best = ranked[0]
    confidence = best[3]["confidence"]
    # Dwa równie dobre mecze (np. dwa spotkania tych drużyn tego dnia) - pewność spada do sprawdzenia.
    if len(ranked) > 1 and ranked[1][0] == best[0] and ranked[1][1] == best[1] and confidence == "sure":
        confidence = "likely"
    alternatives = [{"match_id": r[2], "confidence": r[3]["confidence"], "reasons": r[3]["reasons"]} for r in ranked[1:3]]
    return {"parsed": parsed, "match_id": best[2], "confidence": confidence, "points": best[1], "reasons": best[3]["reasons"],
            "alternatives": alternatives}


def half_groups(items: Iterable[Mapping[str, Any]]) -> Dict[str, List[str]]:
    """Mecz w filmach-połowach: {match_id: [video_id I połowy, video_id II połowy]} tylko gdy są obie, w kolejności sklejania."""
    by: Dict[str, Dict[int, str]] = {}
    for it in items:
        mid, half = it.get("match_id"), (it.get("parsed") or {}).get("half")
        if mid and half in (1, 2) and it.get("confidence") in ("sure", "likely"):
            by.setdefault(str(mid), {}).setdefault(int(half), str(it["video_id"]))
    return {mid: [h[1], h[2]] for mid, h in by.items() if 1 in h and 2 in h}


def summary(items: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    """Liczniki przeglądu: pewne / do sprawdzenia / możliwe / bez pary / dodane / odrzucone."""
    out = {"sure": 0, "likely": 0, "possible": 0, "none": 0, "added": 0, "dismissed": 0, "total": 0}
    for it in items:
        out["total"] += 1
        state = it.get("state")
        if state in ("added", "dismissed"):
            out[state] += 1
        else:
            out[it.get("confidence") or "none"] += 1
    return out


_HANDLE = re.compile(r"(?:youtube\.com/)?@([\w.\-]{3,30})", re.I)
_CHANNEL = re.compile(r"youtube\.com/channel/(UC[\w-]{22})", re.I)
_LEGACY = re.compile(r"youtube\.com/(?:c|user)/([\w.\-]{2,60})", re.I)


def channel_ref(value: Any) -> Optional[Dict[str, str]]:
    """Link albo @uchwyt kanału -> {kind: handle|id|user, value}; None = to nie kanał YouTube."""
    text = str(value or "").strip()
    if not text:
        return None
    m = _CHANNEL.search(text)
    if m:
        return {"kind": "id", "value": m.group(1)}
    if re.fullmatch(r"UC[\w-]{22}", text):
        return {"kind": "id", "value": text}
    m = _HANDLE.search(text)
    if m and ("youtube" in text.lower() or text.startswith("@")):
        return {"kind": "handle", "value": "@" + m.group(1)}
    m = _LEGACY.search(text)
    if m:
        return {"kind": "user", "value": m.group(1)}
    return None


def iso_seconds(value: Any) -> Optional[int]:
    """Czas trwania z API („PT1H2M3S”) albo z kafla („1:02:03”) w sekundach."""
    text = str(value or "").strip()
    m = re.fullmatch(r"P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?", text)
    if m and text not in ("P", "PT"):
        d, h, mi, s = (int(x or 0) for x in m.groups())
        return d * 86400 + h * 3600 + mi * 60 + s
    parts = text.split(":")
    if 2 <= len(parts) <= 3 and all(p.isdigit() for p in parts):
        total = 0
        for p in parts:
            total = total * 60 + int(p)
        return total
    return None


def within(days: int, a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    try:
        return abs(date.fromisoformat(a) - date.fromisoformat(b)) <= timedelta(days=days)
    except ValueError:
        return False
