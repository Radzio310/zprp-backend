"""Podpowiedzi zestawień dla klipu (12.11.2026) - reguły czyste: bez bazy.

Przy wycinaniu klipu i na gotowym klipie panel podpowiada jednym stuknięciem zestawienia, do których klip pasuje:
  - z tego meczu: zestawienia, w których są już klipy z tego samego meczu (im więcej, tym wyżej),
  - po kategorii: zestawienia, których klipy mają tę samą kategorię (udział w zestawieniu waży więcej niż sama
    liczba), a nazwa kategorii w nazwie zestawienia („Kary - listopad” dla kategorii „Kary”) to mocny znak,
  - gdy pasujących jest mało, dopełniają je ostatnio zmieniane zestawienia („Ostatnio używane”).
Zestawienie, w którym klip już jest, wraca z `has_clip` (przełącznik „w zestawieniu”), zawsze na górze listy.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

LIMIT = 6
RECENT_FILL = 2


def _norm(text: Any) -> str:
    raw = unicodedata.normalize("NFKD", str(text or "").lower().replace("ł", "l"))
    raw = "".join(ch for ch in raw if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", " ", raw).strip()


def name_has(name: Any, word: Any) -> bool:
    """Nazwa kategorii w nazwie zestawienia, całym słowem i bez polskich znaków („kary” w „Kary - listopad”)."""
    n, w = _norm(name), _norm(word)
    return bool(w) and len(w) >= 3 and re.search(rf"(^| ){re.escape(w)}( |$)", n) is not None


def rank(compilations: Sequence[Mapping[str, Any]], items: Mapping[str, Sequence[str]], clips: Mapping[str, Mapping[str, Any]], *,
         match_id: Optional[str], category_ids: Iterable[str], clip_id: Optional[str], category_names: Mapping[str, str],
         limit: int = LIMIT) -> List[Dict[str, Any]]:
    """Zestawienia uporządkowane od najlepiej pasującego. `items` = {compilation_id: [clip_id, ...]},
    `clips` = {clip_id: {match_id, category_ids}}; `compilations` w kolejności od ostatnio zmienianych."""
    cats = [str(c) for c in category_ids if str(c)]
    scored: List[Dict[str, Any]] = []
    for recency, comp in enumerate(compilations):
        ids = [i for i in items.get(comp["id"], []) if i in clips]
        has_clip = bool(clip_id) and clip_id in ids
        # Liczymy wszystkie klipy zestawienia, także ten - „2 klipy z tego meczu” ma się zgadzać z zestawieniem
        # od razu po dodaniu klipu (zgłoszenie 12.11.2026: licznik nie obejmował właśnie dodanego klipu).
        members = [clips[i] for i in ids]
        reasons: List[Dict[str, Any]] = []
        score = 0.0
        same_match = sum(1 for c in members if match_id and c.get("match_id") == match_id)
        if same_match:
            reasons.append({"kind": "match", "count": same_match})
            score += 100 + same_match * 6
        for cat in cats:
            hits = sum(1 for c in members if cat in (c.get("category_ids") or []))
            in_name = name_has(comp.get("name"), category_names.get(cat))
            if hits or in_name:
                share = hits / len(members) if members else 0.0
                reasons.append({"kind": "category", "category_id": cat, "name": category_names.get(cat) or "", "count": hits,
                                "total": len(members), "in_name": in_name})
                score += 40 + share * 60 + hits * 3 + (45 if in_name else 0)
        if has_clip:
            score += 1000
        if not reasons and not has_clip:
            continue
        score += max(0.0, 8 - recency * 0.5)  # przy remisie świeższe zestawienie wyżej
        scored.append({"id": comp["id"], "name": comp.get("name") or "", "items_count": len(ids), "has_clip": has_clip,
                       "reasons": reasons, "score": round(score, 2), "can_edit": bool(comp.get("can_edit", True))})
    scored.sort(key=lambda x: -x["score"])
    out = scored[:limit]
    if len([s for s in out if not s["has_clip"]]) < 3:
        taken = {s["id"] for s in out}
        for comp in compilations:
            if len(out) >= limit or sum(1 for s in out if s["reasons"] and s["reasons"][0]["kind"] == "recent") >= RECENT_FILL:
                break
            if comp["id"] in taken:
                continue
            ids = [i for i in items.get(comp["id"], []) if i in clips]
            out.append({"id": comp["id"], "name": comp.get("name") or "", "items_count": len(ids), "has_clip": False,
                        "reasons": [{"kind": "recent"}], "score": 0.0, "can_edit": bool(comp.get("can_edit", True))})
    return out


def reason_text(reason: Mapping[str, Any]) -> str:
    """Powód po polsku (to samo zdanie co w panelu i aplikacji)."""
    kind = reason.get("kind")
    if kind == "match":
        n = int(reason.get("count") or 0)
        return f"{n} {'klip' if n == 1 else 'klipy' if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14) else 'klipów'} z tego meczu"
    if kind == "category":
        name = reason.get("name") or "ta kategoria"
        if reason.get("count"):
            return f"{name}: {reason['count']} z {reason.get('total') or reason['count']}"
        return f"{name} w nazwie"
    return "Ostatnio używane"
