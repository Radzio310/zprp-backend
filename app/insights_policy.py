"""
Wnioski z analizy obsad w Automacie - reguły, bez bazy i bez sieci.

Decyzja użytkownika z 16.09.2026: analiza nic nie zmienia sama. Obsadowy
wybiera w karcie Analiza, których wniosków Automat ma się nauczyć, i przy
każdym ustawia:
  - PUNKTY z siłą 0-100 - wniosek tylko przechyla wybór, gniazdo nigdy nie
    zostaje puste z jego powodu,
  - TWARDA ZASADA - kandydat odpada z powodem, jak przy niedyspozycji.

Skala punktów jest skalą Automatu (`app/assignment_auto.py`): tam punkt to mniej
więcej kilometr, a miejscowy dostaje 400. Wniosek na pełnej sile waży najwyżej
`POINTS_SCALE`, czyli tyle, co 300 km dojazdu - wyraźnie, ale nie więcej niż
reguły, które już tam są.

Mecz „trudny" dla Automatu to przewidywana trudność (bez protokołu, bo meczu
jeszcze nie było) od progu `predict_threshold` z analizy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Set, Tuple

from app.insights_rules import TIER, team_key

POINTS_SCALE = 300.0

RULE_KEYS = (
    "experience_before_hard",
    "category_specialization",
    "stable_pairs",
    "team_repetition",
    "development_path",
    "fair_hard_share",
    "mentors",
)

MODES = ("points", "hard")


def normalize_rule(raw: Mapping[str, Any]) -> dict:
    mode = str(raw.get("mode") or "points")
    try:
        strength = int(raw.get("strength") if raw.get("strength") is not None else 50)
    except (TypeError, ValueError):
        strength = 50
    params = raw.get("params") if isinstance(raw.get("params"), Mapping) else {}
    return {
        "enabled": bool(raw.get("enabled")),
        "mode": mode if mode in MODES else "points",
        "strength": max(0, min(100, strength)),
        "params": dict(params),
    }


@dataclass
class Policy:
    """Wybrane wnioski gotowe do zapytań Automatu."""

    rules: Dict[str, dict]
    threshold: float
    experience: Dict[str, int] = field(default_factory=dict)
    dominant: Dict[str, Tuple[str, float]] = field(default_factory=dict)
    top_tier: Dict[str, float] = field(default_factory=dict)
    growing: Set[str] = field(default_factory=set)
    hard_share: Dict[str, float] = field(default_factory=dict)
    peer_share: Dict[str, float] = field(default_factory=dict)
    young: Set[str] = field(default_factory=set)
    mentors: Set[str] = field(default_factory=set)
    stable_pairs: Set[FrozenSet[str]] = field(default_factory=set)
    team_counts: Dict[Tuple[str, str], int] = field(default_factory=dict)

    # --- pomocnicze ---

    def _rule(self, key: str) -> Optional[dict]:
        rule = self.rules.get(key)
        return rule if rule and rule.get("enabled") else None

    def _hard(self, key: str) -> Optional[dict]:
        rule = self._rule(key)
        return rule if rule and rule["mode"] == "hard" else None

    def _points(self, key: str) -> Optional[float]:
        rule = self._rule(key)
        if not rule or rule["mode"] != "points" or rule["strength"] <= 0:
            return None
        return POINTS_SCALE * rule["strength"] / 100.0

    @staticmethod
    def _need(need: Any, name: str, default: Any = None) -> Any:
        return getattr(need, name, default)

    def is_hard(self, need: Any) -> bool:
        value = self._need(need, "difficulty")
        return value is not None and value >= self.threshold

    def _team_count(self, judge_id: str, need: Any) -> Tuple[int, str]:
        best, team = 0, ""
        for name in (self._need(need, "host", ""), self._need(need, "guest", "")):
            count = self.team_counts.get((judge_id, team_key(name)), 0)
            if count > best:
                best, team = count, name
        return best, team

    def _pair_stable(self, a: str, b: Optional[str]) -> bool:
        return bool(b) and frozenset((a, b)) in self.stable_pairs

    def _has_stable_pair(self, judge_id: Optional[str]) -> bool:
        return bool(judge_id) and any(judge_id in pair for pair in self.stable_pairs)

    # --- zapytania Automatu ---

    def refuse(
        self, judge_id: str, need: Any, *, kind: str, partner_id: Optional[str], round_no: int
    ) -> Optional[str]:
        """Powód twardej odmowy albo `None`."""
        if kind != "field":
            return None
        hard_match = self.is_hard(need)

        rule = self._hard("experience_before_hard")
        if rule and hard_match:
            needed = int(rule["params"].get("min_field_matches") or 0)
            have = self.experience.get(judge_id, 0)
            if needed and have < needed:
                return f"za mało meczów przed trudnym ({have} z {needed})"

        rule = self._hard("category_specialization")
        if rule and judge_id in self.dominant:
            category, _share = self.dominant[judge_id]
            if (self._need(need, "tier", 0.0) or 0.0) > TIER.get(category, 0.4) + 0.1:
                return f"ponad specjalizację ({category})"

        rule = self._hard("stable_pairs")
        if rule and hard_match and round_no == 1 and partner_id and self._has_stable_pair(partner_id):
            if not self._pair_stable(judge_id, partner_id):
                return "na trudny mecz najpierw sprawdzona para"

        rule = self._hard("team_repetition")
        if rule:
            limit = int(rule["params"].get("max_per_team") or 0)
            count, team = self._team_count(judge_id, need)
            if limit and count >= limit:
                return f"już {count} mecze drużyny {team} w sezonie"

        rule = self._hard("development_path")
        if rule and (judge_id in self.young or judge_id in self.growing):
            step = float(rule["params"].get("max_step") or 0.15)
            top = self.top_tier.get(judge_id)
            if top is not None and (self._need(need, "tier", 0.0) or 0.0) > top + step:
                return "za wysoki szczebel na teraz"

        rule = self._hard("fair_hard_share")
        if rule and hard_match:
            share, peers = self.hard_share.get(judge_id), self.peer_share.get(judge_id)
            if share is not None and peers and share >= 2 * peers:
                return "dwa razy więcej trudnych niż grupa"

        rule = self._hard("mentors")
        if rule and partner_id:
            if judge_id in self.young and partner_id not in self.mentors:
                return "młody sędzia tylko z mentorem"
            if partner_id in self.young and judge_id not in self.mentors:
                return "partner młodego to mentor"
        return None

    def points(
        self, judge_id: str, need: Any, *, kind: str, partner_id: Optional[str], round_no: int
    ) -> Tuple[float, List[str]]:
        """Punkty (mniej znaczy lepiej, jak w Automacie) i powody słowami."""
        if kind != "field":
            return 0.0, []
        delta = 0.0
        why: List[str] = []
        hard_match = self.is_hard(need)
        tier = self._need(need, "tier", 0.0) or 0.0

        scale = self._points("experience_before_hard")
        rule = self._rule("experience_before_hard")
        if scale and hard_match:
            needed = int(rule["params"].get("min_field_matches") or 0)
            have = self.experience.get(judge_id, 0)
            if needed and have < needed:
                delta += scale * (needed - have) / needed
                why.append("mało doświadczenia na trudny mecz")

        scale = self._points("category_specialization")
        if scale and judge_id in self.dominant:
            category, _share = self.dominant[judge_id]
            if category and category == self._need(need, "category", ""):
                delta -= scale * 0.5
                why.append(f"specjalizacja: {category}")

        scale = self._points("stable_pairs")
        if scale and hard_match and self._pair_stable(judge_id, partner_id):
            delta -= scale * 0.6
            why.append("sprawdzona para")

        scale = self._points("team_repetition")
        rule = self._rule("team_repetition")
        if scale:
            limit = int(rule["params"].get("max_per_team") or 0)
            count, team = self._team_count(judge_id, need)
            if limit and count >= limit - 1:
                delta += scale * 0.3 * (count - limit + 2)
                why.append(f"często z drużyną {team} ({count})")

        scale = self._points("development_path")
        rule = self._rule("development_path")
        if scale and (judge_id in self.young or judge_id in self.growing):
            step = float(rule["params"].get("max_step") or 0.15)
            top = self.top_tier.get(judge_id)
            if top is not None:
                if top < tier <= top + step:
                    delta -= scale * 0.4
                    why.append("krok w rozwoju")
                elif tier > top + step:
                    delta += scale * 0.4
                    why.append("za wysoko na teraz")

        scale = self._points("fair_hard_share")
        if scale and hard_match:
            share, peers = self.hard_share.get(judge_id), self.peer_share.get(judge_id)
            if share is not None and peers:
                if share > peers:
                    delta += scale * min(1.0, (share - peers) / peers)
                    why.append("więcej trudnych niż grupa")
                elif share < 0.5 * peers:
                    delta -= scale * 0.3
                    why.append("mniej trudnych niż grupa")

        scale = self._points("mentors")
        if scale and partner_id:
            if (partner_id in self.young and judge_id in self.mentors) or (
                judge_id in self.young and partner_id in self.mentors
            ):
                delta -= scale * 0.6
                why.append("para z mentorem młodego")
        return delta, why

    def note_assigned(self, judge_id: str, need: Any, *, kind: str) -> None:
        """Automat właśnie przydzielił mecz - licznik drużyny rośnie od razu."""
        if kind != "field":
            return
        for name in {self._need(need, "host", ""), self._need(need, "guest", "")}:
            key = (judge_id, team_key(name))
            if key[1]:
                self.team_counts[key] = self.team_counts.get(key, 0) + 1

    def note_unassigned(self, judge_id: str, need: Any, *, kind: str) -> None:
        """Wyrównanie w Automacie zdjęło sędziego z meczu - licznik drużyny maleje."""
        if kind != "field":
            return
        for name in {self._need(need, "host", ""), self._need(need, "guest", "")}:
            key = (judge_id, team_key(name))
            if key[1] and self.team_counts.get(key, 0) > 0:
                self.team_counts[key] -= 1

    def summary(self) -> List[dict]:
        return [
            {"key": key, "mode": rule["mode"], "strength": rule["strength"], "params": rule["params"]}
            for key, rule in self.rules.items()
            if rule.get("enabled")
        ]


def build_policy(
    analysis: Mapping[str, Any],
    rules: Mapping[str, Mapping[str, Any]],
    *,
    current_season_field: Iterable[Tuple[str, str, str]] = (),
) -> Optional[Policy]:
    """Polityka z analizy (zapisane wagi) i wybranych wniosków.

    `current_season_field` - (sędzia, gospodarz, gość) z meczów bieżącego
    sezonu, do licznika powtarzalności z drużyną. Brak włączonych wniosków =
    `None`, czyli Automat dokładnie taki jak dotąd.
    """
    chosen: Dict[str, dict] = {}
    conclusions = {item.get("key"): item for item in analysis.get("conclusions") or []}
    for key in RULE_KEYS:
        raw = rules.get(key)
        if not raw:
            continue
        rule = normalize_rule(raw)
        if not rule["enabled"] or key not in conclusions:
            continue
        # Parametry z analizy są punktem wyjścia; zapisane przez obsadowego wygrywają.
        rule["params"] = {**(conclusions[key].get("rule") or {}).get("params", {}), **rule["params"]}
        chosen[key] = rule
    if not chosen:
        return None

    judges = analysis.get("judges") or []
    policy = Policy(
        rules=chosen,
        threshold=float((analysis.get("meta") or {}).get("predict_threshold") or 1.0),
    )
    for item in judges:
        judge_id = str(item.get("judge_id"))
        # Doświadczenie z całej historii, nie tylko z horyzontu analizy.
        policy.experience[judge_id] = int(
            item.get("field_all") if item.get("field_all") is not None else item.get("field") or 0
        )
        dominant = item.get("dominant")
        if dominant and int(item.get("field") or 0) >= 10 and float(dominant.get("share") or 0) >= float(
            (chosen.get("category_specialization") or {}).get("params", {}).get("min_share", 0.55)
        ):
            policy.dominant[judge_id] = (str(dominant.get("category") or ""), float(dominant.get("share") or 0))
        if item.get("top_tier") is not None:
            policy.top_tier[judge_id] = float(item["top_tier"])
        if item.get("hard_share") is not None:
            policy.hard_share[judge_id] = float(item["hard_share"])
        if item.get("peer_share"):
            policy.peer_share[judge_id] = float(item["peer_share"])
        if item.get("young"):
            policy.young.add(judge_id)

    growth = conclusions.get("development_path") or {}
    policy.growing = {str(entry.get("judge_id")) for entry in (growth.get("affected") or {}).get("growing") or []}
    pairs = conclusions.get("stable_pairs") or {}
    policy.stable_pairs = {
        frozenset((str(entry.get("a")), str(entry.get("b")))) for entry in (pairs.get("affected") or {}).get("pairs") or []
    }
    mentors = conclusions.get("mentors") or {}
    affected = mentors.get("affected") or {}
    policy.mentors = {str(entry.get("judge_id")) for entry in (affected.get("mentors") or []) + (affected.get("candidates") or [])}

    for judge_id, host, guest in current_season_field:
        for name in {host, guest}:
            key = (str(judge_id), team_key(name))
            if key[1]:
                policy.team_counts[key] = policy.team_counts.get(key, 0) + 1
    return policy
