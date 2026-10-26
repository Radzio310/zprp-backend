"""
Sugestie przy braku chętnych (25.10.2026, noc) - reguły. MODUŁ-LIŚĆ: bez bazy,
sieci i FastAPI.

Gdy na wolne gniazdo oferty obsadowego nikt się nie zgłosił, a inne gniazdo tej
samej roli jest już obsadzone, podpowiadamy:
  - STAŁEGO PARTNERA obsadzonego (kto z nim najczęściej stał w tej samej roli:
    stolik albo boisko - z archiwum obsad),
  - osoby z jego PARY MENTORSKIEJ (mentor / podopieczny / druga osoba pary).
Tożsamość to NUMER sędziego, nigdy nazwisko (pamięć konto-proel-numer-nie-nazwisko).
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping, Optional

ROLE_FIELD = "field"
ROLE_TABLE = "table"

#: Ile zaproszeń może wyjść z jednej oferty (ochrona przed zasypaniem ludzi pushami).
INVITE_LIMIT = 12
#: Ile sugestii na gniazdo.
PER_SLOT = 6
#: Poniżej tylu wspólnych meczów to nie jest „stały" partner.
MIN_TOGETHER = 2

STATE_FREE = "free"
STATE_COLLISION = "collision"
STATE_UNAVAILABLE = "unavailable"
_STATE_ORDER = {STATE_FREE: 0, STATE_COLLISION: 1, STATE_UNAVAILABLE: 2}

RELATION_LABELS = {
    "mentor": "mentor",
    "mentee": "podopieczny",
    "pair_mate": "w parze mentorskiej",
}


def _s(value: Any) -> str:
    return str(value or "").strip()


def _ids(raw: Any) -> list[str]:
    if isinstance(raw, str):
        import json

        try:
            raw = json.loads(raw)
        except ValueError:
            return []
    return [_s(item) for item in (raw or []) if _s(item)]


def together(facts: Iterable[Any], anchors: Iterable[str], role: str) -> dict[str, dict[str, Any]]:
    """
    Wspólne mecze w TEJ SAMEJ roli: dla każdego obsadzonego (`anchors`) kto z nim stał.

    `facts` to mecze z archiwum z polami `field`, `table` (krotki numerów),
    `played`, `season`, `id`. Wynik: partner -> {"matches": n, "last_season": s,
    "with": [numery obsadzonych, z którymi stał]}. Mecz niezagrany się nie liczy.
    """
    wanted = {_s(a) for a in anchors if _s(a)}
    counts: dict[str, Counter] = {}
    last: dict[str, int] = {}
    for fact in facts:
        if not getattr(fact, "played", True):
            continue
        crew = [_s(j) for j in (fact.field if role == ROLE_FIELD else fact.table)]
        here = [j for j in crew if j in wanted]
        if not here:
            continue
        for other in crew:
            if not other or other in wanted:
                continue
            counts.setdefault(other, Counter())
            for anchor in here:
                counts[other][anchor] += 1
            last[other] = max(last.get(other, 0), int(getattr(fact, "season", 0) or 0))
    out: dict[str, dict[str, Any]] = {}
    for other, per_anchor in counts.items():
        # Mecz z dwoma obsadzonymi naraz liczymy raz na partnera: bierzemy najlepszego z nich.
        best, matches = per_anchor.most_common(1)[0]
        if matches >= MIN_TOGETHER:
            out[other] = {"matches": matches, "last_season": last.get(other), "with": [best]}
    return out


def mentor_links(
    pairs: Iterable[Mapping[str, Any]],
    mentors: Iterable[Mapping[str, Any]],
    anchors: Iterable[str],
) -> dict[str, list[dict[str, str]]]:
    """
    Osoby z par mentorskich obsadzonych: kandydat -> [{"anchor", "relation"}].

    `pairs` - aktywne pary ({"id", "judge_ids"}), `mentors` - aktywne przypisania
    mentorów ({"pair_id", "mentor_id"}). Para ma podopiecznych (`judge_ids`) i
    mentorów. Obsadzony podopieczny -> jego mentor ("mentor") i druga osoba pary
    ("pair_mate"); obsadzony mentor -> jego podopieczni ("mentee").
    """
    wanted = {_s(a) for a in anchors if _s(a)}
    by_pair: dict[str, list[str]] = {}
    for row in mentors:
        by_pair.setdefault(_s(row.get("pair_id")), []).append(_s(row.get("mentor_id")))
    out: dict[str, list[dict[str, str]]] = {}

    def add(candidate: str, anchor: str, relation: str) -> None:
        if not candidate or candidate in wanted:
            return
        bucket = out.setdefault(candidate, [])
        if not any(item["anchor"] == anchor and item["relation"] == relation for item in bucket):
            bucket.append({"anchor": anchor, "relation": relation})

    for pair in pairs:
        members = _ids(pair.get("judge_ids"))
        mentor_ids = [m for m in by_pair.get(_s(pair.get("id")), []) if m]
        for anchor in wanted:
            if anchor in members:
                for other in members:
                    add(other, anchor, "pair_mate")
                for mentor in mentor_ids:
                    add(mentor, anchor, "mentor")
            elif anchor in mentor_ids:
                for other in members:
                    add(other, anchor, "mentee")
    return out


def availability(unavailable: Optional[str], collisions: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Dyspozycja w terminie meczu: wolny / niedyspozycja / kolizja (z wyjaśnieniem)."""
    if unavailable:
        return {"state": STATE_UNAVAILABLE, "text": f"Niedyspozycja: {unavailable}"}
    hard = [c for c in collisions if c.get("overlap") or c.get("level") in ("orange", "red")]
    if hard:
        worst = hard[0]
        what = "nakłada się z innym meczem" if worst.get("overlap") else "za mały odstęp od innego meczu"
        code = _s(worst.get("code"))
        return {"state": STATE_COLLISION, "text": f"Kolizja: {what}" + (f" ({code})" if code else "")}
    return {"state": STATE_FREE, "text": "Wolny w tym terminie"}


def rank(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Wolni przed kolizją przed niedyspozycją; w grupie: stali partnerzy, potem mentorzy, potem mniej meczów w tygodniu."""

    def key(item: Mapping[str, Any]) -> tuple:
        partner = max((r.get("matches", 0) for r in item["reasons"] if r["kind"] == "partner"), default=0)
        mentor = 1 if any(r["kind"] == "mentor" for r in item["reasons"]) else 0
        return (
            _STATE_ORDER.get(item["availability"]["state"], 9),
            -partner,
            -mentor,
            item.get("weekMatches") or 0,
            _s(item["judge"].get("name")),
        )

    return sorted(items, key=key)


def refusal_for_candidate(
    *,
    in_province: bool,
    passes_filter: bool,
    holds_slot: bool,
    role_ok: bool,
    already_claimed: bool,
) -> Optional[str]:
    """Czemu tej osoby nie można zaprosić ani przydzielić (zdanie po polsku), albo None."""
    if not in_province:
        return "Tego sędziego nie ma na liście okręgu tej oferty."
    if holds_slot:
        return "Ten sędzia jest już w obsadzie tego meczu."
    if already_claimed:
        return "Ten sędzia już zgłosił się na tę ofertę - użyj jego zgłoszenia."
    if not role_ok:
        return "Reguły obsady nie pozwalają temu sędziemu stanąć w tej roli (np. delegat nie staje na boisku)."
    if not passes_filter:
        return "Oferta jest ograniczona odznakami i ten sędzia nie spełnia filtra, więc nie mógłby się zgłosić."
    return None


def text_invite(offer: Mapping[str, Any], role: str) -> tuple[str, str]:
    from app.match_market_crew_rules import _join, _match_line, when_of

    label = "stolikowy" if role == ROLE_TABLE else "boiskowy"
    return (
        "Obsada proponuje Ci ten mecz",
        _join(f"{_match_line(offer)} - szukamy: {label}", when_of(offer), "Zgłoś się w aplikacji, jeśli możesz"),
    )
