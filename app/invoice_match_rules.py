"""
Dopasowanie nabywcy z faktury do klubu z panelu - czyste reguły, bez bazy.

Kolejność:
  1. NIP zapamiętany przy klubie (tabela `province_club_nips`) - pewność 1.0,
  2. nazwa nabywcy porównana z nazwą klubu i nazwami jego drużyn.

Nazwa na fakturze to nazwa z KRS („KLUB SPORTOWY "ZGODA" RUDA ŚLĄSKA-BIELSZ"),
a w panelu klub nazywa się po ludzku („KS Zgoda Ruda Śląska"). Dlatego:
  - zdejmujemy formy prawne i skróty (klub sportowy, KS, UKS, MKS, ...),
    cudzysłowy, ogonki i myślniki,
  - słowo pasuje także PREFIKSEM (co najmniej 4 litery): „bielsz" to ucięte
    „bielszowice",
  - słowa częste w nazwach klubów okręgu (miasta: „ruda", „slaska",
    „katowice") ważą mniej niż słowa rzadkie („zgoda") - waga odwrotna do
    liczby klubów, w których słowo występuje.

Pewne dopasowanie (zaznaczane w panelu z automatu) to wynik >= CONFIDENT
z przewagą nad drugim klubem co najmniej MARGIN. Resztę panel pokazuje jako
propozycję do sprawdzenia - nigdy nie zatwierdza jej po cichu.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Iterable, Optional

from app.invoice_parse_rules import ascii_fold, normalize_nip

CONFIDENT = 0.75
MARGIN = 0.15
#: Najsłabszy wynik, który w ogóle pokazujemy jako propozycję.
PROPOSE = 0.35

#: Formy prawne i słowa-wypełniacze - nie odróżniają klubów od siebie.
STOP_WORDS = frozenset(
    {
        "klub", "sportowy", "sportowa", "sportowe", "sportowego", "uczniowski", "uczniowska",
        "miejski", "miejska", "ludowy", "ludowa", "gminny", "gminna", "miedzyszkolny",
        "miedzyszkolna", "stowarzyszenie", "sekcja", "pilki", "pilka", "recznej", "reczna",
        "szkolny", "szkolna", "towarzystwo", "zwiazek", "fundacja", "spolka", "sp", "z", "o",
        "oo", "zoo", "w", "we", "i", "im", "imienia", "ks", "uks", "mks", "lks", "gks", "mts",
        "sks", "kps", "mkps", "ts", "kpr", "spr", "mlks", "muks", "gkps", "tsr", "rks", "ssr",
    }
)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def name_tokens(name: Any) -> list[str]:
    """Słowa nazwy bez form prawnych, ogonków, cudzysłowów i myślników."""
    text = ascii_fold(name)
    # Skrót województwa w nawiasie („(SL)") nie jest częścią nazwy.
    text = re.sub(r"\((?:[a-z]{2,3})\)", " ", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    out: list[str] = []
    for token in text.split():
        if token in STOP_WORDS or token in out:
            continue
        out.append(token)
    return out


def _same(a: str, b: str) -> bool:
    if a == b:
        return True
    if len(a) >= 4 and len(b) >= 4:
        return a.startswith(b) or b.startswith(a)
    return False


def _weights(candidates: Iterable[dict]) -> dict[str, float]:
    """Waga słowa: 1 dla słowa jednego klubu, mniej dla słów wielu klubów."""
    df: dict[str, int] = {}
    for club in candidates:
        seen: set[str] = set()
        for name in club.get("names") or [club.get("name")]:
            seen.update(name_tokens(name))
        for token in seen:
            df[token] = df.get(token, 0) + 1
    return {token: 1.0 / (1.0 + math.log(count)) for token, count in df.items()}


def name_score(buyer: Any, candidate: Any, weights: Optional[dict[str, float]] = None) -> float:
    """0..1 - jak dobrze nazwa nabywcy pasuje do jednej nazwy z panelu."""
    weights = weights or {}
    b_tokens = name_tokens(buyer)
    c_tokens = name_tokens(candidate)
    if not b_tokens or not c_tokens:
        return 0.0

    def w(token: str) -> float:
        return weights.get(token, 1.0)

    c_total = sum(w(t) for t in c_tokens)
    c_hit = sum(w(t) for t in c_tokens if any(_same(t, b) for b in b_tokens))
    b_total = sum(w(t) for t in b_tokens)
    b_hit = sum(w(t) for t in b_tokens if any(_same(t, c) for c in c_tokens))
    if c_hit <= 0:
        return 0.0
    score = 0.7 * (c_hit / c_total) + 0.3 * (b_hit / b_total)
    # Zgodne tylko słowa częste (samo miasto) to za mało na pewność.
    distinct = [t for t in c_tokens if any(_same(t, b) for b in b_tokens) and w(t) >= 0.99]
    if not distinct:
        score *= 0.6
    return round(min(score, 1.0), 3)


def rank_clubs(buyer: Any, candidates: list[dict], limit: int = 5) -> list[dict]:
    """
    Kluby od najlepszego: [{club_id, name, score, matched_name}].

    `candidates` to [{club_id, name, names: [nazwa klubu, nazwy drużyn...]}].
    """
    weights = _weights(candidates)
    ranked: list[dict] = []
    for club in candidates:
        names = [n for n in (club.get("names") or []) if _s(n)] or [_s(club.get("name"))]
        best, best_name = 0.0, ""
        for name in names:
            score = name_score(buyer, name, weights)
            if score > best:
                best, best_name = score, name
        if best >= PROPOSE:
            ranked.append({
                "club_id": _s(club.get("club_id")),
                "name": _s(club.get("name")),
                "score": best,
                "matched_name": best_name,
            })
    ranked.sort(key=lambda item: (-item["score"], item["name"]))
    return ranked[:limit]


def propose(
    *,
    buyer_name: Any,
    buyer_nip: Any,
    candidates: list[dict],
    known_nips: dict[str, str],
    budget_main: Optional[dict[str, str]] = None,
) -> dict:
    """
    Propozycja klubu dla faktury.

    Zwraca {club_id, confidence, via ("nip" | "name" | ""), confident, alternatives,
    budget_of}. `budget_main` mapuje klub-członka wspólnego budżetu na klub
    główny - wpłata idzie wtedy do głównego (tam jest wspólne saldo).
    """
    budget_main = budget_main or {}
    by_id = {_s(club.get("club_id")): club for club in candidates}
    nip = normalize_nip(buyer_nip)
    alternatives = rank_clubs(buyer_name, candidates)

    def lift(club_id: str) -> tuple[str, str]:
        main = budget_main.get(club_id)
        if main and main != club_id:
            return main, club_id
        return club_id, ""

    if nip and known_nips.get(nip):
        club_id, member = lift(known_nips[nip])
        return {
            "club_id": club_id,
            "confidence": 1.0,
            "via": "nip",
            "confident": True,
            "alternatives": alternatives,
            "budget_of": member,
            "known_club": club_id in by_id,
        }

    if not alternatives:
        return {
            "club_id": "",
            "confidence": 0.0,
            "via": "",
            "confident": False,
            "alternatives": [],
            "budget_of": "",
            "known_club": False,
        }

    best = alternatives[0]
    second = alternatives[1]["score"] if len(alternatives) > 1 else 0.0
    confident = best["score"] >= CONFIDENT and best["score"] - second >= MARGIN
    club_id, member = lift(best["club_id"])
    return {
        "club_id": club_id,
        "confidence": best["score"],
        "via": "name",
        "confident": confident,
        "alternatives": alternatives,
        "budget_of": member,
        "known_club": True,
    }


def budget_members(raw: Any) -> dict[str, str]:
    """
    Kontrakt `province_club_budgets.season_budgets` na mapę członek -> klub główny.

    Przyjmuje listę [{primary_club_id | club_id, member_ids}] (`budget_groups`) albo słownik {club_id: {member_ids}}
    (albo {club_id: [member_ids]}) - moduł pisze kto inny, więc bez założeń.
    """
    rows: list[tuple[str, Any]] = []
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict):
                rows.append((_s(value.get("club_id")) or _s(key), value.get("member_ids")))
            else:
                rows.append((_s(key), value))
    elif isinstance(raw, (list, tuple)):
        for value in raw:
            if isinstance(value, dict):
                main = _s(value.get("primary_club_id")) or _s(value.get("club_id"))
                rows.append((main, value.get("member_ids")))
    out: dict[str, str] = {}
    for main, members in rows:
        if not main:
            continue
        if isinstance(members, str):
            try:
                members = json.loads(members)
            except Exception:
                members = []
        for member in members or []:
            member_id = _s(member)
            if member_id and member_id != main:
                out[member_id] = main
    return out
