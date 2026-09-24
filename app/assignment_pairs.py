"""
Pary sędziowskie z listy „Sędziowie i Delegaci" baza.zprp.pl.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

Synchronizacja niedyspozycji (`province_offtime_sync._scrape_officials`, co 2 h,
kontem okręgu) i tak przechodzi całą listę oficjeli, a przy każdym stoi kolumna
„Para z : NAZWISKO Imię". Tutaj zamieniamy ją na pary NUMERÓW sędziów okręgu:

  - partnera szukamy po imieniu i nazwisku (`official_roster.person_key` - bez
    ogonków, w dowolnej kolejności członów) wśród sędziów OKRĘGU; gdy nazwisko
    pasuje do kilku osób, nie zgadujemy - para przepada,
  - para musi być spójna: gdy A mówi „para z B", a B „para z C", żadna z tych
    par nie wchodzi (lista ZPRP bywa w trakcie zmian i lepiej nie mieć pary
    niż mieć złą),
  - wynik to pełna mapa „numer -> partner" dla źródła `zprp`. Pary własne
    okręgu (`own`) leżą obok i wygrywają przy odczycie
    (`assignment_context.merge_pairs`) - tu ich nie dotykamy.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from app.official_roster import person_key


def _s(value: Any) -> str:
    return str(value or "").strip()


def zprp_pairs(
    officials: Mapping[str, Mapping[str, Any]],
    judges: Iterable[tuple[Any, Any]],
) -> dict[str, str]:
    """
    Pary z listy oficjeli jako mapa obustronna: numer -> numer partnera.

    `officials` to wynik `_scrape_officials` (numer -> {"name", "partner", …}),
    `judges` to sędziowie okręgu jako pary (numer, imię i nazwisko). Oficjel,
    którego numeru nie ma wśród sędziów okręgu, jest rozpoznawany po nazwisku.
    """
    by_key: dict[str, set[str]] = {}
    known: set[str] = set()
    for judge_id, name in judges:
        jid = _s(judge_id)
        key = person_key(name)
        if not jid:
            continue
        known.add(jid)
        if key:
            by_key.setdefault(key, set()).add(jid)

    def resolve(name: Any) -> str:
        found = by_key.get(person_key(name)) or set()
        return next(iter(found)) if len(found) == 1 else ""

    edges: set[frozenset[str]] = set()
    for official_id, item in officials.items():
        partner_name = _s((item or {}).get("partner"))
        if not partner_name:
            continue
        own_id = _s(official_id)
        if own_id not in known:
            own_id = resolve((item or {}).get("name"))
        other_id = resolve(partner_name)
        if own_id and other_id and own_id != other_id:
            edges.add(frozenset((own_id, other_id)))

    degree: dict[str, int] = {}
    for edge in edges:
        for judge_id in edge:
            degree[judge_id] = degree.get(judge_id, 0) + 1

    out: dict[str, str] = {}
    for edge in edges:
        left, right = sorted(edge)
        if degree[left] == 1 and degree[right] == 1:
            out[left], out[right] = right, left
    return out


def pair_rows_diff(
    existing: Iterable[tuple[Any, Any]],
    wanted: Mapping[str, str],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """
    Co dopisać i co skasować, żeby wiersze źródła `zprp` odpowiadały `wanted`.

    Wiersze są obustronne (A->B i B->A), więc porównujemy skierowane krawędzie.
    Zwraca (do_dopisania, do_skasowania), oba posortowane.
    """
    have = {(_s(a), _s(b)) for a, b in existing if _s(a) and _s(b)}
    want = {(_s(a), _s(b)) for a, b in wanted.items() if _s(a) and _s(b)}
    return sorted(want - have), sorted(have - want)
