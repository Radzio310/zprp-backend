"""
Formularze okręgowe - pytanie „Terminy” (zapisy na terminy, decyzje 24.11.2026). Bez bazy i bez sieci.

Odpowiedź uczestnika to lista id terminów. Znaczenie zależy od trybu pytania:

  optimize     „mogę w tych terminach” (dostępność). Komisja dostaje propozycję
               przydziału (`propose`), przesuwa ludzi ręcznie, zatwierdza i wysyła push.
  first_come   „zapisuję się”. Termin ma limit miejsc, pełny termin serwer odrzuca
               (`full_conflicts`, liczone pod blokadą wiersza formularza).

Zatwierdzony przydział leży w `district_forms.slot_plans`:

    {"<id pytania>": {"assign": {"<id terminu>": ["judge_id", …]},
                      "approved_at": iso | None, "approved_by": judge_id | None,
                      "updated_at": iso}}

Algorytm propozycji: przepływ o najmniejszym koszcie. Źródło -> termin (pojemność =
potrzebna liczba osób), termin -> osoba (1, jeśli zaznaczyła dostępność), osoba -> ujście
równoległymi krawędziami o koszcie 1, 3, 5, … (k-ty termin kosztuje 2k-1, więc suma = k²).
Najpierw liczy się jak najwięcej obsadzonych miejsc (największy przepływ), a wśród takich
przydziałów wybiera ten z najmniejszą sumą kwadratów obciążeń - czyli najrówniejszy.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from app.district_form_schema import FormQuestion, FormSection, questions, slot_label

Assign = Dict[str, List[str]]


def slot_questions(sections: Iterable[FormSection]) -> List[FormQuestion]:
    return [q for q in questions(sections) if q.type == "slots"]


def picks(answers: Any, question_id: str) -> List[str]:
    value = answers.get(question_id) if isinstance(answers, Mapping) else None
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def occupancy(q: FormQuestion, owners: Iterable[Tuple[str, Any]]) -> Dict[str, List[str]]:
    """id terminu -> klucze właścicieli (w kolejności wpisów), tylko istniejące terminy."""
    out: Dict[str, List[str]] = {x.id: [] for x in q.slots}
    for owner, answers in owners:
        for sid in picks(answers, q.id):
            if sid in out and owner not in out[sid]:
                out[sid].append(owner)
    return out


def full_conflicts(q: FormQuestion, chosen: Sequence[str], held: Sequence[str], taken_by_others: Mapping[str, int]) -> List[str]:
    """Terminy NOWO wybrane (bez tych, które osoba już trzyma), które nie mają wolnego miejsca."""
    if q.slot_mode != "first_come":
        return []
    capacity = {x.id: x.capacity for x in q.slots}
    kept = set(held)
    return [sid for sid in chosen if sid not in kept and taken_by_others.get(sid, 0) >= capacity.get(sid, 0)]


def full_message(q: FormQuestion, slot_ids: Sequence[str]) -> str:
    by_id = {x.id: x for x in q.slots}
    names = ", ".join(slot_label(by_id[s]) for s in slot_ids if s in by_id)
    if len(slot_ids) == 1:
        return f"Termin {names} jest już pełny - ktoś zapisał się chwilę przed Tobą. Wybierz inny."
    return f"Terminy {names} są już pełne - ktoś zapisał się chwilę przed Tobą. Wybierz inne."


# ---------------------------------------------------------------------------
# Propozycja przydziału (optimize)
# ---------------------------------------------------------------------------


class _Flow:
    """Przepływ o najmniejszym koszcie - kolejne najkrótsze ścieżki (SPFA), graf mały (terminy × ludzie)."""

    def __init__(self, n: int) -> None:
        self.n = n
        self.to: List[int] = []
        self.cap: List[int] = []
        self.cost: List[int] = []
        self.adj: List[List[int]] = [[] for _ in range(n)]

    def edge(self, a: int, b: int, cap: int, cost: int) -> int:
        self.adj[a].append(len(self.to))
        self.to.append(b)
        self.cap.append(cap)
        self.cost.append(cost)
        self.adj[b].append(len(self.to))
        self.to.append(a)
        self.cap.append(0)
        self.cost.append(-cost)
        return len(self.to) - 2

    def run(self, s: int, t: int) -> int:
        flow = 0
        while True:
            dist = [None] * self.n
            back = [-1] * self.n
            queued = [False] * self.n
            dist[s] = 0
            queue = deque([s])
            while queue:
                u = queue.popleft()
                queued[u] = False
                for e in self.adj[u]:
                    if self.cap[e] <= 0:
                        continue
                    v = self.to[e]
                    nd = dist[u] + self.cost[e]
                    if dist[v] is None or nd < dist[v]:
                        dist[v] = nd
                        back[v] = e
                        if not queued[v]:
                            queued[v] = True
                            queue.append(v)
            if dist[t] is None:
                return flow
            push, v = None, t
            while v != s:
                e = back[v]
                push = self.cap[e] if push is None else min(push, self.cap[e])
                v = self.to[e ^ 1]
            v = t
            while v != s:
                e = back[v]
                self.cap[e] -= push
                self.cap[e ^ 1] += push
                v = self.to[e ^ 1]
            flow += push


def propose(
    slots: Sequence[Tuple[str, int]],
    availability: Mapping[str, Iterable[str]],
    *,
    max_per_person: Optional[int] = None,
) -> Dict[str, Any]:
    """Przydział: każdy termin obsadzony (na ile się da), obciążenie jak najrówniejsze.

    `slots` = [(id, potrzebna liczba osób)], `availability` = osoba -> id terminów, w których może.
    Wynik deterministyczny (kolejność osób po kluczu). Zwraca `assign`, `missing` (termin -> ilu brakuje)
    i `load` (osoba -> liczba terminów).
    """
    slot_ids = [sid for sid, _ in slots]
    known = set(slot_ids)
    people = sorted(p for p, a in availability.items() if known & set(a))
    n_slots, n_people = len(slot_ids), len(people)
    s, t = 0, 1 + n_slots + n_people
    graph = _Flow(t + 1)
    slot_node = {sid: 1 + i for i, sid in enumerate(slot_ids)}
    person_node = {p: 1 + n_slots + i for i, p in enumerate(people)}
    for sid, need in slots:
        graph.edge(s, slot_node[sid], max(0, int(need)), 0)
    pair_edges: Dict[int, Tuple[str, str]] = {}
    for p in people:
        mine = [sid for sid in slot_ids if sid in set(availability[p])]
        for sid in mine:
            pair_edges[graph.edge(slot_node[sid], person_node[p], 1, 0)] = (sid, p)
        ceiling = len(mine) if max_per_person is None else min(len(mine), max_per_person)
        for k in range(1, ceiling + 1):
            graph.edge(person_node[p], t, 1, 2 * k - 1)
    graph.run(s, t)
    assign: Assign = {sid: [] for sid in slot_ids}
    for e, (sid, p) in pair_edges.items():
        if graph.cap[e] == 0:
            assign[sid].append(p)
    for sid in assign:
        assign[sid].sort()
    load: Dict[str, int] = {}
    for members in assign.values():
        for p in members:
            load[p] = load.get(p, 0) + 1
    need = dict(slots)
    missing = {sid: max(0, need[sid] - len(assign[sid])) for sid in slot_ids if need[sid] > len(assign[sid])}
    return {"assign": assign, "missing": missing, "load": load}


def propose_for(q: FormQuestion, availability: Mapping[str, Iterable[str]]) -> Dict[str, Any]:
    return propose([(x.id, x.capacity) for x in q.slots], availability, max_per_person=q.slot_max_per_person)


# ---------------------------------------------------------------------------
# Plan zapisany przez komisję
# ---------------------------------------------------------------------------


class PlanError(ValueError):
    pass


def clean_assign(q: FormQuestion, raw: Any, allowed: Set[str]) -> Assign:
    """Przydział od komisji: znane terminy, znani ludzie, bez powtórzeń w jednym terminie.

    Komisja MOŻE przydzielić kogoś spoza jego dostępności (ręczne przesunięcie) - aplikacja to
    oznacza, serwer nie blokuje. Nie może przekroczyć liczby osób terminu ani wpisać obcego.
    """
    if not isinstance(raw, Mapping):
        raise PlanError("Przydział ma zły kształt.")
    by_id = {x.id: x for x in q.slots}
    out: Assign = {x.id: [] for x in q.slots}
    for sid, members in raw.items():
        if sid not in by_id:
            raise PlanError("Przydział wskazuje termin, którego nie ma.")
        if not isinstance(members, list):
            raise PlanError("Przydział ma zły kształt.")
        clean = list(dict.fromkeys(str(m) for m in members if str(m)))
        stranger = [m for m in clean if m not in allowed]
        if stranger:
            raise PlanError("Przydział wskazuje osobę spoza uczestników formularza.")
        if len(clean) > by_id[sid].capacity:
            raise PlanError(f"Termin {slot_label(by_id[sid])} ma za dużo osób - zwiększ liczbę miejsc albo kogoś przesuń.")
        out[sid] = clean
    return out


def per_person(q: FormQuestion, assign: Mapping[str, Sequence[str]]) -> Dict[str, List[str]]:
    """osoba -> id jej terminów w kolejności terminów."""
    out: Dict[str, List[str]] = {}
    for x in q.slots:
        for p in assign.get(x.id) or []:
            out.setdefault(p, []).append(x.id)
    return out


def push_text(form_title: str, q: FormQuestion, slot_ids: Sequence[str]) -> Tuple[str, str]:
    by_id = {x.id: x for x in q.slots}
    labels = [slot_label(by_id[s]) for s in slot_ids if s in by_id]
    title = f"📅 {form_title}"[:80]
    if len(labels) == 1:
        body = f"Twój termin: {labels[0]}."
    else:
        body = f"Twoje terminy: {'; '.join(labels)}."
    return title, body[:300]
