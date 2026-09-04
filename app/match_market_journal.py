# app/match_market_journal.py
#
# Dziennik giełdy meczów - katalog zdarzeń i ich opisy.
#
# Stany na ofercie mówią, gdzie sprawa jest TERAZ. Dziennik mówi, jak do tego
# doszło: kto wystawił, kto się zgłosił i wycofał, kto rozstrzygnął, czy baza
# związku przyjęła zapis, a jeśli nie - z jakim kodem odmowy. To jedyne
# miejsce, gdzie zostaje ślad po rzeczach, które nadpisał późniejszy stan.
#
# Moduł jest LIŚCIEM: bez bazy, bez sieci, bez FastAPI. Nazwy zdarzeń i zdania
# dla człowieka dają się sprawdzić testem, a jedno źródło opisów znaczy, że
# panel administratora i logi serwera mówią o tym samym tymi samymi słowami.
#
# ZASADA: rodzaj zdarzenia nazywa CZYNNOŚĆ, nie stan. „oferta wycofana" i
# „zgłoszenie wycofane" to dwie różne rzeczy, choć obie kończą się słowem
# „wycofane" - a przy odczycie historii trzeba je rozróżnić bez zaglądania w
# szczegóły.

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Rodzaje zdarzeń. Klucz idzie do bazy i NIE WOLNO go zmieniać - stare wiersze
#: zostają z dawną nazwą. Wartość to (grupa, ikona, krótki podpis).
#:
#: Grupy służą pigułkom filtra w panelu: cztery światy, cztery odpowiedzi na
#: pytanie „czego szukam".
EVENT_KINDS: Dict[str, Tuple[str, str, str]] = {
    # Oferty - cykl życia od strony oddającego.
    "offer_created": ("offers", "hand-right-outline", "Wystawił mecz"),
    "offer_withdrawn": ("offers", "arrow-undo-outline", "Wycofał ofertę"),
    "offer_expired": ("offers", "time-outline", "Minął termin oferty"),
    # Zgłoszenia - kto chciał wziąć mecz.
    "claim_created": ("claims", "hand-left-outline", "Zgłosił się"),
    "claim_withdrawn": ("claims", "close-circle-outline", "Wycofał zgłoszenie"),
    # Decyzje i zapis w bazie związku.
    "decision_approved": ("decisions", "shield-checkmark-outline", "Zatwierdził wymianę"),
    "decision_rejected": ("decisions", "close-circle-outline", "Odrzucił wymianę"),
    "zprp_applied": ("decisions", "checkmark-done-outline", "Zapisano w ZPRP"),
    "zprp_failed": ("decisions", "alert-circle-outline", "Zapis w ZPRP nie przeszedł"),
    # Ustawienia okręgu - ręka administratora.
    "config_changed": ("config", "settings-outline", "Zmienił ustawienia giełdy"),
}

#: Grupy zdarzeń w kolejności pigułek filtra.
EVENT_GROUPS: Tuple[Tuple[str, str], ...] = (
    ("offers", "Oferty"),
    ("claims", "Zgłoszenia"),
    ("decisions", "Decyzje"),
    ("config", "Ustawienia"),
)

#: Zdarzenia, które są PORAŻKĄ - panel maluje je barwą odmowy niezależnie od
#: kolumny `ok`, bo sama nazwa już to mówi.
FAILURE_KINDS = frozenset({"zprp_failed"})


def is_known_kind(kind: object) -> bool:
    """Czy ten rodzaj zdarzenia jest w katalogu."""
    return str(kind or "").strip() in EVENT_KINDS


def kind_group(kind: object) -> str:
    """Grupa filtra dla rodzaju zdarzenia; nieznany trafia do „decisions"."""
    entry = EVENT_KINDS.get(str(kind or "").strip())
    return entry[0] if entry else "decisions"


def kind_icon(kind: object) -> str:
    """Nazwa ikony (Ionicons) dla rodzaju zdarzenia."""
    entry = EVENT_KINDS.get(str(kind or "").strip())
    return entry[1] if entry else "ellipse-outline"


def kind_label(kind: object) -> str:
    """Krótki podpis rodzaju zdarzenia - nagłówek wiersza w osi czasu."""
    entry = EVENT_KINDS.get(str(kind or "").strip())
    return entry[2] if entry else str(kind or "").strip() or "Zdarzenie"


def kinds_in_group(group: object) -> List[str]:
    """Rodzaje należące do grupy - z tego powstaje warunek filtra w zapytaniu."""
    key = str(group or "").strip()
    return [kind for kind, entry in EVENT_KINDS.items() if entry[0] == key]


def _s(value: object) -> str:
    return str(value or "").strip()


def event_sentence(event: Mapping[str, Any]) -> str:
    """Jedno zdanie o zdarzeniu - to, co czyta administrator.

    Buduje się z kolumn, a nie z gotowego tekstu w bazie: nazwiska i numery
    meczów bywają poprawiane, a zdanie ma być zawsze świeże. `message` (powód
    odmowy, treść notatki) dochodzi na końcu, bo to jedyna część, której nie da
    się odtworzyć.
    """
    kind = _s(event.get("kind"))
    actor = _s(event.get("actor_name")) or _s(event.get("actor_judge_id")) or "Ktoś"
    subject = _s(event.get("subject_name")) or _s(event.get("subject_judge_id"))
    code = _s(event.get("match_code"))
    where = f" {code}" if code else ""
    message = _s(event.get("message"))

    if kind == "offer_created":
        head = f"{actor} wystawił mecz{where} na giełdę"
    elif kind == "offer_withdrawn":
        head = f"{actor} zabrał mecz{where} z giełdy"
    elif kind == "offer_expired":
        head = f"Minął termin zgłoszeń na mecz{where}"
    elif kind == "claim_created":
        head = f"{actor} zgłosił się na mecz{where}"
    elif kind == "claim_withdrawn":
        head = f"{actor} wycofał zgłoszenie na mecz{where}"
    elif kind == "decision_approved":
        head = (
            f"{actor} przyznał mecz{where} sędziemu {subject}"
            if subject
            else f"{actor} zatwierdził wymianę meczu{where}"
        )
    elif kind == "decision_rejected":
        head = f"{actor} odrzucił wymianę meczu{where}"
    elif kind == "zprp_applied":
        head = (
            f"Obsada meczu{where} zapisana w bazie związku - prowadzi {subject}"
            if subject
            else f"Obsada meczu{where} zapisana w bazie związku"
        )
    elif kind == "zprp_failed":
        head = f"Zapis obsady meczu{where} w bazie związku nie przeszedł"
    elif kind == "config_changed":
        head = f"{actor} zmienił ustawienia giełdy"
    else:
        head = f"{actor}: {kind_label(kind)}"

    if not message:
        return f"{head}."
    return f"{head}. {message}"


#: Ustawienia okręgu, których zmianę dziennik nazywa po ludzku.
CONFIG_FIELD_LABELS: Dict[str, str] = {
    "market_enabled": "giełda",
    "offer_deadline_hours": "próg oddania (h)",
    "assign_account_mode": "konto obsadowe",
    "approver_badges": "odznaki rozstrzygające",
}


def _config_value(field: str, value: Any) -> str:
    if field == "market_enabled":
        return "włączona" if value else "wyłączona"
    if field == "approver_badges":
        items = value if isinstance(value, (list, tuple)) else []
        return ", ".join(str(x) for x in items) or "brak"
    if field == "assign_account_mode":
        return "własne konto" if _s(value) == "own" else "to samo, co monitor"
    return _s(value) or "brak"


def config_diff_message(
    before: Optional[Mapping[str, Any]],
    after: Mapping[str, Any],
) -> str:
    """Co dokładnie zmienił administrator - „giełda: wyłączona → włączona".

    Bez tego wpis „zmienił ustawienia" nic nie mówi, a to jedyne zdarzenie,
    które potrafi wyłączyć cały moduł w okręgu. Pola nietknięte pomijamy: lista
    wszystkich ustawień przy każdej zmianie zakrywa tę jedną, która się liczy.
    """
    parts: List[str] = []
    for field, label in CONFIG_FIELD_LABELS.items():
        if field not in after:
            continue
        new_value = after[field]
        old_value = (before or {}).get(field)
        new_text = _config_value(field, new_value)
        old_text = _config_value(field, old_value)
        if before is not None and old_text == new_text:
            continue
        if before is None:
            parts.append(f"{label}: {new_text}")
        else:
            parts.append(f"{label}: {old_text} → {new_text}")
    return "; ".join(parts)
