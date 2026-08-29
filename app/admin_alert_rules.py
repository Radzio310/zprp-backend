# app/admin_alert_rules.py
#
# Reguły powiadomień dla administratora - bez bazy, bez sieci, bez zegara.
#
# Liść wydzielony z tego samego powodu, co `app/match_market_rules.py`: te
# funkcje decydują o tym, czy administrator dowie się o czymś, co dzieje się w
# aplikacji przy wyłączonym telefonie. Pomyłka nie kończy się brzydkim ekranem,
# tylko ciszą - a cisza wygląda dokładnie tak samo jak „nic się nie stało".
#
# Zasada nadrzędna: BRAK WPISU ZNACZY ZGODĘ. Administrator, który nigdy nie
# otworzył ustawień, ma dostawać wszystko. Domyślna cisza byłaby najgorszym z
# możliwych ustawień domyślnych dla powiadomień, których się nie widzi.

from __future__ import annotations

from typing import Any, Dict, Optional

#: Rodzaje zdarzeń, o których zawiadamiamy administratora.
#:
#: Klucz jest częścią ładunku powiadomienia i trafia do aplikacji, więc nie
#: zmieniamy go bez powodu - starsze wersje aplikacji czytają go tak samo.
#: Wartość to podpis dla człowieka i ikona, od której zaczyna się tytuł.
ADMIN_ALERT_KINDS: Dict[str, Dict[str, str]] = {
    "new_user": {"emoji": "👋", "label": "Nowy użytkownik"},
    "new_report": {"emoji": "🚨", "label": "Nowe zgłoszenie"},
    "report_reply": {"emoji": "💬", "label": "Odpowiedź w zgłoszeniu"},
    "market_offer": {"emoji": "🔁", "label": "Wymiana do rozstrzygnięcia"},
    "sync_failure": {"emoji": "⚠️", "label": "Awaria synchronizacji"},
    "protocol_failure": {"emoji": "⚠️", "label": "Nieudany protokół"},
}

#: Rodzaje, których NIE DA SIĘ wyciszyć.
#:
#: Awaria synchronizacji okręgu i nieudane generowanie protokołu to rzeczy,
#: które psują aplikację wszystkim innym. Administrator, który je wyłączy,
#: dowie się o awarii od sędziów - a wtedy jest już po meczu.
ALWAYS_ON_KINDS = frozenset({"sync_failure", "protocol_failure"})


def is_known_kind(kind: object) -> bool:
    return str(kind or "").strip() in ADMIN_ALERT_KINDS


def alert_title(kind: object, subject: str = "") -> str:
    """Tytuł powiadomienia: ikona, podpis rodzaju i ewentualny dopisek.

    Nieznany rodzaj dostaje neutralny tytuł zamiast wyjątku - powiadomienie o
    czymś, czego jeszcze nie opisaliśmy, jest wciąż lepsze niż brak
    powiadomienia.
    """
    key = str(kind or "").strip()
    meta = ADMIN_ALERT_KINDS.get(key)
    if not meta:
        return "🔔 BAZA" + (f" - {subject}" if subject else "")
    head = f"{meta['emoji']} {meta['label']}"
    return f"{head} - {subject}" if subject else head


def admin_pushes_allowed(prefs: Any, kind: object) -> bool:
    """Czy na to urządzenie wolno wysłać powiadomienie tego rodzaju.

    Trzy piętra, od najogólniejszego: globalny wyłącznik powiadomień, wyłącznik
    powiadomień administracyjnych i wyłącznik pojedynczego rodzaju. Każde puste
    znaczy zgodę.

    Awarie przechodzą zawsze - patrz `ALWAYS_ON_KINDS`.
    """
    key = str(kind or "").strip()
    if key in ALWAYS_ON_KINDS:
        return True
    if not isinstance(prefs, dict):
        return True
    if prefs.get("enabled") is False:
        return False
    types = prefs.get("notificationTypes")
    if not isinstance(types, dict):
        return True
    if types.get("adminAlerts") is False:
        return False
    per_kind = types.get("adminAlertKinds")
    if isinstance(per_kind, dict) and per_kind.get(key) is False:
        return False
    return True


def dedup_key(kind: object, reference: object) -> str:
    """Klucz, po którym odsiewamy powtórzenia tego samego zdarzenia.

    Ten sam użytkownik zalogowany dwa razy w minutę albo dwa zapisy tego samego
    zgłoszenia nie mają prawa dać dwóch powiadomień. Pusty odnośnik znaczy
    „nie odsiewaj" - są zdarzenia, które naprawdę mogą się powtórzyć.
    """
    key = str(kind or "").strip()
    ref = str(reference or "").strip()
    return f"{key}:{ref}" if key and ref else ""


def alert_payload(
    kind: object,
    reference: object = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Ładunek powiadomienia - stąd aplikacja wie, co otworzyć.

    `kind` na najwyższym poziomie, bo tak samo czyta go dyspozytor odsyłaczy w
    aplikacji dla wszystkich pozostałych powiadomień.
    """
    data: Dict[str, str] = {
        "kind": "admin_alert",
        "alertKind": str(kind or "").strip(),
    }
    ref = str(reference or "").strip()
    if ref:
        data["ref"] = ref
    for name, value in (extra or {}).items():
        if value is None:
            continue
        data[str(name)] = str(value)
    return data
