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

import json
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


def _as_prefs(raw: Any) -> Any:
    """Preferencje jako słownik - także wtedy, gdy kolumna wróci tekstem.

    Kolumny JSON/JSONB potrafią wrócić z bazy jako napis (reszta backendu ma na
    to `_parse_json`). Nierozpakowany napis przechodził tędy jak „brak
    preferencji", więc wyłącznik powiadomień administracyjnych po prostu nic
    nie robił - a to jest cichy błąd w obie strony: albo ktoś dostaje to, co
    wyciszył, albo podgląd zasięgu kłamie, że dostanie.
    """
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return None
    return raw


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
    prefs = _as_prefs(prefs)
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


# ── Dlaczego administrator czegoś nie dostał ────────────────────────────────
#
# „Jeden admin dostał powiadomienie, drugi nie" nie da się rozstrzygnąć
# spojrzeniem na kod wysyłki, bo każdy lejek po drodze odsiewa po cichu:
# urządzenie bez przypisanego sędziego, token unieważniony przez Firebase i
# wyciszony rodzaj powiadomień wyglądają na końcu identycznie - nic nie
# przyszło. Te nazwy stanów są wspólne dla wysyłki (log) i dla panelu
# (podgląd), żeby administrator czytał to samo, co widać w logu.

#: Urządzenie dostanie to powiadomienie.
DEVICE_OK = "ok"
#: Token wyczyszczony po odrzuceniu przez Firebase (`invalidate_rejected_fcm_token`).
#: Wraca sam przy najbliższym starcie aplikacji - ale dopóki nie wróci, cisza.
DEVICE_TOKEN_LOST = "token_lost"
#: Urządzenie zarejestrowane bez tokenu FCM (Expo Go, iOS bez APNs->FCM).
#: `send_push_to_judges` pomija takie wiersze.
DEVICE_NOT_FCM = "not_fcm"
#: Właściciel wyciszył ten rodzaj albo powiadomienia w ogóle.
DEVICE_MUTED = "muted"

#: Administrator, którego żadne urządzenie nie zgłosiło swojego numeru sędziego.
#: To jest najczęstsza przyczyna ciszy i JEDYNA, której właściciel telefonu
#: nie zauważy: aplikacja działa, powiadomienia „są włączone", a serwer po
#: prostu nie wie, gdzie go szukać.
ADMIN_NO_DEVICE = "no_device"


def device_alert_state(device: Any, kind: object) -> str:
    """Stan JEDNEGO urządzenia wobec jednego rodzaju powiadomienia."""
    row = device if isinstance(device, dict) else {}
    token_type = str(row.get("token_type") or "").strip()
    token = str(row.get("token") or "").strip()
    if not admin_pushes_allowed(row.get("notification_prefs"), kind):
        return DEVICE_MUTED
    if token_type == "invalid_fcm" or not token:
        return DEVICE_TOKEN_LOST
    if token_type != "device_fcm":
        return DEVICE_NOT_FCM
    return DEVICE_OK


def summarize_admin_reach(judge_id: str, devices: Any, kind: object) -> Dict[str, Any]:
    """Czy TEN administrator dostanie TEN rodzaj powiadomienia - i dlaczego nie.

    Wystarczy jedno sprawne urządzenie. Stan zbiorczy to stan pierwszego
    urządzenia, które ma najbliżej do sprawności, bo administratora nie
    interesuje, że jeden z trzech telefonów ma wygasły token - interesuje go,
    czy dostanie powiadomienie.
    """
    rows = list(devices or [])
    states = [device_alert_state(row, kind) for row in rows]
    if not states:
        state = ADMIN_NO_DEVICE
    elif DEVICE_OK in states:
        state = DEVICE_OK
    else:
        # Kolejność od najbardziej naprawialnego: token wraca sam przy starcie
        # aplikacji, brak FCM wymaga innego wydania, wyciszenie to decyzja.
        for candidate in (DEVICE_TOKEN_LOST, DEVICE_NOT_FCM, DEVICE_MUTED):
            if candidate in states:
                state = candidate
                break
        else:  # pragma: no cover - lista stanów jest zamknięta
            state = DEVICE_NOT_FCM
    return {
        "judge_id": str(judge_id or "").strip(),
        "devices": len(rows),
        "deliverable": sum(1 for s in states if s == DEVICE_OK),
        "state": state,
        "will_receive": state == DEVICE_OK,
    }
