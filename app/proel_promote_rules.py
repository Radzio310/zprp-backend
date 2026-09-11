"""Zapis szkoleniowy jako oficjalny - reguły bez bazy i bez sieci.

Zdarza się, że mecz prowadzono pod kluczem szkoleniowym (`T-XXXXXXXX/NUMER`),
choć był prawdziwym meczem: sędzia wziął go z terminarza cudzym kontem albo
aplikacja nie rozpoznała pochodzenia. Protokół jest kompletny, tylko leży pod
złym kluczem - lista stolików go nie widzi, a wyniki i statystyki go pomijają.

Administrator przenosi go trasą `POST /proel/archive/promote_training`
(`app/proel_archive.py`). Tu siedzi wszystko, co decyduje o tym, CZY wolno:
wyprowadzenie klucza oficjalnego, przepisanie bloba i werdykt dla każdego
klucza z samych faktów. Testy: `tests/test_proel_promote_rules.py` - testy
z Postgresem są w tym projekcie pomijane, a to jest reguła, która tworzy
oficjalny protokół.

Zapis szkoleniowy zostaje nietknięty i dostaje tylko wskazanie, dokąd go
przeniesiono (`promoted_to`). Dalsze zapisy pod kluczem szkoleniowym serwer
odrzuca z `MATCH_PROMOTED` - inaczej dwa protokoły jednego meczu zaczęłyby się
rozjeżdżać.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.proel_bulk_delete_rules import MAX_BULK, lock_message, normalize_keys
from app.proel_match_key import (
    IDENTITY_CONFLICT,
    identity_verdict,
    local_key_from_blob,
    match_identity,
    zprp_id_of,
)
from app.proel_training_key import (
    blob_is_training,
    is_training_key,
    key_conflicts_with_blob,
    match_number_from_key,
)

__all__ = [
    "MAX_BULK",
    "normalize_keys",
    "official_key_for",
    "exercise_kind",
    "official_blob",
    "official_blob_is_clean",
    "PromotionFacts",
    "promotion_verdict",
    "promoted_detail",
    "promote_lock_message",
]

REASON_NOT_TRAINING = "not_training"
REASON_MISSING = "missing"
REASON_ALREADY_PROMOTED = "already_promoted"
REASON_EXERCISE = "exercise"
REASON_IN_USE = "in_use"
REASON_NUMBER_MISMATCH = "number_mismatch"
REASON_OFFICIAL_EXISTS = "official_exists"
REASON_OFFICIAL_IN_USE = "official_in_use"
REASON_ID_CONFLICT = "id_conflict"
REASON_OVERLAY_NONEMPTY = "overlay_nonempty"

PIN_INVALID_MESSAGE = "Nieprawidłowy PIN - nic nie zostało przeniesione."
FAILED_MESSAGE = "Nie udało się przenieść tego zapisu. Spróbuj jeszcze raz."

#: Status po ludzku - do komunikatu "pod tym numerem już jest zapis".
_STATUS_NAMES = {
    "in_progress": "w toku",
    "finished": "zakończony",
    "approved": "zatwierdzony",
}


def official_key_for(key: Any) -> str:
    """Klucz oficjalnego wiersza: numer ukryty w kluczu szkoleniowym.

    Wielkimi literami, bo tak normalizuje numer aplikacja na granicy sieci
    (`proelMatchKey` w `utils/matchNumber.ts`) - wiersz zapisany inną pisownią
    byłby dla niej niewidzialny.
    """
    return match_number_from_key(key).strip().upper()


def _config(blob_or_config: Any) -> Dict[str, Any]:
    if not isinstance(blob_or_config, dict):
        return {}
    inner = blob_or_config.get("matchConfig")
    if isinstance(inner, dict):
        return inner
    return blob_or_config


def exercise_kind(config: Any) -> str:
    """"test", "course" albo "" - czy to mecz testowy albo ćwiczenie z kursu.

    Przyjmuje samą `matchConfig` albo cały blob. Tych dwóch nigdy nie
    przenosimy: to nie są protokoły prawdziwych meczów, tylko praca na nich.
    """
    cfg = _config(config)
    if cfg.get("isTest"):
        return "test"
    training = cfg.get("training")
    if isinstance(training, dict) and str(training.get("eventId") or "").strip():
        return "course"
    return ""


def official_blob(blob: Any, training_key: str, at_iso: str, by_name: str) -> Dict[str, Any]:
    """Blob oficjalnej kopii: to samo, tylko inne pochodzenie.

    Zmieniamy WYŁĄCZNIE to, co decyduje o tym, pod jakim kluczem mecz żyje:
    pochodzenie przechodzi na "account", klucz szkoleniowy znika, a ślad
    przeniesienia ląduje w `promotedFromTraining`. Przebieg, składy, podpisy
    i wynik zostają co do bajtu - to jest ten sam protokół.
    """
    if not isinstance(blob, dict):
        raise ValueError("blob meczu nie jest obiektem")
    out = copy.deepcopy(blob)
    cfg = out.get("matchConfig")
    cfg = dict(cfg) if isinstance(cfg, dict) else {}
    cfg["origin"] = "account"
    cfg.pop("proelKey", None)
    cfg["promotedFromTraining"] = {
        "key": str(training_key or ""),
        "at": str(at_iso or ""),
        "by": str(by_name or ""),
    }
    out["matchConfig"] = cfg
    return out


def official_blob_is_clean(official_key: str, blob: Any) -> bool:
    """Czy oficjalna kopia przejdzie przez strażnika zapisu jak zwykły mecz.

    Ta sama reguła, którą `PUT` stosuje do każdego zapisu
    (`key_conflicts_with_blob`): mecz szkoleniowy pod czystym numerem to
    dokładnie ta kolizja, przed którą ten strażnik stoi.
    """
    return not key_conflicts_with_blob(official_key, blob) and not blob_is_training(blob)


@dataclass
class PromotionFacts:
    """Fakty o jednym kluczu, zebrane przez trasę z bazy."""

    key: str
    training_exists: bool = False
    #: `promoted_to` wiersza szkoleniowego.
    promoted_to: Optional[str] = None
    #: `matchConfig` bloba szkoleniowego.
    config: Optional[Dict[str, Any]] = None
    training_lease_active: bool = False
    training_lease_holder: str = ""
    #: Status oficjalnego wiersza `proel_matches`; `None` = takiego wiersza nie ma.
    official_status: Optional[str] = None
    #: Inny wiersz (nieszkoleniowy) z tym samym `zprp_match_id`.
    zprp_twin_key: Optional[str] = None
    official_lease_active: bool = False
    official_lease_holder: str = ""
    official_zprp_id: Optional[str] = None
    official_local_key: Optional[str] = None
    official_overlay_nonempty: bool = False


def _refusal(reason: str, message: str) -> Dict[str, str]:
    return {"reason": reason, "message": message}


def promotion_verdict(facts: PromotionFacts) -> Optional[Dict[str, str]]:
    """Odmowa `{reason, message}` albo `None`, gdy klucz wolno przenieść.

    Brak wiersza szkoleniowego wraca jako `{"reason": "missing"}` - trasa
    odkłada go na osobną listę, bo "tego zapisu już nie ma" to nie odmowa.

    Kolejność jest kolejnością pytań, jakie zadałby człowiek: czy to w ogóle
    zapis szkoleniowy, czy jeszcze istnieje, czy nie przeniesiono go już, czy
    to prawdziwy mecz, czy nikt go teraz nie prowadzi - i dopiero potem, czy
    miejsce pod oficjalnym numerem jest wolne.
    """
    key = str(facts.key or "")
    if not is_training_key(key):
        return _refusal(
            REASON_NOT_TRAINING,
            "To nie jest zapis szkoleniowy (klucz bez przedrostka T-). "
            "Do oficjalnych przenosi się wyłącznie zapisy szkoleniowe.",
        )
    official = official_key_for(key)
    if not official:
        return _refusal(
            REASON_NOT_TRAINING,
            "Z tego klucza nie da się odczytać numeru meczu, więc nie ma "
            "dokąd przenieść zapisu.",
        )
    if not facts.training_exists:
        return {"reason": REASON_MISSING, "message": "Tego zapisu szkoleniowego już nie ma."}
    if str(facts.promoted_to or "").strip():
        return _refusal(
            REASON_ALREADY_PROMOTED,
            f"Ten zapis został już przeniesiony do oficjalnego meczu {facts.promoted_to}.",
        )

    cfg = _config(facts.config or {})
    kind = exercise_kind(cfg)
    if kind == "test":
        return _refusal(
            REASON_EXERCISE,
            "To mecz testowy - taki zapis nigdy nie staje się oficjalnym protokołem.",
        )
    if kind == "course":
        return _refusal(
            REASON_EXERCISE,
            "To ćwiczenie z kursokonferencji - takie zapisy nigdy nie stają się "
            "oficjalnym protokołem.",
        )

    if facts.training_lease_active:
        who = str(facts.training_lease_holder or "").strip()
        holder = f" ({who})" if who else ""
        return _refusal(
            REASON_IN_USE,
            f"Ten zapis szkoleniowy jest właśnie prowadzony{holder}. Przenieś go, "
            "gdy prowadzący skończy albo prowadzenie wygaśnie.",
        )

    number = str(cfg.get("matchNumber") or "").strip().upper()
    if number and number != official:
        return _refusal(
            REASON_NUMBER_MISMATCH,
            f"Protokół w tym zapisie opisuje mecz {number}, a klucz wskazuje "
            f"{official}. Nie przenosimy protokołu pod numer innego meczu.",
        )

    if facts.official_status is not None:
        label = _STATUS_NAMES.get(str(facts.official_status or ""), str(facts.official_status or "nieznany"))
        return _refusal(
            REASON_OFFICIAL_EXISTS,
            f"Pod numerem {official} jest już oficjalny zapis (status: {label}). "
            "Nie nadpisujemy go - najpierw usuń albo popraw bieżący zapis.",
        )
    if str(facts.zprp_twin_key or "").strip():
        zprp = zprp_id_of({"matchConfig": cfg})
        return _refusal(
            REASON_OFFICIAL_EXISTS,
            f"Ten mecz (IdZawody {zprp or '?'}) ma już oficjalny zapis pod kluczem "
            f"{facts.zprp_twin_key}. Nie zakładamy drugiego protokołu tego samego meczu.",
        )

    if facts.official_lease_active:
        who = str(facts.official_lease_holder or "").strip() or "inną osobę"
        return _refusal(
            REASON_OFFICIAL_IN_USE,
            f"Oficjalny mecz {official} jest właśnie prowadzony przez: {who}. "
            "Przenieś zapis, gdy prowadzenie wygaśnie.",
        )

    known = match_identity(facts.official_zprp_id, facts.official_local_key)
    incoming = match_identity(
        zprp_id_of({"matchConfig": cfg}), local_key_from_blob({"matchConfig": cfg})
    )
    if identity_verdict(known, incoming) == IDENTITY_CONFLICT:
        return _refusal(
            REASON_ID_CONFLICT,
            f"Pod numerem {official} serwer zna inny mecz (inne IdZawody albo inne "
            "drużyny). Sprawdź, czy to na pewno ten sam mecz.",
        )

    if facts.official_overlay_nonempty:
        return _refusal(
            REASON_OVERLAY_NONEMPTY,
            f"Oficjalny mecz {official} ma już dane współpracy (podpisy, badania "
            "albo obsadę wpisane z innych urządzeń). Przeniesienie pomieszałoby je "
            "z zapisem szkoleniowym - te dane trzeba scalić ręcznie.",
        )
    return None


def promoted_detail(
    official_key: str, official_doc_rev: Optional[int], promoted_from_rev: Optional[int]
) -> Dict[str, Any]:
    """Treść odmowy 409 `MATCH_PROMOTED` dla zapisu pod przeniesiony klucz.

    Telefon dostaje od razu, dokąd pisać dalej i w jakiej wersji jest tam
    treść - nie musi pytać drugi raz, żeby się przełączyć.
    """
    return {
        "code": "MATCH_PROMOTED",
        "message": (
            f"Ten mecz szkoleniowy został przeniesiony do oficjalnego zapisu "
            f"{official_key}. Dalsze zapisy idą do oficjalnego meczu."
        ),
        "official_key": official_key,
        "official_doc_rev": (int(official_doc_rev) if official_doc_rev is not None else None),
        "promoted_from_rev": (int(promoted_from_rev) if promoted_from_rev is not None else None),
    }


def promote_lock_message(seconds_left: int) -> str:
    return lock_message(
        seconds_left, action="Przenoszenie", outcome="nic nie zostało przeniesione"
    )
