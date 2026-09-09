# app/vip_tabs.py
"""
Jedyne miejsce, w ktorym zapisane jest, ktora zakladka baza.zprp.pl zasila
ktory modul BAZA_web.

Konto VIP dostaje uprawnienia recznie (panel admina -> baza_vips.permissions_json),
ale samo uprawnienie niczego nie karmi: dane plyna z menu konta na baza.zprp.pl.
Konto organizatora bez zakladki "Sedziowie i Delegaci" ma czym zasilic Terminarz,
Rozgrywki i Statystyki, a nie ma czym zasilic listy sedziow. Dlatego wygaszamy
POJEDYNCZE moduly i funkcje, nigdy calosc dostepu VIP.

Uwaga: to jest zrodlo prawdy dla trzech konsumentow - /baza_web/login (liczy
tab_access przy logowaniu), /baza_vips/tabs_meta (panel admina w BAZA rysuje
ostrzezenia) i scraperow (czytelna odmowa zamiast 500 z regexem). Nie duplikuj
tej mapy po stronie klienta.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable

# -------------------------
# Klucze zakladek
# -------------------------

TAB_SCHEDULE = "terminarz"
TAB_COMPETITIONS = "rozgrywki"
TAB_STATS = "statystyki"
TAB_OFFICIALS = "sedziowie"

# klucz -> etykieta pokazywana czlowiekowi (tak jak stoi w menu ZPRP)
TAB_LABELS: dict[str, str] = {
    TAB_SCHEDULE: "Terminarz",
    TAB_COMPETITIONS: "Rozgrywki",
    TAB_STATS: "Statystyki",
    TAB_OFFICIALS: "Sędziowie i Delegaci",
}

# etykieta z menu (znormalizowana) -> klucz
_LABEL_TO_KEY: dict[str, str] = {
    "terminarz": TAB_SCHEDULE,
    "rozgrywki": TAB_COMPETITIONS,
    "statystyki": TAB_STATS,
    "sedziowie i delegaci": TAB_OFFICIALS,
    "sedziowie": TAB_OFFICIALS,
}

# -------------------------
# Funkcje (pod-zakladki ekranu "Raporty i podsumowania ZPRP")
# -------------------------

FEATURE_TABS: dict[str, str] = {
    "zprp_reports.schedule": TAB_SCHEDULE,
    "zprp_reports.competitions": TAB_COMPETITIONS,
    "zprp_reports.stats": TAB_STATS,
    "zprp_reports.officials": TAB_OFFICIALS,
}

# -------------------------
# Moduly (kafle na ekranie glownym BAZA_web)
#   mode "all" - potrzebne wszystkie wymienione zakladki
#   mode "any" - wystarczy jedna (modul otwiera sie czesciowo)
#   pusta lista - modul stoi na wlasnym backendzie, ZPRP go nie dotyczy
# -------------------------

MODULE_TABS: dict[str, dict[str, Any]] = {
    # wlasny backend - niedyspozycje okregowe i tablica komisji
    "district_unavailability": {"mode": "all", "tabs": []},
    "district_board": {"mode": "all", "tabs": []},
    # wlasna baza badge'ow (/province_judges)
    "province_judges": {"mode": "all", "tabs": []},
    # obsady chodza po a=terminarz; sedziow bierze z formularza obsady, nie z menu
    "assignments": {"mode": "all", "tabs": [TAB_SCHEDULE]},
    # ekran raportow ma cztery pod-zakladki - otwieramy go, gdy dziala chocby jedna
    "zprp_reports": {
        "mode": "any",
        "tabs": [TAB_SCHEDULE, TAB_COMPETITIONS, TAB_STATS, TAB_OFFICIALS],
    },
    # statystyki wojewodzkie stoja w calosci na /zprp/sedziowie/scrape
    "province_stats": {"mode": "all", "tabs": [TAB_OFFICIALS]},
}

# Nazwy modulow dla czlowieka (panel admina i komunikaty).
MODULE_LABELS: dict[str, str] = {
    "district_unavailability": "Niedyspozycje okręgowe",
    "district_board": "Tablica komisji okręgowej",
    "province_judges": "Lista sędziów okręgowych",
    "assignments": "Moduł obsadowego",
    "zprp_reports": "Raporty i podsumowania ZPRP",
    "province_stats": "Statystyki wojewódzkie",
}

# Uprawnienie z panelu admina -> moduly, ktore realnie otwiera.
# Odwzorowuje dzisiejsze dziedziczenie z BAZA_web/app/(tabs)/index.tsx:
# district_board i zprp_reports ida po assignments, province_stats po zprp_reports.
PERMISSION_MODULES: dict[str, list[str]] = {
    "admin": list(MODULE_TABS.keys()),
    "assignments": [
        "assignments",
        "district_board",
        "zprp_reports",
        "province_stats",
    ],
    "district_unavailability": ["district_unavailability"],
    "province_judges": ["province_judges"],
}


# -------------------------
# Normalizacja
# -------------------------

def normalize_tab_label(value: Any) -> str:
    s = str(value or "").strip().lower()
    if not s:
        return ""
    s = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", s).strip()


def tab_keys_from_labels(labels: Iterable[Any] | None) -> list[str]:
    """Etykiety z menu ZPRP -> znane klucze zakladek (bez powtorzen, w stalej kolejnosci)."""
    out: list[str] = []
    for raw in labels or []:
        key = _LABEL_TO_KEY.get(normalize_tab_label(raw))
        if key and key not in out:
            out.append(key)
    return [k for k in TAB_LABELS if k in out]


def label_for(key: str) -> str:
    return TAB_LABELS.get(key, key)


def labels_for(keys: Iterable[str]) -> list[str]:
    return [label_for(k) for k in keys]


# -------------------------
# Liczenie dostepu
# -------------------------

def _module_verdict(spec: dict[str, Any], present: set[str]) -> dict[str, Any]:
    required: list[str] = list(spec.get("tabs") or [])
    if not required:
        return {"ok": True, "missing": [], "partial": False}

    missing = [k for k in required if k not in present]

    if spec.get("mode") == "any":
        ok = len(missing) < len(required)
        return {
            "ok": ok,
            "missing": labels_for(missing),
            "partial": ok and bool(missing),
        }

    return {"ok": not missing, "missing": labels_for(missing), "partial": False}


def compute_tab_access(available_tabs: Iterable[Any] | None) -> dict[str, Any]:
    """
    Zdejmuje z listy etykiet menu gotowy werdykt dla kazdej funkcji i kazdego modulu.

    Uwaga: `available_tabs=None` znaczy "nie wiem", a nie "nic nie ma". Wtedy
    zwracamy `known=False` i klient ma NIE przycinac uprawnien - inaczej stary
    rekord bez zakladek po cichu zamknalby dziala jace konto.
    """
    if available_tabs is None:
        return {
            "known": False,
            "tabs": [],
            "labels": dict(TAB_LABELS),
            "missing": [],
            "features": {},
            "feature_labels": {},
            "modules": {},
        }

    present = set(tab_keys_from_labels(available_tabs))

    features = {
        feature: (tab in present) for feature, tab in FEATURE_TABS.items()
    }
    feature_labels = {
        feature: label_for(tab) for feature, tab in FEATURE_TABS.items()
    }
    modules = {
        key: _module_verdict(spec, present) for key, spec in MODULE_TABS.items()
    }
    missing = [k for k in TAB_LABELS if k not in present]

    return {
        "known": True,
        "tabs": [k for k in TAB_LABELS if k in present],
        "labels": dict(TAB_LABELS),
        "missing": labels_for(missing),
        "features": features,
        "feature_labels": feature_labels,
        "modules": modules,
    }


def tabs_meta() -> dict[str, Any]:
    """Mapa dla panelu admina w BAZA - zeby nie trzymal wlasnej kopii."""
    return {
        "labels": dict(TAB_LABELS),
        "module_labels": dict(MODULE_LABELS),
        "features": dict(FEATURE_TABS),
        "modules": {
            key: {"mode": spec.get("mode", "all"), "tabs": list(spec.get("tabs") or [])}
            for key, spec in MODULE_TABS.items()
        },
        "permission_modules": {k: list(v) for k, v in PERMISSION_MODULES.items()},
    }


def tab_access_from_login_info(login_info: Any) -> dict[str, Any]:
    """
    Werdykt liczony z zapisanego login_info_json rekordu baza_vips.
    Brak klucza "tabs" znaczy "jeszcze nie wiemy" - wtedy known=False i nikt
    niczego nie przycina.
    """
    info = login_info
    if isinstance(info, str):
        import json

        try:
            info = json.loads(info)
        except Exception:
            info = None

    if not isinstance(info, dict):
        return compute_tab_access(None)

    tabs = info.get("tabs")
    if not isinstance(tabs, list):
        return compute_tab_access(None)

    return compute_tab_access(tabs)
