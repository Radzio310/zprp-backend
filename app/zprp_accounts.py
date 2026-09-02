# app/zprp_accounts.py
#
# Konta ZPRP, którymi serwer działa w imieniu okręgu.
#
# Dwie role, świadomie rozdzielone:
#
#   `sync`   - konto monitora meczów. Tylko czyta: otwiera listy meczów sędziów
#              i terminarz województwa, żeby wykryć zmiany i wysłać push.
#   `assign` - konto obsadowe. ZAPISUJE obsadę w bazie związku, gdy administrator
#              albo obsadowy zatwierdzi wymianę meczu na giełdzie.
#
# Rozdzielenie jest domyślne, bo to dwie różne stawki. Pomyłka w module wymiany
# nie ma jak zepsuć powiadomień dla całego województwa, dopóki chodzą one innym
# kontem. Okręg, który ma jedno konto do wszystkiego, ustawia w panelu tryb
# `same_as_sync` i wtedy zapis schodzi do konta monitora - świadomie, nie przez
# przeoczenie.
#
# HASŁA NIE PRZECHODZĄ PRZEZ TEN MODUŁ NIGDZIE POZA WYWOŁANIEM. Leżą w
# zmiennych Railway, tak jak `app_key` ProEla, i nie ma dla nich ani endpointu
# zapisu, ani kolumny w bazie. Panel administratora dostaje z `account_status`
# wyłącznie odpowiedź „jest / nie ma" i nazwy zmiennych do dodania.

from __future__ import annotations

import os
import re
import unicodedata
from typing import Any, Dict, Mapping, Optional, Tuple

#: Województwo → przyrostek w nazwie zmiennej środowiskowej.
#:
#: Przyrostki są częścią publicznego kontraktu wdrożeniowego. Nie zmieniać ich
#: bez równoczesnej migracji zmiennych na Railway.
PROVINCE_ENV_SUFFIXES: Dict[str, str] = {
    "DOLNOSLASKIE": "DOLNOSLASKIE",
    "KUJAWSKO_POMORSKIE": "KUJAWSKO_POMORSKIE",
    "LUBELSKIE": "LUBELSKIE",
    "LUBUSKIE": "LUBUSKIE",
    "LODZKIE": "LODZKIE",
    "MALOPOLSKIE": "MALOPOLSKIE",
    "MAZOWIECKIE": "MAZOWIECKIE",
    "OPOLSKIE": "OPOLSKIE",
    "PODKARPACKIE": "PODKARPACKIE",
    "PODLASKIE": "PODLASKIE",
    "POMORSKIE": "POMORSKIE",
    "SLASKIE": "SLASKIE",
    "SWIETOKRZYSKIE": "SWIETOKRZYSKIE",
    "WARMINSKO_MAZURSKIE": "WARMINSKO_MAZURSKIE",
    "WIELKOPOLSKIE": "WIELKOPOLSKIE",
    "ZACHODNIOPOMORSKIE": "ZACHODNIOPOMORSKIE",
}

#: Prefiksy zmiennych per rola.
ROLE_PREFIXES: Dict[str, str] = {
    "sync": "ZPRP_SYNC",
    "assign": "ZPRP_ASSIGN",
}


def normalize_province(value: Any) -> str:
    """Nazwa województwa sprowadzona do klucza zmiennej środowiskowej.

    Zdejmuje znaki diakrytyczne, ujednolica separatory i zna kilka nazw
    potocznych. Zwraca pusty string dla czegoś, co nie jest znanym
    województwem - i to jest odpowiedź, nie błąd: wołający sam decyduje, czy
    pominąć wiersz, czy odmówić.
    """
    # Ł NIE JEST literą ze znakiem diakrytycznym - to osobny znak Unicode i NFD
    # go nie rozkłada. Bez tej podmiany „ŁÓDZKIE" i „MAŁOPOLSKIE" wychodziły
    # stąd jako pusty napis, czyli „to nie jest województwo": oba okręgi
    # przepadały po cichu przy każdym dopasowaniu po nazwie.
    raw = str(value or "").replace("Ł", "L").replace("ł", "l")
    raw = unicodedata.normalize("NFD", raw)
    raw = "".join(ch for ch in raw if unicodedata.category(ch) != "Mn")
    raw = re.sub(r"[^A-Z0-9]+", "_", raw.upper()).strip("_")
    if raw.startswith("WOJEWODZTWO_"):
        raw = raw[len("WOJEWODZTWO_") :]
    aliases = {
        "DOLNY_SLASK": "DOLNOSLASKIE",
        "KUJAWSKO_POMORSKIE": "KUJAWSKO_POMORSKIE",
        "LODZKIE": "LODZKIE",
        "MALOPOLSKIE": "MALOPOLSKIE",
        "SLASKIE": "SLASKIE",
        "SWIETOKRZYSKIE": "SWIETOKRZYSKIE",
        "WARMINSKO_MAZURSKIE": "WARMINSKO_MAZURSKIE",
        "ZACHODNIO_POMORSKIE": "ZACHODNIOPOMORSKIE",
    }
    resolved = aliases.get(raw, raw)
    return resolved if resolved in PROVINCE_ENV_SUFFIXES else ""


def env_var_names(province: Any, role: str) -> Tuple[str, str]:
    """Para nazw zmiennych `(login, hasło)` albo `("", "")` dla obcej nazwy.

    Panel administratora pokazuje je wprost, żeby dołożenie okręgu nie wymagało
    zaglądania do kodu.
    """
    key = normalize_province(province)
    prefix = ROLE_PREFIXES.get(role, "")
    if not key or not prefix:
        return "", ""
    suffix = PROVINCE_ENV_SUFFIXES[key]
    return f"{prefix}_{suffix}_USERNAME", f"{prefix}_{suffix}_PASSWORD"


def credentials_for(
    province: Any, role: str, env: Optional[Mapping[str, str]] = None
) -> Optional[Tuple[str, str]]:
    """Para `(login, hasło)` dla roli albo `None`, gdy konta nie ma.

    Podana połowa pary to dla nas brak konta, a nie konto. Logowanie samym
    loginem i tak by nie przeszło, a cicha próba zostawiłaby w logach ZPRP serię
    nieudanych uwierzytelnień z naszego adresu.
    """
    source = os.environ if env is None else env
    user_var, pass_var = env_var_names(province, role)
    if not user_var:
        return None
    username = str(source.get(user_var, "") or "").strip()
    password = str(source.get(pass_var, "") or "").strip()
    if username and password:
        return username, password
    return None


def configured_provinces(
    env: Optional[Mapping[str, str]] = None,
) -> Dict[str, Tuple[str, str]]:
    """Województwa z kompletnym kontem monitora - wejście dla crawlera."""
    out: Dict[str, Tuple[str, str]] = {}
    for province in PROVINCE_ENV_SUFFIXES:
        creds = credentials_for(province, "sync", env)
        if creds:
            out[province] = creds
    return out


def assign_credentials(
    province: Any,
    mode: str = "own",
    env: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Konto do ZAPISU obsady, razem z informacją, skąd zostało wzięte.

    `mode` pochodzi z ustawień okręgu (`province_module_config`):
    `"own"` szuka wyłącznie konta obsadowego, `"same_as_sync"` sięga po konto
    monitora. Zejście z `own` do `sync` NIE jest automatyczne - inaczej
    województwo, w którym zapomniano dodać konto obsadowe, po cichu zapisywałoby
    zmiany kontem monitora, a administrator widziałby w panelu, że wszystko gra.
    """
    wanted_role = "sync" if str(mode) == "same_as_sync" else "assign"
    creds = credentials_for(province, wanted_role, env)
    user_var, pass_var = env_var_names(province, wanted_role)
    return {
        "configured": creds is not None,
        "role": wanted_role,
        "mode": "same_as_sync" if wanted_role == "sync" else "own",
        "username": creds[0] if creds else "",
        "password": creds[1] if creds else "",
        "vars": {"username": user_var, "password": pass_var},
    }


def account_status(
    province: Any,
    mode: str = "own",
    env: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Obraz kont okręgu dla panelu administratora - BEZ wartości haseł.

    Oddaje wyłącznie „jest / nie ma" i nazwy zmiennych. To jedyna droga, jaką
    wiedza o tych kontach opuszcza serwer.
    """
    key = normalize_province(province)
    if not key:
        return {
            "province": str(province or ""),
            "known": False,
            "sync": {"configured": False, "vars": {"username": "", "password": ""}},
            "assign": {"configured": False, "vars": {"username": "", "password": ""}},
            "mode": str(mode or "own"),
            "ready": False,
        }

    sync_vars = env_var_names(key, "sync")
    assign_vars = env_var_names(key, "assign")
    sync_ok = credentials_for(key, "sync", env) is not None
    assign_ok = credentials_for(key, "assign", env) is not None
    resolved = assign_credentials(key, mode, env)

    return {
        "province": key,
        "known": True,
        "sync": {
            "configured": sync_ok,
            "vars": {"username": sync_vars[0], "password": sync_vars[1]},
        },
        "assign": {
            "configured": assign_ok,
            "vars": {"username": assign_vars[0], "password": assign_vars[1]},
        },
        "mode": resolved["mode"],
        # `ready` mówi to, o co naprawdę pyta panel: czy zatwierdzenie wymiany
        # ma dziś czym pojechać do ZPRP.
        "ready": bool(resolved["configured"]),
    }
