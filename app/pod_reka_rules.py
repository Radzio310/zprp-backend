"""Czyste reguły BAZA pod RĘKĄ — bez sieci i bazy, gotowe do testów."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

PUBLIC_DENY_FRAGMENTS = ("pesel", "birth_date", "dataur", "medical", "badania", "phone", "telefon", "email", "address", "adres")


def _query_param(href: str, name: str) -> str:
    values = parse_qs(urlparse(str(href or "").replace("&amp;", "&")).query).get(name) or []
    return str(values[0]).strip() if values else ""


def parse_club_scope(account_html: str, teams_html: str) -> dict[str, Any]:
    """Odczytuje klub i drużyny bez polegania na identyfikatorze od klienta."""
    account = BeautifulSoup(account_html or "", "html.parser")
    teams_page = BeautifulSoup(teams_html or "", "html.parser")

    def selected_value(name: str) -> tuple[str, str]:
        field = account.find(attrs={"name": name}) or account.find(id=name)
        if not field:
            return "", ""
        if field.name == "select":
            option = field.find("option", selected=True) or field.find("option")
            return (str(option.get("value") or "").strip(), option.get_text(" ", strip=True) if option else "")
        return str(field.get("value") or "").strip(), ""

    club_id, _ = selected_value("NrKlubu")
    account_value, account_label = selected_value("uprawnienia")
    active_value, _ = selected_value("czy_aktywny")
    account_type = "club" if account_value == "2" or "klub" in account_label.lower() else "unknown"
    active = active_value in {"1", "true", "tak", "yes"}

    display_name = ""
    logged = re.search(r"Zalogowany:\s*</small>\s*([^<]+)", account_html or "", re.I)
    if logged:
        display_name = re.sub(r"\s+", " ", logged.group(1)).strip(" |")

    team_ids: set[str] = set()
    for link in teams_page.find_all("a", href=True):
        href = str(link.get("href") or "")
        team_id = _query_param(href, "Filtr_zespol") or _query_param(href, "ID_zespoly")
        linked_club = _query_param(href, "NrKlubu")
        if team_id and (not linked_club or linked_club == club_id):
            team_ids.add(team_id)
    if not team_ids:
        for select_node in teams_page.find_all("select", attrs={"name": re.compile(r"Filtr_zespol", re.I)}):
            for option in select_node.find_all("option"):
                value = str(option.get("value") or "").strip()
                if value:
                    team_ids.add(value)

    return {"account_type": account_type, "active": active, "club_id": club_id, "team_ids": sorted(team_ids), "display_name": display_name}


def sanitize_public(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: sanitize_public(item)
            for key, item in value.items()
            if not any(fragment in str(key).lower().replace("-", "_") for fragment in PUBLIC_DENY_FRAGMENTS)
        }
    if isinstance(value, list):
        return [sanitize_public(item) for item in value]
    return value
