"""
Formularze okręgowe - gotowe szablony (§13), stałe w kodzie.

Szablon to punkt startu kreatora: schemat i ustawienia przechodzą przez te same
walidacje co formularz ręczny (`district_form_schema.clean_schema`), więc zły
szablon nie przejdzie testów (`tests/test_district_forms_rules.py`).
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

_STATUS = {
    "id": "status",
    "type": "status",
    "title": "Obecność",
    "editor": "self",
    "visibility": "all",
    "required": True,
    "options": [
        {"id": "yes", "label": "Będę", "tone": "positive"},
        {"id": "no", "label": "Nie będę", "tone": "negative"},
    ],
}

TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "party_payment",
        "title": "Impreza z wpłatą",
        "kind": "list",
        "description": "Będę / Nie będę, wpłata zgłaszana przez sędziego i potwierdzana przez komisję, menu i osoby towarzyszące.",
        "schema": {
            "columns": [
                _STATUS,
                {
                    "id": "payment",
                    "type": "confirm",
                    "title": "Wpłata",
                    "hint": "Zaznacz „Zapłaciłem”, komisja potwierdzi wpływ.",
                    "editor": "self_confirm",
                    "visibility": "self",
                    "amount": None,
                    "lock_after_deadline": False,
                },
                {
                    "id": "menu",
                    "type": "choice",
                    "title": "Menu",
                    "editor": "self",
                    "visibility": "all",
                    "options": [
                        {"id": "meat", "label": "Mięsne"},
                        {"id": "vege", "label": "Wegetariańskie"},
                    ],
                },
                {
                    "id": "guests",
                    "type": "number",
                    "title": "Osoby towarzyszące",
                    "editor": "self",
                    "visibility": "all",
                    "min": 0,
                    "max": 3,
                    "integer": True,
                },
            ]
        },
        "settings": {"reminders": "standard", "roster_visible": True, "home_prompt": True},
        # Bloki do uzupełnienia w kreatorze (§17). Bez kreatora puste bloki odpadają
        # (`district_form_info.adapt_template_info`), a tytuł przelewu bierze tytuł formularza.
        "info": {
            "above": [
                {"id": "countdown", "type": "countdown", "title": "Do końca zapisów", "target": "deadline"},
                {
                    "id": "payment",
                    "type": "payment",
                    "title": "Dane do przelewu",
                    "recipient": "",
                    "account": "",
                    "transfer_title": "Impreza z wpłatą – {imie_nazwisko}",
                    "amount_column": "payment",
                    "confirm_column": "payment",
                    "bank_qr": True,
                },
            ],
            "below": [{"id": "contact", "type": "contact", "title": "Kontakt", "people": []}],
        },
    },
    {
        "id": "fee",
        "title": "Składka",
        "kind": "list",
        "description": "Sędzia zgłasza wpłatę składki, komisja potwierdza wpływ.",
        "schema": {
            "columns": [
                {
                    "id": "fee",
                    "type": "confirm",
                    "title": "Składka",
                    "editor": "self_confirm",
                    "visibility": "self",
                    "required": True,
                    "amount": None,
                    "lock_after_deadline": False,
                }
            ]
        },
        "settings": {"reminders": "gentle", "roster_visible": False, "home_prompt": True},
    },
    {
        "id": "meeting",
        "title": "Zebranie / szkolenie",
        "kind": "list",
        "description": "Będę / Nie będę / Może i miejsce na uwagi.",
        "schema": {
            "columns": [
                {
                    **_STATUS,
                    "options": [
                        {"id": "yes", "label": "Będę", "tone": "positive"},
                        {"id": "no", "label": "Nie będę", "tone": "negative"},
                        {"id": "maybe", "label": "Może", "tone": "warning"},
                    ],
                },
                {"id": "notes", "type": "text", "title": "Uwagi", "editor": "self", "visibility": "managers", "max_length": 300},
            ]
        },
        "settings": {"reminders": "standard", "roster_visible": True, "home_prompt": True},
        # Licznik do wydarzenia (bez spięcia odlicza do terminu) i miejsce do uzupełnienia.
        "info": {
            "above": [
                {"id": "countdown", "type": "countdown", "title": "Do rozpoczęcia", "target": "event"},
                {"id": "place", "type": "place", "title": "Miejsce", "name": ""},
            ],
            "below": [],
        },
    },
    {
        "id": "attendance",
        "title": "Lista obecności z potwierdzeniem",
        "kind": "list",
        "description": "Sędzia deklaruje obecność, komisja odhacza, kto naprawdę był.",
        "schema": {
            "columns": [
                _STATUS,
                {"id": "present", "type": "check", "title": "Obecny", "editor": "managers", "visibility": "all"},
            ]
        },
        "settings": {"reminders": "standard", "roster_visible": True, "home_prompt": True},
    },
    {
        "id": "training_survey",
        "title": "Ankieta po szkoleniu",
        "kind": "form",
        "description": "Ocena szkolenia: skala, wybór i miejsce na uwagi.",
        "schema": {
            "sections": [
                {
                    "id": "s1",
                    "title": "Twoja ocena",
                    "questions": [
                        {
                            "id": "overall",
                            "type": "scale",
                            "title": "Jak oceniasz szkolenie?",
                            "required": True,
                            "scale_min": 1,
                            "scale_max": 5,
                            "min_label": "Słabo",
                            "max_label": "Świetnie",
                        },
                        {
                            "id": "best",
                            "type": "single",
                            "title": "Co było najbardziej przydatne?",
                            "options": [
                                {"id": "rules", "label": "Przepisy"},
                                {"id": "video", "label": "Analiza wideo"},
                                {"id": "fitness", "label": "Przygotowanie fizyczne"},
                            ],
                            "other": True,
                        },
                        {"id": "notes", "type": "long_text", "title": "Co zmienić następnym razem?"},
                    ],
                }
            ]
        },
        "settings": {"reminders": "gentle", "anonymous": True, "results_visibility": "managers", "allow_edit": True},
    },
    {
        "id": "application",
        "title": "Zgłoszenie",
        "kind": "form",
        "description": "Dane kontaktowe, wybór terminu i uwagi.",
        "schema": {
            "sections": [
                {
                    "id": "s1",
                    "title": "Zgłoszenie",
                    "questions": [
                        {"id": "phone", "type": "phone", "title": "Telefon", "required": True},
                        {"id": "email", "type": "email", "title": "E-mail"},
                        {
                            "id": "term",
                            "type": "single",
                            "title": "Który termin Ci pasuje?",
                            "required": True,
                            "options": [
                                {"id": "t1", "label": "Termin 1"},
                                {"id": "t2", "label": "Termin 2"},
                            ],
                        },
                        {"id": "notes", "type": "long_text", "title": "Uwagi"},
                    ],
                }
            ]
        },
        "settings": {"reminders": "standard", "results_visibility": "managers", "allow_edit": True},
    },
]


def all_templates() -> List[Dict[str, Any]]:
    return copy.deepcopy(TEMPLATES)


def template(template_id: Any) -> Optional[Dict[str, Any]]:
    for item in TEMPLATES:
        if item["id"] == str(template_id or "").strip():
            return copy.deepcopy(item)
    return None
