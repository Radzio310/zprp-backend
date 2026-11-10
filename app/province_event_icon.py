"""Ikona (emoji) wydarzenia okręgowego dobierana przy generowaniu grafiki."""
from __future__ import annotations

import logging
import os
from typing import Dict, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

#: Dozwolony zestaw; aplikacja pokazuje te same emoji do ręcznego wyboru.
ICONS: Tuple[str, ...] = (
    "🎄", "🎉", "🍽️", "🔥", "🏆", "🏐", "🤾", "⏱️", "📝", "🎓",
    "📚", "🎤", "🤝", "🗓️", "📣", "🚌", "⚽", "🧘", "🍻", "🎁",
    "🏔️", "🌞", "❄️", "🎯",
)

_KEYWORDS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("🎄", ("wigili", "święt", "swiet", "boże narodzenie", "choink", "opłat", "oplat", "mikołaj", "mikolaj")),
    ("🎁", ("prezent", "nagrod", "upomin")),
    ("🍻", ("grill", "piwo", "biesiad", "ognisk", "impreza", "imprez")),
    ("🍽️", ("kolacj", "obiad", "uroczyst", "bankiet", "gala", "spotkanie przy")),
    ("🏆", ("turniej", "puchar", "finał", "final", "mistrz")),
    ("⏱️", ("biegow", "bieg", "yo-yo", "yoyo", "sprawnoś", "sprawnos")),
    ("📝", ("egzamin", "test", "sprawdzian")),
    ("🎤", ("konferencj", "prelekcj", "panel")),
    ("🎓", ("kurs", "szkolen", "warsztat", "akademi")),
    ("📚", ("przepis", "regulamin", "nauka")),
    ("🤝", ("integracj", "zebran", "narad", "spotkani")),
    ("🚌", ("wyjazd", "wycieczk", "autokar")),
    ("🏔️", ("góry", "gory", "zakopane", "szczyrk", "wisła", "wisla")),
    ("🌞", ("lato", "letni", "plaż", "plaz", "beach")),
    ("❄️", ("zima", "zimow", "narty", "sylwester")),
    ("🏐", ("mecz", "piłk", "pilk", "ręczn", "reczn")),
    ("🧘", ("regeneracj", "relaks", "joga")),
)

_TYPE_DEFAULT: Dict[str, str] = {
    "training": "🎓",
    "exam": "📝",
    "fitness_test": "⏱️",
    "meeting": "🤝",
    "conference": "🎤",
    "course": "📚",
    "integration": "🎉",
    "other": "🗓️",
}


def valid_icon(value: object) -> Optional[str]:
    text = str(value or "").strip()
    return text if text in ICONS else None


def keyword_icon(name: str, event_type: str = "", extra: str = "") -> str:
    haystack = f"{name} {extra}".lower()
    for icon, words in _KEYWORDS:
        if any(w in haystack for w in words):
            return icon
    return _TYPE_DEFAULT.get(event_type or "", "🗓️")


async def _ask_model(name: str, event_type: str, extra: str) -> Optional[str]:
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        return None
    options = " ".join(ICONS)
    payload = {
        "model": os.getenv("OPENAI_ICON_MODEL", "gpt-4o-mini"),
        "temperature": 0,
        "max_tokens": 8,
        "messages": [
            {
                "role": "system",
                "content": "Wybierasz jedną ikonę emoji do wydarzenia sędziów piłki ręcznej. "
                f"Odpowiedz wyłącznie jednym emoji z listy: {options}",
            },
            {"role": "user", "content": f"Nazwa: {name}\nTyp: {event_type}\nOpis: {extra}"},
        ],
    }
    async with httpx.AsyncClient(timeout=12.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json=payload,
        )
    if resp.status_code >= 400:
        logger.warning("ikona wydarzenia: OpenAI %s %s", resp.status_code, resp.text[:200])
        return None
    content = (((resp.json().get("choices") or [{}])[0]).get("message") or {}).get("content") or ""
    for icon in ICONS:
        if icon in content or icon.replace("️", "") in content:
            return icon
    return None


async def pick_icon(name: str, event_type: str = "", extra: str = "") -> Tuple[str, str]:
    """(emoji, źródło): `ai` albo `keywords`. Nigdy nie rzuca wyjątku."""
    try:
        icon = await _ask_model(name, event_type, extra)
        if icon:
            return icon, "ai"
    except Exception:
        logger.exception("ikona wydarzenia: błąd modelu, używam słownika")
    return keyword_icon(name, event_type, extra), "keywords"
