# app/groq_client.py

import os
import httpx
from typing import List, Literal, TypedDict, Optional

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# ---------------------------------------------------------------------------
# Model: decyduje SERWER, nie aplikacja.
#
# Groq wycofuje modele z dnia na dzien - "llama-3.1-8b-instant" i
# "llama-3.3-70b-versatile" zostaly wygaszone 16.08.2026 i kazde zapytanie
# wracalo z 404 "model_not_found". Nazwa modelu byla wpisana na sztywno w
# dziewieciu miejscach, w tym w aplikacji, wiec naprawa oznaczalaby nowe
# wydanie APK i czekanie, az wszyscy je zainstaluja.
#
# Dlatego model wybiera backend: zmienna srodowiskowa GROQ_MODEL (do zmiany
# na Railway bez ruszania kodu), a nazwa przyslana przez aplikacje jest tylko
# PODPOWIEDZIA - jesli wskazuje model wygaszony, wraca domyslny. Dzieki temu
# stare wersje aplikacji dzialaja dalej po kolejnym wycofaniu.
# ---------------------------------------------------------------------------

DEFAULT_GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b").strip()

#: Modele wygaszone po stronie Groqa - nigdy ich nie wysylamy, nawet gdy
#: poprosi o nie klient. Zalecane zamienniki wg dokumentacji Groqa:
#: llama-3.1-8b-instant -> openai/gpt-oss-20b,
#: llama-3.3-70b-versatile / qwen3-32b -> openai/gpt-oss-120b.
RETIRED_MODELS = {
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "qwen/qwen3-32b",
    "llama3-8b-8192",
    "llama3-70b-8192",
    "mixtral-8x7b-32768",
    "gemma-7b-it",
    "gemma2-9b-it",
}


def resolve_model(requested: Optional[str]) -> str:
    """Nazwa modelu, ktora naprawde poleci do Groqa."""
    name = (requested or "").strip()
    if not name or name in RETIRED_MODELS:
        return DEFAULT_GROQ_MODEL
    return name


class ChatMessage(TypedDict):
  role: Literal["system", "user", "assistant"]
  content: str


async def groq_chat_completion(
    messages: List[ChatMessage],
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 1024,
) -> str:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("Brak GROQ_API_KEY w zmiennych środowiskowych backendu")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": resolve_model(model),
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    async with httpx.AsyncClient(timeout=60) as client:
        res = await client.post(GROQ_API_URL, headers=headers, json=payload)

    if res.status_code != 200:
        raise RuntimeError(f"Groq API error {res.status_code}: {res.text}")

    data = res.json()
    return data.get("choices", [{}])[0].get("message", {}).get("content", "") or ""
