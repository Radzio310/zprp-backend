# app/groq_client.py

import os
import httpx
from typing import List, Literal, TypedDict, Optional

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


class ChatMessage(TypedDict):
  role: Literal["system", "user", "assistant"]
  content: str


async def groq_chat_completion(
    messages: List[ChatMessage],
    model: str = "llama-3.1-8b-instant",
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
        "model": model,
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
