"""Dyktowanie w panelu Mentor (18.11.2026): tytuł i notatka klipu głosem.

Panel pokazuje słowa na żywo z rozpoznawania mowy przeglądarki, a po zatrzymaniu wysyła nagranie tutaj -
Whisper (Groq, `whisper-large-v3-turbo`) oddaje dokładny tekst, który podmienia wersję roboczą. Różnice wobec
starego `/speech_to_text` aplikacji: trasa wymaga sesji panelu i prawa tworzenia w parze, typ pliku z nagrania
(przeglądarka nagrywa webm/ogg/mp4, nie m4a), limit długości i tempa, a do Whispera idzie PODPOWIEDŹ słownictwa:
drużyny, nazwiska sędziów i słowa piłki ręcznej, które klient zna z pokoju meczu. Whisper z taką podpowiedzią
pisze „Korona Handball Kielce”, „progresja kar” i „7 m” zamiast ich fonetycznych zgadywanek.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import time
from typing import Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app import mentor_panel_core as C
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger(__name__)
router = APIRouter()

Actor = C.MentorActor

GROQ_URL = "https://api.groq.com/openai/v1/audio/transcriptions"
MODEL = "whisper-large-v3-turbo"
# ~3 min mowy w opus to ok. 1,5 MB; zapas na mp4/aac z Safari.
MAX_AUDIO_BYTES = 8 * 1024 * 1024
RATE_WINDOW_S = 300
RATE_MAX = 40

# Słowa, które Whisper bez podpowiedzi przekręca najczęściej (zapis jak w arkuszach).
HANDBALL_TERMS = (
    "piłka ręczna", "rzut karny 7 m", "faul w ataku", "progresja kar", "2 minuty", "żółta kartka", "czerwona kartka",
    "niebieska kartka", "gra pasywna", "obszar bramkowy", "rzut wolny", "rzut z autu", "kroki", "błąd kroków",
    "przytrzymanie", "pchnięcie", "zablokowanie", "gwizdek", "przywilej korzyści", "time-out", "sędzia boczny",
    "sędzia bramkowy", "delegat", "ZPRP",
)

_MIME_EXT = {"webm": "webm", "ogg": "ogg", "mp4": "mp4", "mpeg": "mp3", "mp3": "mp3", "wav": "wav", "x-m4a": "m4a", "m4a": "m4a", "aac": "m4a"}


def audio_name(mime: Optional[str]) -> tuple:
    """Nazwa pliku i typ dla Whispera z typu nagrania przeglądarki („audio/webm;codecs=opus” -> audio.webm)."""
    raw = str(mime or "").lower().split(";")[0].strip()
    sub = raw.split("/")[-1] if "/" in raw else raw
    ext = _MIME_EXT.get(sub, "webm")
    return f"audio.{ext}", (raw if raw.startswith("audio/") else f"audio/{ext}")


def speech_prompt(context: Optional[List[str]], limit: int = 600) -> str:
    """Podpowiedź słownictwa: nazwy z pokoju (drużyny, osoby, kategorie) przed słowami piłki ręcznej, bez dubli."""
    seen: set = set()
    words: List[str] = []
    for raw in [*(context or []), *HANDBALL_TERMS]:
        w = re.sub(r"\s+", " ", str(raw or "")).strip()[:60]
        key = w.lower()
        if not w or key in seen:
            continue
        seen.add(key)
        words.append(w)
    out = ""
    for w in words:
        nxt = f"{out}, {w}" if out else w
        if len(nxt) > limit:
            break
        out = nxt
    return out


def tidy(text: str) -> str:
    """Tekst do pola: bez dubli spacji, z wielką literą na początku; bez kropki na końcu krótkich fraz (tytuły)."""
    t = re.sub(r"\s+", " ", str(text or "")).strip()
    if not t:
        return ""
    t = t[0].upper() + t[1:]
    if len(t) <= 80 and t.endswith(".") and t.count(".") == 1:
        t = t[:-1]
    return t


_calls: Dict[str, List[float]] = {}


def _rate_ok(judge_id: str, now: Optional[float] = None) -> bool:
    now = time.time() if now is None else now
    recent = [t for t in _calls.get(judge_id, []) if now - t < RATE_WINDOW_S]
    if len(recent) >= RATE_MAX:
        _calls[judge_id] = recent
        return False
    recent.append(now)
    _calls[judge_id] = recent
    return True


class SpeechBody(BaseModel):
    audio_base64: str = Field(..., min_length=16)
    mime: Optional[str] = Field(None, max_length=80)
    language: str = Field("pl", max_length=8)
    context: List[str] = Field(default_factory=list, max_length=40)


async def _transcribe(audio: bytes, mime: Optional[str], language: str, prompt: str) -> str:
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise C.err(503, "STT_OFF", "Rozpoznawanie mowy na serwerze jest wyłączone.")
    name, ctype = audio_name(mime)
    data = {"model": MODEL, "response_format": "json", "language": language or "pl", "temperature": "0"}
    if prompt:
        data["prompt"] = prompt
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(GROQ_URL, headers={"Authorization": f"Bearer {key}"}, data=data, files={"file": (name, audio, ctype)})
    except Exception:
        logger.exception("mentor STT: brak połączenia z Groq")
        raise C.err(502, "STT_FAILED", "Nie udało się połączyć z rozpoznawaniem mowy.")
    if resp.status_code >= 400:
        logger.error("mentor STT: Groq %s %s", resp.status_code, resp.text[:300])
        raise C.err(502, "STT_FAILED", "Rozpoznawanie mowy nie zadziałało - tekst z przeglądarki zostaje.")
    return str((resp.json() or {}).get("text") or "")


@router.post("/pairs/{pair_id}/speech")
async def transcribe(pair_id: str, body: SpeechBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    C.check(ctx, "create")
    try:
        audio = base64.b64decode(body.audio_base64, validate=False)
    except Exception:
        raise C.err(400, "BAD_AUDIO", "Nagranie nie dotarło w całości.")
    if len(audio) > MAX_AUDIO_BYTES:
        raise C.err(413, "AUDIO_TOO_LONG", "Nagranie jest za długie - dyktuj krótszymi fragmentami.")
    if not _rate_ok(str(actor.judge_id)):
        raise C.err(429, "STT_RATE", "Za dużo nagrań w krótkim czasie - chwila przerwy.")
    text = await _transcribe(audio, body.mime, body.language, speech_prompt(body.context))
    return {"text": tidy(text)}
