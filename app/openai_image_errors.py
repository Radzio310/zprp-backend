"""Czytelne komunikaty po polsku z odpowiedzi OpenAI Images API."""
from __future__ import annotations

import json
import re
from typing import Any, Optional, Tuple

MODERATION_CODES = {
    "moderation_blocked",
    "content_policy_violation",
    "safety_violation",
}
QUOTA_CODES = {"insufficient_quota", "billing_hard_limit_reached", "billing_not_active"}
RATE_CODES = {"rate_limit_exceeded", "rate_limit"}
AUTH_CODES = {"invalid_api_key", "incorrect_api_key", "invalid_organization"}


def parse_openai_error(body: Any) -> Tuple[str, str, str]:
    """Zwraca (code, type, message) z surowej treści odpowiedzi; puste łańcuchy, gdy brak."""
    data: Any = body
    if isinstance(body, (bytes, str)):
        try:
            data = json.loads(body)
        except Exception:
            return "", "", str(body or "")[:300]
    err = data.get("error") if isinstance(data, dict) else None
    if not isinstance(err, dict):
        return "", "", ""
    return (
        str(err.get("code") or "").lower(),
        str(err.get("type") or "").lower(),
        str(err.get("message") or ""),
    )


def error_param(body: Any) -> str:
    try:
        data = json.loads(body) if isinstance(body, (bytes, str)) else body
        return str((data.get("error") or {}).get("param") or "").lower()
    except Exception:
        return ""


def error_kind(status: int, code: str, etype: str, message: str, param: str = "") -> str:
    low = message.lower()
    if param == "model" or code == "model_not_found" or ("model" in low and "does not exist" in low):
        return "model"
    if code in MODERATION_CODES or "safety system" in low or "content policy" in low:
        return "moderation"
    if code in QUOTA_CODES or etype == "insufficient_quota" or "billing" in low and "limit" in low:
        return "quota"
    if code in AUTH_CODES or status == 401:
        return "auth"
    if "must be verified" in low or code == "organization_must_be_verified":
        return "verify"
    if code in RATE_CODES or status == 429:
        return "rate"
    if status == 404:
        return "model"
    if status >= 500:
        return "server"
    if status == 400 or etype == "invalid_request_error":
        return "invalid"
    return "other"


def is_retryable(kind: str) -> bool:
    return kind in {"rate", "server"}


def polish_message(kind: str, message: str = "", subject: str = "turnieju") -> str:
    if kind == "moderation":
        return "OpenAI odrzucił opis grafiki przez filtr treści - zmień dopisek albo spróbuj ponownie"
    if kind == "quota":
        return "Skończył się limit konta OpenAI - daj znać administratorowi aplikacji"
    if kind == "rate":
        return "Za dużo próśb naraz, spróbuj za minutę"
    if kind == "verify":
        return "Model grafik OpenAI wymaga weryfikacji organizacji - daj znać administratorowi aplikacji"
    if kind == "auth":
        return "Klucz OpenAI na serwerze jest nieprawidłowy - daj znać administratorowi aplikacji"
    if kind == "model":
        return "Model grafik OpenAI jest niedostępny dla konta - administrator musi ustawić OPENAI_IMAGE_MODEL"
    if kind == "server":
        return "Serwer OpenAI chwilowo nie działa, spróbuj za chwilę"
    if kind == "invalid":
        short = " ".join(message.split())[:140]
        return f"OpenAI odrzucił zapytanie o grafikę ({short})" if short else "OpenAI odrzucił zapytanie o grafikę"
    return f"OpenAI nie wygenerował grafiki {subject}"


def classify(status: int, body: Any, subject: str = "turnieju") -> Tuple[str, str, str]:
    """(kind, kod do logu, komunikat po polsku)."""
    code, etype, message = parse_openai_error(body)
    kind = error_kind(status, code, etype, message, error_param(body))
    return kind, f"{code or '-'}/{etype or '-'}", polish_message(kind, message, subject)


def _version(model_id: str) -> float:
    nums = re.findall(r"\d+(?:\.\d+)?", model_id)
    return float(nums[0]) if nums else 0.0


def pick_image_model(ids: Any) -> Optional[str]:
    """Najnowszy gpt-image* (bez mini i wersji z datą), inaczej dall-e-3."""
    names = [str(i) for i in ids]
    family = [n for n in names if n.startswith("gpt-image")]
    plain = [n for n in family if "mini" not in n and not re.search(r"\d{4}-\d{2}-\d{2}", n)]
    pool = plain or family
    if pool:
        return max(pool, key=lambda n: (_version(n), -len(n)))
    return "dall-e-3" if "dall-e-3" in names else None


def image_payload(model: str, prompt: str, quality: Optional[str]) -> dict:
    q = (quality or "medium").lower()
    if model.startswith("dall-e-3"):
        return {
            "model": model,
            "prompt": prompt,
            "size": "1792x1024",
            "quality": "hd" if q in ("high", "hd") else "standard",
            "response_format": "b64_json",
            "n": 1,
        }
    return {"model": model, "prompt": prompt, "size": "1536x1024", "quality": q, "n": 1}
