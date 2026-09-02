import os
import json
import base64
import hashlib
import time
from typing import Any, Dict, Optional

import httpx

_access_token_cache: Dict[str, Any] = {
    "token": None,
    "exp": 0,
}


class FcmSendError(RuntimeError):
    """Ustrukturyzowany błąd HTTP v1 bez umieszczania tokenu w logach."""

    def __init__(
        self,
        *,
        http_status: int,
        status: str = "",
        error_code: str = "",
        message: str = "",
    ) -> None:
        self.http_status = int(http_status)
        self.status = str(status or "").strip().upper()
        self.error_code = str(error_code or "").strip().upper()
        self.fcm_message = str(message or "").strip()
        labels = " ".join(part for part in (self.status, self.error_code) if part)
        suffix = f" {labels}" if labels else ""
        detail = f": {self.fcm_message[:300]}" if self.fcm_message else ""
        super().__init__(f"FCM error {self.http_status}{suffix}{detail}")


def build_fcm_send_error(http_status: int, response_body: str) -> FcmSendError:
    """Odczytuje oficjalny `google.firebase.fcm.v1.FcmError` z odpowiedzi FCM."""

    status = ""
    error_code = ""
    message = ""
    try:
        payload = json.loads(response_body)
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict):
            status = str(error.get("status") or "")
            message = str(error.get("message") or "")
            details = error.get("details")
            if isinstance(details, list):
                for detail in details:
                    if not isinstance(detail, dict):
                        continue
                    candidate = str(detail.get("errorCode") or "").strip()
                    if candidate:
                        error_code = candidate
                        break
    except (TypeError, ValueError, json.JSONDecodeError):
        message = str(response_body or "")[:300]

    return FcmSendError(
        http_status=http_status,
        status=status,
        error_code=error_code,
        message=message,
    )


def is_permanently_invalid_fcm_token(error: BaseException) -> bool:
    """True wyłącznie, gdy Firebase jednoznacznie unieważnił token urządzenia.

    Samo HTTP 400/404 nie wystarcza: może oznaczać błąd payloadu albo projektu.
    Usuwanie tokenów w takim przypadku mogłoby wyłączyć wszystkie urządzenia.
    """

    if not isinstance(error, FcmSendError):
        return False
    if error.error_code == "UNREGISTERED":
        return True
    message = error.fcm_message.lower()
    return (
        error.error_code == "INVALID_ARGUMENT"
        and "registration token" in message
        and ("not a valid" in message or "invalid" in message)
    )

def _load_sa_info() -> Dict[str, Any]:
    b64 = os.getenv("FIREBASE_SA_B64", "")
    if not b64:
        raise RuntimeError("Missing FIREBASE_SA_B64")
    raw = base64.b64decode(b64).decode("utf-8")
    return json.loads(raw)

def _get_project_id() -> str:
    pid = os.getenv("FIREBASE_PROJECT_ID", "").strip()
    if not pid:
        # fallback: try from SA
        info = _load_sa_info()
        pid = (info.get("project_id") or "").strip()
    if not pid:
        raise RuntimeError("Missing FIREBASE_PROJECT_ID")
    return pid

async def _get_access_token() -> str:
    """
    Minimalny OAuth token dla scope firebase.messaging.
    Wymaga biblioteki google-auth w środowisku.
    """
    now = int(time.time())
    if _access_token_cache["token"] and _access_token_cache["exp"] - 60 > now:
        return _access_token_cache["token"]

    try:
        from google.oauth2 import service_account
        from google.auth.transport.requests import Request
    except Exception as e:
        raise RuntimeError("Missing dependency google-auth (google.oauth2.service_account)") from e

    info = _load_sa_info()
    creds = service_account.Credentials.from_service_account_info(
        info,
        scopes=["https://www.googleapis.com/auth/firebase.messaging"],
    )

    # refresh is sync; run it in thread to avoid blocking event loop
    import asyncio
    def _refresh():
        creds.refresh(Request())
        return creds.token, int(creds.expiry.timestamp()) if creds.expiry else now + 300

    token, exp = await asyncio.to_thread(_refresh)

    _access_token_cache["token"] = token
    _access_token_cache["exp"] = exp
    return token

def notification_tag(data: Optional[Dict[str, Any]], title: str, body: str) -> str:
    """Znacznik, po ktorym Android odroznia jedno powiadomienie od drugiego.

    DLACZEGO TO ISTNIEJE. Dwa powiadomienia bez wlasnego `tag` potrafia sie na
    Androidzie zastapic - drugie wchodzi na miejsce pierwszego i uzytkownik
    widzi tylko ostatnie. Przy zmianie meczu to jest regula, a nie wyjatek:
    zmiana daty, dopisanie adresu hali i edycja wyniku ida jednym przebiegiem
    monitora, w odstepie sekund. Sedzia dostawal wtedy jedno powiadomienie
    zamiast trzech i nie mial pojecia, ze data sie przesunela.

    Zrodlem znacznika jest `event_key`, czyli ten sam identyfikator, ktorym
    odsiewamy duplikaty w bazie. Dzieki temu POWTORZENIE tego samego zdarzenia
    nadal zastapi stare powiadomienie zamiast mnozyc kopie, a ROZNE zdarzenia
    zostaja obok siebie.
    """
    payload = data or {}
    key = str(payload.get("event_key") or "").strip()
    if key:
        return f"evt-{key[:32]}"
    seed = "|".join(
        [
            str(payload.get("kind") or ""),
            str(payload.get("offerId") or ""),
            str(payload.get("matchNumber") or payload.get("match_id") or ""),
            title,
            body,
        ]
    )
    return "gen-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


async def send_fcm_message(
    fcm_token: str,
    title: str,
    body: str,
    data: Optional[Dict[str, Any]] = None,
) -> None:
    access_token = await _get_access_token()
    project_id = _get_project_id()

    tag = notification_tag(data, title, body)
    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    payload = {
        "message": {
            "token": fcm_token,
            "notification": {"title": title, "body": body},
            "data": {k: str(v) for k, v in (data or {}).items()},
            "android": {
                # Bez wlasnego klucza FCM potrafi scalic wiadomosci czekajace na
                # wylaczony telefon. Tu kazde zdarzenie ma wlasny.
                "collapse_key": tag,
                "priority": "high",
                # Ten kanał aplikacja zakłada jako MAX. Bez jawnego channel_id
                # Android potrafi skierować zdalny push do fallbacku FCM, który
                # na części telefonów jest cichy albo wcześniej wyłączony.
                "notification": {
                    "tag": tag,
                    "channel_id": "default",
                    "sound": "default",
                },
            },
            "apns": {
                # Odpowiednik `tag` na iOS. Rozne watki = rozne powiadomienia.
                "payload": {"aps": {"thread-id": tag}},
            },
        }
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code >= 400:
            raise build_fcm_send_error(resp.status_code, resp.text)
