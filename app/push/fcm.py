import os
import json
import base64
import time
from typing import Any, Dict, Optional

import httpx

_access_token_cache: Dict[str, Any] = {
    "token": None,
    "exp": 0,
}

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

async def send_fcm_message(
    fcm_token: str,
    title: str,
    body: str,
    data: Optional[Dict[str, Any]] = None,
) -> None:
    access_token = await _get_access_token()
    project_id = _get_project_id()

    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"

    data = data or {}
    kind = str(data.get("kind") or "")

    # DATA-ONLY dla chronometru (żeby system nie wyświetlił "zwykłego" powiadomienia)
    if kind == "match_countdown":
        payload = {
            "message": {
                "token": fcm_token,
                "data": {k: str(v) for k, v in {
                    **data,
                    "__title": title,
                    "__body": body,
                }.items()},
                "android": {
                    "priority": "HIGH",
                },
            }
        }
    else:
        payload = {
            "message": {
                "token": fcm_token,
                "notification": {"title": title, "body": body},
                "data": {k: str(v) for k, v in (data or {}).items()},
                "android": {
                    "priority": "HIGH",
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
            raise RuntimeError(f"FCM error {resp.status_code}: {resp.text[:400]}")
