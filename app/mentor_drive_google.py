"""Teczka pary: cienka warstwa nad Google (OAuth + Drive v3 przez httpx). Jedyne miejsce z prawdziwą siecią.

Testy podmieniają obiekt przez `set_api(...)` (atrapa o tych samych metodach). Tokeny nigdy nie trafiają do logów ani
do treści wyjątków.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import httpx

from app import mentor_drive_rules as R

logger = logging.getLogger("app.mentor_drive")

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
FILES = "https://www.googleapis.com/drive/v3/files"
UPLOAD = "https://www.googleapis.com/upload/drive/v3/files"
FOLDER_MIME = "application/vnd.google-apps.folder"
FILE_FIELDS = "id,name,mimeType,webViewLink,trashed,size,parents,driveId,capabilities(canAddChildren,canShare,canMoveItemWithinDrive)"


class GoogleError(Exception):
    """Błąd Google: `status` (0 = sieć), `reason` (np. invalid_grant, notFound), `kind` wg `classify`."""

    def __init__(self, status: int, reason: str = "", message: str = ""):
        super().__init__(f"google {status} {reason}".strip())
        self.status, self.reason, self.message = status, reason or "", message or ""

    @property
    def kind(self) -> str:
        return R.classify(self.status, self.reason)


def auth_url(client_id: str, redirect_uri: str, state: str, login_hint: Optional[str] = None) -> str:
    params = {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code", "scope": R.SCOPE,
              "access_type": "offline", "prompt": "consent", "include_granted_scopes": "false", "state": state}
    if login_hint:
        params["login_hint"] = login_hint
    return f"{AUTH_URL}?{urlencode(params)}"


def _reason(response: httpx.Response) -> Tuple[str, str]:
    try:
        body = response.json()
    except Exception:  # noqa: BLE001
        return "", ""
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, str):
            return err, str(body.get("error_description") or "")
        if isinstance(err, dict):
            errors = err.get("errors") or []
            reason = (errors[0].get("reason") if errors and isinstance(errors[0], dict) else None) or err.get("status") or ""
            return str(reason), str(err.get("message") or "")
    return "", ""


class GoogleApi:
    def __init__(self, client_id: str, client_secret: str, transport: Optional[httpx.AsyncBaseTransport] = None):
        self.client_id, self.client_secret, self._transport = client_id, client_secret, transport

    def _client(self, timeout: float = 30.0) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, transport=self._transport)

    async def _send(self, method: str, url: str, *, ok: Tuple[int, ...] = (200,), timeout: float = 30.0, **kwargs: Any) -> httpx.Response:
        try:
            async with self._client(timeout) as client:
                response = await client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise GoogleError(0, "network", exc.__class__.__name__) from None
        if response.status_code not in ok:
            reason, message = _reason(response)
            raise GoogleError(response.status_code, reason, message)
        return response

    @staticmethod
    def _bearer(access: str) -> Dict[str, str]:
        return {"Authorization": f"Bearer {access}"}

    # ─── OAuth ───
    async def exchange_code(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        data = {"code": code, "client_id": self.client_id, "client_secret": self.client_secret,
                "redirect_uri": redirect_uri, "grant_type": "authorization_code"}
        return (await self._send("POST", TOKEN_URL, data=data)).json()

    async def refresh(self, refresh_token: str) -> Dict[str, Any]:
        data = {"refresh_token": refresh_token, "client_id": self.client_id, "client_secret": self.client_secret,
                "grant_type": "refresh_token"}
        return (await self._send("POST", TOKEN_URL, data=data)).json()

    async def revoke(self, token: str) -> None:
        try:
            await self._send("POST", REVOKE_URL, data={"token": token})
        except GoogleError:
            pass  # odłączenie ma się udać także, gdy Google już nie zna tokenu

    # ─── Drive ───
    async def about(self, access: str) -> Dict[str, Any]:
        params = {"fields": "user(emailAddress,displayName)"}
        found = (await self._send("GET", "https://www.googleapis.com/drive/v3/about", params=params, headers=self._bearer(access))).json()
        return found.get("user") or {}

    async def get_file(self, access: str, file_id: str) -> Dict[str, Any]:
        params = {"fields": FILE_FIELDS, "supportsAllDrives": "true"}
        return (await self._send("GET", f"{FILES}/{file_id}", params=params, headers=self._bearer(access))).json()

    async def file_state(self, access: str, file_id: str) -> Dict[str, Any]:
        """Lekki odczyt do sprawdzania, czy zapisany plik nadal jest: `id,trashed,webViewLink`. 404 = pliku nie ma."""
        params = {"fields": "id,trashed,webViewLink", "supportsAllDrives": "true"}
        return (await self._send("GET", f"{FILES}/{file_id}", params=params, headers=self._bearer(access))).json()

    async def create_folder(self, access: str, name: str, parent: Optional[str] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"name": name, "mimeType": FOLDER_MIME}
        if parent:
            body["parents"] = [parent]
        return (await self._send("POST", FILES, params={"fields": FILE_FIELDS, "supportsAllDrives": "true"},
                                 json=body, headers=self._bearer(access))).json()

    async def find_folder(self, access: str, parent: str, name: str) -> Optional[Dict[str, Any]]:
        safe = name.replace("\\", "\\\\").replace("'", "\\'")
        q = f"'{parent}' in parents and name = '{safe}' and mimeType = '{R_FOLDER}' and trashed = false"
        params = {"q": q, "fields": f"files({FILE_FIELDS})", "pageSize": "5", "supportsAllDrives": "true", "includeItemsFromAllDrives": "true"}
        files = (await self._send("GET", FILES, params=params, headers=self._bearer(access))).json().get("files") or []
        return files[0] if files else None

    async def find_by_prop(self, access: str, parent: str, key: str, value: str) -> Optional[Dict[str, Any]]:
        """Plik z naszym znacznikiem (`appProperties`) w danym folderze - chroni przed dublem po restarcie."""
        safe = value.replace("\\", "\\\\").replace("'", "\\'")
        q = f"'{parent}' in parents and appProperties has {{ key='{key}' and value='{safe}' }} and trashed = false"
        params = {"q": q, "fields": f"files({FILE_FIELDS})", "pageSize": "2", "supportsAllDrives": "true", "includeItemsFromAllDrives": "true"}
        files = (await self._send("GET", FILES, params=params, headers=self._bearer(access))).json().get("files") or []
        return files[0] if files else None

    async def create_permission(self, access: str, file_id: str, email: str, role: str = "writer") -> Dict[str, Any]:
        params = {"sendNotificationEmail": "true", "supportsAllDrives": "true", "fields": "id"}
        body = {"type": "user", "role": role, "emailAddress": email}
        return (await self._send("POST", f"{FILES}/{file_id}/permissions", params=params, json=body, headers=self._bearer(access))).json()

    async def list_permissions(self, access: str, file_id: str) -> List[Dict[str, Any]]:
        """Osoby z dostępem do folderu (odczyt na żywo, do 3 stron po 100)."""
        out: List[Dict[str, Any]] = []
        token: Optional[str] = None
        for _ in range(3):
            params = {"fields": R.PERMISSION_FIELDS, "pageSize": "100", "supportsAllDrives": "true"}
            if token:
                params["pageToken"] = token
            body = (await self._send("GET", f"{FILES}/{file_id}/permissions", params=params, headers=self._bearer(access))).json()
            out += [p for p in (body.get("permissions") or []) if isinstance(p, dict)]
            token = body.get("nextPageToken")
            if not token:
                break
        if token:
            raise GoogleError(400, "permissionListTooLarge")
        return out

    async def update_permission(self, access: str, file_id: str, permission_id: str, role: str) -> Dict[str, Any]:
        params = {"supportsAllDrives": "true", "fields": "id,role"}
        return (await self._send("PATCH", f"{FILES}/{file_id}/permissions/{permission_id}", params=params,
                                 json={"role": role}, headers=self._bearer(access))).json()

    async def delete_permission(self, access: str, file_id: str, permission_id: str) -> None:
        await self._send("DELETE", f"{FILES}/{file_id}/permissions/{permission_id}", ok=(200, 204),
                         params={"supportsAllDrives": "true"}, headers=self._bearer(access))

    async def create_transfer_folder(self, access: str, name: str, transfer_id: str, parent: Optional[str] = None) -> Dict[str, Any]:
        body = {"name": name, "mimeType": FOLDER_MIME, "appProperties": {"baza_transfer": transfer_id}}
        if parent:
            body["parents"] = [parent]
        return (await self._send("POST", FILES, params={"fields": FILE_FIELDS, "supportsAllDrives": "true"},
                                 json=body, headers=self._bearer(access))).json()

    async def move_file(self, access: str, file_id: str, source: str, destination: str) -> Dict[str, Any]:
        params = {"addParents": destination, "removeParents": source, "fields": FILE_FIELDS, "supportsAllDrives": "true"}
        return (await self._send("PATCH", f"{FILES}/{file_id}", params=params, json={}, headers=self._bearer(access))).json()

    async def transfer_permission(self, access: str, file_id: str, permission: Dict[str, Any],
                                  existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Odtworzenie osoby/grupy bez obniżania istniejącego dostępu i bez przenoszenia własności."""
        if permission.get("expirationTime") or (existing and existing.get("expirationTime")):
            raise GoogleError(400, "temporaryPermissionUnsupported")
        rank = {"reader": 1, "commenter": 2, "writer": 3, "owner": 4}
        role = permission["role"]
        if existing and rank.get(existing.get("role"), 0) > rank[role]:
            role = existing["role"]
        body: Dict[str, Any] = {"role": role}
        params = {"supportsAllDrives": "true", "fields": "id"}
        if existing:
            method, url = "PATCH", f"{FILES}/{file_id}/permissions/{existing['id']}"
        else:
            params["sendNotificationEmail"] = "true"
            body.update(type=permission["type"], emailAddress=permission["emailAddress"])
            method, url = "POST", f"{FILES}/{file_id}/permissions"
        return (await self._send(method, url, params=params, json=body, headers=self._bearer(access))).json()

    # ─── Wysyłka wznawialna ───
    async def start_upload(self, access: str, metadata: Dict[str, Any], size: int, mime: str = "video/mp4") -> str:
        headers = {**self._bearer(access), "Content-Type": "application/json; charset=UTF-8",
                   "X-Upload-Content-Type": mime, "X-Upload-Content-Length": str(size)}
        params = {"uploadType": "resumable", "fields": FILE_FIELDS, "supportsAllDrives": "true"}
        response = await self._send("POST", UPLOAD, params=params, headers=headers, content=json.dumps(metadata).encode("utf-8"))
        location = response.headers.get("location")
        if not location:
            raise GoogleError(502, "no_upload_session")
        return location

    async def put_chunk(self, session_uri: str, data: bytes, start: int, total: int) -> Tuple[str, Any]:
        """Jedna część: `("more", następny_offset)` albo `("done", plik)`."""
        end = start + len(data) - 1
        headers = {"Content-Length": str(len(data)), "Content-Range": f"bytes {start}-{end}/{total}"}
        try:
            async with self._client(300.0) as client:
                response = await client.put(session_uri, content=data, headers=headers)
        except httpx.HTTPError as exc:
            raise GoogleError(0, "network", exc.__class__.__name__) from None
        if response.status_code in (200, 201):
            return "done", response.json()
        if response.status_code == 308:
            sent = response.headers.get("range", "")
            nxt = int(sent.rsplit("-", 1)[1]) + 1 if "-" in sent else 0
            return "more", nxt
        reason, message = _reason(response)
        raise GoogleError(response.status_code, reason, message)


R_FOLDER = FOLDER_MIME

_api: Optional[Any] = None


def api() -> Any:
    global _api
    if _api is None:
        from app.deps import get_settings

        settings = get_settings()
        _api = GoogleApi(settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET)
    return _api


def set_api(value: Optional[Any]) -> None:
    global _api
    _api = value


def client_id() -> str:
    try:
        from app.deps import get_settings

        return get_settings().GOOGLE_CLIENT_ID
    except Exception:  # noqa: BLE001
        return ""
