"""Klient connectora Handball Bastion (serwer-serwer, token Bearer) - bez logiki UI i bez bazy.

Krótkie timeouty, circuit breaker i cache zdrowia: awaria connectora nie może wieszać panelu ani
wywoływać lawiny żądań. Błąd sieci / 5xx / zła odpowiedź = `ConnectorUnavailable` (to NIE dowód wygaśnięcia sesji
Bastionu). Odpowiedzi 4xx connectora (409 brak sesji, 403 odmowa, 429 limit) wracają jako zwykły `Reply`.

Adres embed Bunny jest wrażliwy: tu nie jest ani logowany, ani zapisywany.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

import httpx

from app import mentor_bastion_rules as BR

logger = logging.getLogger("app.mentor_bastion")


class ConnectorUnavailable(Exception):
    """Connector nie odpowiada poprawnie (timeout, sieć, 5xx, niepoprawny JSON, otwarty bezpiecznik)."""

    def __init__(self, reason: str = "network"):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Reply:
    status: int
    body: Dict[str, Any]


@dataclass
class Breaker:
    """Po `threshold` kolejnych awariach otwiera się na `cooldown_s`; potem przepuszcza jedną próbę."""

    threshold: int = 3
    cooldown_s: float = 20.0
    clock: Callable[[], float] = time.monotonic
    failures: int = 0
    opened_at: Optional[float] = None
    probing: bool = False

    def allow(self) -> bool:
        if self.opened_at is None:
            return True
        if self.clock() - self.opened_at >= self.cooldown_s and not self.probing:
            self.probing = True
            return True
        return False

    @property
    def is_open(self) -> bool:
        return self.opened_at is not None

    def success(self) -> None:
        self.failures, self.opened_at, self.probing = 0, None, False

    def failure(self) -> None:
        self.failures += 1
        self.probing = False
        if self.failures >= self.threshold or self.opened_at is not None:
            self.opened_at = self.clock()


@dataclass
class ConnectorClient:
    base_url: str
    token: str
    timeout_s: float = 8.0
    transport: Optional[httpx.AsyncBaseTransport] = None
    breaker: Breaker = field(default_factory=Breaker)
    health_ttl_s: float = 10.0
    clock: Callable[[], float] = time.monotonic
    _http: Optional[httpx.AsyncClient] = None
    _health: Optional[tuple] = None  # (monotonic, ok)

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                base_url=self.base_url, transport=self.transport,
                timeout=httpx.Timeout(self.timeout_s, connect=min(3.0, self.timeout_s)),
                headers={"Authorization": f"Bearer {self.token}"}, follow_redirects=False)
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None,
                      json: Optional[Dict[str, Any]] = None) -> Reply:
        if not self.breaker.allow():
            raise ConnectorUnavailable("circuit_open")
        try:
            res = await self._client().request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            self.breaker.failure()
            logger.warning("bastion connector: %s %s -> %s", method, path, type(exc).__name__)
            raise ConnectorUnavailable("network") from exc
        if res.status_code == 401:
            # Zły token serwer-serwer to błąd konfiguracji BAZY, nie wygaśnięcie sesji Bastionu.
            logger.error("bastion connector odrzucil token serwer-serwer")
            self.breaker.failure()
            raise ConnectorUnavailable("connector_auth")
        try:
            body = res.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            self.breaker.failure()
            raise ConnectorUnavailable("bad_response")
        if res.status_code >= 500 and not (body.get("code") or body.get("error")):
            # 5xx bez kodu connectora to awaria serwisu/proxy; 503 z kodem (np. BASTION_UNAVAILABLE z `/playback`)
            # to werdykt o portalu - connector sam działa.
            self.breaker.failure()
            raise ConnectorUnavailable("server_error")
        self.breaker.success()
        return Reply(res.status_code, body if isinstance(body, dict) else {})

    # ─── Trasy connectora ───────────────────────────────────────────────

    async def healthy(self) -> bool:
        """`GET /health` z cache (nie pytamy connectora przy każdym żądaniu panelu)."""
        now = self.clock()
        if self._health and now - self._health[0] < self.health_ttl_s:
            return self._health[1]
        try:
            ok = (await self.request("GET", "/health")).status == 200
        except ConnectorUnavailable:
            ok = False
        self._health = (now, ok)
        return ok

    async def create_attempt(self, scope: str, judge_id: str, probe: Optional[int]) -> Reply:
        body: Dict[str, Any] = {"scope": scope, "judge_id": judge_id}
        if probe:
            body["probe_bunny_item_id"] = int(probe)
        return await self.request("POST", "/attempts", json=body)

    async def get_attempt(self, attempt_id: str) -> Reply:
        return await self.request("GET", f"/attempts/{attempt_id}")

    async def new_ticket(self, attempt_id: str) -> Reply:
        return await self.request("POST", f"/attempts/{attempt_id}/ticket")

    async def cancel_attempt(self, attempt_id: str) -> Reply:
        return await self.request("POST", f"/attempts/{attempt_id}/cancel")

    async def connection_status(self, scope: str, judge_id: Optional[str]) -> Reply:
        return await self.request("GET", "/connections/status", params=_scope_params(scope, judge_id))

    async def disconnect(self, scope: str, judge_id: Optional[str]) -> Reply:
        return await self.request("DELETE", "/connections", params=_scope_params(scope, judge_id))

    async def playback(self, scope: str, judge_id: Optional[str], bunny_item_id: int, *, include_embed: bool = True) -> Reply:
        params = {**_scope_params(scope, judge_id), "bunny_item_id": int(bunny_item_id)}
        if not include_embed:
            params["include_embed"] = "false"
        return await self.request("GET", "/playback", params=params)


def _scope_params(scope: str, judge_id: Optional[str]) -> Dict[str, Any]:
    params: Dict[str, Any] = {"scope": scope}
    if scope == "personal":
        params["judge_id"] = judge_id
    return params


_client: Optional[ConnectorClient] = None
_client_key: Optional[tuple] = None


def get_client() -> ConnectorClient:
    """Singleton na proces (jeden bezpiecznik i cache zdrowia). Testy podmieniają tę funkcję."""
    global _client, _client_key
    flags = BR.load_flags()
    if not flags.configured:
        raise ConnectorUnavailable("not_configured")
    key = (flags.connector_url, flags.connector_token, flags.timeout_s)
    if _client is None or _client_key != key:
        _client, _client_key = ConnectorClient(flags.connector_url, flags.connector_token, flags.timeout_s), key
    return _client
