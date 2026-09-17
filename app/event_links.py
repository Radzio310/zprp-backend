"""
Link kodu obecności otwierany ZWYKŁYM aparatem telefonu.

Decyzja z 17.09.2026: „zeskanowanie zwykłym aparatem ma przejść do aplikacji
do odpowiedniego miejsca i od razu zaznaczyć obecność - nie na stronę".

Kod QR wydarzenia niesie `https://<serwer>/e/<id>/<token>`. Telefon z BAZĄ
oddaje taki adres wprost aplikacji, bez przeglądarki:
  * iOS - Universal Links, plik `/.well-known/apple-app-site-association`
    (identyfikator zespołu + bundle; aplikacja deklaruje `applinks:<serwer>`),
  * Android - App Links, plik `/.well-known/assetlinks.json` z odciskiem
    SHA-256 klucza, którym podpisana jest ZAINSTALOWANA aplikacja. Wersja ze
    Sklepu Play jest podpisana kluczem Google (Play App Signing) - jego odcisk
    z Konsoli Play idzie do zmiennej `ANDROID_APP_LINK_SHA256` na Railway.

Sama trasa `/e/<id>/<token>` to siatka bezpieczeństwa na wypadek, gdy system
jeszcze nie zweryfikował domeny: Android dostaje przekierowanie `intent://`,
które otwiera BAZĘ (przeglądarka mignie na ułamek sekundy), a iOS i reszta -
krótką stronę z przyciskiem. Strona nie pokazuje nic o wydarzeniu: link nie
niesie logowania, a obecność zapisuje dopiero aplikacja z tokenem sędziego.

MODUŁ BEZ BAZY: same stałe, budowanie plików i trasy.
"""

from __future__ import annotations

import html
import os
import re
from typing import Any, Dict, List
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

#: Adres, pod którym wiszą pliki weryfikacyjne i trasa `/e/...` - ten serwer.
LINK_BASE = os.getenv("EVENT_LINK_BASE", "https://zprp-backend-production.up.railway.app").rstrip("/")
APP_SCHEME = "refhandballapp"
APPLE_TEAM_ID = os.getenv("APPLE_TEAM_ID", "R3G25RFSHW")
APP_ID = "com.radzio.RefHandballApp"
DEV_APP_ID = "com.radzio.RefHandballApp.dev"
APP_STORE_URL = "https://apps.apple.com/app/id6751402205"
PLAY_STORE_URL = f"https://play.google.com/store/apps/details?id={APP_ID}"

#: Klucz EAS wersji deweloperskiej (odczytany z podpisu APK z 17.09.2026).
DEV_SHA256 = "38:97:5D:A1:B1:3C:E5:6A:D4:F6:B5:CF:40:06:C2:73:05:E2:F7:54:DF:2E:AC:65:00:9E:A8:97:CB:13:19:D9"

TOKEN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_FINGERPRINT = re.compile(r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")


def fingerprints(raw: Any) -> List[str]:
    """Odciski SHA-256 z listy po przecinku; śmieci odpadają, zapis wielkimi literami."""
    out: List[str] = []
    for part in str(raw or "").replace(";", ",").split(","):
        value = part.strip().upper()
        if _FINGERPRINT.match(value) and value not in out:
            out.append(value)
    return out


def assetlinks(prod: List[str], dev: List[str]) -> List[Dict[str, Any]]:
    """`assetlinks.json` - pakiet bez odcisku nie trafia do pliku (nie ma czym go zweryfikować)."""
    out: List[Dict[str, Any]] = []
    for package, keys in ((APP_ID, prod), (DEV_APP_ID, dev)):
        if keys:
            out.append(
                {
                    "relation": ["delegate_permission/common.handle_all_urls"],
                    "target": {"namespace": "android_app", "package_name": package, "sha256_cert_fingerprints": keys},
                }
            )
    return out


def apple_app_site_association(team_id: str) -> Dict[str, Any]:
    """Obie wersje BAZY i tylko ścieżki kodu obecności - reszta adresów serwera zostaje w przeglądarce."""
    details = []
    for bundle in (APP_ID, DEV_APP_ID):
        app_id = f"{team_id}.{bundle}"
        details.append(
            {
                "appIDs": [app_id],
                "components": [{"/": "/e/*", "comment": "Kod obecności na wydarzeniu okręgowym"}],
                # Stary zapis dla iOS 12 i starszych.
                "appID": app_id,
                "paths": ["/e/*"],
            }
        )
    return {"applinks": {"apps": [], "details": details}}


def app_link(event_id: int, token: str) -> str:
    return f"{APP_SCHEME}://e/{int(event_id)}/{token}"


def android_intent(event_id: int, token: str) -> str:
    """`intent://` bez nazwy pakietu - otworzy każdą BAZĘ (sklepową albo dev), a bez niej stronę zapasową."""
    fallback = quote(f"{LINK_BASE}/e/{int(event_id)}/{token}?web=1", safe="")
    return f"intent://e/{int(event_id)}/{token}#Intent;scheme={APP_SCHEME};S.browser_fallback_url={fallback};end"


def _page(event_id: int, token: str, android: bool) -> str:
    open_url = android_intent(event_id, token) if android else app_link(event_id, token)
    store = PLAY_STORE_URL if android else APP_STORE_URL
    return f"""<!DOCTYPE html>
<html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Obecność - BAZA</title>
<style>
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(circle at 50% 20%,#15233d,#06080E 70%);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#F3F1EE}}
main{{width:min(420px,calc(100% - 40px));text-align:center}}
.icon{{width:84px;height:84px;margin:0 auto 18px;border-radius:28px;display:flex;align-items:center;justify-content:center;background:rgba(156,203,255,.14);border:1px solid rgba(156,203,255,.35);font-size:40px}}
h1{{font-size:24px;margin:0 0 8px}}p{{color:rgba(228,224,218,.7);font-size:15px;line-height:1.5;margin:0 0 22px}}
a.btn{{display:block;padding:16px;border-radius:16px;background:#9CCBFF;color:#07101E;font-weight:800;font-size:17px;text-decoration:none}}
a.alt{{display:inline-block;margin-top:18px;color:#9CCBFF;font-weight:700;font-size:14px;text-decoration:none}}
</style></head><body><main>
<div class="icon">✓</div>
<h1>Obecność na wydarzeniu</h1>
<p>Otwórz BAZĘ - obecność zapisze się sama, na Twoim koncie sędziego.</p>
<a class="btn" href="{html.escape(open_url)}">Otwórz BAZĘ i zapisz obecność</a>
<a class="alt" href="{html.escape(store)}">Nie masz BAZY? Pobierz aplikację</a>
</main></body></html>"""


router = APIRouter(include_in_schema=False)


@router.get("/.well-known/apple-app-site-association")
async def aasa() -> JSONResponse:
    return JSONResponse(apple_app_site_association(APPLE_TEAM_ID), media_type="application/json")


@router.get("/.well-known/assetlinks.json")
async def android_asset_links() -> JSONResponse:
    prod = fingerprints(os.getenv("ANDROID_APP_LINK_SHA256", ""))
    dev = fingerprints(os.getenv("ANDROID_DEV_APP_LINK_SHA256", DEV_SHA256))
    return JSONResponse(assetlinks(prod, dev))


@router.get("/e/{event_id}/{token}")
async def open_event_link(event_id: int, token: str, request: Request, web: int = 0):
    if not TOKEN.match(token):
        return HTMLResponse("<h1>Nieznany kod</h1>", status_code=404)
    android = "android" in request.headers.get("user-agent", "").lower()
    if android and not web:
        return RedirectResponse(android_intent(event_id, token), status_code=302)
    return HTMLResponse(_page(event_id, token, android))
