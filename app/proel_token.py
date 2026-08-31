# app/proel_token.py
#
# Włączanie i wyłączanie tokenu ProEl dla pojedynczego meczu.
#
# Na stronie ZPRP (lista meczów sędziego) przy numerze meczu stoi checkbox
# „Włącz / Wyłącz ProEl". Jego `onclick` woła `zapiszProtok3(IdZawody,'ProEl',
# this.value, this.checked)` z `zawody_zapisz3.js`, a ta funkcja robi zwykły
# POST formularzowy:
#
#     POST /zawody_zapisz3.php
#     ad1=<IdZawody>&ad2=ProEl&ad3=1&ad4=<true|false>&sid=<losowe>
#
# Odpowiedź jest tekstowa: "OK|<TOKEN>" przy powodzeniu (przy wyłączeniu token
# jest pusty), "ERROR" przy odmowie. Strona rozcina ją po „|" i wstawia drugą
# część do <span id="token_proel_<IdZawody>">.
#
# NAJPIERW OTWIERAMY LISTĘ, POTEM ZAPISUJEMY. Trzy powody, każdy sam
# wystarczający:
#   1. ZPRP odpowiada ERROR na „włącz" dla meczu, który JUŻ jest włączony.
#      Aplikacja, która nie zna stanu, prosi dokładnie o to i dostaje błąd,
#      choć wszystko jest w porządku - kod istnieje, tylko go nie widać.
#   2. Na liście stoi aktualny token. Przy zgodnym stanie oddajemy go bez
#      ruszania czegokolwiek w ZPRP.
#   3. To jedyny sposób, żeby odróżnić „nie masz prawa" od „tego meczu nie ma
#      na Twojej liście" - a te dwie rzeczy naprawia się inaczej.
#
# Akcję wykonuje serwer, tak samo jak edycję danych sędziego i zapis
# niedyspozycyjności: aplikacja przysyła zaszyfrowane RSA poświadczenia, serwer
# loguje się do ZPRP i klika. Telefon nie musi trzymać żywej sesji ZPRP.

import base64
import random
import re
from typing import List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric import padding

from app.deps import get_settings, Settings, get_rsa_keys
from app.utils import fetch_with_correct_encoding

router = APIRouter()

#: Ile sezonów wstecz wolno przejrzeć w poszukiwaniu meczu. Domyślna strona
#: pokazuje bieżący sezon i to on pokrywa każdy mecz, który da się jeszcze
#: rozegrać. Starsze przeglądamy tylko awaryjnie i nie bez końca - to koszt
#: kolejnych żądań do ZPRP.
MAX_SEASONS_TO_SCAN = 4


class ProelTokenRequest(BaseModel):
    #: Base64-RSA, jak w pozostałych akcjach idących przez serwer.
    username: str
    password: str
    judge_id: str
    #: `IdZawody` z listy meczów - jawne, to nie jest tajemnica.
    match_id: str
    #: Czy token ma być włączony.
    enabled: bool


def _find_proel_cell(html: str, match_id: str) -> Optional[str]:
    """Zwraca HTML komórki z checkboxem ProEla dla danego meczu (albo None).

    Komórka jest jedna na wiersz i trzyma naraz link do meczu, checkbox i
    miejsce na kod. Szukamy po `zapiszProtok3(<IdZawody>,'ProEl'`, bo to
    jedyne miejsce na stronie, gdzie numer meczu stoi tuż przy tym checkboxie.
    """
    marker = re.search(
        r"zapiszProtok3\(\s*%s\s*,\s*'ProEl'" % re.escape(match_id),
        html,
    )
    if not marker:
        return None
    start = html.rfind("<td", 0, marker.start())
    end = html.find("</td>", marker.start())
    if start < 0 or end < 0:
        return None
    return html[start:end]


def _read_proel_cell(cell_html: str) -> Tuple[bool, str]:
    """(czy włączony, token) - dokładnie tak, jak czyta to aplikacja."""
    input_tag = re.search(r'<input[^>]*name="ProEl"[^>]*>', cell_html, re.I)
    enabled = bool(input_tag) and bool(
        re.search(r"\schecked(\s|=|>)", input_tag.group(0), re.I)
    )

    token = ""
    span = re.search(
        r'id="token_proel_\d+"[^>]*>(.*?)</span>', cell_html, re.I | re.S
    )
    if span:
        raw = re.sub(r"<[^>]*>", " ", span.group(1))
        raw = re.sub(r"ProEl\s*:", " ", raw, flags=re.I)
        raw = raw.replace("&nbsp;", " ")
        token = re.sub(r"\s+", " ", raw).strip()

    return enabled, token


def _season_values(html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    sel = soup.find("select", {"name": "Filtr_sezon"})
    if not sel:
        return []
    out: List[str] = []
    for opt in sel.find_all("option"):
        v = (opt.get("value") or "").strip()
        if v:
            out.append(v)
    return out


@router.post("/match/proel")
async def set_match_proel(
    data: ProelTokenRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    def decrypt_field(enc_b64: str) -> str:
        cipher = base64.b64decode(enc_b64)
        return private_key.decrypt(cipher, padding.PKCS1v15()).decode("utf-8")

    try:
        user_plain = decrypt_field(data.username)
        pass_plain = decrypt_field(data.password)
        judge_plain = decrypt_field(data.judge_id)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    match_id = (data.match_id or "").strip()
    if not match_id.isdigit():
        raise HTTPException(400, "match_id musi być numerem IdZawody")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
    ) as client:
        resp_login, _ = await fetch_with_correct_encoding(
            client,
            "/login.php",
            method="POST",
            data={
                "login": user_plain,
                "haslo": pass_plain,
                "from": "/index.php?",
            },
        )
        if "/index.php" not in resp_login.url.path:
            raise HTTPException(401, "Logowanie nie powiodło się")
        # Ciasteczka trzyma klient, nie pojedyncza odpowiedź: sesja powstaje
        # w PRZEKIEROWANIU, a `resp_login` to już strona docelowa.
        client.cookies.update(resp_login.cookies)

        # ── 1) Lista meczów sędziego ────────────────────────────────────────
        list_path = (
            f"/index.php?a=statystyki&b=sedzia&NrSedzia={judge_plain}"
            "&Filtr_sezon="
        )
        _, html = await fetch_with_correct_encoding(
            client, list_path, method="GET"
        )
        cell = _find_proel_cell(html, match_id)

        # Mecz ze starszego sezonu nie jest na stronie domyślnej. Zaglądamy do
        # kolejnych sezonów, ale tylko kilku - patrz MAX_SEASONS_TO_SCAN.
        if cell is None:
            for season in _season_values(html)[:MAX_SEASONS_TO_SCAN]:
                _, html_season = await fetch_with_correct_encoding(
                    client,
                    f"/index.php?a=statystyki&b=sedzia&NrSedzia={judge_plain}"
                    f"&Filtr_sezon={season}",
                    method="GET",
                )
                cell = _find_proel_cell(html_season, match_id)
                if cell is not None:
                    break

        if cell is None:
            raise HTTPException(
                404,
                "Tego meczu nie ma na Twojej liście w ZPRP - ProEla można "
                "włączyć tylko z własnej obsady.",
            )

        current_enabled, current_token = _read_proel_cell(cell)

        # ── 2) Stan już zgodny = nic nie robimy ─────────────────────────────
        # To NIE jest optymalizacja, tylko poprawność: ZPRP odpowiada ERROR na
        # ponowne włączenie i aplikacja pokazywała błąd nad działającym kodem.
        if current_enabled == bool(data.enabled):
            return {
                "success": True,
                "enabled": current_enabled,
                "token": current_token if current_enabled else "",
                "changed": False,
            }

        # ── 3) Klikamy checkbox ─────────────────────────────────────────────
        # `ad3` to `this.value` checkboxa (na stronie zawsze "1"), `ad4` to
        # javascriptowy `this.checked`. `sid` jest cache-busterem oryginału.
        # Nagłówki dokładamy takie, jakie wysyła przeglądarka przy tym
        # XMLHttpRequest - żądanie ma być nieodróżnialne od kliknięcia.
        value_attr = "1"
        if cell:
            m_val = re.search(
                r'<input[^>]*name="ProEl"[^>]*value="([^"]*)"', cell, re.I
            )
            if m_val:
                value_attr = m_val.group(1)

        _, body = await fetch_with_correct_encoding(
            client,
            "/zawody_zapisz3.php",
            method="POST",
            data={
                "ad1": match_id,
                "ad2": "ProEl",
                "ad3": value_attr,
                "ad4": "true" if data.enabled else "false",
                "sid": str(random.random()),
            },
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{settings.ZPRP_BASE_URL.rstrip('/')}{list_path}",
            },
        )

    text = (body or "").strip()
    if not text.upper().startswith("OK"):
        # ZPRP odmówił - oddajemy jego własną odpowiedź, zamiast zgadywać.
        raise HTTPException(
            502,
            f"ZPRP nie przyjął zmiany ProEl: {text[:200] or 'pusta odpowiedź'}",
        )

    parts = text.split("|")
    token = parts[1].strip() if len(parts) > 1 else ""

    # Token przychodzi TYLKO przy włączaniu. Przy wyłączaniu strona czyści
    # miejsce na token, więc pusty ciąg jest tu poprawną odpowiedzią, a nie
    # brakiem danych.
    return {
        "success": True,
        "enabled": bool(data.enabled),
        "token": token if data.enabled else "",
        "changed": True,
    }
