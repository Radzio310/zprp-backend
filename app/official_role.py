# app/official_role.py
#
# „Czy to konto jest sędzią boiskowym albo delegatem TEGO meczu?"
#
# Po co: akcje pomeczowe (wynik skrócony, pełne dane, protokół, SMS) należą do
# sędziów prowadzących i delegata. Mecz bywa jednak prowadzony na telefonie
# stolikowego - a ten wchodzi do protokołu tokenem albo własnym kontem i tych
# akcji wykonywać nie powinien. Żeby dokończyć protokół na tym samym urządzeniu,
# sędzia boiskowy loguje się tu swoim kontem baza.zprp.pl i dostaje dostęp na
# czas jednego ekranu.
#
# DWA PYTANIA, DWA ŹRÓDŁA. Tożsamość rozstrzyga logowanie do baza.zprp.pl (bez
# hasła nikt nie poda się za kogoś innego), a obsadę - publiczne API rozgrywek.
# Rozdzielenie jest celowe: numer sędziego wpisany z palca niczego by nie
# dowodził, a samo logowanie nie mówi, czy ten sędzia ma cokolwiek wspólnego
# z tym meczem.
#
# CZEGO TU NIE MA: hasła nie zapisujemy nigdzie ani nie oddajemy aplikacji.
# Oddajemy NUMER SĘDZIEGO - i to on wystarcza, bo oficjalne API ZPRP autoryzuje
# właśnie numerem (`POST /proel/zprp/auth`, `nr_sedzia`). Telefon stolikowego
# nie musi więc trzymać cudzego hasła nawet przez chwilę.

import base64
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel

from cryptography.hazmat.primitives.asymmetric import padding

from app.deps import get_settings, Settings, get_rsa_keys

router = APIRouter()

DETAILS_URL = "https://rozgrywki.zprp.pl/api/pokaz_mecze_szczegoly.php"

#: Rola → (pola z numerem sędziego, pola z nazwiskiem).
#: Kolejność ma znaczenie: pierwsza dopasowana rola jest tą, którą pokazujemy.
ROLE_KEYS: List[Tuple[str, List[str], List[str]]] = [
    ("referee1", ["NrSedzia_pierwszy"], ["NrSedzia_pierwszy_nazwisko"]),
    ("referee2", ["NrSedzia_drugi"], ["NrSedzia_drugi_nazwisko"]),
    (
        "delegate",
        ["NrSedzia_delegat", "NrSedzia_delegat2"],
        ["NrSedzia_delegat_nazwisko", "NrSedzia_delegat2_nazwisko"],
    ),
    ("secretary", ["NrSedzia_sekretarz"], ["NrSedzia_sekretarz_nazwisko"]),
    ("timekeeper", ["NrSedzia_czas"], ["NrSedzia_czas_nazwisko"]),
]

#: Role, które otwierają akcje pomeczowe.
AUTHORIZED_ROLES = frozenset({"referee1", "referee2", "delegate"})


class OfficialRoleRequest(BaseModel):
    #: Base64-RSA. To NIE są poświadczenia właściciela telefonu - to konto
    #: sędziego, który chce dokończyć protokół na cudzym urządzeniu.
    username: str
    password: str
    #: `IdZawody` - jawne, to nie jest tajemnica.
    match_id: str


def _clean(v: Any) -> str:
    return str(v or "").strip()


def _roles_for(match: Dict[str, Any], judge_id: str) -> List[str]:
    """Wszystkie role tego numeru sędziego w tym meczu.

    Porównujemy WYŁĄCZNIE po numerze. Nazwisko jest tu do pokazania, nie do
    rozstrzygania - dwóch Kowalskich na jednym meczu to realny przypadek
    (ta sama reguła co w `BAZA/utils/matchRole.ts`).
    """
    out: List[str] = []
    for role, id_keys, _ in ROLE_KEYS:
        for key in id_keys:
            if _clean(match.get(key)) and _clean(match.get(key)) == judge_id:
                out.append(role)
                break
    return out


def _name_for(match: Dict[str, Any], roles: List[str]) -> str:
    for role, _, name_keys in ROLE_KEYS:
        if role not in roles:
            continue
        for key in name_keys:
            name = _clean(match.get(key))
            if name:
                return name
    return ""


@router.post("/match/official-role")
async def match_official_role(
    data: OfficialRoleRequest,
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
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    match_id = _clean(data.match_id)
    if not match_id.isdigit():
        raise HTTPException(400, "match_id musi być numerem IdZawody")

    # ── 1) Kim jesteś: logowanie do baza.zprp.pl ────────────────────────────
    #
    # Ciało formularza idzie w ISO-8859-2, tak jak wysyła je przeglądarka i jak
    # robi to `BAZA/utils/zprpLegacyLogin.ts`. Serwis NIE rozumie UTF-8: hasło
    # z polskim znakiem wysłane po UTF-8 wraca jako „złe hasło", co przy
    # sprawdzaniu uprawnień wyglądałoby na odmowę dostępu.
    body = urlencode(
        {"login": user_plain, "haslo": pass_plain, "from": "/index.php?"},
        encoding="iso-8859-2",
        errors="replace",
    ).encode("ascii")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
    ) as client:
        resp = await client.post(
            "/login.php",
            content=body,
            headers={
                "Content-Type": (
                    "application/x-www-form-urlencoded; charset=ISO-8859-2"
                )
            },
        )
        if "/index.php" not in resp.url.path:
            raise HTTPException(401, "Nieprawidłowy login lub hasło")
        html = resp.content.decode("iso-8859-2", errors="replace")

    judge_id = ""
    m = re.search(r"NrSedzia=(\d+)", html)
    if m:
        judge_id = m.group(1)
    if not judge_id:
        # Konto organizacyjne (klub, okręg) loguje się poprawnie, ale nie jest
        # niczyim numerem sędziego - i nigdy nie będzie w obsadzie meczu.
        raise HTTPException(
            403,
            "To konto nie ma numeru sędziego, więc nie może być w obsadzie "
            "meczu.",
        )

    # ── 2) Czy jesteś w obsadzie: publiczne API rozgrywek ───────────────────
    async with AsyncClient(timeout=30.0) as public:
        details = await public.get(DETAILS_URL, params={"Zawody": match_id})
        details.raise_for_status()
        payload = details.json()

    match: Optional[Dict[str, Any]] = None
    if isinstance(payload, dict):
        first = payload.get("0")
        if isinstance(first, list) and first and isinstance(first[0], dict):
            match = first[0]
    if match is None:
        raise HTTPException(
            502,
            "Baza rozgrywek nie oddała obsady tego meczu - nie mam czego "
            "sprawdzić.",
        )

    roles = _roles_for(match, judge_id)
    return {
        "ok": True,
        "judgeId": judge_id,
        "fullName": _name_for(match, roles),
        "roles": roles,
        # Rozstrzygnięcie zapada TU, nie w aplikacji: telefon może mieć
        # nieświeże dane meczu, a to jest odczyt prosto ze źródła.
        "authorized": any(r in AUTHORIZED_ROLES for r in roles),
    }
