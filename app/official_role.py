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

from fastapi import APIRouter, Depends, Header, HTTPException
from httpx import AsyncClient
from sqlalchemy import func
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


def is_authorized(roles: List[str], admin: bool) -> bool:
    """Czy ta osoba może wykonać akcje pomeczowe tego meczu.

    DWIE DROGI, nie jedna. Pierwsza to obsada: sędzia boiskowy albo delegat.
    Druga to administrator aplikacji - i nie jest to obejście reguły, tylko jej
    druga część. Ktoś musi móc dokończyć protokół, gdy sędzia z obsady zgubił
    telefon albo pomylił konto; do dziś jedynym wyjściem było wysłanie kogoś
    z obsady po hasło, czyli najgorsza możliwa odpowiedź.

    Osobna funkcja, bo to JEDYNE zdanie, które rozstrzyga o dostępie - i musi
    dać się przetestować bez sieci i bez bazy.
    """
    return bool(admin) or any(r in AUTHORIZED_ROLES for r in roles)


async def _zprp_judge_id_by_login(
    settings: Settings, user_plain: str, pass_plain: str
) -> Tuple[str, str]:
    """Zaloguj do baza.zprp.pl i oddaj `(numer sędziego, nazwisko i imię)`.

    Ciało formularza idzie w ISO-8859-2, tak jak wysyła je przeglądarka i jak
    robi to `BAZA/utils/zprpLegacyLogin.ts`. Serwis NIE rozumie UTF-8: hasło z
    polskim znakiem wysłane po UTF-8 wraca jako „złe hasło", co przy sprawdzaniu
    uprawnień wyglądałoby na odmowę dostępu.

    Nazwisko jest BEST-EFFORT i wolno mu być puste. Do obsady meczu bierzemy je
    stamtąd, gdzie obsada naprawdę stoi (publiczne API rozgrywek); tutaj potrzeba
    go tylko wtedy, gdy zalogowanego NIE MA w obsadzie - czyli przy administratorze.
    Nieudany odczyt profilu nie może wywrócić sprawdzenia uprawnień, więc idzie
    w `try` i kończy się pustym napisem.
    """
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

        m = re.search(r"NrSedzia=(\d+)", html)
        if not m:
            # Konto organizacyjne (klub, okręg) loguje się poprawnie, ale nie
            # jest niczyim numerem sędziego - i nigdy nie będzie w obsadzie.
            raise HTTPException(
                403,
                "To konto nie ma numeru sędziego, więc nie może być w obsadzie "
                "meczu.",
            )
        judge_id = m.group(1)

        full_name = ""
        try:
            # Import LENIWY: `app.baza_web` ciągnie za sobą własne zależności,
            # a ten moduł ma się dać zaimportować także bez nich.
            from app.baza_web import _parse_profile_from_edit_form

            prof = await client.get(
                f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_id}"
            )
            parsed = _parse_profile_from_edit_form(
                prof.content.decode("iso-8859-2", errors="replace")
            )
            values = (parsed or {}).get("values", {}) or {}
            last = _clean(values.get("Nazwisko"))
            first = _clean(values.get("Imie"))
            full_name = f"{last} {first}".strip()
        except Exception:  # noqa: BLE001 — nazwisko to ozdoba, nie dowód
            full_name = ""

    return judge_id, full_name


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


def _authorized_crew(match: Dict[str, Any]) -> List[Dict[str, str]]:
    """Numery sędziów, którzy mają w ZPRP prawo pisać do TEGO meczu.

    PO CO TO ISTNIEJE. Oficjalne API ZPRP autoryzuje parą `(IdZawody,
    nr_sedzia)` - bez hasła. Administrator aplikacji, którego w obsadzie nie
    ma, dostanie tam odmowę własnym numerem, choć u nas jest uprawniony do
    dokończenia protokołu. Ta lista pozwala mu otworzyć sesję numerem sędziego
    prowadzącego ten mecz.

    SKĄD TE NUMERY. Wyłącznie z publicznego API rozgrywek, z obsady TEGO
    JEDNEGO meczu - tej samej odpowiedzi, którą i tak czytamy, żeby rozpoznać
    rolę. To NIE jest przeszukiwanie bazy użytkowników ani dopasowywanie po
    nazwisku: `login_records` odpowiada na pytanie „kto używa aplikacji", a nie
    „kto prowadzi ten mecz", i szukanie tam numerów wróciłoby do zbieżności
    nazwisk, którą świadomie zamknęliśmy.

    ODDAJEMY TO WYŁĄCZNIE ADMINISTRATOROWI. Numer sędziego jest w publicznym
    API jawny, ale para z `IdZawody` jest w ZPRP kluczem do zapisu - więc lista
    wychodzi stąd tylko dla konta, które przeszło logowanie i jest na liście
    administratorów.

    CZEGO TO NIE NAPRAWIA: wpis po stronie ZPRP będzie podpisany numerem
    sędziego, a nie administratora. Nasz dziennik zapisuje prawdę (kto
    naprawdę wykonał czynność), dziennik ZPRP tej prawdy mieć nie będzie - i
    aplikacja musi to powiedzieć wprost, zanim ktoś naciśnie.
    """
    out: List[Dict[str, str]] = []
    seen: set[str] = set()
    for role, id_keys, name_keys in ROLE_KEYS:
        if role not in AUTHORIZED_ROLES:
            continue
        for idx, key in enumerate(id_keys):
            nr = _clean(match.get(key))
            if not nr or nr in seen:
                continue
            seen.add(nr)
            name_key = name_keys[idx] if idx < len(name_keys) else ""
            out.append(
                {
                    "role": role,
                    "judgeId": nr,
                    "fullName": _clean(match.get(name_key)) if name_key else "",
                }
            )
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
    judge_id, full_name = await _zprp_judge_id_by_login(
        settings, user_plain, pass_plain
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

    # ── 3) Furtka administratora ────────────────────────────────────────────
    #
    # Administrator aplikacji odblokowuje akcje pomeczowe NIEZALEŻNIE od obsady.
    # Nie jest to obejście reguły, tylko jej druga część: ktoś musi móc dokończyć
    # protokół, gdy sędzia z obsady zgubił telefon albo pomylił konto - a dziś
    # jedynym wyjściem było wysłanie kogoś z obsady po hasło.
    #
    # Lista adminów jest TA SAMA, z której korzysta reszta aplikacji
    # (`admin_settings.allowed_admins` przez `is_admin`), a numer, po którym
    # sprawdzamy, pochodzi z zalogowania do baza.zprp.pl - nie z nagłówka.
    from app.proel_auth import is_admin  # lazy — patrz nota w tamtym module

    admin = await is_admin(judge_id)
    authorized = is_authorized(roles, admin)

    # ── 4) Dowód tożsamości na czas dokończenia protokołu ───────────────────
    #
    # Bez niego uprawnienie kończyło się na ekranie: aplikacja odblokowywała
    # przyciski, a serwer odrzucał każdy zapis, bo instalacja należy do
    # stolikowego (`ACTOR_MISMATCH` w `proel_actor`). Token jest jedynym
    # miejscem, w którym da się to powiedzieć uczciwie - powstaje TU, zaraz po
    # sprawdzeniu hasła, i tylko dla kogoś, kto to sprawdzenie przeszedł.
    #
    # Szczegóły i uzasadnienie krótkiego życia: `app/proel_elevation.py`.
    from app.proel_elevation import create_elevation_token, token_expires_at

    elevation = (
        create_elevation_token(judge_id, admin=admin, match_id=match_id)
        if authorized
        else ""
    )

    return {
        "ok": True,
        "judgeId": judge_id,
        # Z obsady, gdy jest w obsadzie; z profilu ZPRP, gdy wchodzi adminem.
        "fullName": _name_for(match, roles) or full_name,
        "roles": roles,
        "admin": admin,
        # Obsada uprawniona do zapisu w ZPRP - TYLKO dla administratora.
        "crew": _authorized_crew(match) if admin else [],
        # Rozstrzygnięcie zapada TU, nie w aplikacji: telefon może mieć
        # nieświeże dane meczu, a to jest odczyt prosto ze źródła.
        "authorized": authorized,
        # Dowód tożsamości dla zapisów wykonanych na cudzym urządzeniu.
        # Pusty, gdy uprawnienia nie ma - nie ma czego dowodzić.
        "elevation": elevation,
        "elevationExpiresAt": token_expires_at(elevation) if elevation else 0,
    }


# ═══════════════ potwierdzenie numeru sędziego dla konta ProEl ═══════════════
#
# Konto ProEl przestało dostawać rolę w meczu ze zbieżności nazwisk (patrz
# `roles_for` w `app/proel_auth.py`). Token konta dowodzi, że konto istnieje -
# nie dowodzi, że jego właściciel jest tym człowiekiem z obsady, bo nazwisko
# przyjeżdżało nagłówkiem od aplikacji.
#
# Ten endpoint jest DROGĄ WYJŚCIA i jedyną: konto raz loguje się do
# baza.zprp.pl, serwer odczytuje `NrSedzia` z sesji i zapisuje go razem ze
# znacznikiem czasu. Od tej chwili `account_actor` oddaje prawdziwy numer, więc
# takie konto jest w regule ról nieodróżnialne od zalogowanego sędziego BAZY.
#
# Hasło do ZPRP NIE JEST zapisywane. Zapisujemy wyłącznie numer i moment
# potwierdzenia.


class VerifyJudgeRequest(BaseModel):
    #: Base64-RSA, poświadczenia do baza.zprp.pl.
    username: str
    password: str


@router.post("/proel/account/verify-judge")
async def verify_proel_account_judge(
    data: VerifyJudgeRequest,
    authorization: Optional[str] = Header(None),
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    from app.db import database, proel_users
    from app.proel_users.tokens import _bearer, verify_access_token

    token = _bearer(authorization)
    if not token:
        raise HTTPException(401, "Zaloguj się na konto ProEl")
    try:
        uid = int(verify_access_token(token)["uid"])
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(401, "Niepoprawny token konta ProEl")

    private_key, _ = keys

    def decrypt_field(enc_b64: str) -> str:
        cipher = base64.b64decode(enc_b64)
        return private_key.decrypt(cipher, padding.PKCS1v15()).decode("utf-8")

    try:
        user_plain = decrypt_field(data.username)
        pass_plain = decrypt_field(data.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    judge_id, _ = await _zprp_judge_id_by_login(settings, user_plain, pass_plain)

    # Jeden numer sędziego = jedno konto ProEl. Bez tego dwie osoby mogłyby
    # potwierdzić ten sam numer i obie dostałyby rolę w cudzym meczu.
    taken = await database.fetch_one(
        proel_users.select().where(
            (proel_users.c.judge_id == judge_id)
            & (proel_users.c.judge_id_verified_at.isnot(None))
            & (proel_users.c.id != uid)
        )
    )
    if taken is not None:
        raise HTTPException(
            409,
            "Ten numer sędziego jest już potwierdzony przy innym koncie ProEl.",
        )

    await database.execute(
        proel_users.update()
        .where(proel_users.c.id == uid)
        .values(judge_id=judge_id, judge_id_verified_at=func.now())
    )

    return {"ok": True, "judgeId": judge_id}
