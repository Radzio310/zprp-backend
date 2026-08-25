"""Tożsamość aktora i role w meczu dla endpointów ProEl.

BAZA nie ma tokenów sesyjnych nadających się do użycia w hali: JWT z
`/auth/login` żyje 15 minut, a jego odświeżenie wymaga zalogowania się przez
scraping baza.zprp.pl. Sędzia potwierdzający badania przy słabym zasięgu nie
może być od tego zależny.

Dlatego aktor przedstawia się parą `judge_id` + `installation_id`, którą
weryfikujemy o tabelę `push_tokens` (PK = `installation_id`, indeks na
`judge_id`) — czyli o rejestr urządzeń, który aplikacja i tak utrzymuje.

To NIE jest twarda granica bezpieczeństwa i nie udajemy, że jest; to jest
o dwie klasy więcej niż dzisiejsze zero na `/proel/*` i wystarcza do
atrybucji („kto potwierdził badania"). Stare endpointy zostają bez auth,
bo inaczej złamalibyśmy aplikacje w terenie.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from fastapi import Header, HTTPException
from sqlalchemy import select

from app.proel_fields import ALL_ROLES, normalize_name

#: Aktor, który NIE deklaruje numeru sędziego - konto ProEl albo samo urządzenie.
#:
#: Do sierpnia 2026 tożsamością mógł być wyłącznie numer sędziego z
#: baza.zprp.pl, więc każdy, kto wszedł do ProEla kontem ProEl albo profilem
#: lokalnym, dostawał 401 na WSZYSTKICH trasach z `Depends(proel_actor)`:
#: liście meczów, stanie, leasingu, patchu. Aplikacja umiała tylko zapisać
#: dokument meczu (`POST /proel/`, miękki aktor), więc awaria wyglądała jak
#: „baza ProEl jest pusta".
#:
#: Prefiks jest tu po to, żeby takiego identyfikatora NIGDY nie pomylić z
#: numerem sędziego: nie porównujemy go z rejestrem urządzeń, nie daje roli w
#: meczu przez numer i nie wchodzi na listę adminów.
PROEL_ACCOUNT_PREFIX = "proel:"
DEVICE_PREFIX = "inst:"


def is_synthetic_judge_id(value: Any) -> bool:
    """Czy to identyfikator zastępczy, a nie numer sędziego."""
    v = str(value or "").strip()
    return v.startswith(PROEL_ACCOUNT_PREFIX) or v.startswith(DEVICE_PREFIX)

# UWAGA: `app.db` importujemy LENIWIE, wewnątrz funkcji, które naprawdę sięgają
# do bazy. Import modułu bazy wykonuje `metadata.create_all(engine)`, czyli
# wymaga żywego Postgresa — a czysta logika ról (`names_match`, `roles_for`)
# decyduje teraz o prawie do zapisu i musi dać się testować bez bazy.

logger = logging.getLogger(__name__)


@dataclass
class Actor:
    judge_id: str
    installation_id: str
    name: str = ""
    #: True gdy para (installation_id, judge_id) zgadza się z `push_tokens`.
    #: False oznacza „nie potrafimy potwierdzić", nie „na pewno oszust".
    verified: bool = False
    roles: Set[str] = field(default_factory=set)

    def as_by(self) -> Dict[str, Any]:
        """Kształt zapisywany w overlayu i audycie."""
        return {
            "judge_id": self.judge_id,
            "name": self.name,
            "install": self.installation_id,
            "verified": self.verified,
        }


def header_text(v: Any) -> str:
    """
    Tekst z nagłówka HTTP, z naprawionymi polskimi znakami.

    Nagłówki HTTP są ze specyfikacji latin-1 i Starlette tak je dekoduje.
    Aplikacja wysyła nazwisko w UTF-8, więc „Radosław" dociera jako
    „RadosÅ‚aw" — dwa bajty UTF-8 odczytane jako dwa znaki latin-1.

    Naprawa to przewinięcie tego z powrotem: bierzemy bajty, jakie faktycznie
    przyszły po drucie (`encode("latin-1")`), i czytamy je jako UTF-8. Nazwy
    z samego ASCII przechodzą przez to bez zmian, a cokolwiek, co się nie
    składa w poprawny UTF-8, zostaje jak było — lepiej pokazać dziwny znak niż
    uciąć nazwisko.

    Świadomie NIE naprawiamy tego po stronie aplikacji (procent-kodowaniem):
    naprawa na serwerze działa od razu także dla wersji już zainstalowanych,
    a te wysyłają nazwiska od kilku wydań.
    """
    s = str(v or "").strip()
    if not s or s.isascii():
        return s
    try:
        return s.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def _clean(v: Any) -> str:
    return str(v or "").strip()


async def _load_proel_account(user_id: int) -> Optional[Dict[str, Any]]:
    """Konto ProEl do tożsamości aktora - nazwisko i to, czy nie jest zablokowane.

    Osobna funkcja, żeby dało się ją podmienić w teście: ścieżka konta kończy
    się przed dotknięciem `push_tokens`, więc poza tym odczytem cała reguła
    chodzi bez Postgresa.
    """
    from app.db import database, proel_users  # lazy — patrz nota przy imporcie

    row = await database.fetch_one(
        select(proel_users.c.id, proel_users.c.full_name, proel_users.c.is_active).where(
            proel_users.c.id == int(user_id)
        )
    )
    return dict(row) if row is not None else None


async def account_actor(
    authorization: Optional[str],
    installation_id: str = "",
    name: Optional[str] = None,
) -> Optional[Actor]:
    """Aktor przedstawiony TOKENEM konta ProEl.

    Token jest dowodem mocniejszym niż para nagłówków - jest podpisany HMAC-iem
    serwera - więc taki aktor jest od razu `verified` i nie przechodzi przez
    rejestr urządzeń. Rejestr odpowiada na pytanie „czy ten telefon należy do
    tego sędziego", a tu żadnego sędziego nie ma.

    Identyfikatorem jest ZAWSZE `proel:<id konta>`, nigdy numer sędziego wpisany
    przy zakładaniu konta: ten numer nikt nie sprawdza, a wpuszczony tutaj
    dawałby prawa w cudzych meczach. Rola w meczu zostaje więc dopasowaniem po
    nazwisku - dokładnie tak jak dla starszych wpisów obsady bez numerów.

    `None` znaczy „ten nagłówek nic nie wnosi" (brak tokenu, token zły albo
    wygasły, konto skasowane) i wołający idzie dalej swoją drogą.
    """
    from app.proel_users.tokens import _bearer, verify_access_token  # lazy

    token = _bearer(authorization)
    if not token:
        return None
    try:
        uid = int(verify_access_token(token)["uid"])
    except HTTPException:
        return None
    except Exception:  # noqa: BLE001
        return None

    try:
        account = await _load_proel_account(uid)
    except Exception:  # noqa: BLE001 — awaria odczytu nie może blokować meczu
        logger.warning("account_actor: nie udało się odczytać konta ProEl", exc_info=True)
        return None
    if account is None:
        return None
    if not account.get("is_active", True):
        # Cisza byłaby tu najgorsza: konto istnieje, token jest poprawny, a
        # użytkownik dostawałby „Brak tożsamości urządzenia" i nie wiedział, że
        # to administrator go zablokował.
        raise HTTPException(
            403,
            detail={
                "code": "ACCOUNT_BLOCKED",
                "message": "Konto ProEl zostało zablokowane przez administratora.",
            },
        )

    return Actor(
        judge_id=f"{PROEL_ACCOUNT_PREFIX}{uid}",
        installation_id=_clean(installation_id),
        name=header_text(name) or _clean(account.get("full_name")),
        verified=True,
    )


async def proel_actor(
    x_judge_id: Optional[str] = Header(None, alias="X-Judge-Id"),
    x_installation_id: Optional[str] = Header(None, alias="X-Installation-Id"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
    authorization: Optional[str] = Header(None),
) -> Actor:
    """Zależność FastAPI: kto wykonuje zapis.

    Tożsamość ma trzy postacie, w kolejności mocy:
      • numer sędziego z baza.zprp.pl (para nagłówków, weryfikowana o rejestr
        urządzeń),
      • konto ProEl (token HMAC - patrz `account_actor`),
      • samo urządzenie (`inst:<installation_id>`) - dla profilu lokalnego bez
        numeru sędziego; nigdy nie jest zweryfikowane i nie daje nic ponad to,
        co daje znajomość adresu API.

    Reguła weryfikacji numeru sędziego jest celowo asymetryczna:
      • jest wiersz dla tego `installation_id` i zgadza się `judge_id` → verified,
      • jest wiersz, ale z INNYM `judge_id` → 401 (to realny sygnał, nie szum),
      • nie ma wiersza → przepuszczamy jako niezweryfikowanego.

    Ten ostatni przypadek jest konieczny: użytkownik, który odmówił zgody na
    powiadomienia, nigdy nie trafia do `push_tokens`. Odrzucanie go oznaczałoby,
    że sędzia bez powiadomień nie może potwierdzić badań.
    """
    judge_id = _clean(x_judge_id)
    installation_id = _clean(x_installation_id)

    # Prawdziwy numer sędziego wygrywa: daje rolę w meczu i prawa admina,
    # których token konta dać nie może. Token pytamy dopiero, gdy numeru nie ma
    # albo gdy jest zastępczy.
    if not judge_id or is_synthetic_judge_id(judge_id):
        from_account = await account_actor(authorization, installation_id, x_actor_name)
        if from_account is not None:
            return from_account

    if not judge_id or not installation_id:
        raise HTTPException(
            401,
            detail={
                "code": "ACTOR_REQUIRED",
                "message": "Brak tożsamości urządzenia. Zaloguj się ponownie.",
            },
        )

    if is_synthetic_judge_id(judge_id):
        # Nie ma tu deklaracji numeru sędziego, więc nie ma czego porównywać z
        # rejestrem urządzeń - a porównanie zwracałoby ACTOR_MISMATCH na każdym
        # telefonie, na którym ktoś kiedykolwiek logował się jako sędzia.
        return Actor(
            judge_id=judge_id,
            installation_id=installation_id,
            name=header_text(x_actor_name),
            verified=False,
        )

    verified = False
    try:
        # Import W ŚRODKU: `app/db.py` odpala `create_all` i wymaga żywego
        # Postgresa. Obietnica niżej („awaria odczytu nie może blokować meczu")
        # była nieprawdziwa dopóki ta linia stała nad `try` - awaria importu
        # przewracała całe żądanie.
        from app.db import database, push_tokens  # lazy — patrz nota przy imporcie

        row = await database.fetch_one(
            select(push_tokens.c.judge_id).where(
                push_tokens.c.installation_id == installation_id
            )
        )
        if row is not None:
            known = _clean(row["judge_id"])
            if known and known != judge_id:
                raise HTTPException(
                    401,
                    detail={
                        "code": "ACTOR_MISMATCH",
                        "message": "To urządzenie jest przypisane do innego sędziego.",
                    },
                )
            verified = bool(known)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 — awaria odczytu nie może blokować meczu
        logger.warning("proel_actor: nie udało się zweryfikować urządzenia", exc_info=True)

    return Actor(
        judge_id=judge_id,
        installation_id=installation_id,
        name=header_text(x_actor_name),
        verified=verified,
    )


async def is_admin(judge_id: str) -> bool:
    """Admin = numer sędziego na liście `admin_settings.allowed_admins`.

    Ta sama lista, z której korzysta aplikacja (`GET /admin/admins`), więc
    uprawnienie widoczne w UI i egzekwowane na serwerze są tym samym.
    """
    from app.db import admin_settings, database  # lazy — patrz nota przy imporcie

    jid = _clean(judge_id)
    if not jid:
        return False
    try:
        row = await database.fetch_one(select(admin_settings).limit(1))
        if not row:
            return False
        allowed = row["allowed_admins"] or []
        return jid in {str(a).strip() for a in allowed}
    except Exception:  # noqa: BLE001
        logger.warning("is_admin: odczyt listy adminów nieudany", exc_info=True)
        return False


# ─────────────────────────── role w meczu ───────────────────────────

_ROLE_KEYS = ("referee1", "referee2", "secretary", "timekeeper", "delegate")


def _tokens(s: Any) -> Set[str]:
    return {t for t in normalize_name(s).split(" ") if t}


def names_match(a: Any, b: Any) -> bool:
    """Port `namesMatch` z BAZA/utils/matchRole.ts, symetryczny.

    Oryginał wymaga, żeby WSZYSTKIE tokeny `a` były w `b`. Przy dwuczłonowym
    nazwisku po jednej stronie i jednoczłonowym po drugiej rola przepadała.
    Skoro rola daje teraz prawo zapisu, sprawdzamy obie strony.
    """
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return False
    return ta.issubset(tb) or tb.issubset(ta)


#: Czym API ZPRP wypełnia NIEOBSADZONE role: „--- ---", „---", myślnik, kropka.
#: Port `isBlankRefereeName` z BAZA/utils/refereeName.ts.
_PLACEHOLDER_RE = re.compile(r"^[\s\-\u2013\u2014_.\u00b7\u2022]+$")


def clean_person_name(value: Any) -> str:
    """Nazwisko z obsady - pusty string, gdy to w istocie pusty slot."""
    v = _clean(value)
    return "" if not v or _PLACEHOLDER_RE.match(v) else v


def clean_judge_number(value: Any) -> str:
    """Numer sędziego z obsady - pusty, gdy to placeholder albo same zera.

    Aplikacja czyści placeholdery w NAZWISKACH przy pobieraniu meczu, ale numeru
    roli nie czyścił nikt: pusty slot delegata jechał dalej jako `"0"`. Serwer
    widział wtedy „delegat jest" i żądał jego zgody na zatwierdzenie meczu, w
    którym delegata nie było wcale - a aplikacja, patrząc na puste nazwisko,
    pokazywała przycisk sędziemu. Zapalony przycisk i odmowa serwera to ten sam
    błąd widziany z dwóch stron.
    """
    v = _clean(value)
    if not v or _PLACEHOLDER_RE.match(v):
        return ""
    if v.isdigit() and not v.lstrip("0"):
        return ""
    return v


def official_name(raw: Any) -> str:
    """Nazwisko z wpisu obsady - wpis bywa słownikiem albo samym napisem."""
    if isinstance(raw, dict):
        return clean_person_name(raw.get("name") or raw.get("fullName"))
    return clean_person_name(raw)


def official_judge_id(raw: Any) -> str:
    """Numer sędziego z wpisu obsady."""
    if isinstance(raw, dict):
        return clean_judge_number(raw.get("judgeId") or raw.get("judge_id"))
    return ""


def _official_filled(raw: Any) -> bool:
    """Czy ten wpis obsady wskazuje KOGOKOLWIEK - nazwiskiem albo numerem."""
    return bool(official_name(raw) or official_judge_id(raw))


def crew_is_known(officials: Optional[Dict[str, Any]]) -> bool:
    """Czy o obsadzie tego meczu wiemy cokolwiek."""
    if not isinstance(officials, dict):
        return False
    return any(_official_filled(officials.get(key)) for key in _ROLE_KEYS)


#: Nazwa historyczna - używana w tym module od początku.
_crew_is_known = crew_is_known


def merged_officials(
    state_officials: Optional[Dict[str, Any]],
    doc_officials: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Obsada z wiersza stanu, uzupełniona tym, co wie zapisany protokół.

    Wiersz stanu jest źródłem lepszym (ma numery sędziów prosto z ZPRP), ale
    bywa pusty albo częściowy - zakłada go `/ensure` z guardem. Wpis wypełniony
    wygrywa z pustym, niezależnie od źródła.
    """
    out = dict(doc_officials or {})
    for key, value in (state_officials or {}).items():
        if _official_filled(value):
            out[key] = value
    return out


def _as_dict(value: Any) -> Dict[str, Any]:
    """Słownik z czegoś, co bywa też tekstem JSON albo śmieciem."""
    if isinstance(value, str):
        # Starsze wiersze bywają zapisane jako tekst JSON - klient też to
        # toleruje (`parseMatchBlob`), więc i my tolerujemy.
        try:
            value = json.loads(value)
        except Exception:  # noqa: BLE001
            return {}
    return value if isinstance(value, dict) else {}


def officials_from_config(match_config: Any) -> Dict[str, Any]:
    """Obsada z `matchConfig` protokołu.

    Osobno od całego bloba, bo trasa stanu czyta z bazy SAMĄ konfigurację
    (`data_json -> 'matchConfig'`), a nie protokół z przebiegiem i składami.
    """
    cfg = _as_dict(match_config)
    from_extras = _as_dict(_as_dict(cfg.get("extras")).get("officials"))

    out: Dict[str, Any] = {}
    for key in _ROLE_KEYS:
        raw = from_extras.get(key)
        # Starszy zapis trzyma same nazwiska wprost w `matchConfig`.
        name = official_name(raw) or clean_person_name(cfg.get(key))
        judge_id = official_judge_id(raw)
        if name or judge_id:
            out[key] = {"name": name, "judgeId": judge_id}
    return out


def officials_from_blob(data_json: Any) -> Dict[str, Any]:
    """Obsada wyczytana z zapisanego protokołu.

    Wiersz stanu współpracy (`proel_match_state.guard_json`) zna obsadę tylko
    wtedy, gdy ktoś zawołał `/ensure` z guardem. Bez tego odczytu reguła „kto
    może zatwierdzić" trafiałaby na pustą obsadę i przepuszczała każdego, czyli
    nie robiła nic.
    """
    return officials_from_config(_as_dict(data_json).get("matchConfig"))


def approve_roles(officials: Optional[Dict[str, Any]]) -> Set[str]:
    """Kto zamyka protokół i kto może go z powrotem otworzyć.

    Port reguły, którą ekran finalizacji stosuje od początku: gdy w meczu jest
    delegat, decyzja należy do niego; gdy go nie ma - do sędziów prowadzących.
    Stolikowi zostają poza tym zbiorem świadomie - protokół zamyka ten, kto go
    podpisuje.

    Do tej pory reguła istniała WYŁĄCZNIE w aplikacji i sterowała samą
    widocznością przycisku, a `PUT /proel/{numer}` przyjmował zmianę statusu od
    każdego, kto znał numer meczu. Zatwierdzony protokół potrafił więc odtwierdzić
    ktokolwiek - także osoba spoza tego meczu.
    """
    if isinstance(officials, dict) and _official_filled(officials.get("delegate")):
        return {"delegate"}
    return {"referee1", "referee2"}


def can_approve(actor: Actor, officials: Optional[Dict[str, Any]]) -> bool:
    """Czy ten aktor może zatwierdzić mecz albo cofnąć zatwierdzenie.

    OBSADA NIEZNANA przepuszcza wszystkich - z tego samego powodu, dla którego
    robi to `roles_for`: mecz stolikowy założony ręcznie nigdy nie będzie miał
    obsady z ZPRP, a musi dać się zamknąć.
    """
    roles = roles_for(actor, officials)
    return bool(roles & approve_roles(officials))


def roles_for(actor: Actor, officials: Optional[Dict[str, Any]]) -> Set[str]:
    """Zbiór ról aktora w tym meczu.

    NUMER SĘDZIEGO PRZED NAZWISKIEM: gdy znamy `judgeId` obsady, porównujemy
    numery i nie zgadujemy po nazwisku. Dopasowanie po nazwisku zostaje jako
    zapasowe, bo starsze wpisy w bazie nie mają numerów.

    `officials` ma kształt {"referee1": {"name": ..., "judgeId": ...}, ...}
    albo (starsze seedy) {"referee1": "NAZWISKO Imię", ...}.

    OBSADA NIEZNANA = WSZYSTKIE ROLE. Mecz stolikowy założony ręcznie nie ma
    obsady z ZPRP i nigdy jej mieć nie będzie. Gdybyśmy przy pustej liście
    odmawiali wszystkim, jedyny człowiek prowadzący taki mecz nie mógłby zapisać
    ani badań, ani danych pomeczowych — dostawałby „Nie masz roli uprawniającej
    do tej zmiany" przy każdym dotknięciu. Brak wiedzy o obsadzie to nie to samo
    co wiedza, że ktoś do niej nie należy: pierwsze przepuszczamy, drugie nie.
    """
    out: Set[str] = set()
    if not isinstance(officials, dict):
        return out
    if not _crew_is_known(officials):
        return set(ALL_ROLES)

    for key in _ROLE_KEYS:
        raw = officials.get(key)
        if raw is None:
            continue
        # Placeholder („--- ---", numer „0") nie jest ani nazwiskiem, ani
        # numerem - nie ma prawa nikomu dać roli ani nikogo od niej odciąć.
        oid = official_judge_id(raw)
        oname = official_name(raw)

        if oid:
            if oid == actor.judge_id:
                out.add(key)
                continue
            # Numer jest rozstrzygający: gdy jest po OBU stronach i się nie
            # zgadza, nie ratujemy roli zbieżnością nazwisk (dwóch Kowalskich
            # na mecz). Aktor bez numeru - konto ProEl, profil lokalny - nie ma
            # czego porównywać, więc dla niego zostaje nazwisko, dokładnie tak
            # jak dla starszych wpisów obsady zapisanych bez numerów. Inaczej
            # sędzia prowadzący protokół kontem ProEl nie miałby w swoim własnym
            # meczu żadnej roli.
            if actor.judge_id and not is_synthetic_judge_id(actor.judge_id):
                continue

        if actor.name and names_match(actor.name, oname):
            out.add(key)

    return out & ALL_ROLES


def _merge_official(existing: Any, incoming: Any) -> Any:
    """Scala jeden wpis obsady, nigdy nie tracąc numeru sędziego."""
    def as_dict(v: Any) -> Dict[str, Any]:
        if isinstance(v, dict):
            return dict(v)
        return {"name": _clean(v)} if _clean(v) else {}

    prev, nxt = as_dict(existing), as_dict(incoming)
    if not nxt:
        return existing
    out = dict(prev)
    for key, value in nxt.items():
        # Pusta wartość nie kasuje wypełnionej — ekran, który nie zna numerów,
        # nie może wymazać tych, które ktoś już przysłał.
        if _clean(value) or not _clean(out.get(key)):
            out[key] = value
    # Numer jest rozstrzygający dla roli i nigdy nie znika przez ekran, który
    # zna tylko nazwiska.
    for id_key in ("judgeId", "judge_id"):
        if _clean(prev.get(id_key)) and not _clean(out.get(id_key)):
            out[id_key] = prev[id_key]
    return out


def merge_guard(
    existing: Optional[Dict[str, Any]], incoming: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Scala `guard_json` przy `/ensure`.

    Płytkie `dict.update` gubiłoby tu numery sędziów: ekran finalizacji zna
    obsadę wyłącznie z nazwisk, więc jego `officials` zastąpiłby w całości
    wpisy z numerami, które przysłał wcześniej ekran meczu. A numer jest
    rozstrzygający przy rozpoznawaniu roli.
    """
    out: Dict[str, Any] = dict(existing or {})
    for key, value in (incoming or {}).items():
        if key != "officials":
            out[key] = value
            continue
        prev_off = out.get("officials")
        prev_off = dict(prev_off) if isinstance(prev_off, dict) else {}
        for role in _ROLE_KEYS:
            if not isinstance(value, dict) or role not in value:
                continue
            merged = _merge_official(prev_off.get(role), value.get(role))
            if merged:
                prev_off[role] = merged
        out["officials"] = prev_off
    return out


def can_confirm_exams(roles: Set[str]) -> bool:
    """Kto WIDZI przycisk „Sprawdź badania" — sędziowie główni i delegat.

    Serwer przyjmuje zapis `exam.*` od wszystkich pięciu ról (patrz rejestr):
    stolikowy robi to dzisiaj w ekranie konfiguracji i odebranie mu tego byłoby
    regresją. Asymetria UI ↔ serwer jest świadoma.
    """
    return bool(roles & {"referee1", "referee2", "delegate"})
