"""
Wdrożenie okręgu - REGUŁY (moduł-liść: bez bazy, bez sieci, bez FastAPI).

Specyfikacja: `docs/wdrozenie-okregu.md`. Okręg wchodzi na
bazapodreka.app/okreg/start z kodem od administratora i sam wgrywa wszystko,
czego potrzebuje panel okręgowy. Każda rzecz to KLUCZ; wgrany klucz zapala
funkcje okręgu, a postęp wypełnia naczynie województwa na publicznej mapie.

Tu mieszka wszystko, co da się policzyć bez bazy: lista kluczy i ich skutki,
zakres kluczy z wybranych modułów cennika, postęp i etap, kod (generowanie,
zapis, skrót), token sesji, limit prób, walidacja szkiców z edytora, treść
łączonego powiadomienia i czyszczenie zdarzeń z sekretów.

Hasła ZPRP NIGDY tu nie trafiają jawnie: strona szyfruje je w przeglądarce
kluczem publicznym administratora (NaCl sealed box), serwer trzyma wyłącznie
szyfrogram, a odszyfrowuje dopiero BAZA na telefonie administratora.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ── Klucze ──────────────────────────────────────────────────────────────────

FORM_SECRET = "secret"
FORM_FILE_OR_EDITOR = "file_or_editor"
FORM_FORM = "form"
FORM_PEOPLE = "people"


@dataclass(frozen=True)
class KeyMeta:
    key: str
    label: str
    form: str
    #: Jednym zdaniem: co zapala.
    effect: str
    weight: int
    skippable: bool = False
    #: Co się dzieje, gdy okręg świadomie pominie klucz.
    skip_effect: str = ""
    #: Krótka nazwa do treści powiadomienia („konto odczytu").
    short: str = ""


KEYS: Tuple[KeyMeta, ...] = (
    KeyMeta(
        "zprp_sync", "Konto ZPRP do odczytu", FORM_SECRET,
        "Terminarz okręgu, powiadomienia o obsadach, kalendarz i statystyki schodzą same.",
        20, short="konto odczytu",
    ),
    KeyMeta(
        "zprp_assign", "Konto komisyjne ZPRP", FORM_SECRET,
        "Obsada z zapisem w ZPRP, wymiany z giełdy i logowanie panelu kodem QR.",
        20, short="konto komisyjne",
    ),
    KeyMeta(
        "rates", "Ryczałty okręgowe", FORM_FILE_OR_EDITOR,
        "Rozliczenia, rachunki sędziowskie i „Moje rozliczenie”.",
        20, short="ryczałty",
    ),
    KeyMeta(
        "distances", "Tabela odległości", FORM_FILE_OR_EDITOR,
        "Kilometry z tabeli okręgu w rachunkach.",
        10, skippable=True,
        skip_effect="Bez tabeli kilometry policzymy z map Google.",
        short="tabela odległości",
    ),
    KeyMeta(
        "keeper", "Opiekun panelu", FORM_FORM,
        "Jeden człowiek, z którym administrator ustala wszystko w okręgu.",
        5, short="opiekun panelu",
    ),
    KeyMeta(
        "commission", "Komisja z prawami", FORM_PEOPLE,
        "Dostęp do panelu webowego i panelu okręgowego w BAZA.",
        15, short="komisja",
    ),
    KeyMeta(
        "masters", "Masterzy", FORM_PEOPLE,
        "Ogłoszenia, kalendarz okręgu i egzaminy.",
        5, skippable=True,
        skip_effect="Bez masterów ogłoszenia, kalendarz i egzaminy prowadzi komisja.",
        short="masterzy",
    ),
    KeyMeta(
        "mentors", "Mentorzy i delegaci", FORM_PEOPLE,
        "Oceny młodych, para mentor z delegatem i Panel Mentor.",
        5, skippable=True,
        skip_effect="Bez mentorów oceny młodych poczekają, aż ich dopiszecie.",
        short="mentorzy",
    ),
)

KEY_META: Dict[str, KeyMeta] = {k.key: k for k in KEYS}
KEY_ORDER: Tuple[str, ...] = tuple(k.key for k in KEYS)
SECRET_KEYS = frozenset({"zprp_sync", "zprp_assign"})
EDITOR_KEYS = frozenset({"rates", "distances"})
PEOPLE_KEYS = frozenset({"keeper", "commission", "masters", "mentors"})

# ── Moduły cennika (`BAZA_web/.../district/pricing.ts`) ─────────────────────

CORE = "rdzen"
MODULES: Tuple[str, ...] = ("obsada", "rozliczenia", "statystyki", "rozwoj", "egzaminy")

MODULE_KEYS: Dict[str, Tuple[str, ...]] = {
    CORE: ("zprp_sync", "keeper", "commission"),
    "obsada": ("zprp_assign",),
    "rozliczenia": ("rates", "distances"),
    "statystyki": (),
    "rozwoj": ("mentors",),
    "egzaminy": ("masters",),
}


def clean_modules(raw: Any) -> List[str]:
    """Wybrane moduły w kolejności cennika. Rdzeń jest zawsze, więc go nie zapisujemy."""
    wanted = {str(x).strip() for x in (raw or []) if isinstance(x, str)}
    return [m for m in MODULES if m in wanted]


def scope_keys(modules: Iterable[str]) -> List[str]:
    """Klucze potrzebne dla wybranych modułów, w kolejności szyny."""
    needed = set(MODULE_KEYS[CORE])
    for module in clean_modules(modules):
        needed.update(MODULE_KEYS[module])
    return [k for k in KEY_ORDER if k in needed]


# ── Statusy, postęp, etap ───────────────────────────────────────────────────

MISSING = "missing"
SUBMITTED = "submitted"
IN_REVIEW = "in_review"
ACTIVE = "active"
SKIPPED = "skipped"
REJECTED = "rejected"
STATUSES = (MISSING, SUBMITTED, IN_REVIEW, ACTIVE, SKIPPED, REJECTED)

STATUS_FACTOR: Dict[str, float] = {
    MISSING: 0.0,
    SUBMITTED: 0.6,
    IN_REVIEW: 0.6,
    ACTIVE: 1.0,
    SKIPPED: 1.0,
    REJECTED: 0.0,
}

STAGE_WAITING = "waiting"
STAGE_IN_PROGRESS = "in_progress"
STAGE_READY = "ready"
STAGE_LIVE = "live"
STAGES = (STAGE_WAITING, STAGE_IN_PROGRESS, STAGE_READY, STAGE_LIVE)

DONE = frozenset({ACTIVE, SKIPPED})


def item_status(items: Mapping[str, Any], key: str) -> str:
    entry = items.get(key) if isinstance(items, Mapping) else None
    status = (entry or {}).get("status") if isinstance(entry, Mapping) else None
    return status if status in STATUSES else MISSING


def compute_progress(items: Mapping[str, Any], modules: Iterable[str]) -> int:
    """0-100 z wag kluczy w zakresie okręgu (wagi normalizowane do zakresu)."""
    keys = scope_keys(modules)
    total = sum(KEY_META[k].weight for k in keys)
    if not total:
        return 0
    got = sum(KEY_META[k].weight * STATUS_FACTOR[item_status(items, k)] for k in keys)
    return int(round(100 * got / total))


def compute_stage(items: Mapping[str, Any], modules: Iterable[str], *, entered: bool, live: bool) -> str:
    if live:
        return STAGE_LIVE
    if not entered:
        return STAGE_WAITING
    keys = scope_keys(modules)
    if keys and all(item_status(items, k) in DONE for k in keys):
        return STAGE_READY
    return STAGE_IN_PROGRESS


def lit_modules(items: Mapping[str, Any], modules: Iterable[str], *, live: bool = False) -> List[str]:
    """Moduły, których wszystkie klucze są zatwierdzone albo świadomie pominięte.

    Rdzeń świeci jako `rdzen`. Moduł bez własnych kluczy (statystyki) świeci
    razem z rdzeniem - nie potrzebuje niczego ponad niego.
    """
    chosen = clean_modules(modules)
    if live:
        return [CORE, *chosen]

    def done(keys: Iterable[str]) -> bool:
        return all(item_status(items, k) in DONE for k in keys)

    core_ok = done(MODULE_KEYS[CORE])
    out = [CORE] if core_ok else []
    for module in chosen:
        if core_ok and done(MODULE_KEYS[module]):
            out.append(module)
    return out


def skipped_keys(items: Mapping[str, Any], modules: Iterable[str]) -> List[str]:
    return [k for k in scope_keys(modules) if item_status(items, k) == SKIPPED]


def missing_summary(items: Mapping[str, Any], modules: Iterable[str]) -> Dict[str, int]:
    """Ile kluczy brakuje do każdego modułu (zdanie stanu na stole okręgu)."""
    out: Dict[str, int] = {}
    for module in [CORE, *clean_modules(modules)]:
        out[module] = sum(1 for k in MODULE_KEYS[module] if item_status(items, k) not in DONE)
    return out


# ── Województwa ─────────────────────────────────────────────────────────────

#: Przymiotnik do „Okręg pomorski" - tytuły powiadomień i nagłówek stołu.
PROVINCE_ADJECTIVE: Dict[str, str] = {
    "DOLNOSLASKIE": "dolnośląski",
    "KUJAWSKO_POMORSKIE": "kujawsko-pomorski",
    "LUBELSKIE": "lubelski",
    "LUBUSKIE": "lubuski",
    "LODZKIE": "łódzki",
    "MALOPOLSKIE": "małopolski",
    "MAZOWIECKIE": "mazowiecki",
    "OPOLSKIE": "opolski",
    "PODKARPACKIE": "podkarpacki",
    "PODLASKIE": "podlaski",
    "POMORSKIE": "pomorski",
    "SLASKIE": "śląski",
    "SWIETOKRZYSKIE": "świętokrzyski",
    "WARMINSKO_MAZURSKIE": "warmińsko-mazurski",
    "WIELKOPOLSKIE": "wielkopolski",
    "ZACHODNIOPOMORSKIE": "zachodniopomorski",
}
PROVINCES: Tuple[str, ...] = tuple(PROVINCE_ADJECTIVE)


def province_label(province: str) -> str:
    adj = PROVINCE_ADJECTIVE.get(province)
    return f"Okręg {adj}" if adj else "Okręg"


# ── Liczebniki ──────────────────────────────────────────────────────────────


def plural(n: int, one: str, few: str, many: str) -> str:
    """1 rzecz, 2 rzeczy, 5 rzeczy - polska odmiana liczebników."""
    n = abs(int(n))
    if n == 1:
        return one
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return few
    return many


# ── Kod ─────────────────────────────────────────────────────────────────────

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 8


def generate_code(rand: Optional[Any] = None) -> str:
    pick = (rand.choice if rand is not None else secrets.choice)
    return "".join(pick(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def normalize_code(raw: Any) -> str:
    """Kod z wpisu człowieka: bez spacji i myślników, wielkie litery.

    Zwraca pusty napis dla czegokolwiek, co nie może być kodem - wtedy w ogóle
    nie pytamy bazy.
    """
    text = re.sub(r"[\s\-_.]", "", str(raw or "")).upper()
    if len(text) != CODE_LENGTH or any(ch not in CODE_ALPHABET for ch in text):
        return ""
    return text


def format_code(code: str) -> str:
    """`WK7Q3MPX` -> `WK7Q-3MPX` (tak jak na tablicy)."""
    return f"{code[:4]}-{code[4:]}" if len(code) == CODE_LENGTH else code


def code_hash(code: str, pepper: str) -> str:
    return hashlib.sha256(f"{pepper}:{code}".encode("utf-8")).hexdigest()


def code_link(code: str) -> str:
    """Kod we fragmencie (`#`): nie leci do serwera strony ani do jej logów."""
    return f"https://www.bazapodreka.app/okreg/start#{code}"


# ── Token sesji okręgu ──────────────────────────────────────────────────────

TOKEN_TTL_SECONDS = 12 * 3600


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_token(secret: str, *, province: str, code_version: int, name: str, now: Optional[float] = None) -> str:
    issued = int(now if now is not None else time.time())
    body = _b64(json.dumps(
        {"p": province, "v": int(code_version), "n": name, "exp": issued + TOKEN_TTL_SECONDS},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8"))
    sig = _b64(hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}"


@dataclass(frozen=True)
class TokenClaims:
    province: str
    code_version: int
    name: str
    exp: int


def verify_token(secret: str, token: Any, now: Optional[float] = None) -> Optional[TokenClaims]:
    """Podpis i termin. Wersję kodu porównuje wołający z bazą (rotacja)."""
    text = str(token or "").strip()
    body, sep, sig = text.partition(".")
    if not sep or not body or not sig:
        return None
    want = _b64(hmac.new(secret.encode("utf-8"), body.encode("ascii", "ignore"), hashlib.sha256).digest())
    if not hmac.compare_digest(want, sig):
        return None
    try:
        data = json.loads(_unb64(body).decode("utf-8"))
        claims = TokenClaims(str(data["p"]), int(data["v"]), str(data.get("n") or ""), int(data["exp"]))
    except (ValueError, KeyError, TypeError):
        return None
    if claims.exp <= (now if now is not None else time.time()):
        return None
    return claims


# ── Podpis wchodzącego ──────────────────────────────────────────────────────

NAME_MAX = 80


def clean_name(raw: Any) -> str:
    """Imię i nazwisko z wejścia albo pusty napis, gdy to nie wygląda na podpis."""
    text = "".join(ch for ch in str(raw or "") if unicodedata.category(ch)[0] != "C")
    text = " ".join(text.split())[:NAME_MAX]
    words = [w for w in text.split(" ") if any(c.isalpha() for c in w)]
    if len(words) < 2 or len(text) < 5:
        return ""
    return text


# ── Limit prób wejścia ──────────────────────────────────────────────────────

ATTEMPTS_PER_MINUTE = 5
FAILS_BEFORE_BLOCK = 20
BLOCK_SECONDS = 3600


@dataclass
class EnterLimiter:
    """5 prób na minutę z jednego adresu, po 20 nieudanych blokada na godzinę.

    W pamięci procesu, tak jak inne limity logowania w tym serwerze: restart
    zeruje liczniki, a to akceptowalne przy kodzie z 32^8 możliwości.
    """

    per_minute: int = ATTEMPTS_PER_MINUTE
    fails_before_block: int = FAILS_BEFORE_BLOCK
    block_seconds: int = BLOCK_SECONDS
    max_keys: int = 5000
    _attempts: Dict[str, List[float]] = field(default_factory=dict)
    _fails: Dict[str, List[float]] = field(default_factory=dict)
    _blocked_until: Dict[str, float] = field(default_factory=dict)

    def retry_after(self, ip: str, now: Optional[float] = None) -> int:
        """Sekundy do następnej dozwolonej próby; 0 = wolno próbować."""
        now = now if now is not None else time.time()
        until = self._blocked_until.get(ip, 0.0)
        if until > now:
            return int(until - now) + 1
        recent = [t for t in self._attempts.get(ip, []) if t > now - 60]
        self._attempts[ip] = recent
        if len(recent) >= self.per_minute:
            return int(min(recent) + 60 - now) + 1
        return 0

    def is_blocked(self, ip: str, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return self._blocked_until.get(ip, 0.0) > now

    def attempt(self, ip: str, ok: bool, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        self._trim(now)
        self._attempts.setdefault(ip, []).append(now)
        if ok:
            self._fails.pop(ip, None)
            return
        fails = [t for t in self._fails.get(ip, []) if t > now - self.block_seconds]
        fails.append(now)
        self._fails[ip] = fails
        if len(fails) >= self.fails_before_block:
            self._blocked_until[ip] = now + self.block_seconds
            self._fails.pop(ip, None)

    def _trim(self, now: float) -> None:
        if len(self._attempts) + len(self._fails) <= self.max_keys:
            return
        self._attempts = {k: v for k, v in self._attempts.items() if v and v[-1] > now - 60}
        self._fails = {k: v for k, v in self._fails.items() if v and v[-1] > now - self.block_seconds}
        self._blocked_until = {k: v for k, v in self._blocked_until.items() if v > now}


def wait_message(seconds: int) -> str:
    minutes = max(1, (int(seconds) + 59) // 60)
    if minutes >= 60:
        return "Za dużo nieudanych prób z tego miejsca. Spróbuj znów za godzinę."
    return f"Za dużo prób naraz. Spróbuj znów za {minutes} {plural(minutes, 'minutę', 'minuty', 'minut')}."


BAD_CODE = "Ten kod nie działa. Sprawdź go albo poproś administratora BAZY o nowy."


# ── Pliki ───────────────────────────────────────────────────────────────────

FILE_MAX_BYTES = 15 * 1024 * 1024
FILE_TYPES: Dict[str, str] = {
    "pdf": "application/pdf",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "xls": "application/vnd.ms-excel",
    "csv": "text/csv",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "heic": "image/heic",
    "webp": "image/webp",
}


def file_kind(filename: Any) -> str:
    """Rozszerzenie z listy dozwolonych albo pusty napis."""
    name = str(filename or "").strip().lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    return ext if ext in FILE_TYPES else ""


def safe_filename(filename: Any) -> str:
    name = str(filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C").strip()
    return name[:160] or "plik"


# ── Sejf ────────────────────────────────────────────────────────────────────

SEAL_ALG = "nacl-sealedbox-x25519-xsalsa20poly1305"
#: Nakład sealed boxa: klucz efemeryczny (32) + MAC (16).
SEAL_OVERHEAD = 48
CIPHERTEXT_MAX = 4096


def check_ciphertext(raw: Any) -> str:
    """Base64 szyfrogramu albo pusty napis, gdy to nie może być sealed box.

    Serwer nie umie (i nie ma umieć) go otworzyć. Sprawdza tylko kształt, żeby
    do sejfu nie trafiło przez pomyłkę jawne hasło.
    """
    text = str(raw or "").strip()
    if not text or len(text) > CIPHERTEXT_MAX:
        return ""
    try:
        data = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        return ""
    if len(data) <= SEAL_OVERHEAD:
        return ""
    return text


def check_public_key(raw: Any) -> str:
    """Klucz publiczny X25519 w base64 (32 bajty) albo pusty napis."""
    text = str(raw or "").strip()
    try:
        data = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        return ""
    return text if len(data) == 32 else ""


def railway_env_names(province: str, key: str) -> Tuple[str, str]:
    prefix = {"zprp_sync": "ZPRP_SYNC", "zprp_assign": "ZPRP_ASSIGN"}.get(key)
    if not prefix or province not in PROVINCE_ADJECTIVE:
        return "", ""
    return f"{prefix}_{province}_USERNAME", f"{prefix}_{province}_PASSWORD"


#: Pola, które nigdy nie trafiają do zdarzeń ani do logów.
SECRET_FIELDS = frozenset({"password", "haslo", "hasło", "ciphertext", "secret", "code", "token", "pass"})


def scrub(payload: Any) -> Any:
    """Kopia ładunku zdarzenia bez żadnych pól sekretnych (na każdym poziomie)."""
    if isinstance(payload, Mapping):
        return {
            str(k): scrub(v)
            for k, v in payload.items()
            if str(k).strip().lower() not in SECRET_FIELDS
        }
    if isinstance(payload, (list, tuple)):
        return [scrub(v) for v in payload]
    return payload


# ── Ludzie ──────────────────────────────────────────────────────────────────

RIGHTS = ("assignments", "settlements", "admin")
RIGHT_LABELS = {"assignments": "obsada", "settlements": "rozliczenia", "admin": "admin okręgu"}
PEOPLE_MAX = 60
MASTER_KINDS = ("news", "calendar", "teach", "match")
MENTOR_ROLES = ("mentor", "delegate")


def _text(raw: Any, limit: int = 120) -> str:
    text = "".join(ch for ch in str(raw or "") if unicodedata.category(ch)[0] != "C")
    return " ".join(text.split())[:limit]


def clean_people(key: str, raw: Any) -> Tuple[Any, List[str]]:
    """(dane do zapisu, błędy). Błąd mówi człowiekowi, co poprawić."""
    errors: List[str] = []
    if key == "keeper":
        src = raw if isinstance(raw, Mapping) else {}
        person = {
            "first_name": _text(src.get("first_name"), 60),
            "last_name": _text(src.get("last_name"), 80),
            "phone": re.sub(r"[^\d+ ]", "", str(src.get("phone") or ""))[:20].strip(),
            "email": _text(src.get("email"), 120).lower(),
        }
        if not person["first_name"] or not person["last_name"]:
            errors.append("Podaj imię i nazwisko opiekuna.")
        if len(re.sub(r"\D", "", person["phone"])) < 9:
            errors.append("Podaj telefon opiekuna (9 cyfr).")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", person["email"]):
            errors.append("Podaj poprawny e-mail opiekuna.")
        return person, errors

    rows = raw if isinstance(raw, list) else []
    if len(rows) > PEOPLE_MAX:
        errors.append(f"Najwyżej {PEOPLE_MAX} osób na liście.")
        rows = rows[:PEOPLE_MAX]
    out: List[Dict[str, Any]] = []
    seen = set()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        person: Dict[str, Any] = {
            "first_name": _text(row.get("first_name"), 60),
            "last_name": _text(row.get("last_name"), 80),
            "judge_id": _text(row.get("judge_id"), 20),
        }
        if not person["first_name"] or not person["last_name"]:
            errors.append("Każda osoba potrzebuje imienia i nazwiska.")
            continue
        if key == "commission":
            person["login"] = _text(row.get("login"), 80)
            rights = row.get("rights") if isinstance(row.get("rights"), list) else []
            person["rights"] = [r for r in RIGHTS if r in rights]
            if not person["login"]:
                errors.append(f"Podaj login ZPRP osoby: {person['first_name']} {person['last_name']}.")
            if not person["rights"]:
                errors.append(f"Zapal choć jedno prawo osobie: {person['first_name']} {person['last_name']}.")
            ident = person["login"].lower()
        elif key == "masters":
            kinds = row.get("kinds") if isinstance(row.get("kinds"), list) else []
            person["kinds"] = [k for k in MASTER_KINDS if k in kinds] or list(MASTER_KINDS[:3])
            ident = person["judge_id"] or f"{person['first_name']} {person['last_name']}".lower()
        else:  # mentors
            role = str(row.get("role") or "mentor")
            person["role"] = role if role in MENTOR_ROLES else "mentor"
            ident = person["judge_id"] or f"{person['first_name']} {person['last_name']}".lower()
        if ident in seen:
            continue
        seen.add(ident)
        out.append(person)
    if not out and not errors:
        errors.append("Lista jest pusta. Dodaj choć jedną osobę albo pomiń ten klucz.")
    return out, errors


def people_count(draft: Any) -> int:
    if isinstance(draft, list):
        return len(draft)
    return 1 if isinstance(draft, Mapping) and draft else 0


# ── Szkice z edytora ────────────────────────────────────────────────────────

#: Wiersze edytora ryczałtów - kategorie okręgowe z `settlement_rates.district_category`.
RATE_CATEGORIES = ("Młodzik mł.", "Młodzik", "Junior mł.", "Junior", "III liga", "Dzieci", "Inne")
#: Kolumny - role rozliczeniowe (`settlement_rates.ROLES`).
RATE_ROLES = ("Sędzia boiskowy", "Sędzia stolikowy", "Delegat")
RATE_REQUIRED_ROLES = ("Sędzia boiskowy", "Sędzia stolikowy")
RATE_MAX = 5000


def _as_date(raw: Any) -> Optional[date]:
    try:
        return date.fromisoformat(str(raw or "")[:10])
    except ValueError:
        return None


def _number(raw: Any) -> Optional[float]:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    try:
        return float(str(raw).replace(",", ".").replace(" ", ""))
    except (TypeError, ValueError):
        return None


def validate_rates_draft(draft: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Szkic ryczałtów: `{validFrom, content: {rola: {kategoria: kwota}}}`.

    Kwota to liczba albo `{miejscowy, zamiejscowy}` - dokładnie to, co czyta
    `settlement_rates.provincial_gross`. Kompletność: data obowiązywania i choć
    jedna kategoria dla sędziego boiskowego i stolikowego.
    """
    errors: List[str] = []
    src = draft if isinstance(draft, Mapping) else {}
    valid_from = _as_date(src.get("validFrom"))
    if not valid_from:
        errors.append("Podaj datę, od której obowiązują stawki.")
    content_in = src.get("content") if isinstance(src.get("content"), Mapping) else {}
    content: Dict[str, Dict[str, Any]] = {}
    for role in RATE_ROLES:
        row = content_in.get(role)
        if not isinstance(row, Mapping):
            continue
        clean: Dict[str, Any] = {}
        for category, value in row.items():
            cat = _text(category, 40)
            if not cat:
                continue
            if isinstance(value, Mapping):
                local = _number(value.get("miejscowy"))
                away = _number(value.get("zamiejscowy"))
                if local is None and away is None:
                    continue
                cell = {}
                for name, number in (("miejscowy", local), ("zamiejscowy", away)):
                    if number is None:
                        continue
                    if not 0 <= number <= RATE_MAX:
                        errors.append(f"Kwota poza zakresem: {role}, {cat}.")
                    cell[name] = round(number, 2)
                clean[cat] = cell
                continue
            if value is None or value == "":
                continue
            number = _number(value)
            if number is None:
                errors.append(f"To nie jest kwota: {role}, {cat}.")
                continue
            if not 0 <= number <= RATE_MAX:
                errors.append(f"Kwota poza zakresem: {role}, {cat}.")
            clean[cat] = round(number, 2)
        if clean:
            content[role] = clean
    for role in RATE_REQUIRED_ROLES:
        if not content.get(role):
            errors.append(f"Brakuje stawek dla roli: {role}.")
    out = {"validFrom": valid_from.isoformat() if valid_from else None, "content": content}
    return out, errors


DISTANCE_MAX_CITIES = 150
DISTANCE_MAX_KM = 1500


def validate_distances_draft(draft: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Szkic tabeli: `{validFrom, cities, edges: [{from, to, distance_km}]}`.

    Ten sam kształt i ta sama kontrola co `app/distance_table_seed.py`: pełna
    macierz par (n·(n-1)/2), bez powtórzeń, bez par miasta z samym sobą.
    """
    errors: List[str] = []
    src = draft if isinstance(draft, Mapping) else {}
    valid_from = _as_date(src.get("validFrom"))
    if not valid_from:
        errors.append("Podaj datę, od której obowiązuje tabela.")
    cities: List[str] = []
    for raw in src.get("cities") or []:
        name = _text(raw, 60)
        if name and name not in cities:
            cities.append(name)
    if len(cities) < 2:
        errors.append("Tabela potrzebuje co najmniej dwóch miast.")
    if len(cities) > DISTANCE_MAX_CITIES:
        errors.append(f"Najwyżej {DISTANCE_MAX_CITIES} miast w tabeli.")
        cities = cities[:DISTANCE_MAX_CITIES]
    known = set(cities)
    pairs: Dict[frozenset, Dict[str, Any]] = {}
    for edge in src.get("edges") or []:
        if not isinstance(edge, Mapping):
            continue
        a, b = _text(edge.get("from"), 60), _text(edge.get("to"), 60)
        km = _number(edge.get("distance_km", edge.get("km")))
        if a not in known or b not in known or a == b or km is None:
            continue
        if not 0 <= km <= DISTANCE_MAX_KM:
            errors.append(f"Odległość poza zakresem: {a} - {b}.")
            continue
        if cities.index(a) > cities.index(b):
            a, b = b, a  # kierunek jak w macierzy: wcześniejsze miasto pierwsze
        pairs[frozenset((a, b))] = {"from": a, "to": b, "distance_km": int(round(km))}
    expected = len(cities) * (len(cities) - 1) // 2
    missing = expected - len(pairs)
    if cities and missing > 0:
        errors.append(
            f"Brakuje {missing} {plural(missing, 'pary', 'par', 'par')} miast."
        )
    ordered = [
        pairs[frozenset((a, b))]
        for i, a in enumerate(cities)
        for b in cities[i + 1:]
        if frozenset((a, b)) in pairs
    ]
    out = {"validFrom": valid_from.isoformat() if valid_from else None, "cities": cities, "edges": ordered}
    return out, errors


def validate_draft(key: str, draft: Any) -> Tuple[Dict[str, Any], List[str]]:
    if key == "rates":
        return validate_rates_draft(draft)
    if key == "distances":
        return validate_distances_draft(draft)
    return {}, ["Ten klucz nie ma edytora."]


# ── Łączone powiadomienie dla administratora ────────────────────────────────

NOTIFY_WINDOW_SECONDS = 600


def change_phrase(change: Mapping[str, Any]) -> str:
    """Jedna zmiana po ludzku: „ryczałty (plik)", „2 osoby komisji"."""
    key = str(change.get("key") or "")
    action = str(change.get("action") or "")
    meta = KEY_META.get(key)
    short = meta.short if meta else key
    if action == "skipped":
        return f"{short}: pominięte"
    if action == "unskipped":
        return f"{short}: wraca"
    if action == "modules_changed":
        return "zmiana zakresu"
    if action == "opened":
        return f"wejście: {change.get('by') or 'ktoś z okręgu'}"
    via = change.get("via")
    if key == "commission" and change.get("count"):
        n = int(change["count"])
        return f"{n} {plural(n, 'osoba', 'osoby', 'osób')} komisji"
    if key in ("masters", "mentors") and change.get("count"):
        n = int(change["count"])
        return f"{short}: {n} {plural(n, 'osoba', 'osoby', 'osób')}"
    if via == "file":
        return f"{short} (plik)"
    if via == "editor":
        return f"{short} (edytor)"
    return short


def batch_text(province: str, changes: Sequence[Mapping[str, Any]]) -> Tuple[str, str]:
    """(tytuł, treść) łączonego pusha: „Okręg pomorski: 3 nowe rzeczy"."""
    n = len(changes)
    title = f"{province_label(province)}: {n} {plural(n, 'nowa rzecz', 'nowe rzeczy', 'nowych rzeczy')}"
    phrases: List[str] = []
    for change in changes:
        phrase = change_phrase(change)
        if phrase in phrases:
            phrases.remove(phrase)  # nowsza wersja tej samej rzeczy idzie na koniec
        phrases.append(phrase)
    body = ", ".join(phrases)
    body = body[:1].upper() + body[1:]
    return title, body[:240]


@dataclass
class NotifyBatcher:
    """Jeden push na okręg na 10 minut, z liczbą zmian.

    `add` zwraca zmiany do wysłania OD RAZU (pierwsza zmiana po ciszy) albo
    nic - wtedy wołający planuje `flush` na `due_at`. Pamięć procesu: restart
    gubi co najwyżej jedną zaległą paczkę, a stan i tak widać w aplikacji.
    """

    window: int = NOTIFY_WINDOW_SECONDS
    _pending: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    _last_sent: Dict[str, float] = field(default_factory=dict)

    def add(self, province: str, change: Mapping[str, Any], now: Optional[float] = None) -> List[Dict[str, Any]]:
        now = now if now is not None else time.time()
        self._pending.setdefault(province, []).append(dict(change))
        if now - self._last_sent.get(province, -1e12) >= self.window:
            return self._take(province, now)
        return []

    def due_at(self, province: str) -> float:
        return self._last_sent.get(province, 0.0) + self.window

    def flush(self, province: str, now: Optional[float] = None) -> List[Dict[str, Any]]:
        now = now if now is not None else time.time()
        if not self._pending.get(province):
            return []
        if now < self.due_at(province):
            return []
        return self._take(province, now)

    def pending(self, province: str) -> int:
        return len(self._pending.get(province, []))

    def _take(self, province: str, now: float) -> List[Dict[str, Any]]:
        out = self._pending.pop(province, [])
        if out:
            self._last_sent[province] = now
        return out


# ── Stan wdrożenia dla okręgu ───────────────────────────────────────────────


def public_items(items: Mapping[str, Any], *, for_admin: bool = False) -> Dict[str, Any]:
    """Klucze dla okręgu: bez sekretów; szkic tylko u kluczy z edytora i ludzi."""
    out: Dict[str, Any] = {}
    for key in KEY_ORDER:
        entry = items.get(key) if isinstance(items, Mapping) else None
        entry = dict(entry) if isinstance(entry, Mapping) else {}
        clean = {
            "status": item_status(items, key),
            "updated_at": entry.get("updated_at"),
            "by": entry.get("by"),
            "note": entry.get("note"),
            "skip_reason": entry.get("skip_reason"),
        }
        if key in EDITOR_KEYS or key in PEOPLE_KEYS:
            clean["draft"] = entry.get("draft")
            if key in EDITOR_KEYS:
                clean["draft_by_admin"] = bool(entry.get("draft_by_admin"))
                clean["files"] = int(entry.get("files") or 0)
        if key in SECRET_KEYS:
            clean["sealed"] = bool(entry.get("sealed"))
            if key == "zprp_assign":
                clean["same_as_sync"] = bool(entry.get("same_as_sync"))
            if for_admin:
                clean["login"] = entry.get("login")
        out[key] = clean
    return out


def keys_catalog() -> List[Dict[str, Any]]:
    """Opis kluczy dla strony i aplikacji - jedno źródło nazw i skutków."""
    module_of = {k: m for m, keys in MODULE_KEYS.items() for k in keys}
    return [
        {
            "key": k.key,
            "label": k.label,
            "form": k.form,
            "effect": k.effect,
            "skippable": k.skippable,
            "skip_effect": k.skip_effect,
            "module": module_of.get(k.key, CORE),
        }
        for k in KEYS
    ]
