from datetime import datetime
from zoneinfo import ZoneInfo
import json
import unicodedata

from app.board_rules import COMMITTEE_BADGES


# Osobny koszyk administracyjny dla par złożonych z sędziów dwóch okręgów.
# Nie jest województwem i nigdy nie może odziedziczyć uprawnień komisji.
CROSS_PROVINCE = "MIĘDZYOKRĘGOWE"

#: Program pary. „Mentor 2028" to para ZPRP: zakłada ją administrator, a
#: komisja okręgu tylko ją ogląda. Para wojewódzka należy do komisji.
PROGRAM_2028 = "mentor2028"
PROGRAM_PROVINCE = "province"


def json_value(value, fallback):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return fallback
    return value if isinstance(value, type(fallback)) else fallback


def pair_matches(judge_ids, state):
    """No surname fallback: unknown identity never grants access."""
    judge_ids = json_value(judge_ids, [])
    state = json_value(state, {})
    refs = {str(state.get(key) or "").strip() for key in ("NrSedzia_pierwszy", "NrSedzia_drugi")}
    return len(set(judge_ids)) == 2 and "" not in refs and refs == set(judge_ids)


#: Okręg bez zapisanej konfiguracji: zarządzanie WŁĄCZONE, bez dodatkowych osób.
#: Decyzja użytkownika z 15.10.2026 - członek komisji z odznaką ma móc tworzyć
#: pary od razu, a administrator może okręg świadomie wyłączyć.
DEFAULT_CONFIG = {"enabled": True, "manager_ids": []}

def has_committee_badge(badges) -> bool:
    """Odznaka komisji w każdym zapisie, którym wpuszcza tablica komisji.

    Dawniej mentoring żądał dokładnie „Komisja sędziowska" i odznaka
    „Komisja Sędziowska" (tak pisze ją tablica) nie dawała tu nic.
    """
    return any(
        unicodedata.normalize("NFC", str(name or "")).strip().casefold() in COMMITTEE_BADGES
        for name in badges or ()
    )


def may_manage(admin, actor_id, actor_province, badges, province, config):
    """Czy wolno zakładać, zmieniać i kończyć pary tego okręgu.

    Komisja z odznaką w SWOIM okręgu - zawsze, póki administrator nie wyłączył
    okręgu. Osoby wskazane przez administratora DOKŁADAJĄ SIĘ do komisji
    (decyzja z 15.10.2026), a nie ją zastępują.
    """
    if admin:
        return True
    if province == CROSS_PROVINCE or not actor_province or actor_province != province:
        return False
    config = config or DEFAULT_CONFIG
    if not config.get("enabled"):
        return False
    managers = {str(m) for m in json_value(config.get("manager_ids"), [])}
    return str(actor_id) in managers or has_committee_badge(badges)


def season_bounds(now=None):
    now = now or datetime.now(ZoneInfo("Europe/Warsaw"))
    # Same boundary as match_market_rules.SEASON_START_MONTH/DAY.
    year = now.year if now.month >= 9 else now.year - 1
    return datetime(year, 9, 1, tzinfo=ZoneInfo("Europe/Warsaw")), datetime(year + 1, 9, 1, tzinfo=ZoneInfo("Europe/Warsaw"))


def pair_program(stored, created_by_admin=False, province=""):
    """Program pary; wiersz bez znacznika (sprzed 15.10.2026) - po autorze."""
    value = str(stored or "").strip()
    if value in (PROGRAM_2028, PROGRAM_PROVINCE):
        return value
    return PROGRAM_2028 if created_by_admin or province == CROSS_PROVINCE else PROGRAM_PROVINCE


def program_for_new_pair(admin, province, wanted=None):
    """Znacznik nowej pary. Administrator: domyślnie „Mentor 2028", na życzenie
    wojewódzka. Komisja zakłada wyłącznie pary wojewódzkie."""
    if not admin:
        return PROGRAM_PROVINCE
    if province == CROSS_PROVINCE or wanted is None:
        return PROGRAM_2028
    return PROGRAM_2028 if wanted else PROGRAM_PROVINCE


def pair_locked(admin, manage, program):
    """Czy ten ktoś widzi parę tylko do odczytu."""
    if admin:
        return False
    return not manage or program == PROGRAM_2028

