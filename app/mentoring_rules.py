from datetime import datetime
from zoneinfo import ZoneInfo
import json


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


def may_manage(admin, actor_id, actor_province, badges, province, config):
    if admin:
        return True
    if actor_province != province or not config or not config.get("enabled"):
        return False
    managers = json_value(config.get("manager_ids"), [])
    return actor_id in managers if managers else "Komisja sędziowska" in badges


def season_bounds(now=None):
    now = now or datetime.now(ZoneInfo("Europe/Warsaw"))
    # Same boundary as match_market_rules.SEASON_START_MONTH/DAY.
    year = now.year if now.month >= 9 else now.year - 1
    return datetime(year, 9, 1, tzinfo=ZoneInfo("Europe/Warsaw")), datetime(year + 1, 9, 1, tzinfo=ZoneInfo("Europe/Warsaw"))
