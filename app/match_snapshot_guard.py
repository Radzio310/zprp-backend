"""A response requested before a verified write cannot undo that write."""
from datetime import datetime, timezone


def explicit_removals(old: dict, new: dict) -> set[str]:
    fields = [f"NrSedzia_{slot}" for slot in ("pierwszy", "drugi", "sekretarz", "czas", "delegat", "delegat2")]
    current = {str(new.get(k) or "").strip() for k in fields}
    return {str(old.get(k) or "").strip() for k in fields
        if str(old.get(k) or "").strip().isdigit() and str(old.get(k)).strip() != "0"
        and str(new.get(k) or "").strip().isdigit()
        and str(old.get(k)).strip() not in current}


def verified_state(old: dict, new: dict, *, now=None) -> dict:
    stamp = now or datetime.now(timezone.utc)
    changed = {k: v for k, v in new.items() if not k.startswith("_") and old.get(k) != v}
    prior = old.get("_verified_write") or {}
    return {**new, "_verified_write": {
        "at": stamp.isoformat(), "fields": {**{k: old.get(k) for k in prior.get("fields", {})}, **changed},
    }}


def merge_observation(previous: dict, incoming: dict) -> dict:
    merged = {**previous, **incoming}
    verified = previous.get("_verified_write") or {}
    try:
        written = datetime.fromisoformat(verified["at"])
        requested = datetime.fromisoformat(incoming["_observed_at"])
        if requested < written:
            merged.update(verified.get("fields") or {})
    except (KeyError, TypeError, ValueError):
        pass
    # An old response must not replace the marker used by the next response.
    if verified:
        merged["_verified_write"] = verified
    return merged
