"""Small, deterministic cache manifest; no DB imports (also safe to unit test)."""
import hashlib
import json
from datetime import date


def build_rates_manifest(rows, today: date):
    groups = {}
    for row in rows:
        item = {
            key: (value.isoformat() if hasattr(value, "isoformat") else value)
            for key, value in dict(row).items()
            if key in ("id", "province", "enabled", "valid_from", "valid_to", "updated_at")
        }
        groups.setdefault(item["province"], []).append(item)

    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    provinces = {}
    day = today.isoformat()
    for province, items in sorted(groups.items()):
        items.sort(key=lambda item: item["id"])
        effective = [item for item in items if item["enabled"]
                     and (not item["valid_from"] or item["valid_from"] <= day)
                     and (not item["valid_to"] or item["valid_to"] >= day)]
        active = max(effective, key=lambda item: (item["valid_from"] or "", item["updated_at"] or "", item["id"]), default=None)
        active_id = active["id"] if active else None
        provinces[province] = {"revision": digest([items, active_id]), "active_id": active_id}
    return {"schema": 1, "revision": digest(provinces), "provinces": provinces}
