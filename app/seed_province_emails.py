"""Jednorazowy wsad adresów e-mail okręgów (z Excela właściciela, 22.10.2026).

1. Niedyspo ZPRP: lista kopii (`province_cc`) każdego okręgu jest ZASTĘPOWANA
   jednym adresem DW.
2. Dodatkowy raport: adres „okręg" wpisujemy TYLKO tam, gdzie lista okręgu jest pusta.

Ślad w `app_migrations` zapisujemy dopiero po sukcesie obu kroków, a po nim
wsad nie wraca - późniejsze zmiany admina w panelu zostają.

⚠ `app.db` łączy się z Postgresem przy imporcie - importy bazy w funkcjach.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping

logger = logging.getLogger(__name__)

MARKER = "seed_province_emails_2026_10"

# okręg: (DW, okręg)
SEED: dict[str, tuple[str, str]] = {
    "DOLNOŚLĄSKIE": ("gskrobak@o2.pl", "dzpr@dzpr.eu"),
    "KUJAWSKO-POMORSKIE": ("komisjakpwzpr@gmail.com", "szczypiorniak_kp@wp.pl"),
    "LUBELSKIE": ("jakub.saluk@gmail.com", "lublin@zprp.org.pl"),
    "LUBUSKIE": ("kbak1@wp.pl", "prezeslzpr@onet.pl"),
    "ŁÓDZKIE": ("wojciechkulinski82@gmail.com", "lodz@zprp.org.pl"),
    "MAŁOPOLSKIE": ("ks@mzrp.pl", "biuro@mzpr.pl"),
    "MAZOWIECKIE": ("komisja.sedziowska.wmzpr@gmail.com", "biuro@wmzpr.pl"),
    "OPOLSKIE": ("stona_93@interia.pl", "biuro@ozpr.pl"),
    "PODKARPACKIE": ("zydek.10@interia.pl", "rzeszow@zprp.org.pl"),
    "PODLASKIE": ("ks.pwzpr@gmail.com", "ts.wieczorek@wp.pl"),
    "POMORSKIE": ("dominikkorda79@gmail.com", "gdansk@zprp.org.pl"),
    "ŚLĄSKIE": ("artur_jedrycha@interia.pl", "slaskie@zprp.org.pl"),
    "ŚWIĘTOKRZYSKIE": ("kamilboski@interia.pl", "kielce@zprp.org.pl"),
    "WARMIŃSKO-MAZURSKIE": ("sedziowie@w-mozpr.pl", "w-mwzprrusznicki@wp.pl"),
    "WIELKOPOLSKIE": ("sylwia_bartkowiak@interia.pl", "biuro@wzprpoznan.pl"),
    "ZACHODNIOPOMORSKIE": ("ks@zzpr.pl", "biuro@zzpr.pl"),
}


def _addr(value: str) -> str:
    return str(value or "").strip().lower()


def merge_dw(
    current: Mapping[str, Any] | None,
    seed: Mapping[str, tuple[str, str]],
    normalize,
) -> dict[str, list[str]]:
    """Niedyspo: lista każdego okręgu z seeda = jeden adres DW; reszta bez zmian."""
    out: dict[str, list[str]] = {
        str(k): list(v or []) for k, v in dict(current or {}).items()
    }
    for name, (dw, _district) in seed.items():
        key = normalize(name)
        if key and _addr(dw):
            out[key] = [_addr(dw)]
    return out


def merge_district(
    current: Mapping[str, list[str]] | None,
    seed: Mapping[str, tuple[str, str]],
    normalize,
) -> dict[str, list[str]]:
    """Dodatkowy raport: zwraca TYLKO okręgi do uzupełnienia (lista była pusta)."""
    cur = {k: list(v or []) for k, v in dict(current or {}).items()}
    out: dict[str, list[str]] = {}
    for name, (_dw, district) in seed.items():
        key = normalize(name)
        if key and _addr(district) and not cur.get(key):
            out[key] = [_addr(district)]
    return out


async def run_seed() -> bool:
    """Wykonuje wsad raz. Zwraca True, gdy właśnie się wykonał."""
    from sqlalchemy import select, update

    from app.db import database, extra_report_province_recipients as ER
    from app.one_time import claim_once, was_claimed
    from app.zprp_accounts import normalize_province
    from app.zprp_unavailability import SETTINGS, _settings_row

    if await was_claimed(MARKER):
        return False

    async with database.transaction():
        row = await _settings_row()
        province_cc = merge_dw(row.get("province_cc"), SEED, normalize_province)
        await database.execute(
            update(SETTINGS)
            .where(SETTINGS.c.id == 1)
            .values(province_cc=province_cc, updated_at=datetime.now(timezone.utc))
        )

        existing = {
            dict(r)["province"]: dict(r)
            for r in await database.fetch_all(select(ER))
        }
        fill = merge_district(
            {k: v.get("emails") or [] for k, v in existing.items()},
            SEED,
            normalize_province,
        )
        now = datetime.now(timezone.utc)
        for province, emails in fill.items():
            if province in existing:
                await database.execute(
                    update(ER)
                    .where(ER.c.province == province)
                    .values(emails=emails, updated_at=now)
                )
            else:
                await database.execute(
                    ER.insert().values(province=province, emails=emails, updated_at=now)
                )

    # Ślad dopiero po sukcesie.
    await claim_once(MARKER)
    logger.info("Wsad adresów okręgów: DW %s, okręg %s", len(SEED), len(fill))
    return True
