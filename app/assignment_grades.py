"""
Uprawnienia sedziow do szczebli - zbierane z formularza obsady ZPRP.

Litery w nawiasach przy nazwisku na liscie wyboru sedziego to jedyne miejsce,
w ktorym baza zwiazku mowi nam, kto ma jakie uprawnienia: (SL) Superliga,
(LC) ligi centralne, (PP) Puchar Polski, (MP) Mistrzostwa Polski, (I) (II) (III)
ligi, (Mł) mlodziez. Automat obsady bez nich nie odrozni stolika ligowego od
okregowego - a osobnej listy uprawnien ZPRP nie wystawia.

Zbieramy je WIEC PRZY OKAZJI: za kazdym razem, gdy panel otwiera formularz
meczu, zapamietujemy to, co w nim stalo. Nic nie kasujemy - brak kogos na
JEDNEJ liscie (filtr potrafi ja przyciac) nie znaczy, ze stracil uprawnienia.

⚠ Kluczem jest NAZWISKO, nie numer: `value` opcji w tym formularzu nie jest
stalym numerem sedziego (ZPRP przenumerowuje opcje zaleznie od filtra). Klucz
liczy `name_key`, wiec „NOWAK Jan" i „Jan Nowak" trafiaja w to samo miejsce.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping

from app.assignment_people import letter_key, name_key

logger = logging.getLogger(__name__)

#: Ile formularzy otwiera jednorazowe uzupelnienie. Jeden formularz oddaje CALA
#: liste sedziow, ktorych konto moze obsadzic na tym szczeblu - kilka roznych
#: szczebli wystarczy, zeby tabela uprawnien przestala byc pusta.
BACKFILL_FORMS = 6

#: Litery, ktore cokolwiek znacza dla automatu. Reszta („[MECZ]", smieci
#: z formatowania) nie ma po co zajmowac miejsca w tabeli.
KNOWN_LETTERS = frozenset(
    letter_key(item) for item in ("SL", "LC", "PP", "MP", "I", "II", "III", "Mł")
)


def options_grades(parsed: Mapping[str, Any]) -> dict[str, tuple[str, list[str]]]:
    """
    Sparsowany formularz -> `{klucz nazwiska: (nazwisko, litery)}`.

    Ta sama osoba stoi w kilku gniazdach naraz, wiec litery z nich SUMUJEMY:
    lista dla stolika bywa przyciagnieta filtrem i pokazuje mniej niz boiskowa.
    """
    out: dict[str, tuple[str, set[str]]] = {}
    slots = parsed.get("slots") if isinstance(parsed, Mapping) else None
    for slot in (slots or {}).values():
        for option in (slot or {}).get("options") or ():
            name = str((option or {}).get("name") or "").strip()
            key = name_key(name)
            if not key:
                continue
            letters = {
                letter_key(item)
                for item in ((option or {}).get("badges") or ())
                if letter_key(item) in KNOWN_LETTERS
            }
            known_name, known = out.get(key, (name, set()))
            out[key] = (known_name or name, known | letters)
    return {key: (name, sorted(letters)) for key, (name, letters) in out.items() if letters}


async def remember_grades(parsed: Mapping[str, Any]) -> int:
    """
    Zapisuje zebrane uprawnienia. Oddaje, ilu ludzi dotyczyl zapis.

    Osloniete: to czynnosc uboczna przy otwieraniu formularza. Gdyby zapis
    padl, obsadowy ma zobaczyc formularz, a nie blad - automat przy nastepnym
    otwarciu dowie sie tego samego.
    """
    grades = options_grades(parsed)
    if not grades:
        return 0
    try:
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        from app.db import database, zprp_judge_grades

        for key, (full_name, letters) in grades.items():
            await database.execute(
                pg_insert(zprp_judge_grades)
                .values(name_key=key, full_name=full_name, letters=letters)
                .on_conflict_do_update(
                    index_elements=[zprp_judge_grades.c.name_key],
                    set_={"full_name": full_name, "letters": letters},
                )
            )
        return len(grades)
    except Exception:
        logger.exception("obsada: nie udało się zapamiętać uprawnień z formularza")
        return 0


# ── jednorazowe uzupełnienie ────────────────────────────────────────────────


async def backfill_grades(province: str, *, limit: int = BACKFILL_FORMS) -> dict:
    """
    RAZ na okreg: otwieramy kilka formularzy obsady i zapisujemy litery.

    Po co: uprawnienia zbieraja sie przy okazji, gdy obsadowy otwiera mecz -
    wiec zaraz po wdrozeniu tabela jest PUSTA, a automat nie odrozni wtedy
    stolika ligowego od okregowego (`table_rule` patrzy na litery). Zamiast
    kazac czlowiekowi klikac po meczach, robimy to sami, kontem monitora.

    Wybieramy mecze z ROZNYCH rozgrywek, bo lista opcji w formularzu zalezy od
    szczebla: jeden formularz II ligi i jeden okregowy daja razem wiecej niz
    szesc formularzy tej samej rozgrywki.

    Slad w `app_migrations` sprawia, ze to sie nie powtarza - takze wtedy, gdy
    Railway wstanie dziesiec razy albo gdy automat puszcza dwoch ludzi naraz.
    Brak konta monitora NIE zajmuje sladu: konto moze dojsc jutro.
    """
    from app.one_time import claim_once
    from app.zprp_accounts import credentials_for

    out = {"ran": False, "forms": 0, "judges": 0, "reason": ""}

    creds = credentials_for(province, "sync")
    if not creds:
        out["reason"] = "brak konta monitora dla tego okręgu"
        return out
    if not await claim_once(f"assignment-grades-{province}"):
        out["reason"] = "już wykonane"
        return out

    # ⚠ `app.db` laczy sie z Postgresem przy imporcie, wiec wchodzi dopiero tutaj,
    # PO bramkach - inaczej nawet „nie ma czego robic" wymagaloby bazy.
    from sqlalchemy import and_, select

    from app.db import database, province_matches
    from app.settlement_province import spellings

    rows = await database.fetch_all(
        select(
            province_matches.c.match_id,
            province_matches.c.match_code,
        )
        .where(
            and_(
                province_matches.c.province.in_(spellings(province)),
                province_matches.c.active.is_(True),
                province_matches.c.match_id.is_not(None),
            )
        )
        .order_by(province_matches.c.match_at.desc())
        .limit(600)
    )

    # Po jednym meczu z rozgrywek - patrz nota wyzej.
    picked: dict[str, str] = {}
    for row in rows:
        code = str(row["match_code"] or "").strip()
        match_id = str(row["match_id"] or "").strip()
        if not code or not match_id:
            continue
        key = code.split("/")[0].upper() if "/" in code else code.upper()
        picked.setdefault(key, match_id)
        if len(picked) >= max(1, int(limit)):
            break
    if not picked:
        out["reason"] = "terminarz okręgu jest jeszcze pusty"
        return out

    username, password = creds
    seen: set[str] = set()
    try:
        from httpx import AsyncClient

        from app.config import get_settings
        from app.utils import fetch_with_correct_encoding
        from app.zprp.assignments import _parse_referee_form
        from app.zprp.schedule import _login_zprp_and_get_cookies

        settings = get_settings()
        async with AsyncClient(
            base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0
        ) as client:
            cookies = await _login_zprp_and_get_cookies(client, username, password)
            for match_id in picked.values():
                try:
                    _, html = await fetch_with_correct_encoding(
                        client,
                        "/zawody_UstawSedziow.php",
                        method="POST",
                        data={"IdZawody": match_id, "akcja": "UstawSedziow", "user": ""},
                        cookies=cookies,
                    )
                    parsed = _parse_referee_form(html)
                    found = options_grades(parsed)
                    if not found:
                        continue
                    await remember_grades(parsed)
                    seen.update(found)
                    out["forms"] += 1
                except Exception:
                    # Jeden mecz bez formularza nie przerywa reszty - konto
                    # bywa bez przycisku „Sędziowie" przy pojedynczym meczu.
                    logger.info(
                        "obsada: formularz meczu %s nie oddał uprawnień", match_id
                    )
        out["judges"] = len(seen)
        out["ran"] = True
        logger.info(
            "obsada %s: uzupełniono uprawnienia z %s formularzy (%s sędziów)",
            province, out["forms"], out["judges"],
        )
        return out
    except Exception as exc:
        # Slad juz zajety - i tak ma byc. Uprawnienia i tak doczytaja sie przy
        # pierwszym meczu otwartym w panelu, a automat dziala bez nich, tylko
        # ostrozniej. Powtarzanie logowania przy kazdym przebiegu byloby gorsze.
        logger.exception("obsada: jednorazowe uzupełnienie uprawnień nie doszło do skutku")
        out["reason"] = str(exc)
        return out
