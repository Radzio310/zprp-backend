# app/training_spk_meta.py
#
# Nagłówek meczu wzorcowego - to, co ekran startowy, karta w panelu i okładka
# PDF muszą o nim wiedzieć.
#
# OSOBNY MODUŁ, bo `app/training_spk.py` ciąga `app.db`, a tego nie da się
# zaimportować w teście lokalnym (JSONB na SQLite). Ta sama zasada, co przy
# `training_spk_score.py` i `training_spk_slides.py`: reguła, którą da się
# sprawdzić, mieszka poza trasą.
#
# CZEMU TO W OGÓLE MA WŁASNY PLIK, skoro to przepisanie kilku pól. Bo protokół
# nie trzyma wyniku w jednym kształcie: końcowy leży w dwóch osobnych polach,
# a wynik do przerwy w SŁOWNIKU `{"host": 10, "guest": 14}`. Zlepiony bez
# rozróżnienia trafiał na ekran jako surowy zapis Pythona.

from __future__ import annotations

from typing import Any, Dict


def _text(v: Any) -> str:
    """Liczba, tekst albo nic - zawsze jako tekst, nigdy jako „None"."""
    if v is None:
        return ""
    s = str(v).strip()
    return "" if s.lower() in {"none", "null"} else s


def half_scores(blob: Dict[str, Any]) -> tuple[str, str]:
    """
    Wynik do przerwy z protokołu, w obu kształtach, jakie tam bywają.

    Aplikacja zapisuje `halfScore` jako `{"host": 10, "guest": 14}`
    (`utils/finishedMatch.ts`), ale starsze zapisy i wpisy z API niosą to samo
    jako tekst „10-14" albo „10:14". Rozbicie po myślniku na słowniku daje
    JEDEN człon - cały jego zapis - i tak właśnie na karcie panelu pojawiło się
    `{'host': 10, 'guest': 14}` zamiast wyniku.
    """
    raw = blob.get("halfScore")

    if isinstance(raw, dict):
        return _text(raw.get("host")), _text(raw.get("guest"))

    text = _text(raw)
    if not text:
        return "", ""

    for sep in ("-", ":", "–"):
        if sep in text:
            left, _, right = text.partition(sep)
            return _text(left), _text(right)

    # Jeden człon bez separatora nie jest wynikiem połowy - lepiej nie pokazać
    # nic, niż pokazać liczbę, o której nie wiadomo, czyja jest.
    return "", ""


def meta_from_blob(blob: Dict[str, Any]) -> Dict[str, Any]:
    """Co ekran startowy, karta w panelu i PDF muszą wiedzieć o tym meczu.

    Czytamy z tego samego dokumentu, z którego bierze się oś czasu - bo tylko
    tak wynik pokazany sędziemu i wynik, z którym porównujemy podejście, są na
    pewno tym samym wynikiem.
    """
    cfg = blob.get("matchConfig")
    cfg = cfg if isinstance(cfg, dict) else {}
    half_host, half_guest = half_scores(blob)

    return {
        "matchNumber": _text(cfg.get("matchNumber")) or "SPK/1",
        "zprpMatchId": _text(cfg.get("matchId")),
        "hostTeamName": _text(cfg.get("hostTeamName")),
        "guestTeamName": _text(cfg.get("guestTeamName")),
        "date": _text(blob.get("date")) or _text(cfg.get("dateTime")),
        "finalHost": _text(blob.get("scoreHost")),
        "finalGuest": _text(blob.get("scoreGuest")),
        "halfHost": half_host,
        "halfGuest": half_guest,
        "hostPlayers": blob.get("hostPlayers") or [],
        "guestPlayers": blob.get("guestPlayers") or [],
    }
