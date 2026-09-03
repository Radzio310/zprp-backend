# app/training_spk_shootout.py
#
# Seria rzutów karnych wzorca - wyciągnięta z dokumentu meczu i ustawiona w
# KOLEJNOŚCI STRZELANIA.
#
# CZEMU OSOBNO OD OSI CZASU. Bo w protokole jej nie ma. Rzuty po meczu
# aplikacja trzyma w `penaltyShots` - dwie listy po jednym wpisie na rzut - a
# nie jako zdarzenia w `protocol`. Prezentacja składana z samej osi czasu
# kończyła się więc ostatnią akcją drugiej połowy i sędzia ćwiczący zostawał z
# remisem 26:26, jakby mecz na tym się skończył.
#
# CO ZNACZY „KOLEJNOŚĆ STRZELANIA". Serie idą naprzemiennie: najpierw drużyna,
# która rozpoczyna (`penaltyStarterTeam`), potem druga, i tak seria po serii.
# Bez tego przeplotu slajdy szłyby najpierw wszystkie rzuty gospodarzy, a potem
# gości - czyli w kolejności, w jakiej nikt tej serii nie widział.
#
# RZUT NIEODDANY NIE ISTNIEJE. Aplikacja trzyma z góry przygotowane rundy z
# `result: None`; te są pustymi miejscami w tabeli, nie rzutami. Slajd z takiego
# miejsca kazałby sędziemu wpisać coś, czego w meczu nie było.

from __future__ import annotations

from typing import Any, Dict, List

#: Która drużyna strzela pierwsza, gdy dokument tego nie mówi.
DEFAULT_STARTER = "host"


def _player(value: Any) -> str:
    """Numer zawodnika jako tekst - „16.0" i 16 to ten sam człowiek."""
    if value is None:
        return ""
    text = str(value).strip()
    if text.endswith(".0"):
        text = text[:-2]
    return "" if text.lower() in {"none", "null"} else text


def _shot_list(raw: Any) -> List[Dict[str, Any]]:
    return [s for s in raw if isinstance(s, dict)] if isinstance(raw, list) else []


def shootout_shots(blob: Any) -> List[Dict[str, Any]]:
    """Oddane rzuty serii, w kolejności strzelania.

    Każdy wpis niesie wszystko, czego potrzebuje slajd i wykrywanie wykonania:
    drużynę, numer, wynik rzutu, numer serii oraz `shotIndex` - który to rzut
    TEJ drużyny. Ten ostatni jest kluczem parowania na telefonie: sędzia sam
    wybiera, kto rozpoczyna serię, więc numer rzutu w serii bywa inny niż we
    wzorcu, ale „trzeci rzut gospodarzy" znaczy zawsze to samo.
    """
    if not isinstance(blob, dict):
        return []

    raw = blob.get("penaltyShots")
    raw = raw if isinstance(raw, dict) else {}
    lists = {
        "host": _shot_list(raw.get("host")),
        "guest": _shot_list(raw.get("guest")),
    }

    starter = str(blob.get("penaltyStarterTeam") or "").strip()
    if starter not in ("host", "guest"):
        starter = DEFAULT_STARTER
    order = (starter, "guest" if starter == "host" else "host")

    taken = {team: 0 for team in order}
    out: List[Dict[str, Any]] = []
    rounds = max(len(lists["host"]), len(lists["guest"]))
    for round_index in range(rounds):
        for team in order:
            shots = lists[team]
            if round_index >= len(shots):
                continue
            shot = shots[round_index]
            result = shot.get("result")
            if result is None:
                continue
            out.append(
                {
                    "team": team,
                    "player": _player(shot.get("player")),
                    "scored": bool(result),
                    "round": round_index + 1,
                    # Który to rzut tej drużyny - liczony po ODDANYCH, bo tak
                    # samo liczy je tabela serii w aplikacji.
                    "shotIndex": taken[team],
                }
            )
            taken[team] += 1
    return out
