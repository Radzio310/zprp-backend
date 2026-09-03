"""Trzy prędkości monitora - co wolno, a czego nie wolno szybkiemu przebiegowi.

Lekki przebieg loguje się do bazy związku i przechodzi listę meczów KAŻDEGO
sędziego z osobna, więc jego koszt rośnie z liczbą sędziów, a nie meczów.
Przebiegi `hot` i `warm` pytają publiczne API wprost o znane identyfikatory -
bez sesji, bez ciasteczek i bez tej zależności.

Trzy rzeczy, które przy takim skrócie najłatwiej zepsuć, i wszystkie trzy kończą
się FAŁSZYWYM powiadomieniem u sędziego:

* pole, którego publiczne API nie zwraca, wygląda jak skasowane („usunięto
  delegata" przy meczu, w którym nikt niczego nie ruszył),
* odpowiedź API brana jako dowód, że mecz nadal wisi w terminarzu, na zawsze
  zatrzymuje wygaszanie meczów przeniesionych do innego okręgu,
* okna czasu, które się nie stykają, zostawiają mecze nieodpytywane przez
  nikogo.

Ten plik nie dotyka bazy - czyta reguły i drzewo składni modułu.
"""
from __future__ import annotations

import ast
import importlib
import pathlib
import sys
from unittest.mock import MagicMock

import pytest


def _load_monitor():
    """Monitor wczytany z atrapą `app.db`, ZAŁOŻONĄ NA CHWILĘ IMPORTU.

    `app.db` przy imporcie zakłada tabele na lokalnym SQLite, a schemat używa
    typów wyłącznie postgresowych (ARRAY, JSONB) - lokalnie po prostu nie
    wstaje. Badane funkcje są czyste i bazy nie tykają; monitor importuje ją
    tylko po nazwy tabel.

    Atrapa MUSI zniknąć zaraz po imporcie. Zostawiona w `sys.modules` trafia do
    każdego kolejnego testu, który sięga po prawdziwą bazę - a wtedy zamiast
    błędu dostaje się zawieszenie, bo atrapy nie da się awaitować.
    """
    saved_db = sys.modules.get("app.db")
    saved_mod = sys.modules.get("app.province_match_monitor")
    sys.modules["app.db"] = MagicMock()
    try:
        sys.modules.pop("app.province_match_monitor", None)
        return importlib.import_module("app.province_match_monitor")
    finally:
        if saved_db is None:
            sys.modules.pop("app.db", None)
        else:
            sys.modules["app.db"] = saved_db
        if saved_mod is None:
            sys.modules.pop("app.province_match_monitor", None)
        else:
            sys.modules["app.province_match_monitor"] = saved_mod


_monitor = _load_monitor()
_api_to_state = _monitor._api_to_state
build_change_events = _monitor.build_change_events
is_eligible_for_refresh = _monitor.is_eligible_for_refresh

SOURCE = (
    pathlib.Path(__file__).resolve().parents[1] / "app" / "province_match_monitor.py"
).read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCTIONS = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}


def calls_in(name: str) -> set[str]:
    out: set[str] = set()
    for sub in ast.walk(FUNCTIONS[name]):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                out.add(func.id)
            elif isinstance(func, ast.Attribute):
                out.add(func.attr)
    return out


# ── Scalanie odpowiedzi API ze stanem zapisanym ─────────────────────────────

STORED = {
    "Id": "208136",
    "RozgrywkiCode": "OSM/12",
    "data_fakt": "2026-09-13 14:00:00",
    "NrSedzia_pierwszy_nazwisko": "NOWAK Jan",
    "NrSedzia_delegat_nazwisko": "MAZUR Adam",
    # Pola, których publiczne API NIE zwraca - żyją tylko na stronie za
    # logowaniem i przychodzą z lekkiego przebiegu.
    "delegate_note": "ocena 8",
    "host_contact": {"phone": "600100200"},
    "guest_contact": {"phone": "600300400"},
    "season": "2026/2027",
}


def api_payload(**over):
    match = {
        "Id": "208136",
        "RozgrywkiCode": "OSM/12",
        "data_fakt": "2026-09-13 14:00:00",
        "NrSedzia_pierwszy_nazwisko": "NOWAK Jan",
        "NrSedzia_delegat_nazwisko": "MAZUR Adam",
    }
    match.update(over)
    return {"0": [match]}


def test_fields_the_public_api_never_returns_survive():
    """Najgroźniejszy przypadek w całym przebiegu.

    Ocena delegata i kontakty klubów nie wychodzą z publicznego API. Gdyby
    scalanie szło po całym stanie, ich brak w odpowiedzi wyglądałby jak
    skasowanie i sędzia dostawałby powiadomienie o zmianie, której nie było.
    """
    merged = _api_to_state(api_payload(), dict(STORED))

    assert merged["delegate_note"] == "ocena 8"
    assert merged["host_contact"] == {"phone": "600100200"}
    assert merged["guest_contact"] == {"phone": "600300400"}


def test_merged_state_produces_no_phantom_events():
    # Ten sam mecz, nic się nie zmieniło - zero powiadomień.
    merged = _api_to_state(api_payload(), dict(STORED))
    assert build_change_events(STORED, merged) == []


def test_a_real_change_still_gets_through():
    merged = _api_to_state(
        api_payload(data_fakt="2026-09-14 18:00:00"), dict(STORED)
    )
    events = build_change_events(STORED, merged)

    assert [e["event_type"] for e in events] == ["match_date_changed"]


def test_crew_change_is_visible_to_the_fast_pass():
    """Dopisanie sędziego to najpilniejsze powiadomienie i ma być szybkie.

    Obsada jest w odpowiedzi publicznego API, więc `hot` ją widzi - nie trzeba
    czekać na logowanie się do bazy związku.
    """
    merged = _api_to_state(
        api_payload(NrSedzia_pierwszy_nazwisko="KOWALSKI Piotr"), dict(STORED)
    )
    events = build_change_events(STORED, merged)

    assert any(e["event_type"] == "lineup_changed" for e in events)


# ── Czego szybki przebieg NIE ma prawa zrobić ───────────────────────────────


def test_public_pass_does_not_claim_the_match_is_in_the_schedule():
    source = ast.unparse(FUNCTIONS["_run_public"])
    assert "seen_in_schedule=False" in source


def test_upsert_only_resets_the_schedule_counters_when_it_saw_the_schedule():
    """`missing_full_runs` liczy nieobecności w terminarzu.

    Zerowanie go z przebiegu publicznego sprawiłoby, że mecz przeniesiony do
    innego okręgu nigdy by u nas nie wygasł - pełny przebieg zaczynałby liczyć
    od zera po każdym szybkim odpytaniu.
    """
    source = ast.unparse(FUNCTIONS["_upsert_match"])
    assert "seen_in_schedule" in source
    assert "missing_full_runs" in source


def test_public_pass_never_logs_in():
    # Cała oszczędność polega na tym, że ten przebieg nie potrzebuje sesji.
    calls = calls_in("_run_public")
    assert "_login_zprp_and_get_cookies" not in calls
    assert "fetch_with_correct_encoding" not in calls
    assert "_fetch_details_many" in calls


def test_public_pass_asks_only_about_matches_with_our_crew():
    # Mecz bez sędziego z naszego województwa nie ma adresata powiadomienia,
    # więc odpytywanie o niego byłoby obciążaniem cudzego serwera bez powodu.
    source = ast.unparse(FUNCTIONS["_public_window_states"])
    assert "province_match_judges" in source
    assert "_PUBLIC_LIMIT" in ast.unparse(FUNCTIONS["_run_public"])


def test_approved_matches_are_left_alone():
    # Po zatwierdzeniu protokołu nic się już nie zmieni.
    assert not is_eligible_for_refresh({"protocol_status": "approved"})
    assert not is_eligible_for_refresh({}, approved=True)


# ── Okna czasu ──────────────────────────────────────────────────────────────


def test_hot_and_warm_windows_touch_without_a_gap():
    """Mecz nie może wypaść między prędkościami.

    `hot` kończy się tam, gdzie `warm` się zaczyna - obie granice liczone są z
    tej samej stałej, więc nie da się ich rozjechać przez przeoczenie.
    """
    source = ast.unparse(FUNCTIONS["_run_public"])
    assert "since = now + timedelta(days=_HOT_DAYS)" in source
    assert "until = now + timedelta(days=_HOT_DAYS)" in source


def test_hot_window_reaches_into_the_past():
    # Po meczu jeszcze długo zmienia się wynik i status protokołu.
    assert _monitor._HOT_PAST_DAYS >= 1


def test_warm_starts_where_hot_ends():
    assert _monitor._WARM_DAYS > _monitor._HOT_DAYS


def test_every_mode_has_a_loop():
    source = ast.unparse(FUNCTIONS["run_province_match_monitor"])
    for mode in ("hot", "warm", "light", "full"):
        assert f"'{mode}'" in source or f'"{mode}"' in source


def test_fast_passes_do_not_queue_behind_the_crawler():
    # Czekanie na zajęte województwo zbudowałoby ogon przebiegów pytających
    # o to samo. Szybki przebieg pomija cykl i wraca za chwilę.
    source = ast.unparse(FUNCTIONS["_execute_run"])
    assert "hot" in source and "warm" in source
    assert "max_wait = 20" in source


# ── Zapytanie o okno czasu ──────────────────────────────────────────────────


def test_okno_publiczne_nie_uzywa_distinct():
    """`SELECT DISTINCT` + `ORDER BY` po kolumnie spoza listy = błąd Postgresa.

    Tak właśnie wyglądało to zapytanie: złączenie z tabelą sędziów mnożyło
    wiersze (kilku sędziów przy jednym meczu), więc doszedł `DISTINCT`, a
    sortowanie po `match_at` zostało. Postgres odrzucał to za każdym razem:

        InvalidColumnReferenceError: for SELECT DISTINCT, ORDER BY expressions
        must appear in select list

    Czyli szybki przebieg publiczny nie odpytał ANI JEDNEGO meczu - po cichu,
    bo wyjątek lądował w logu pętli w tle. Warunek „stoi przy nim czynny
    sędzia" jest teraz podzapytaniem EXISTS, które wierszy nie mnoży.
    """
    assert "distinct" not in calls_in("_public_window_states")
    assert "exists" in calls_in("_public_window_states")


# ── Mecze spoza terminarza okregu (powierzona II liga, turnieje) ─────────────


def test_puste_pola_obsady_z_api_nie_kasuja_prywatnej_listy():
    """Publiczne API bywa ubozsze od prywatnej listy sedziego.

    Przy czesci rozgrywek oddaje puste pola obsady, ktore lista zna - a po
    nadpisaniu pustka mecz przestawal byc "moj" (`slots_held_by` nie mial po
    czym szukac) i znikal z gieldy meczow.
    """
    base = {
        "Id": "7",
        "data_fakt": "2026-10-05 18:00",
        "NrSedzia_pierwszy_nazwisko": "KOWALSKI Jan",
        "NrSedzia_drugi_nazwisko": "STARY Piotr",
    }
    payload = {
        "0": [
            {
                "Id": "7",
                "NrSedzia_pierwszy_nazwisko": "",
                "NrSedzia_drugi_nazwisko": "NOWY Marek",
                "Hala_miasto": "",
            }
        ]
    }
    state = _api_to_state(payload, base)
    assert state["NrSedzia_pierwszy_nazwisko"] == "KOWALSKI Jan"
    assert state["NrSedzia_drugi_nazwisko"] == "NOWY Marek"
    # Pola spoza obsady nadpisuja sie jak dotad - wzbogacamy tylko obsade.
    assert state["Hala_miasto"] == ""


def test_pelny_przebieg_nie_gasi_meczow_swiezo_widzianych_gdzie_indziej():
    """Terminarz wojewodztwa nie jest jedynym zrodlem prawdy.

    Mecz powierzonej grupy II ligi zyje na prywatnych listach sedziow, a w
    terminarzu okregu nie wystepuje - pelny przebieg gasil go po dwoch
    obiegach z falszywym "Usunieto Twoj mecz" i mecz znikal z gieldy.
    """
    src = ast.unparse(FUNCTIONS["_mark_missing_full_matches"])
    assert "last_seen_at" in src
    assert "_FULL_MISS_GRACE_HOURS" in src


# ── Kolumny JSON jako napis (asyncpg bez kodeka jsonb) ───────────────────────


def test_preferencje_w_napisie_umieja_odmowic():
    """Napis '{"enabled": false}' przechodzil jako "nie-slownik", czyli zgoda."""
    assert _monitor._prefs_allow('{"enabled": false}', "match_added") is False
    assert _monitor._prefs_allow('{"enabled": true}', "match_added") is True
    assert _monitor._prefs_allow("nie-json", "match_added") is True


def test_stan_z_bazy_przechodzi_przez_parser_kolumny_json():
    """`dict("...")` na napisie rzuca ValueError - monitor umieral na PIERWSZYM
    istniejacym wierszu i nowe mecze (powierzona II liga) nie dochodzily do
    zapisu. Kazdy odczyt stanu idzie przez `state_dict`."""
    import ast as _ast
    for name in ("_upsert_match", "_run_light", "_run_full", "_public_window_states"):
        src_fn = _ast.unparse(FUNCTIONS[name])
        assert "state_dict" in src_fn, name
        assert 'dict(old_row["state_json"]' not in src_fn.replace("state_dict", "X"), name


def test_szczegoly_przyjmuja_oba_ksztalty_odpowiedzi():
    """Swiezy mecz bez danych protokolu wraca GOLA LISTA `[[{...}]]` zamiast
    `{"0": [...]}` - odrzucanie jej odcinalo takim meczom numery sedziow."""
    import ast as _ast
    src_fn = _ast.unparse(FUNCTIONS["_fetch_public_details"])
    assert "isinstance(payload, list)" in src_fn
    assert "payload[0]" in src_fn
