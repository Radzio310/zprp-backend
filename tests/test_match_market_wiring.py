"""Wiązania modułu giełdy meczów - czytane z drzewa składni, nie z importu.

`app.match_market` ciągnie `app.db`, a ten żąda żywego Postgresa, więc ten plik
NIE importuje modułu. Czyta jego źródło, tak samo jak `test_proel_actor_attrs`.
Dzięki temu chodzi na maszynie deweloperskiej i w CI, a łapie dokładnie te
pomyłki, które inaczej wykonałyby się pierwszy raz na produkcji:

* zapis do ZPRP puszczony inną drogą niż wspólny rdzeń z modułem obsadowego,
* trasa zmieniająca stan bez sprawdzenia uprawnień,
* wysyłka powiadomień z pominięciem osłony, która nigdy nie rzuca.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
SOURCE = (APP_DIR / "match_market.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)

FUNCTIONS = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}


def calls_in(name: str) -> set[str]:
    """Nazwy wołanych funkcji wewnątrz danej funkcji modułu."""
    node = FUNCTIONS[name]
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                out.add(func.id)
            elif isinstance(func, ast.Attribute):
                out.add(func.attr)
    return out


def code_of(name: str) -> str:
    """Źródło funkcji BEZ jej docstringa.

    Komentarz bywa dokładnie o tym, czego w kodzie już nie ma („czytamy
    terminarz, a NIE `province_match_judges`"), więc test szukający nazwy
    tabeli potykał się o wyjaśnienie, dlaczego jej tam nie ma.
    """
    node = FUNCTIONS[name]
    body = [
        sub
        for sub in node.body
        if not (
            isinstance(sub, ast.Expr)
            and isinstance(sub.value, ast.Constant)
            and isinstance(sub.value.value, str)
        )
    ]
    return chr(10).join(ast.unparse(sub) for sub in body)


def routes() -> list[tuple[str, str, str]]:
    """(metoda, ścieżka, nazwa funkcji) dla każdej trasy modułu."""
    found = []
    for node in TREE.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "router" and dec.args:
                    path = dec.args[0]
                    if isinstance(path, ast.Constant):
                        found.append((func.attr, path.value, node.name))
    return found


def test_all_routes_are_registered():
    paths = {(m, p) for m, p, _ in routes()}
    assert ("get", "/context") in paths
    assert ("get", "/my-matches") in paths
    assert ("post", "/offers") in paths
    assert ("delete", "/offers/{offer_id}") in paths
    assert ("post", "/offers/{offer_id}/claims") in paths
    assert ("delete", "/offers/{offer_id}/claims/me") in paths
    assert ("post", "/offers/{offer_id}/approve") in paths
    assert ("post", "/offers/{offer_id}/reject") in paths
    assert ("get", "/admin/provinces") in paths
    assert ("put", "/admin/provinces/{province}") in paths


def test_every_route_asks_who_is_calling():
    # Trasa bez `market_actor` byłaby otwarta dla świata - a ten moduł zmienia
    # obsadę meczów, które naprawdę się odbędą.
    for _, path, name in routes():
        node = FUNCTIONS[name]
        args = [a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs]
        assert "actor" in args, f"{path} nie pyta, kto woła"


def test_only_the_shared_core_writes_to_zprp():
    # Zapis obsady ma JEDNĄ drogę: `apply_referee_assignment`. Druga ścieżka
    # znaczyłaby drugie miejsce, w którym można zapomnieć o `akcja_edycja`.
    writers = [name for name in FUNCTIONS if "apply_referee_assignment" in calls_in(name)]
    assert writers == ["approve_offer"], writers


def test_approval_locks_the_row_and_checks_the_badge():
    calls = calls_in("approve_offer")
    assert "_require_approver" in calls
    # `with_for_update` to jedyna rzecz, która nie pozwala dwóm obsadowym wejść
    # na to samo zgłoszenie w tej samej sekundzie.
    assert "with_for_update" in calls
    assert "transaction" in calls


def test_rejection_is_guarded_too():
    calls = calls_in("reject_offer")
    assert "_require_approver" in calls
    assert "with_for_update" in calls


def test_state_changes_go_through_the_transition_table():
    # Ręczne wpisanie statusu ominęłoby tabelę przejść, czyli jedyne miejsce,
    # w którym te reguły są opisane i przetestowane.
    for name in ("withdraw_offer", "reject_offer", "approve_offer"):
        assert "next_offer_status" in calls_in(name), name
    for name in ("withdraw_claim",):
        assert "next_claim_status" in calls_in(name), name


def test_notifications_never_escape_the_shield():
    # `_notify` łapie wyjątki - `send_push_to_judges` wołane wprost mogłoby
    # wywrócić operację, przy której powstało.
    senders = [
        name
        for name in FUNCTIONS
        if name != "_notify" and "send_push_to_judges" in calls_in(name)
    ]
    assert senders == [], senders


def test_config_endpoints_are_admin_only():
    for name in ("admin_provinces", "admin_set_province"):
        assert "may_manage_config" in calls_in(name), name


def test_offer_creation_verifies_ownership_and_threshold():
    calls = calls_in("create_offer")
    assert "slots_held_by" in calls, "kto inny mógłby oddać cudze gniazdo"
    assert "slot_is_tradeable" in calls, "delegat nie należy do giełdy"
    assert "can_offer" in calls, "próg czasowy okręgu"


def test_apply_uses_the_slot_guard():
    # `expect=` w wywołaniu rdzenia to strażnik przed nadpisaniem cudzej
    # decyzji, gdy obsada zmieniła się poza aplikacją.
    node = FUNCTIONS["approve_offer"]
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
            if sub.func.id == "apply_referee_assignment":
                assert "expect" in {kw.arg for kw in sub.keywords}
                return
    pytest.fail("nie znalazłem wywołania rdzenia zapisu")


def test_router_is_registered_in_main():
    main = (APP_DIR.parent / "main.py").read_text(encoding="utf-8")
    assert "from app.match_market import router as match_market_router" in main
    assert "app.include_router(match_market_router)" in main


def test_offer_creation_asks_whether_the_district_assigns_this_match():
    """Najważniejsza bramka w module.

    Sędzia widzi w aplikacji wszystkie swoje mecze, a okręg obsadza tylko część
    z nich. Bez tego wywołania dałoby się wystawić mecz ligi centralnej, którego
    konto wojewódzkie nie ma prawa tknąć - i wyszłoby to dopiero przy
    zatwierdzaniu, gdy oddający dawno przestał szukać zastępstwa.
    """
    assert "_require_assignable" in calls_in("create_offer")


def test_the_gate_is_the_last_check_not_the_first():
    # Sonda to wejście na serwer związku. Tanie sprawdzenia - gniazdo, próg,
    # duplikat - muszą odpaść wcześniej, żeby nie płacić za nie ruchem po sieci.
    body = ast.unparse(FUNCTIONS["create_offer"])
    gate = body.index("_require_assignable")
    for cheap in ("slot_is_tradeable", "slots_held_by", "can_offer"):
        assert body.index(cheap) < gate, f"{cheap} stoi po sondzie"


def test_probe_answers_are_cached_but_failures_are_not():
    # Zapisany błąd sieci wyglądałby w pamięci tak samo jak odmowa okręgu i
    # blokowałby mecz na całą dobę.
    source = ast.unparse(FUNCTIONS["_store_verdict"])
    assert "PROBE_FAILED" in source
    assert "return" in source


def test_probe_reads_rights_and_never_writes():
    # Sonda ma jedno zadanie: zapytać. Zapis idzie wyłącznie przez rdzeń.
    assert "apply_referee_assignment" not in calls_in("_probe")
    assert "probe_assignment_rights" in calls_in("_probe")


def test_my_matches_reports_what_it_did_not_check():
    # Zasada „bez cichych limitów": paczka sondy jest przycięta, więc liczba
    # niesprawdzonych meczów musi wyjść na zewnątrz.
    source = ast.unparse(FUNCTIONS["my_matches"])
    assert "PROBE_BATCH_LIMIT" in source
    assert "unchecked" in source


def test_the_gate_cannot_be_skipped_by_a_missing_account():
    # Okręg bez konta obsadowego nie zapisze niczego w ZPRP. Odmowa ma paść
    # przy wystawianiu, a nie po umowie dwóch sędziów.
    source = ast.unparse(FUNCTIONS["_require_assignable"])
    assert "assign_credentials" in source
    assert "NO_ACCOUNT" in source


def test_verdict_is_written_with_a_single_upsert():
    """Dwie sondy potrafią trafić na ten sam mecz w tej samej sekundzie.

    Zapis w dwóch krokach (update, a jak nie poszło to insert) przewracał się
    wtedy o unikat klucza głównego - a `databases` i tak nie oddaje pewnej
    liczby zmienionych wierszy, więc krok pierwszy nie miał jak rozstrzygnąć,
    czy trafił. Stąd jedna instrukcja, jak w monitorze meczów i w `admin.py`.
    """
    calls = calls_in("_store_verdict")
    assert "pg_insert" in calls
    assert "on_conflict_do_update" in calls
    assert "update" not in calls


def test_my_matches_reads_the_district_schedule_not_the_push_list():
    """Sędzia bez zgody na powiadomienia też musi móc oddać mecz.

    `province_match_judges` powstaje z list meczów pobieranych wyłącznie dla
    sędziów z zarejestrowanym tokenem push, a token powstaje dopiero po zgodzie
    na powiadomienia. Oparcie o tę tabelę dawało takiemu sędziemu pustą listę
    bez słowa wyjaśnienia - a on po prostu odmówił powiadomień.

    Terminarz województwa jest niezależny od tego, kto ma aplikację.
    """
    source = ast.unparse(FUNCTIONS["my_matches"])
    assert "province_matches" in source
    assert "province_match_judges" not in source
    # O tym, który mecz jest mój, rozstrzyga ta sama reguła, co przy wystawianiu.
    assert "slots_held_by" in calls_in("my_matches")


def test_the_schedule_scan_is_bounded_and_says_so():
    # Skan terminarza ma bezpiecznik, więc granice muszą być nazwane, a nie
    # wpisane liczbą w środku zapytania.
    source = ast.unparse(FUNCTIONS["my_matches"])
    assert "MY_MATCHES_SCAN_LIMIT" in source
    assert "MY_MATCHES_HORIZON_DAYS" in source


def test_a_failed_probe_is_not_a_refusal():
    """„Nie udało się sprawdzić" to nie „okręg tego nie obsadza".

    `_store_verdict` z tego samego powodu nie zapisuje PROBE_FAILED do pamięci:
    zerwana odpowiedź zablokowałaby mecz na całą dobę. W jednej odpowiedzi skutek
    był ten sam - po jednym potknięciu serwera związku CAŁA lista meczów do
    oddania lądowała w sekcji „poza giełdą" i sędzia nie miał czego wybrać.
    O wystawieniu decyduje i tak twarda bramka przy `POST /offers`.
    """
    source = ast.unparse(FUNCTIONS["_probe_view"])
    assert "PROBE_FAILED" in source
    assert "'assignable': None" in source


def test_my_matches_separates_waiting_from_broken():
    # „Czeka w kolejce" i „pytaliśmy, nie doszło" to dwie różne wiadomości.
    source = ast.unparse(FUNCTIONS["my_matches"])
    assert "probeFailed" in source
    # Gniazdo, które już wisi na giełdzie, nie może udawać „do oddania" -
    # wcześniej wiersz stał na liście, a w środku czekał wygaszony przycisk.
    assert "free_slots" in source


def test_offer_creation_asks_about_the_slot_and_survives_the_race():
    """Sonda pyta o TO gniazdo, a wyścig kończy się odmową, nie pięćsetką."""
    source = ast.unparse(FUNCTIONS["create_offer"])
    assert "slot=slot" in source
    # Ta sama, ludzka odmowa przy sprawdzeniu i przy naruszeniu unikatu.
    assert source.count("To gniazdo już wisi na giełdzie.") >= 2


def test_withdrawal_locks_the_row_like_the_decisions_do():
    """Wycofanie nie może wejść w środek zapisu do ZPRP.

    Bez rygla odczytywało `open`, nadpisywało `applying` stanem `cancelled`, a
    zatwierdzanie po powrocie z bazy związku i tak stawiało `done`: obsada
    zmieniona, a oddający przekonany, że mecz wrócił do niego.
    """
    source = ast.unparse(FUNCTIONS["withdraw_offer"])
    assert "with_for_update" in source
    assert "match_market_offers.c.status ==" in source


def test_zprp_write_never_goes_without_a_name_in_the_slot():
    """`expect` to jedyna osłona przed nadpisaniem świeższej decyzji."""
    source = ast.unparse(FUNCTIONS["approve_offer"])
    assert "SLOT_UNKNOWN" in source
    assert "expect=(select_name, holder)" in source
    # Porzucony zapis da się powtórzyć - inaczej oferta wisi w `applying` na
    # zawsze i nikt jej nie odzyska.
    assert "_apply_is_stale" in source


def test_conflicts_come_from_the_schedule_not_the_push_list():
    """Kolizje liczymy tak samo, jak „moje mecze" - ze stanu meczu.

    Sędzia, który odmówił powiadomień, nie ma wierszy w `province_match_judges`,
    więc wychodził ZAWSZE „bez kolizji" - a obsadowy czytał to jako zgodę i
    wsadzał go na drugi mecz tego samego dnia.
    """
    source = code_of("_same_day_matches")
    assert "province_match_judges" not in source
    assert "_holds_any_role" in source


def test_every_state_read_goes_through_the_parser():
    """`state_json` i `match_snapshot` bywaja napisem - gole `.get` sie o nie
    wywraca, wiec kazda granica odczytu przechodzi przez `state_dict`."""
    for name in ("my_matches", "_same_day_matches", "create_offer", "_match_view"):
        assert "state_dict" in ast.unparse(FUNCTIONS[name]), name
    assert "state_dict(offer.get('match_snapshot'))" in ast.unparse(
        FUNCTIONS["_offer_payload"]
    )


def test_dateless_matches_survive_the_scan_limit():
    """Mecz "termin do ustalenia" nie moze wypadac przez bezpiecznik LIMIT.

    W jednym zapytaniu mecze bez daty sortowaly sie na koniec (`nulls_last`),
    wiec LIMIT ucinal wlasnie je - wbrew wlasnemu opisowi o "meczach
    najdalszych". Osobne zapytanie zdejmuje je spod tego bezpiecznika.
    """
    source = ast.unparse(FUNCTIONS["my_matches"])
    assert "undated_rows" in source
    assert "nulls_last" not in source


# ─────────────────────────── dziennik giełdy ───────────────────────────


def test_every_state_changing_route_writes_to_the_journal():
    """Rejestr jest PELNY albo go nie ma.

    Trasa, ktora zmienia stan i nie dopisuje wpisu, robi w historii dziure -
    a dziennik czyta sie wlasnie po to, zeby wiedziec, czego w stanach nie
    widac (wycofane zgloszenia, nieudane zapisy, kto co odrzucil).
    """
    for name in (
        "create_offer",
        "withdraw_offer",
        "create_claim",
        "withdraw_claim",
        "reject_offer",
        "approve_offer",
        "admin_set_province",
    ):
        assert "_log" in calls_in(name), f"{name} nie pisze do dziennika"


def test_the_journal_never_breaks_the_action_it_describes():
    """Dziennik jest swiadkiem, nie strona.

    Gdyby zapis wpisu potrafil rzucic, zatwierdzenie wymiany wracaloby bledem
    PO zmianie obsady w bazie zwiazku - obsadowy probowalby drugi raz, a mecz
    byl juz przepisany. Stad `try/except` wokol calego zapisu.
    """
    node = FUNCTIONS["_log"]
    assert any(isinstance(sub, ast.Try) for sub in ast.walk(node)), "_log bez oslony"
    source = code_of("_log")
    assert "logger.exception" in source


def test_decision_and_its_zprp_outcome_are_separate_entries():
    """Decyzja obsadowego i skutek zapisu to DWA zdarzenia.

    Przy nieudanym zapisie tylko tak widac, ze obsadowy zrobil swoje, a nie
    przeszlo cos dalej - jeden wspolny wpis kazalby zgadywac.
    """
    source = ast.unparse(FUNCTIONS["approve_offer"])
    assert "'decision_approved'" in source
    assert "'zprp_applied'" in source
    assert "'zprp_failed'" in source


def test_journal_is_read_only_by_the_app_admin():
    paths = {(m, p) for m, p, _ in routes()}
    assert ("get", "/admin/provinces/{province}/journal") in paths
    calls = calls_in("admin_journal")
    assert "may_manage_config" in calls
    # Okreg podaje sie sluggiem - bez normalizacji "ŚLĄSKIE" nie trafiloby w nic.
    assert "normalize_province" in calls


def test_journal_pages_by_cursor_not_by_offset():
    """Strona liczona offsetem gubi wpis, gdy w tym czasie dojdzie nowy."""
    source = code_of("admin_journal")
    assert "before_id" in source
    assert ".offset(" not in source


# ─────────────────────────── treści powiadomień ───────────────────────────


def test_notification_texts_come_from_the_tested_leaf():
    """Zdania powiadomień NIE skladaja sie w trasach.

    Sklejanie technicznej etykiety z czasownikiem dalo „IIM4/1 · sedzia 1
    przejmuje Krzysztof WITKOWICZ" - numer meczu na miejscu podmiotu. Tresci
    mieszkaja w `app.match_market_notify`, bo tam daja sie sprawdzic testem.
    """
    for name in (
        "create_offer",
        "withdraw_offer",
        "create_claim",
        "reject_offer",
        "approve_offer",
    ):
        calls = calls_in(name)
        assert any(c.startswith("text_") for c in calls), f"{name} sklada tresc sam"


def test_the_label_that_caused_it_is_gone():
    # `_offer_line` produkowal „IIM4/1 · sedzia 1" i wchodzil wprost w zdania.
    assert "_offer_line" not in SOURCE
    assert " · " not in SOURCE


def test_notify_takes_a_ready_pair_not_loose_strings():
    """Jeden argument tresci znaczy, ze nie da sie wyslac zdania z palca."""
    node = FUNCTIONS["_notify"]
    args = [a.arg for a in node.args.args]
    assert args == ["judge_ids", "text", "offer"], args


# ─────────────────── migawka terminarza po wymianie ───────────────────


def test_applied_swap_refreshes_the_province_snapshot():
    """Zgloszone z terenu: wymiana "w tę i z powrotem" i mecz nie wraca.

    `province_matches.state_json` wypelnia monitor, wiec do jego przebiegu
    gielda czytala w gniezdzie poprzednika i `slots_held_by` nie oddawalo
    wlascicielowi jego wlasnego meczu. Odswiezenie migawki nalezy do czynnosci,
    ktora ja uniewaznila - inaczej lista klamie i nawet nie ma czego wygasic.
    """
    calls = calls_in("approve_offer")
    assert "_sync_slot_holder" in calls
    source = code_of("approve_offer")
    # Po ZAPISIE, nie zamiast niego: migawka idzie za potwierdzona zmiana.
    assert source.index("apply_referee_assignment") < source.index("_sync_slot_holder")


def test_snapshot_refresh_never_breaks_a_saved_swap():
    """Obsada w ZPRP jest juz zmieniona - kopia nie ma prawa tego przewrocic."""
    node = FUNCTIONS["_sync_slot_holder"]
    assert any(isinstance(n, ast.Try) for n in ast.walk(node))
    source = ast.unparse(node)
    # Nazwiska i numeru nie sklejamy tutaj - to robi sprawdzony lisc.
    assert "with_slot_holder" in source
    # Odcisk stanu liczony od nowa, zeby monitor nie oglosil tego drugi raz.
    assert "fingerprint" in source


def test_the_rest_of_the_crew_hears_it_from_the_market():
    """Skoro migawka jest poprawiona, monitor nie zauwazy zmiany obsady."""
    calls = calls_in("approve_offer")
    assert "crew_judge_ids" in calls
    assert "text_crew_changed" in calls


def test_my_matches_never_forgets_our_own_swaps():
    """Zgloszone DWA razy: mecz przejety wymiana nie wraca na liste.

    Migawka terminarza nadazy dopiero z monitorem, wiec lista naklada na nia
    wlasna pamiec gieldy - wymiany potwierdzone w bazie zwiazku. Bez tego
    zapisana wymiana jest widoczna w ZPRP i niewidoczna w aplikacji.
    """
    calls = calls_in("my_matches")
    assert "_applied_swaps" in calls
    assert "apply_known_swaps" in calls


def test_only_confirmed_swaps_count_as_memory():
    """Zamowienie, ktore nie przeszlo, nic o obsadzie nie mowi."""
    source = code_of("_applied_swaps")
    assert "'done'" in source
    assert "applied_at" in source
    # Wybrany chetny, nie dowolne zgloszenie - inaczej mecz "przejmowaliby"
    # wszyscy, ktorzy sie na niego zglosili.
    assert "'chosen'" in source


def test_every_gate_reads_the_same_corrected_state():
    """Lista i bramka musza odpowiadac na to samo pytanie tak samo.

    Gdyby "Oddaj mecz" pokazywalo mecz poprawiony pamiecia gieldy, a
    `POST /offers` sprawdzal samą migawke, wystawienie konczyloby sie odmowa
    "to nie Twoje gniazdo" - sprzecznoscia gorsza niz brak wiersza.
    """
    for name in ("my_matches", "create_offer", "_same_day_matches"):
        assert "apply_known_swaps" in calls_in(name), name
