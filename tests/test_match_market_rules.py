"""Reguły giełdy meczów - czysta logika, bez bazy.

Te funkcje decydują o cudzej obsadzie na mecz, który naprawdę się odbędzie.
Najważniejszy test w tym pliku to `test_failed_apply_returns_to_open`: nieudany
zapis w ZPRP musi oddać ofertę z powrotem na giełdę, bo inaczej sędzia z
wygasłą sesją obsadowego zostaje z meczem, którego nikt już nie widzi.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.match_market_rules import (
    ASSIGNABILITY_TTL_HOURS,
    CREW_STATE_FIELDS,
    apply_known_swaps,
    crew_judge_ids,
    with_slot_holder,
    PROBE_BATCH_LIMIT,
    assignability_is_fresh,
    assignability_message,
    market_pushes_allowed,
    DEFAULT_DEADLINE_HOURS,
    LIVE_OFFER_STATUSES,
    TRADEABLE_SLOTS,
    can_offer,
    deadline_for,
    may_claim,
    next_claim_status,
    next_offer_status,
    normalize_deadline_hours,
    offer_is_live,
    slot_is_tradeable,
    slot_label,
    slot_select_name,
)

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def at(hours: float) -> datetime:
    return NOW + timedelta(hours=hours)


# ── gniazda ─────────────────────────────────────────────────────────────────

def test_only_field_and_table_slots_are_tradeable():
    assert slot_is_tradeable("sedzia1")
    assert slot_is_tradeable("sekretarz")
    assert slot_is_tradeable("czas")
    # Delegat jest poza giełdą świadomie - jego zmiana należy do okręgu.
    assert not slot_is_tradeable("delegat")
    assert not slot_is_tradeable("delegat2")


def test_unknown_slot_never_slips_through():
    assert not slot_is_tradeable("")
    assert not slot_is_tradeable(None)
    assert not slot_is_tradeable("NrSedzia_pierwszy")


def test_slot_maps_to_zprp_field_name():
    assert slot_select_name("sedzia2") == "NrSedzia_drugi"
    assert slot_select_name("czas") == "NrSedzia_czas"
    # Gniazdo spoza giełdy nie ma prawa oddać nazwy pola - inaczej pomyłka
    # wyżej zamieniłaby się w zapis do cudzej rubryki.
    assert slot_select_name("delegat") == ""


def test_every_tradeable_slot_has_a_label():
    # Każde gniazdo z giełdy musi mieć podpis dla człowieka. „sekretarz"
    # nazywa się tak samo po obu stronach i to jest w porządku - liczy się to,
    # żeby wpis w słowniku istniał, bo powiadomienia biorą go bez sprawdzania.
    from app.match_market_rules import SLOT_LABELS

    assert set(SLOT_LABELS) == set(TRADEABLE_SLOTS)
    assert slot_label("sedzia1") == "sędzia 1"
    assert slot_label("czas") == "mierzący czas"
    # Nieznane gniazdo oddajemy bez zmiany, zamiast podstawiać cokolwiek.
    assert slot_label("delegat") == "delegat"


# ── próg czasowy ────────────────────────────────────────────────────────────

def test_offer_allowed_well_before_the_match():
    assert can_offer(at(72), NOW, 48)


def test_offer_blocked_inside_the_threshold():
    assert not can_offer(at(24), NOW, 48)


def test_threshold_boundary_is_closed():
    # Dokładnie 48 h przed meczem próg już obowiązuje: `now < limit` jest
    # fałszem. Granica należy do obsadowego, nie do oddającego.
    assert not can_offer(at(48), NOW, 48)


def test_zero_hours_means_no_threshold():
    assert can_offer(at(1), NOW, 0)


def test_past_match_is_never_offerable():
    assert not can_offer(at(-1), NOW, 0)
    assert not can_offer(NOW, NOW, 0)


def test_match_without_date_passes():
    # Brak terminu w bazie związku to luka w danych, a nie powód, żeby odciąć
    # sędziego od jedynej drogi oddania meczu.
    assert can_offer(None, NOW, 48)


def test_deadline_is_computed_from_match_time():
    assert deadline_for(at(72), 48) == at(24)
    assert deadline_for(at(72), 0) is None
    assert deadline_for(None, 48) is None


def test_deadline_hours_are_clamped():
    assert normalize_deadline_hours(-5) == 0
    assert normalize_deadline_hours(9999) == 336
    assert normalize_deadline_hours("nie liczba") == DEFAULT_DEADLINE_HOURS
    assert normalize_deadline_hours(None) == DEFAULT_DEADLINE_HOURS
    assert normalize_deadline_hours(12) == 12


# ── przejścia oferty ────────────────────────────────────────────────────────

def test_offer_happy_path():
    assert next_offer_status("open", "approve") == "applying"
    assert next_offer_status("applying", "applied") == "done"


def test_failed_apply_returns_to_open():
    # Nieudany zapis w ZPRP to najczęściej wygasła sesja albo obsada zmieniona
    # w międzyczasie - czyli coś, co za pięć minut może się udać.
    assert next_offer_status("applying", "apply_failed") == "open"


def test_offer_cannot_be_decided_twice():
    assert next_offer_status("rejected", "approve") is None
    assert next_offer_status("done", "withdraw") is None
    assert next_offer_status("cancelled", "approve") is None


def test_offer_being_applied_is_closed_to_everyone():
    # To jest sedno stanu `applying`: drugi obsadowy nie może wejść na
    # zgłoszenie, które właśnie jedzie do ZPRP.
    assert next_offer_status("applying", "approve") is None
    assert next_offer_status("applying", "reject") is None
    assert next_offer_status("applying", "withdraw") is None


def test_live_statuses_hold_the_slot():
    assert LIVE_OFFER_STATUSES == {"open", "applying"}
    assert offer_is_live("open")
    assert offer_is_live("applying")
    assert not offer_is_live("done")
    assert not offer_is_live("expired")


def test_unknown_action_is_answered_with_none():
    assert next_offer_status("open", "cokolwiek") is None
    assert next_offer_status("", "approve") is None


# ── przejścia zgłoszenia ────────────────────────────────────────────────────

def test_claim_transitions():
    assert next_claim_status("pending", "choose") == "chosen"
    assert next_claim_status("pending", "decline") == "declined"
    assert next_claim_status("pending", "withdraw") == "withdrawn"


def test_chosen_claim_returns_to_pool_after_failed_apply():
    assert next_claim_status("chosen", "release") == "pending"
    assert next_claim_status("declined", "release") is None


# ── kto może się zgłosić ────────────────────────────────────────────────────

def test_claim_allowed_on_open_offer():
    assert may_claim("open", "1000", "2000", at(24), NOW) is None


def test_cannot_claim_own_match():
    assert may_claim("open", "1000", "1000", at(24), NOW) is not None


def test_cannot_claim_closed_offer():
    assert may_claim("applying", "1000", "2000", at(24), NOW) is not None
    assert may_claim("done", "1000", "2000", at(24), NOW) is not None


def test_cannot_claim_after_deadline():
    assert may_claim("open", "1000", "2000", at(-1), NOW) is not None


def test_offer_without_deadline_accepts_claims():
    assert may_claim("open", "1000", "2000", None, NOW) is None


def test_collision_is_not_checked_here():
    # Kolizja terminarza jest OSTRZEŻENIEM dla obsadowego, a nie zakazem -
    # sędzia bywa mądrzejszy od własnego kalendarza sprzed miesiąca. Ten test
    # pilnuje, żeby nikt nie dołożył tu twardej blokady bez decyzji.
    assert may_claim("open", "1000", "2000", at(24), NOW) is None


# ── rozpoznanie gniazda ─────────────────────────────────────────────────────

from app.match_market_rules import names_match, slot_holder_name, slots_held_by  # noqa: E402

DEEP_STATE = {
    "NrSedzia_pierwszy": "1847",
    "NrSedzia_pierwszy_nazwisko": "ŁACNY Tomasz",
    "NrSedzia_drugi": "1887",
    "NrSedzia_drugi_nazwisko": "OKOS Tomasz",
    "NrSedzia_sekretarz": "",
    "NrSedzia_sekretarz_nazwisko": "",
}

LIGHT_STATE = {
    "NrSedzia_pierwszy_nazwisko": "ŁACNY Tomasz",
    "NrSedzia_drugi_nazwisko": "OKOS Tomasz",
    "NrSedzia_czas_nazwisko": "MAZUR Adam",
}


def test_number_decides_when_it_is_there():
    assert slots_held_by(DEEP_STATE, "1847", "Tomasz Łacny") == ["sedzia1"]
    assert slots_held_by(DEEP_STATE, "1887", "kto inny") == ["sedzia2"]


def test_number_beats_the_name():
    # Dwóch sędziów o tym samym nazwisku w okręgu to nie teoria. Gdy numer jest
    # po obu stronach i się nie zgadza, nazwisko nie ma prawa nic uratować.
    assert slots_held_by(DEEP_STATE, "9999", "Tomasz Łacny") == []


def test_name_matches_when_the_number_is_missing():
    # Lekki przebieg monitora czyta listę meczów sędziego, która numerów nie ma.
    assert slots_held_by(LIGHT_STATE, "1847", "Tomasz Łacny") == ["sedzia1"]
    assert slots_held_by(LIGHT_STATE, "0", "Adam Mazur") == ["czas"]


def test_one_judge_can_hold_two_slots():
    state = {
        "NrSedzia_pierwszy": "1847",
        "NrSedzia_pierwszy_nazwisko": "ŁACNY Tomasz",
        "NrSedzia_czas": "1847",
        "NrSedzia_czas_nazwisko": "ŁACNY Tomasz",
    }
    assert slots_held_by(state, "1847", "") == ["sedzia1", "czas"]


def test_empty_slot_belongs_to_nobody():
    assert slots_held_by(LIGHT_STATE, "", "") == []
    assert slots_held_by({}, "1847", "Tomasz Łacny") == []


def test_holder_name_is_returned_as_zprp_writes_it():
    # Ta sama postać, którą niesie opcja w formularzu obsady - stąd nadaje się
    # wprost na strażnika przy zapisie.
    assert slot_holder_name(DEEP_STATE, "sedzia1") == "ŁACNY Tomasz"
    assert slot_holder_name(DEEP_STATE, "sekretarz") == ""
    assert slot_holder_name(DEEP_STATE, "delegat") == ""


def test_name_matching_survives_order_and_diacritics():
    assert names_match("NOWAK Jan", "Jan Nowak")
    assert names_match("ŁACNY Tomasz", "tomasz lacny")
    assert names_match("KOWALCZYK Bartłomiej O", "Bartłomiej Kowalczyk")


def test_single_part_is_not_a_match():
    # Samo „Nowak" pasowałoby do każdego Nowaka w okręgu.
    assert not names_match("NOWAK", "Jan Nowak")
    assert not names_match("", "Jan Nowak")


# ── Uprawnienia okręgu ──────────────────────────────────────────────────────
#
# Werdykt sondy jest pamiętany, bo każde sprawdzenie to wejście na serwer
# związku. Te testy pilnują, żeby pamięć nie stała się źródłem prawdy.

NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


def test_verdict_stays_fresh_within_the_window():
    assert assignability_is_fresh(NOW - timedelta(hours=23), NOW)
    assert assignability_is_fresh(NOW - timedelta(minutes=1), NOW)


def test_verdict_goes_stale_after_the_window():
    assert not assignability_is_fresh(NOW - timedelta(hours=25), NOW)


def test_never_checked_is_not_fresh():
    # Brak werdyktu to nie jest zgoda. Wołający ma dopytać ZPRP.
    assert not assignability_is_fresh(None, NOW)


def test_verdict_from_the_future_counts_as_fresh():
    # Zegar bazy potrafi wyprzedzić nasz o sekundy. Odrzucanie takich werdyktów
    # kazałoby sondzie chodzić przy każdym wejściu na ekran.
    assert assignability_is_fresh(NOW + timedelta(seconds=5), NOW)


def test_zero_ttl_disables_the_cache():
    assert not assignability_is_fresh(NOW, NOW, 0)


def test_broken_ttl_falls_back_to_the_default():
    assert assignability_is_fresh(NOW - timedelta(hours=1), NOW, "godzina")


def test_every_refusal_explains_itself():
    # Zasada „zero cichych blokad": każdy powód ma zdanie dla człowieka.
    for reason in ("NO_FORM", "NO_OPTIONS", "NO_ACCOUNT", "PROBE_FAILED", "UNCHECKED"):
        assert len(assignability_message(reason)) > 20


def test_consent_needs_no_explanation():
    assert assignability_message("OK") == ""


def test_unknown_reason_still_says_something_true():
    message = assignability_message("COKOLWIEK")
    assert message
    assert "obsadza" in message


def test_probe_limit_is_reported_not_guessed():
    # Liczba używana przez serwer do przycięcia paczki musi być jedna i jawna,
    # bo ekran pokazuje, ile meczów zostało niesprawdzonych.
    assert PROBE_BATCH_LIMIT > 0
    assert ASSIGNABILITY_TTL_HOURS > 0


# ── Przełącznik powiadomień ─────────────────────────────────────────────────
#
# Rozsyłka o nowej ofercie idzie do CAŁEGO województwa i jest jedynym
# powiadomieniem giełdy, które trafia do ludzi niezwiązanych z konkretną
# wymianą. Dlatego jako jedyne ma własny wyłącznik.


def test_market_broadcast_is_on_by_default():
    # Moduł ma działać od razu po włączeniu w okręgu, a nie dopiero po tym, jak
    # każdy sędzia odszuka przełącznik w ustawieniach.
    assert market_pushes_allowed(None)
    assert market_pushes_allowed({})
    assert market_pushes_allowed({"notificationTypes": {}})


def test_global_switch_wins():
    assert not market_pushes_allowed({"enabled": False})


def test_market_switch_can_be_turned_off():
    assert not market_pushes_allowed({"notificationTypes": {"matchMarket": False}})


def test_other_switches_do_not_silence_the_market():
    # Sędzia, który wyłączył powiadomienia o zmianach składu, nadal chce
    # wiedzieć, że ktoś oddaje mecz.
    assert market_pushes_allowed(
        {"notificationTypes": {"changeLineup": False, "newMatchAdded": False}}
    )


def test_broken_prefs_do_not_silence_anyone():
    # Zepsuty kształt preferencji to nie jest zgoda na ciszę.
    assert market_pushes_allowed("cokolwiek")
    assert market_pushes_allowed({"notificationTypes": "cokolwiek"})


# ── Kolumna JSON jako napis ──────────────────────────────────────────────────
from app.match_market_rules import state_dict  # noqa: E402


def test_state_dict_przyjmuje_kazdy_ksztalt_kolumny():
    """Slownik przechodzi, napis sie parsuje, smieci znacza brak stanu.

    Pierwsza awaria gieldy na produkcji to `'str' object has no attribute
    'get'`: asyncpg pod `databases` oddal JSONB surowym napisem i cala lista
    "moich meczow" polegla o format kolumny.
    """
    assert state_dict({"a": 1}) == {"a": 1}
    assert state_dict('{"NrSedzia_pierwszy": "123"}') == {"NrSedzia_pierwszy": "123"}
    assert state_dict(b'{"x": 1}') == {"x": 1}
    assert state_dict("") == {}
    assert state_dict("   ") == {}
    assert state_dict(None) == {}
    assert state_dict("[1, 2]") == {}
    assert state_dict("nie-json") == {}
    assert state_dict(123) == {}


def test_slots_held_by_dziala_na_stanie_z_napisu():
    state = '{"NrSedzia_pierwszy": "1847", "NrSedzia_pierwszy_nazwisko": "KOWALSKI Jan"}'
    assert slots_held_by(state_dict(state), "1847") == ["sedzia1"]


def test_preferencje_w_napisie_nadal_umieja_odmowic():
    # Bez parsowania napis '{"enabled": false}' przechodzil jako "nie-slownik",
    # czyli ZGODA - i powiadomienie szlo do kogos, kto je wylaczyl.
    assert market_pushes_allowed('{"enabled": false}') is False
    assert market_pushes_allowed('{"enabled": true}') is True
    assert market_pushes_allowed("cokolwiek")


# ─────────────────── migawka meczu po zapisanej wymianie ───────────────────
#
# Zgloszone z terenu 2026-09-05: sedzia zrobil wymiane "w tę i z powrotem" i
# meczu, ktory wlasnie odzyskal, nie widzial na liscie "Oddaj mecz". Migawke
# terminarza wypelnia monitor, wiec do jego przebiegu w gniezdzie siedzial
# poprzednik - a wiersz nie powstawal wcale, wiec nie mial nawet czego
# wytlumaczyc.


def test_migawka_dostaje_nowego_gospodarza_gniazda():
    state = {
        "NrSedzia_pierwszy": "111",
        "NrSedzia_pierwszy_nazwisko": "WITKOWICZ Krzysztof",
        "NrSedzia_drugi": "222",
        "NrSedzia_drugi_nazwisko": "NOWAK Jan",
    }
    patched = with_slot_holder(state, "sedzia1", "333", "WITKOWICZ Radoslaw")
    assert patched["NrSedzia_pierwszy"] == "333"
    assert patched["NrSedzia_pierwszy_nazwisko"] == "WITKOWICZ Radoslaw"
    # Gniazdo obok zostaje nietkniete - wymiana dotyczy JEDNEJ roli.
    assert patched["NrSedzia_drugi"] == "222"
    # Kopia, nie zmiana w miejscu: wolajacy porownuje stary stan z nowym.
    assert state["NrSedzia_pierwszy"] == "111"


def test_poprawiona_migawka_oddaje_mecz_wlascicielowi():
    """To jest cala poprawka, w jednym zdaniu."""
    state = {"NrSedzia_pierwszy": "111", "NrSedzia_pierwszy_nazwisko": "WITKOWICZ Krzysztof"}
    assert slots_held_by(state, "333", "WITKOWICZ Radoslaw") == []
    patched = with_slot_holder(state, "sedzia1", "333", "WITKOWICZ Radoslaw")
    assert slots_held_by(patched, "333", "WITKOWICZ Radoslaw") == ["sedzia1"]


def test_gniazdo_spoza_mapy_nie_psuje_migawki():
    state = {"NrSedzia_pierwszy": "111"}
    assert with_slot_holder(state, "kibic", "333", "X") == state


def test_obsada_do_powiadomienia_bez_stron_wymiany():
    state = {
        "NrSedzia_pierwszy": "111",
        "NrSedzia_drugi": "222",
        "NrSedzia_sekretarz": "0",
        "NrSedzia_czas": "",
        "NrSedzia_delegat": "444",
    }
    # "0" przy pustym nazwisku to ZPRP-owe "nikogo tu nie ma", nie numer.
    assert crew_judge_ids(state) == ["111", "222", "444"]
    assert crew_judge_ids(state, exclude=["111", "444"]) == ["222"]
    assert crew_judge_ids({}) == []


def test_ten_sam_sedzia_w_dwoch_gniazdach_dostaje_jedno_powiadomienie():
    state = {"NrSedzia_sekretarz": "222", "NrSedzia_czas": "222"}
    assert crew_judge_ids(state) == ["222"]


def test_delegaci_sa_w_obsadzie_choc_nie_w_gieldzie():
    """Delegat niczym nie handluje, ale ocenia to, co zobaczy w sobote."""
    assert set(TRADEABLE_SLOTS) < set(CREW_STATE_FIELDS)
    assert "delegat" in CREW_STATE_FIELDS
    assert "delegat2" in CREW_STATE_FIELDS


# ─────────────── pamiec wlasnych wymian nalozona na migawke ───────────────
#
# Zgloszone dwa razy tego samego wieczora (2026-09-05): po wymianie sedzia,
# ktory mecz PRZEJAL, nie widzial go na liscie "Oddaj mecz". `with_slot_holder`
# poprawia migawke w chwili zapisu, ale to nie pomaga wymianie zapisanej
# wczesniej. Dlatego lista naklada jeszcze wlasna pamiec gieldy.

SWAP = {
    "slot": "sedzia1",
    "from_judge_id": "111",
    "from_name": "WITKOWICZ Radoslaw",
    "to_judge_id": "222",
    "to_name": "WITKOWICZ Krzysztof",
}


def test_wlasna_wymiana_oddaje_mecz_temu_kto_go_przejal():
    state = {"NrSedzia_pierwszy": "111", "NrSedzia_pierwszy_nazwisko": "WITKOWICZ Radoslaw"}
    assert slots_held_by(state, "222", "WITKOWICZ Krzysztof") == []
    fixed = apply_known_swaps(state, [SWAP])
    assert slots_held_by(fixed, "222", "WITKOWICZ Krzysztof") == ["sedzia1"]
    # I przestaje byc meczem oddajacego - on go wlasnie oddal.
    assert slots_held_by(fixed, "111", "WITKOWICZ Radoslaw") == []


def test_migawka_bez_numeru_dopasowuje_sie_nazwiskiem():
    """Lekki przebieg monitora czyta liste meczow, ktora podaje same nazwiska."""
    state = {"NrSedzia_pierwszy_nazwisko": "Radoslaw WITKOWICZ"}
    fixed = apply_known_swaps(state, [SWAP])
    assert fixed["NrSedzia_pierwszy"] == "222"
    assert fixed["NrSedzia_pierwszy_nazwisko"] == "WITKOWICZ Krzysztof"


def test_kto_trzeci_w_gniezdzie_wygrywa_z_nasza_pamiecia():
    """Obsadowy zmienil obsade recznie w ZPRP - nasza pamiec jest starsza."""
    state = {"NrSedzia_pierwszy": "999", "NrSedzia_pierwszy_nazwisko": "NOWAK Jan"}
    assert apply_known_swaps(state, [SWAP]) == state


def test_puste_gniazdo_nie_przyjmuje_wymiany():
    # ZPRP wpisuje "0" przy zdjetym sedziu - to nie jest oddajacy.
    assert apply_known_swaps({"NrSedzia_pierwszy": "0"}, [SWAP]) == {"NrSedzia_pierwszy": "0"}


def test_lancuch_wymian_tego_samego_gniazda_sklada_sie_po_kolei():
    """Wymiana "w te i z powrotem" - oba zgloszenia z tego wieczora."""
    back = {
        "slot": "sedzia1",
        "from_judge_id": "222",
        "from_name": "WITKOWICZ Krzysztof",
        "to_judge_id": "111",
        "to_name": "WITKOWICZ Radoslaw",
    }
    state = {"NrSedzia_pierwszy": "111", "NrSedzia_pierwszy_nazwisko": "WITKOWICZ Radoslaw"}
    fixed = apply_known_swaps(state, [SWAP, back])
    assert fixed["NrSedzia_pierwszy"] == "111"
    assert slots_held_by(fixed, "111", "WITKOWICZ Radoslaw") == ["sedzia1"]


def test_wymiana_innego_gniazda_nie_rusza_mojego():
    state = {
        "NrSedzia_pierwszy": "111",
        "NrSedzia_drugi": "333",
        "NrSedzia_drugi_nazwisko": "KOWALSKI Piotr",
    }
    fixed = apply_known_swaps(state, [{**SWAP, "slot": "sedzia2", "from_judge_id": "333"}])
    assert fixed["NrSedzia_pierwszy"] == "111"
    assert fixed["NrSedzia_drugi"] == "222"


def test_brak_wymian_zostawia_migawke_w_spokoju():
    state = {"NrSedzia_pierwszy": "111"}
    assert apply_known_swaps(state, []) == state
    assert apply_known_swaps(state, [{"slot": "kibic"}]) == state
    # Kopia, nie zmiana w miejscu.
    assert apply_known_swaps(state, [SWAP]) is not state
