# Tresci powiadomien gieldy meczow.
#
# Zgloszone z terenu 2026-09-05: push o tresci "IIM4/1 · sedzia 1 przejmuje
# Krzysztof WITKOWICZ" - numer meczu na miejscu podmiotu, czlowiek na koncu
# jak dopisek. Te testy pilnuja trzech rzeczy: podmiotem jest CZLOWIEK, rola
# odmienia sie razem z przyimkiem, a brak danych skraca zdanie zamiast robic
# w nim dziure.

from datetime import datetime, timezone

import pytest

from app.match_market_notify import (
    SLOT_AS,
    SLOT_FOR,
    apply_failed,
    claim_created,
    claim_lost,
    crew_changed,
    giver_released,
    judge,
    match_of,
    offer_created,
    offer_rejected,
    offer_withdrawn,
    match_gen,
    slot_as,
    slot_for,
    taker_won,
    teams_of,
    when_of,
)
from app.match_market_rules import TRADEABLE_SLOTS

SNAPSHOT = {
    "ID_zespoly_gosp_ZespolNazwa": "MKS WiRy Siódemka Mysłowice",
    "ID_zespoly_gosc_ZespolNazwa": "Hutnik Kraków",
}


def offer(**over):
    base = {
        "id": 1,
        "province": "SLASKIE",
        "match_id": "208136",
        "match_code": "IIM4/1",
        "slot": "sedzia1",
        "match_at": datetime(2026, 9, 12, 14, 0, tzinfo=timezone.utc),
        "match_snapshot": SNAPSHOT,
    }
    base.update(over)
    return base


# ─────────────────────────── formy roli ───────────────────────────


def test_every_tradeable_slot_has_both_forms():
    """Gniazdo bez formy biernika wyszlo by jako "na sedzia 1"."""
    for slot in TRADEABLE_SLOTS:
        assert SLOT_AS.get(slot), slot
        assert SLOT_FOR.get(slot), slot


@pytest.mark.parametrize(
    "slot,as_form,for_form",
    [
        ("sedzia1", "sędzia 1", "sędziego 1"),
        ("sedzia2", "sędzia 2", "sędziego 2"),
        ("sekretarz", "sekretarz", "sekretarza"),
        ("czas", "mierzący czas", "mierzącego czas"),
    ],
)
def test_role_declines_with_the_preposition(slot, as_form, for_form):
    assert slot_as(slot) == as_form
    assert slot_for(slot) == for_form


def test_unknown_slot_does_not_vanish():
    assert slot_as("delegat") == "delegat"
    assert slot_for("delegat") == "delegat"


# ─────────────────────────── drobne formy ───────────────────────────


def test_match_reads_as_a_phrase_not_a_label():
    assert match_of(offer()) == "mecz IIM4/1"
    assert match_of(offer(match_code="")) == "mecz"


def test_genitive_form_exists_for_obsada_and_wymiana():
    # "obsada mecz IIM4/1" widac od pierwszego spojrzenia.
    assert match_gen(offer()) == "meczu IIM4/1"
    assert match_gen(offer(match_code="")) == "meczu"


def test_capitalizing_does_not_lowercase_the_match_number():
    _, body = claim_lost(offer())
    assert "IIM4/1" in body
    assert "iim4/1" not in body


def test_date_is_in_the_genitive():
    assert when_of(offer()) == "sob. 12 września, 14:00"
    # Brak terminu to odpowiedz sama w sobie - nie zmyslamy daty.
    assert when_of(offer(match_at=None)) == ""
    assert when_of(offer(match_at="nie-data")) == ""


def test_teams_need_both_sides_or_what_there_is():
    assert teams_of(SNAPSHOT) == "MKS WiRy Siódemka Mysłowice - Hutnik Kraków"
    assert teams_of({"ID_zespoly_gosp_ZespolNazwa": "MKS"}) == "MKS"
    assert teams_of({}) == ""
    assert teams_of(None) == ""


def test_missing_name_never_leaves_a_hole():
    assert judge("") == "Sędzia"
    assert judge(None) == "Sędzia"
    assert judge("NOWAK Jan") == "NOWAK Jan"


# ─────────────────────────── zdania ───────────────────────────


def test_the_reported_notification_now_starts_with_the_person():
    """To zdanie bylo zgloszone jako nienaturalne."""
    title, body = giver_released(offer(), "Krzysztof WITKOWICZ")
    assert title == "✅ Mecz oddany"
    assert body.startswith("Krzysztof WITKOWICZ przejmuje Twój mecz IIM4/1 jako sędzia 1.")
    # Numer meczu NIE stoi na poczatku - to byl caly klopot.
    assert not body.startswith("IIM4/1")
    assert "·" not in body
    assert "Sob. 12 września, 14:00" in body


def test_new_offer_says_who_looks_for_what():
    title, body = offer_created(offer(), "Radosław WITKOWICZ")
    assert title == "🔁 Mecz do wzięcia"
    assert body.startswith(
        "Radosław WITKOWICZ szuka zastępstwa na mecz IIM4/1 na sędziego 1."
    )
    assert "Hutnik Kraków" in body


def test_new_offer_for_the_table_slot_declines_correctly():
    _, body = offer_created(offer(slot="czas"), "NOWAK Jan")
    assert "na mierzącego czas" in body
    assert "na mierzący czas" not in body


def test_withdrawal_tells_the_claimant_what_it_means_for_them():
    title, body = offer_withdrawn(offer(), "Radosław WITKOWICZ")
    assert title == "↩️ Mecz wrócił do właściciela"
    assert body.startswith("Radosław WITKOWICZ zabrał mecz IIM4/1 z giełdy")
    assert "Twoje zgłoszenie jest już nieaktualne." in body


def test_claim_names_the_role_in_the_nominative():
    title, body = claim_created(offer(slot="sekretarz"), "KOWALSKI Piotr")
    assert title == "🙋 Zgłoszenie na mecz"
    assert body.startswith("KOWALSKI Piotr zgłasza się na mecz IIM4/1 jako sekretarz.")
    assert "Czeka na Twoją decyzję." in body


def test_rejection_names_who_keeps_the_match_and_why():
    _, body = offer_rejected(offer(), "Radosław WITKOWICZ", "obsada już ustalona")
    assert body.startswith(
        "Obsada meczu IIM4/1 zostaje bez zmian - prowadzi go Radosław WITKOWICZ."
    )
    assert "Powód: obsada już ustalona." in body


def test_rejection_without_a_name_or_reason_still_reads():
    _, body = offer_rejected(offer(), "", "")
    assert "zostaje bez zmian." in body
    # Zaden wiszacy przecinek ani podwojna kropka.
    assert ".." not in body
    assert "Powód" not in body


def test_failed_write_leads_with_what_failed():
    title, body = apply_failed(offer(), "Krzysztof WITKOWICZ nie występuje na liście.")
    assert title == "⚠️ Wymiana niezapisana"
    assert body.startswith("Nie udało się zapisać wymiany meczu IIM4/1 w bazie związku.")
    assert "nie występuje na liście." in body
    assert ".." not in body


def test_taker_learns_when_and_against_whom():
    title, body = taker_won(offer())
    assert title == "✅ Masz nowy mecz"
    assert body.startswith("Prowadzisz mecz IIM4/1 jako sędzia 1.")
    assert "Sob. 12 września, 14:00" in body
    assert "Hutnik Kraków" in body
    assert "Obsada jest już zapisana w bazie związku." in body


def test_losing_claimants_get_a_full_sentence():
    title, body = claim_lost(offer())
    assert title == "🔁 Mecz zajęty"
    assert body.startswith("Mecz IIM4/1 poprowadzi kto inny.")
    assert "Twoje zgłoszenie nie zostało wybrane." in body


def test_dateless_match_shortens_the_body_instead_of_breaking_it():
    _, body = giver_released(offer(match_at=None), "KOWALSKI Piotr")
    assert body.startswith("KOWALSKI Piotr przejmuje Twój mecz IIM4/1 jako sędzia 1.")
    assert "Obsada jest już zmieniona" in body
    assert ".." not in body
    assert " ." not in body


def test_no_body_ends_without_a_full_stop():
    for title, body in (
        offer_created(offer(), "A"),
        offer_withdrawn(offer(), "A"),
        claim_created(offer(), "A"),
        offer_rejected(offer(), "A", "B"),
        apply_failed(offer(), "B"),
        taker_won(offer()),
        giver_released(offer(), "A"),
        crew_changed(offer(), "A", "B"),
        claim_lost(offer()),
    ):
        assert title
        assert body.endswith("."), body
        assert ".." not in body, body


def test_each_sentence_starts_with_a_capital():
    """Termin wchodzil jako "sob. 12 wrzesnia" w srodku akapitu.

    Kazdy czlon `_join` staje samodzielnym zdaniem, wiec musi zaczynac sie
    wielka litera - a numer meczu w srodku zdania ma zostac numerem.
    """
    for _, body in (
        offer_created(offer(), "Radosław WITKOWICZ"),
        claim_created(offer(), "KOWALSKI Piotr"),
        taker_won(offer()),
        giver_released(offer(), "KOWALSKI Piotr"),
    ):
        for sentence in body.split(". "):
            first = sentence.strip()[:1]
            assert first == first.upper(), (first, body)
        assert "IIM4/1" in body


# ─────────────────────── reszta obsady ───────────────────────
#
# Wczesniej o zmianie partnera mowil monitor, gdy zauwazyl roznice w migawce
# terminarza. Odkad gielda poprawia migawke sama (zeby oddany mecz wracal na
# liste), monitor nie ma czego zauwazyc - i wiadomosc nalezy do gieldy.


def test_crew_learns_who_replaced_whom():
    title, body = crew_changed(offer(), "Krzysztof WITKOWICZ", "Radosław WITKOWICZ")
    assert title == "🔁 Zmiana w Twoim meczu"
    assert body.startswith("Nowy sędzia 1 w meczu IIM4/1: Krzysztof WITKOWICZ.")
    assert "Wcześniej: Radosław WITKOWICZ." in body
    assert "Sob. 12 września, 14:00" in body


def test_crew_message_declines_the_table_role():
    _, body = crew_changed(offer(slot="czas"), "NOWAK Jan")
    assert body.startswith("Nowy mierzący czas w meczu IIM4/1: NOWAK Jan.")


def test_crew_message_without_the_previous_name_still_reads():
    _, body = crew_changed(offer(match_at=None), "NOWAK Jan", "")
    assert body == "Nowy sędzia 1 w meczu IIM4/1: NOWAK Jan."
