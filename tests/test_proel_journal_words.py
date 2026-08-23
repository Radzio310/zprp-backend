"""Dziennik meczu po ludzku.

Administrator oglądał w osi czasu wiersze w rodzaju „Zmiana pól" z podpisem
`post.protocolSent` i surowym `{"paths":["post.protocolSent"],"rev":313}`.
Nazwy pól to rejestr z `app/proel_fields.py` - dla człowieka sprawdzającego,
co się działo przy meczu, jest to szyfr.
"""
from __future__ import annotations

import pytest

from app.proel_journal import EVENT_LABELS, describe_field, event_summary


# ───────────────────────── nazwy pól ─────────────────────────


@pytest.mark.parametrize(
    "path,expected",
    [
        ("post.spectatorsCount", "liczba widzów"),
        ("post.venueCapacity", "pojemność hali"),
        ("post.notesText", "treść uwag sędziów"),
        ("cfg.venueAddress", "adres hali"),
        ("extras.matchDate", "data meczu"),
        ("sig.team.host", "podpis gospodarzy"),
        ("sig.team.guest", "podpis gości"),
        ("official.referee1.city", "sędzia 1 - miejscowość"),
        ("official.timekeeper.signature", "mierzący czas - podpis"),
        ("companion.guest.C.license", "osoba towarzysząca C gości - licencja"),
        ("exam.host.#7", "badania zawodnika nr 7 (gospodarzy)"),
    ],
)
def test_sciezki_pol_po_polsku(path, expected):
    assert describe_field(path) == expected


def test_znaczniki_wysylki_sa_zdaniem_a_nie_nazwa_pola():
    # To jedyne „pola", których zmiana jest sama w sobie zdarzeniem.
    assert describe_field("post.protocolSent") == "protokół PDF trafił do załączników meczu"
    assert describe_field("post.fullDataSent") == "pełne dane meczu trafiły do bazy ZPRP"


def test_nieznana_sciezka_wraca_bez_zmian():
    # Techniczna prawda jest lepsza od ładnego zmyślenia - i od razu widać,
    # że doszło pole bez nazwy.
    assert describe_field("cos.nowego") == "cos.nowego"
    assert describe_field("") == ""


# ───────────────────────── zdanie o zdarzeniu ─────────────────────────


def test_zmiana_pol_wymienia_je_po_polsku():
    out = event_summary(
        "field.changed",
        {"paths": ["post.spectatorsCount", "sig.team.host"], "rev": 7},
    )
    assert out == "Zmieniono: liczba widzów, podpis gospodarzy"


def test_dluga_lista_pol_sie_skraca_z_odmiana():
    out = event_summary(
        "field.changed",
        {
            "paths": [
                "post.spectatorsCount",
                "post.venueCapacity",
                "sig.team.host",
                "sig.team.guest",
                "cfg.venueAddress",
            ]
        },
    )
    assert out.endswith("i 2 pola więcej")

    jedno = event_summary(
        "field.changed",
        {"paths": ["post.spectatorsCount", "post.venueCapacity", "sig.team.host", "sig.team.guest"]},
    )
    assert jedno.endswith("i 1 pole więcej")


def test_znacznik_wysylki_mowi_calym_zdaniem():
    out = event_summary("field.changed", {"paths": ["post.protocolSent"], "rev": 313})
    assert out == "Protokół PDF trafił do załączników meczu"
    # Wielka litera tylko pierwsza - skrót w środku zdania zostaje skrótem.
    assert "PDF" in out


def test_zmiana_statusu_czyta_sie_po_polsku():
    assert (
        event_summary("match.unapproved", {"from": "approved", "to": "finished"})
        == "Stan meczu: zatwierdzony → zakończony"
    )


def test_konflikt_numeru_meczu_tlumaczy_sie_sam():
    out = event_summary("match.id_conflict", {"known": "208135", "incoming": "208136"})
    assert "208135" in out and "208136" in out


def test_kazde_zdarzenie_ma_nazwe():
    # Pusta nazwa znaczy, że w osi czasu stanie surowy klucz zdarzenia.
    assert all(str(v).strip() for v in EVENT_LABELS.values())
    assert "match.reopened" in EVENT_LABELS
    assert EVENT_LABELS["match.unapproved"] == "Cofnięcie zatwierdzenia"


def test_stary_wpis_o_cofnieciu_prostuje_sie_przy_odczycie():
    """Wiersze sprzed poprawki emitera nazywały cofnięcie zatwierdzenia
    „Zakończeniem meczu" - w osi czasu wyglądało to na drugi koniec meczu."""
    from app.proel_journal import _effective_event

    assert (
        _effective_event("match.finished", {"from": "approved", "to": "finished"})
        == "match.unapproved"
    )
    # Zwykłe zakończenie zostaje zakończeniem.
    assert (
        _effective_event("match.finished", {"from": "in_progress", "to": "finished"})
        == "match.finished"
    )
    assert _effective_event("match.approved", {"from": "finished", "to": "approved"}) == "match.approved"
