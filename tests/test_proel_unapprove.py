"""Cofnięcie zatwierdzenia meczu: jedyny zapis dozwolony na „approved".

Blokada zapisu na zatwierdzonym meczu odrzucała KAŻDE żądanie PUT, także to,
którego jedynym celem było zdjęcie zatwierdzenia. Sędzia widział „Nie można
edytować zatwierdzonego meczu" po naciśnięciu „Cofnij zatwierdzenie", a mecz
dało się odtwierdzić wyłącznie w bazie.

Druga strona tej samej reguły jest równie ważna: furtka nie może być na tyle
szeroka, żeby przecisnął się przez nią zwykły autozapis starej wersji aplikacji.
Stare klienty nie wysyłają `status`, tylko `is_finished=True` - i gdyby to
wystarczało, protokół odtwierdzałby się sam, w ciszy, co minutę.

Czysta logika, bez bazy - wzorem `test_proel_fields.py`.
"""
from __future__ import annotations

from app.proel_status import resolve_status, unapprove_requested


def test_jawny_finished_cofa_zatwierdzenie():
    """To robi przycisk „Cofnij zatwierdzenie" w aplikacji."""
    assert unapprove_requested("finished") is True


def test_jawny_in_progress_tez_przechodzi():
    """Powrót na tor meczowy to również wyjście ze stanu zatwierdzonego."""
    assert unapprove_requested("in_progress") is True


def test_approved_nie_odblokowuje_sam_siebie():
    """Ponowne zatwierdzenie nie jest powodem, żeby wpuścić zapis bloba."""
    assert unapprove_requested("approved") is False


def test_brak_statusu_nie_cofa():
    """Autozapis bez `status` - dokładnie to wysyła stara wersja aplikacji."""
    assert unapprove_requested(None) is False
    assert unapprove_requested("") is False
    assert unapprove_requested("   ") is False


def test_smiec_w_statusie_nie_cofa():
    assert unapprove_requested("FINISZ") is False
    assert unapprove_requested("done") is False


def test_wielkosc_liter_i_spacje_nie_maja_znaczenia():
    assert unapprove_requested(" Finished ") is True


def test_stary_klient_z_is_finished_nie_przechodzi_ta_droga():
    """Sedno zabezpieczenia.

    `resolve_status` zamienia `is_finished=True` na "finished", więc gdyby
    blokada patrzyła na WYNIK tej funkcji zamiast na jawne pole, stary klient
    odtwierdzałby mecz swoim rutynowym zapisem.
    """
    assert resolve_status(None, True, "approved") == "finished"
    assert unapprove_requested(None) is False


# ─────────── Cofniecie zmienia STATUS, a nie tresc (13.09.2026) ───────────
#
# Raport z telefonu, ktory to rozstrzygnal (mecz TEST/2):
#   wersja bazowa: 0 | serwer doc_rev: 0, autor nieznany, status approved
#   wyslano X-Proel-Base-Rev: 0  ->  409 DOC_STALE
#
# Pierwszy warunek `is_stale_write` czyta baze 0 jako "telefon nie widzial
# serwera" i przy nieznanym autorze odmawia ZAWSZE. Dla wierszy sprzed
# numerowania wersji znaczylo to, ze zatwierdzonego meczu nie dawalo sie cofnac
# niczym - poza stara wersja aplikacji, ktora naglowka wersji nie wysyla wcale.

from app.proel_status import unapprove_only
from app.proel_doc_version import is_stale_write, write_changes_content


def test_cofniecie_zatwierdzonego_to_zapis_samego_statusu():
    assert unapprove_only("approved", "finished") is True
    assert unapprove_only("approved", "in_progress") is True


def test_na_niezatwierdzonym_meczu_nie_ma_czego_cofac():
    assert unapprove_only("finished", "finished") is False
    assert unapprove_only("in_progress", "finished") is False


def test_autozapis_starego_klienta_to_nie_cofniecie():
    # Bez jawnego `status` - dokladnie to wysyla stara wersja aplikacji.
    assert unapprove_only("approved", None) is False


def test_cofniecie_nie_zmienia_tresci_choc_niesie_inny_blob():
    # Telefon przysyla pelny blob (tak zbudowana jest ta trasa), ale zapis
    # tresci nie dotyka - wiec nie ma z czym kolidowac.
    assert (
        write_changes_content(
            status_only=True, incoming={"scoreHost": 20}, stored={"scoreHost": 21}
        )
        is False
    )


def test_odeslanie_tresci_serwera_tez_nie_jest_zmiana():
    # Kolumna JSON wraca ze sterownika raz obiektem, raz NAPISEM - porownanie
    # musi to znosic, inaczej kazdy zapis wygladalby na zmiane.
    assert (
        write_changes_content(
            status_only=False, incoming={"a": 1}, stored='{"a": 1}'
        )
        is False
    )


def test_prawdziwa_zmiana_tresci_dalej_jest_zmiana():
    assert (
        write_changes_content(status_only=False, incoming={"a": 1}, stored={"a": 2})
        is True
    )


def test_ZGLOSZENIE_TEST2_cofniecie_przechodzi_mimo_wersji_zero():
    """Dokladnie sytuacja z raportu: baza 0, serwer 0, autor nieznany."""
    changed = write_changes_content(
        status_only=unapprove_only("approved", "finished"),
        incoming={"scoreHost": 20},
        stored={"scoreHost": 20, "podpisy": ["X"]},
    )
    assert changed is False
    assert (
        is_stale_write(
            0,
            0,
            None,  # autor nieznany - wiersz sprzed numerowania wersji
            "moj-telefon",
            doc_exists=True,
            content_changed=changed,
        )
        is False
    )


def test_ta_sama_sytuacja_przy_ZWYKLYM_zapisie_dalej_odmawia():
    """Furtka nie moze byc szersza, niz trzeba.

    Swiezy, pusty mecz z drugiego telefonu nadal nie nadpisze cudzego
    protokolu sprzed numerowania wersji - to powod, dla ktorego ten warunek
    w ogole powstal.
    """
    changed = write_changes_content(
        status_only=unapprove_only("finished", None),
        incoming={"scoreHost": 0},
        stored={"scoreHost": 20},
    )
    assert changed is True
    assert (
        is_stale_write(
            0, 0, None, "moj-telefon", doc_exists=True, content_changed=changed
        )
        is True
    )
