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
