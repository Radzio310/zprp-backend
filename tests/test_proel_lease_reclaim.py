"""Odzyskanie prowadzenia i skrót dla tego samego sędziego.

Dwie reguły, które rozstrzygają o tym, KTO pisze protokół w trakcie meczu -
czyli o rzeczy, której pomyłka kosztuje drugi protokół tego samego meczu.
Obie są czystą arytmetyką (`app/proel_lease.py`), więc testują się wprost,
bez bazy.
"""

from datetime import timedelta

from app.proel_lease import (
    LEASE_KIND_ADMIN,
    LEASE_KIND_APP,
    may_reclaim_lead,
    may_take_over_as_same_judge,
    now_utc,
)

MOJ = "install-aaa"
CUDZY = "install-bbb"


def _lease(
    install: str = CUDZY,
    *,
    judge_id: str = "9999",
    kind: str = LEASE_KIND_APP,
    alive: bool = True,
) -> dict:
    return {
        "lease_install": install,
        "lease_judge_id": judge_id,
        "lease_kind": kind,
        "lease_until": now_utc() + timedelta(seconds=60 if alive else -60),
    }


# ── odzyskanie prowadzenia ──────────────────────────────────────────────


def test_autor_wersji_odzyskuje_prowadzenie():
    """Dowodem jest to, że ten protokół napisało TO urządzenie."""
    assert (
        may_reclaim_lead(_lease(), doc_writer_install=MOJ, actor_install=MOJ) is True
    )


def test_kto_nic_nie_napisal_nie_ma_czym_odzyskiwac():
    """Inaczej „odzyskaj" byłoby drugim przyciskiem do przejmowania."""
    assert (
        may_reclaim_lead(_lease(), doc_writer_install=CUDZY, actor_install=MOJ)
        is False
    )


def test_przejecia_administratora_nie_da_sie_cofnac():
    """Rozstrzygnięcie sporu przy stoliku ma się utrzymać."""
    assert (
        may_reclaim_lead(
            _lease(kind=LEASE_KIND_ADMIN),
            doc_writer_install=MOJ,
            actor_install=MOJ,
        )
        is False
    )


def test_wygasly_leasing_to_nie_odzyskiwanie():
    """Nie ma czego odzyskiwać - od tego jest zwykłe objęcie prowadzenia."""
    assert (
        may_reclaim_lead(
            _lease(alive=False), doc_writer_install=MOJ, actor_install=MOJ
        )
        is False
    )
    assert (
        may_reclaim_lead(None, doc_writer_install=MOJ, actor_install=MOJ) is False
    )


def test_wlasnego_leasingu_sie_nie_odzyskuje():
    assert (
        may_reclaim_lead(
            _lease(install=MOJ), doc_writer_install=MOJ, actor_install=MOJ
        )
        is False
    )


def test_pusty_identyfikator_nie_czyni_autorem():
    """Puste równe pustemu uznałoby każdego za autora protokołu."""
    assert may_reclaim_lead(_lease(), doc_writer_install="", actor_install="") is False
    assert (
        may_reclaim_lead(_lease(), doc_writer_install=None, actor_install=MOJ) is False
    )


# ── skrót dla tego samego sędziego ──────────────────────────────────────


def test_zweryfikowany_sedzia_przechodzi_z_drugiego_urzadzenia():
    assert (
        may_take_over_as_same_judge(
            _lease(judge_id="1234"), "1234", verified=True
        )
        is True
    )


def test_sama_deklaracja_numeru_nie_wystarcza():
    """Numer jedzie w nagłówku - bez dowodu jest życzeniem, nie tożsamością."""
    assert (
        may_take_over_as_same_judge(
            _lease(judge_id="1234"), "1234", verified=False
        )
        is False
    )


def test_odmowa_dotyczy_SKROTU_a_nie_prowadzenia_meczu():
    """Sędzia bez weryfikacji ma POCZEKAĆ, a nie stracić mecz.

    Po wygaśnięciu leasingu nie ma już czyjegoś prowadzenia do przejęcia,
    więc ta reguła w ogóle nie jest pytana - `/proel/lease` idzie wtedy
    gałęzią „leasingu nie ma nikt". Test pilnuje, żeby nikt nie zamienił
    tego opóźnienia w trwałą blokadę.
    """
    wygasly = _lease(judge_id="1234", alive=False)
    assert may_take_over_as_same_judge(wygasly, "1234", verified=False) is False
    from app.proel_lease import lease_active

    assert lease_active(wygasly) is False


def test_obcy_numer_nie_przechodzi_nawet_zweryfikowany():
    assert (
        may_take_over_as_same_judge(
            _lease(judge_id="1234"), "9999", verified=True
        )
        is False
    )
