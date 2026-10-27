"""
Postep liczenia rozliczenia (`app/settlement_progress.py`) - bez bazy.

Zgloszenie z 27.10.2026: zaslona „Przeliczam rozliczenia" miala pasek jadacy
sam z siebie. Teraz panel pyta serwer, na jakim etapie jest liczenie.
"""

import asyncio

from app import settlement_progress as SP


def setup_function():
    SP.clear()


def run(coro):
    return asyncio.run(coro)


def test_etapy_ida_po_kolei_i_koniec_je_zamyka():
    seen = []

    async def scenario():
        async with SP.tracking(("summary", "SLASKIE", 2026, 10)):
            SP.stage("facts")
            seen.append(SP.snapshot(("summary", "SLASKIE", 2026, 10)))
            SP.stage("rates")
            seen.append(SP.snapshot(("summary", "SLASKIE", 2026, 10)))
        seen.append(SP.snapshot(("summary", "SLASKIE", 2026, 10)))

    run(scenario())
    assert seen[0]["active"] is True and seen[0]["stage"] == "facts" and seen[0]["done"] == []
    assert seen[1]["stage"] == "rates" and seen[1]["done"] == ["facts"]
    assert seen[2]["active"] is False and seen[2]["stage"] is None
    assert seen[2]["done"] == ["facts", "rates"]


def test_poza_sledzeniem_etap_nic_nie_robi():
    SP.stage("facts")  # PDF, telefon sedziego - nikt nie patrzy
    assert SP.snapshot(("summary", "SLASKIE", 2026, 10)) is None


def test_drugie_pytanie_o_to_samo_nie_zaklada_drugiego_wpisu():
    key = ("summary", "SLASKIE", 2026, 10)
    seen = []

    async def scenario():
        async with SP.tracking(key):
            SP.stage("clubs")
            async with SP.tracking(key):
                # Drugi pytajacy czeka na pierwszego - jego etapy nie mieszaja.
                SP.stage("facts")
                seen.append(SP.snapshot(key))

    run(scenario())
    assert seen[0]["stage"] == "clubs"


def test_rozne_miesiace_maja_osobny_postep():
    async def scenario():
        async with SP.tracking(("summary", "SLASKIE", 2026, 10)):
            SP.stage("rates")
            async with SP.tracking(("summary", "SLASKIE", 2026, 11)):
                SP.stage("facts")
                return (
                    SP.snapshot(("summary", "SLASKIE", 2026, 10))["stage"],
                    SP.snapshot(("summary", "SLASKIE", 2026, 11))["stage"],
                )

    assert run(scenario()) == ("rates", "facts")


def test_etap_widac_tez_w_watku_roboczym():
    """Silnik liczy w `asyncio.to_thread` - kontekst idzie razem z nim."""
    key = ("summary", "SLASKIE", 2026, 10)

    async def scenario():
        async with SP.tracking(key):
            await asyncio.to_thread(SP.stage, "rates")
            return SP.snapshot(key)["stage"]

    assert run(scenario()) == "rates"


def test_przebieg_zprp_niesie_licznik_sedziow():
    SP.run_step(7, "matches", done=12, total=80)
    assert SP.run_snapshot(7) == {"stage": "matches", "done": 12, "total": 80}
    SP.run_end(7)
    assert SP.run_snapshot(7) is None
    assert SP.run_snapshot("smiec") is None
