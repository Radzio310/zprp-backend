# Rozmowa z modelem o podejściu - co dostaje i co z niego zapisujemy.
#
# Model ma UBRAĆ LICZBY W SŁOWA, nie liczyć od nowa - więc pilnujemy, że
# prompt niesie policzony raport (tryb, wynik, różnice jako zdania), a
# odpowiedź wraca przycięta i bez ozdób.

from app.training_spk_ai import (
    MAX_DIFF_LINES,
    MAX_SUMMARY_CHARS,
    ai_messages,
    clean_ai_summary,
)


def report(**over):
    base = {
        "mode": "video",
        "score": 74.5,
        "grade": "dobrze",
        "counts": {
            "reference": 71,
            "mine": 68,
            "matched": 64,
            "missed": 7,
            "extra": 4,
            "wrongPlayer": 3,
            "lateOrEarly": 5,
        },
        "parts": {"events": 80, "players": 70, "timing": 60},
        "result": {
            "final": {"reference": "26:26", "mine": "25:26", "ok": False},
            "half": {"reference": "10:14", "mine": "10:14", "ok": True},
        },
        "missed": [
            {"type": "goal", "team": "host", "player": "16", "time": 60_000},
        ],
        "extra": [
            {"type": "penalty2", "team": "guest", "player": "7", "time": 120_000},
        ],
        "matched": [
            {
                "type": "goal",
                "team": "guest",
                "refPlayer": "9",
                "myPlayer": "6",
                "refTime": 200_000,
                "myTime": 214_000,
                "deltaMs": 14_000,
            },
        ],
    }
    base.update(over)
    return base


class TestPrompt:
    def test_dwie_wiadomosci_system_i_raport(self):
        msgs = ai_messages(report())
        assert [m["role"] for m in msgs] == ["system", "user"]

    def test_raport_niesie_tryb_wynik_i_liczby(self):
        content = ai_messages(report())[1]["content"]
        assert "74.5" in content
        assert "pominięte 7" in content
        assert "nagranie" in content

    def test_roznice_ida_jako_zdania_ze_slajdow(self):
        content = ai_messages(report())[1]["content"]
        assert "Bramka gospodarzy nr 16" in content
        assert "Kara 2 minut dla gości nr 7" in content

    def test_niedokladne_dopasowanie_mowi_o_rozjezdzie(self):
        content = ai_messages(report())[1]["content"]
        assert "rozjazd czasu 14 s" in content
        assert "wpisany nr 6 zamiast 9" in content

    def test_rozny_wynik_koncowy_wykrzyczany(self):
        content = ai_messages(report())[1]["content"]
        assert "RÓŻNI SIĘ" in content

    def test_dluga_lista_przycieta_z_liczba_reszty(self):
        missed = [
            {"type": "goal", "team": "host", "player": str(i), "time": i * 1000}
            for i in range(MAX_DIFF_LINES + 6)
        ]
        content = ai_messages(report(missed=missed))[1]["content"]
        assert "...i jeszcze 6" in content

    def test_pusty_raport_nie_wywraca(self):
        msgs = ai_messages({})
        assert len(msgs) == 2


class TestOdpowiedz:
    def test_przycieta_do_limitu_na_koncu_zdania(self):
        text = ("Dobre podejście. " * 200).strip()
        out = clean_ai_summary(text)
        assert len(out) <= MAX_SUMMARY_CHARS
        assert out.endswith(".")

    def test_cudzyslowy_i_biale_znaki_znikaja(self):
        assert clean_ai_summary('  "Świetnie."  ') == "Świetnie."

    def test_pusto_zostaje_puste(self):
        assert clean_ai_summary(None) == ""
        assert clean_ai_summary("   ") == ""
