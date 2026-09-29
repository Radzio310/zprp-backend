"""Reguły ocen mentora - liść bez bazy."""
import unittest

from app.mentor_evaluation_rules import (
    DELEGATE,
    NOT_A_MENTOR,
    NOT_A_PAIR,
    OBSADA_NOT_IN_CREW,
    OWN_PAIR,
    can_view_published,
    clean_sheet,
    eligibility,
    pair_key,
    pair_of,
    sheet_points,
)

STATE = {
    "NrSedzia_pierwszy": "101",
    "NrSedzia_drugi": "102",
    "NrSedzia_sekretarz": "201",
    "NrSedzia_czas": "202",
    "NrSedzia_delegat": "301",
}


def verdict(actor, mentoring=False, obsada=False, state=STATE):
    return eligibility(actor_id=actor, state=state, mentoring_mentor=mentoring, obsada_mentor=obsada)


class EligibilityTests(unittest.TestCase):
    def test_mentor_z_programu_ocenia_bez_obsady(self):
        self.assertEqual(verdict("900", mentoring=True), {"can_rate": True, "source": "mentoring", "reason": ""})

    def test_para_mentorska_okregu_tylko_w_obsadzie(self):
        self.assertEqual(verdict("201", obsada=True)["source"], "obsada")
        self.assertEqual(verdict("900", obsada=True)["reason"], OBSADA_NOT_IN_CREW)

    def test_delegat_nigdy(self):
        # Nawet mentor z programu - jego oceną jest arkusz delegata w ZPRP.
        self.assertEqual(verdict("301", mentoring=True)["reason"], DELEGATE)
        self.assertFalse(verdict("301", mentoring=True)["can_rate"])

    def test_drugi_delegat_tez_nie(self):
        state = {**STATE, "NrSedzia_delegat2": "302"}
        self.assertEqual(verdict("302", mentoring=True, state=state)["reason"], DELEGATE)

    def test_wlasna_para_nie(self):
        self.assertEqual(verdict("101", mentoring=True)["reason"], OWN_PAIR)

    def test_bez_pary_nie_ma_kogo_ocenic(self):
        self.assertEqual(verdict("900", mentoring=True, state={"NrSedzia_pierwszy": "101"})["reason"], NOT_A_PAIR)

    def test_obcy_nie(self):
        self.assertEqual(verdict("900")["reason"], NOT_A_MENTOR)


class PairTests(unittest.TestCase):
    def test_para_bez_kolejnosci(self):
        self.assertEqual(pair_of({"NrSedzia_pierwszy": "9", "NrSedzia_drugi": "10"}), ("10", "9"))
        self.assertEqual(pair_key(["9", "10"]), pair_key(["10", "9"]))


class VisibilityTests(unittest.TestCase):
    def test_kto_widzi_opublikowana(self):
        base = dict(pair=("101", "102"), authors=["900"], is_pair_mentor=False, province_access=False)
        self.assertTrue(can_view_published(actor_id="101", **base))
        self.assertTrue(can_view_published(actor_id="900", **base))
        self.assertFalse(can_view_published(actor_id="555", **base))
        self.assertTrue(can_view_published(actor_id="555", **{**base, "province_access": True}))
        self.assertTrue(can_view_published(actor_id="555", **{**base, "is_pair_mentor": True}))


class SheetTests(unittest.TestCase):
    def test_srednia_z_liter_sekcji_bez_nd(self):
        sheet = clean_sheet({"sections": {"I": {"main": "E"}, "II": {"main": "D"}, "III": {"main": "ND"}}})
        self.assertEqual(sheet_points(sheet), (4.5, "E"))

    def test_polowka_w_gore_jak_w_aplikacji(self):
        # round() Pythona dałby tu D - aplikacja pokazuje E.
        sheet = clean_sheet({"sections": {"I": {"main": "E"}, "II": {"main": "D"}}})
        self.assertEqual(sheet_points(sheet)[1], "E")

    def test_pusty_arkusz(self):
        self.assertEqual(sheet_points(clean_sheet({})), (None, None))

    def test_przyciecie_do_wzoru(self):
        sheet = clean_sheet(
            {
                "sections": {"I": {"main": "Z", "items": {"a": "q", "x": "F"}}},
                "character": {"k": "Może"},
                "situations": [{"category": "hack", "time": "1:00:00:00"}] * 9,
                "priorities": ["1", "2", "3", "4"],
                "difficulty": "Ekstremalny",
            }
        )
        self.assertIsNone(sheet["sections"]["I"]["main"])
        self.assertEqual(sheet["sections"]["I"]["items"], {"a": None, "x": "F"})
        self.assertIsNone(sheet["character"]["k"])
        self.assertEqual(len(sheet["situations"]), 5)
        self.assertIsNone(sheet["situations"][0]["category"])
        self.assertEqual(sheet["priorities"], ["1", "2", "3"])
        self.assertIsNone(sheet["difficulty"])


if __name__ == "__main__":
    unittest.main()
