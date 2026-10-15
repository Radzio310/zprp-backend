import unicodedata
import unittest
from datetime import datetime, timezone
from app.mentoring_rules import CROSS_PROVINCE, pair_matches, may_manage, season_bounds


class MentoringRulesTests(unittest.TestCase):
    def test_only_both_court_referees(self):
        self.assertTrue(pair_matches(["1", "2"], {"NrSedzia_pierwszy": "2", "NrSedzia_drugi": "1"}))
        self.assertFalse(pair_matches(["1", "2"], {"NrSedzia_pierwszy": "1", "NrSedzia_drugi": "3", "NrSedzia_delegat": "2"}))
        self.assertFalse(pair_matches(["1", "2"], {"NrSedzia_pierwszy_nazwisko": "1", "NrSedzia_drugi_nazwisko": "2"}))
        self.assertFalse(pair_matches(["1", "1"], {"NrSedzia_pierwszy": "1", "NrSedzia_drugi": "1"}))

    def test_commission_default_and_explicit_managers(self):
        args = (False, "1", "ŚLĄSKIE", ["Komisja sędziowska"], "ŚLĄSKIE")
        self.assertTrue(may_manage(*args, {"enabled": True, "manager_ids": []}))
        # Wskazane osoby DOKŁADAJĄ SIĘ do komisji (decyzja z 15.10.2026).
        self.assertTrue(may_manage(*args, {"enabled": True, "manager_ids": ["2"]}))
        self.assertFalse(may_manage(*args, {"enabled": False, "manager_ids": ["1"]}))
        self.assertTrue(may_manage(False, "2", "ŚLĄSKIE", [], "ŚLĄSKIE", {"enabled": True, "manager_ids": ["2"]}))
        self.assertFalse(may_manage(False, "3", "ŚLĄSKIE", [], "ŚLĄSKIE", {"enabled": True, "manager_ids": ["2"]}))

    def test_commission_works_without_admin_switch(self):
        # Okręg bez zapisanej konfiguracji jest WŁĄCZONY - komisja z odznaką
        # zakłada pary od razu.
        self.assertTrue(may_manage(False, "1", "DOLNOŚLĄSKIE", ["Komisja sędziowska"], "DOLNOŚLĄSKIE", None))
        self.assertFalse(may_manage(False, "1", "DOLNOŚLĄSKIE", [], "DOLNOŚLĄSKIE", None))
        self.assertFalse(may_manage(False, "1", "", ["Komisja sędziowska"], "", None))

    def test_badge_spellings(self):
        # Tablica komisji pisze „Komisja Sędziowska" - mentoring żądał dokładnie
        # „Komisja sędziowska" i członek komisji dostawał „Tylko podgląd".
        for badge in ("Komisja Sędziowska", "komisja sedziowska", " Komisja sędziowska ", "Komisja",
                      unicodedata.normalize("NFD", "Komisja s\u0119dziowska")):
            self.assertTrue(may_manage(False, "1", "ŚLĄSKIE", [badge], "ŚLĄSKIE", None), badge)
        self.assertFalse(may_manage(False, "1", "ŚLĄSKIE", ["Komisja wyróżnień"], "ŚLĄSKIE", None))

    def test_admin_cross_province_only(self):
        self.assertTrue(may_manage(True, "1", "ŚLĄSKIE", [], "OPOLSKIE", None))
        self.assertFalse(may_manage(False, "1", "ŚLĄSKIE", ["Komisja sędziowska"], "OPOLSKIE", {"enabled": True, "manager_ids": ["1"]}))
        self.assertTrue(may_manage(True, "1", "ŚLĄSKIE", [], CROSS_PROVINCE, None))
        self.assertFalse(may_manage(False, "1", CROSS_PROVINCE, ["Komisja sędziowska"], CROSS_PROVINCE, {"enabled": True, "manager_ids": ["1"]}))

    def test_current_season_boundary(self):
        self.assertEqual(season_bounds(datetime(2026, 8, 31, tzinfo=timezone.utc))[0].year, 2025)
        start, end = season_bounds(datetime(2026, 9, 8, tzinfo=timezone.utc))
        self.assertEqual((start.year, start.month, end.year), (2026, 9, 2027))


if __name__ == "__main__":
    unittest.main()
