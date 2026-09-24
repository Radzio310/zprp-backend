"""
Obsada 2.0 - reguły szkicu kolejki, dziennika zapisów do ZPRP, par
mentorskich i pamięci podręcznej panelu.
"""

import pytest
from sqlalchemy import MetaData

from app import assignment_board_cache as C
from app import assignment_board_rules as B
from app.assignment_board_tables import define_tables


class TestNaglowkaSedziego:
    def test_nazwisko_wielkimi_przodem(self):
        assert B.display_name("Jan NOWAK") == "NOWAK Jan"
        assert B.display_name("NOWAK Jan") == "NOWAK Jan"
        assert B.display_name("KOWALSKA-NOWAK Anna Maria") == "KOWALSKA-NOWAK Anna Maria"

    def test_zapis_listy_zwiazku_nazwisko_imie(self):
        assert B.display_name("Witkowicz Radosław") == "WITKOWICZ Radosław"
        assert B.display_name("łuszczykiewicz maksymilian") == "ŁUSZCZYKIEWICZ Maksymilian"

    def test_pustki(self):
        assert B.display_name("") == ""
        assert B.display_name(None) == ""
        assert B.display_name("Nowak") == "NOWAK"


class TestGniazd:
    def test_trzy_zapisy_gniazda(self):
        assert B.normalize_slot("pierwszy") == "pierwszy"
        assert B.normalize_slot("sedzia2") == "drugi"
        assert B.normalize_slot("NrSedzia_czas") == "czas"
        assert B.normalize_slot("hala") == ""


class TestParMentorskich:
    def test_para_to_dwoch_roznych(self):
        assert B.clean_pair_ids(["12", "3"]) == ["12", "3"]
        with pytest.raises(ValueError):
            B.clean_pair_ids(["3", "3"])
        with pytest.raises(ValueError):
            B.clean_pair_ids(["3"])
        with pytest.raises(ValueError):
            B.clean_pair_ids(["1", "2", "3"])

    def test_mentorzy(self):
        assert B.clean_mentor_ids([], ["1", "2"]) == []
        assert B.clean_mentor_ids(["9", "8", "9"], ["1", "2"]) == ["8", "9"]
        with pytest.raises(ValueError):
            B.clean_mentor_ids(["1", "8"], ["1", "2"])
        with pytest.raises(ValueError):
            B.clean_mentor_ids(["7", "8", "9"], ["1", "2"])


def change(**extra):
    item = {"id": "c1", "match_id": "m1", "kind": "slot", "slot": "pierwszy", "judge_id": "5"}
    item.update(extra)
    return item


class TestSzkicuKolejki:
    def test_poprawny_szkic_przechodzi_bez_zmian(self):
        items = [change(), change(id="c2", kind="hall", slot=None, hall_value="7")]
        assert B.clean_draft_changes(items) == items
        assert B.clean_draft_changes(None) == []

    @pytest.mark.parametrize(
        "bad, word",
        [
            ({"id": "", "match_id": "m", "kind": "slot", "slot": "czas"}, "identyfikatora"),
            ({"id": "x", "match_id": "", "kind": "slot", "slot": "czas"}, "meczu"),
            ({"id": "x", "match_id": "m", "kind": "coś"}, "rodzaj"),
            ({"id": "x", "match_id": "m", "kind": "slot", "slot": "bramkarz"}, "gniazdo"),
        ],
    )
    def test_odmowa_mowi_co_nie_tak(self, bad, word):
        with pytest.raises(ValueError) as err:
            B.clean_draft_changes([bad])
        assert word in str(err.value)

    def test_limity(self):
        with pytest.raises(ValueError):
            B.clean_draft_changes({"id": "x"})
        with pytest.raises(ValueError):
            B.clean_draft_changes([change(id=str(i)) for i in range(B.DRAFT_MAX_ITEMS + 1)])
        with pytest.raises(ValueError):
            B.clean_draft_changes([change(note="x" * (B.DRAFT_MAX_BYTES + 10))])

    def test_wersja_szkicu(self):
        assert not B.draft_conflict(0, 0)
        assert not B.draft_conflict(4, 4)
        assert B.draft_conflict(3, 4)
        assert B.draft_conflict("x", 1)

    def test_kolumna_json_napisem(self):
        assert B.load_list('[{"id": "a"}]') == [{"id": "a"}]
        assert B.load_list("") == [] and B.load_list(None) == [] and B.load_list("{") == []


class TestExpect:
    ACTUAL = {"pierwszy": "NOWAK Jan", "drugi": "", "sekretarz": "KOWAL Ewa"}

    def test_ten_sam_stan_bez_konfliktu(self):
        expect = {"pierwszy": "Jan Nowak", "drugi": "", "sekretarz": "KOWAL Ewa"}
        assert B.expect_conflicts(expect, self.ACTUAL) == {}

    def test_ktos_zmienil_gniazdo(self):
        expect = {"pierwszy": "NOWAK Jan", "drugi": "", "sedzia2": ""}
        actual = {**self.ACTUAL, "drugi": "ZIELIŃSKI Paweł"}
        assert B.expect_conflicts(expect, actual) == {
            "drugi": {"expected": "", "actual": "ZIELIŃSKI Paweł"},
            "sedzia2": {"expected": "", "actual": "ZIELIŃSKI Paweł"},
        }

    def test_zdjety_to_tez_zmiana(self):
        conflicts = B.expect_conflicts({"sekretarz": "KOWAL Ewa"}, {"sekretarz": ""})
        assert conflicts == {"sekretarz": {"expected": "KOWAL Ewa", "actual": ""}}

    def test_nieznane_gniazdo_to_konflikt_nie_zgoda(self):
        assert B.expect_conflicts({"bramkarz": "X"}, self.ACTUAL) == {
            "bramkarz": {"expected": "X", "actual": ""}
        }

    def test_bez_expect_bez_konfliktu(self):
        assert B.expect_conflicts(None, self.ACTUAL) == {}


class TestDziennika:
    def test_tylko_wyslane_i_zmienione(self):
        rows = B.journal_slot_rows(
            ["sedzia1", "sedzia2", "sekretarz"],
            before={"pierwszy": "NOWAK Jan", "drugi": "", "sekretarz": "KOWAL Ewa"},
            after={"pierwszy": "Jan Nowak", "drugi": "ZIELIŃSKI Paweł", "sekretarz": ""},
            ids_after={"drugi": "77"},
            ids_before={"sekretarz": "55"},
        )
        assert rows == [
            {
                "kind": "slot",
                "slot": "drugi",
                "before_id": None,
                "before_name": None,
                "after_id": "77",
                "after_name": "ZIELIŃSKI Paweł",
            },
            {
                "kind": "slot",
                "slot": "sekretarz",
                "before_id": "55",
                "before_name": "KOWAL Ewa",
                "after_id": None,
                "after_name": None,
            },
        ]

    def test_cofniecie_liczba_albo_slownik(self):
        assert B.reverted_for(12, "czas") == 12
        assert B.reverted_for("12", "czas") == 12
        assert B.reverted_for({"sedzia1": 5, "czas": 6}, "pierwszy") == 5
        assert B.reverted_for({"czas": 6}, "drugi") is None
        assert B.reverted_for(None, "czas") is None
        assert B.reverted_for("abc", "czas") is None

    def test_partie(self):
        rows = [
            {"batch_id": "b2", "actor": "Ola", "at": "t3", "item": {"id": 3}},
            {"batch_id": "b1", "actor": "Jan", "at": "t2", "item": {"id": 2}},
            {"batch_id": "b1", "actor": "Jan", "at": "t1", "item": {"id": 1}},
        ]
        batches = B.group_batches(rows)
        assert [batch["batch_id"] for batch in batches] == ["b2", "b1"]
        assert batches[1]["at"] == "t2"
        assert [item["id"] for item in batches[1]["items"]] == [1, 2]

    def test_podpis_meczu(self):
        state = {
            "RozgrywkiCode": "S/JmM/12",
            "ID_zespoly_gosp_ZespolNazwa": "SPR Gliwice",
            "ID_zespoly_gosc_ZespolNazwa": "MKS Zabrze",
        }
        assert B.match_label(state) == "S/JmM/12 SPR Gliwice - MKS Zabrze"
        assert B.match_label({}, "S/DZM/1") == "S/DZM/1"


class TestPamieciPanelu:
    def setup_method(self):
        C.clear()

    def test_zapis_uniewaznia_wpis(self):
        clock = [1000.0]
        built = C.version("ŚLĄSKIE")
        C.put("SLASKIE", 2026, "bootstrap", {"a": 1}, built_version=built, now=lambda: clock[0])
        assert C.get("SLASKIE", 2026, "bootstrap", now=lambda: clock[0])[2] == {"a": 1}
        C.bump("śląskie")
        assert C.get("SLASKIE", 2026, "bootstrap", now=lambda: clock[0]) is None

    def test_zapis_w_trakcie_budowania_nie_przykrywa_swiezej_zmiany(self):
        built = C.version("SLASKIE")
        C.bump("SLASKIE")  # zapis przyszedł, gdy stan się budował
        C.put("SLASKIE", 2026, "bootstrap", {"stary": True}, built_version=built)
        assert C.get("SLASKIE", 2026, "bootstrap") is None

    def test_ttl(self):
        clock = [1000.0]
        C.put("SLASKIE", 2026, "x", 1, now=lambda: clock[0])
        clock[0] += C.TTL_SECONDS + 1
        assert C.get("SLASKIE", 2026, "x", now=lambda: clock[0]) is None

    def test_okregi_niezalezne(self):
        C.put("SLASKIE", 2026, "x", 1)
        C.bump("MAZOWIECKIE")
        assert C.get("SLASKIE", 2026, "x") is not None
        C.bump_all()
        assert C.get("SLASKIE", 2026, "x") is None

    def test_etag_zalezy_od_wersji_chwili_i_szkicu(self):
        base = C.etag(1, 10.0, 0)
        assert base == C.etag(1, 10.0, 0)
        assert base != C.etag(2, 10.0, 0)
        assert base != C.etag(1, 11.0, 0)
        assert base != C.etag(1, 10.0, 1)
        assert base.startswith('W/"')


def test_tabele_obsady_2_0():
    metadata = MetaData()
    mentor_pairs, drafts, journal = define_tables(metadata)
    assert [c.name for c in mentor_pairs.primary_key] == ["province", "pair_key"]
    assert [c.name for c in drafts.primary_key] == ["province"]
    for column in ("batch_id", "match_id", "kind", "slot", "before_id", "after_name",
                   "hall_before", "hall_after", "actor", "reverted_of", "created_at"):
        assert column in journal.c
    # JSON jako Text - JSONB wraca z tym sterownikiem napisem.
    assert str(drafts.c.changes.type) == "TEXT"
    assert str(mentor_pairs.c.mentor_ids.type) == "TEXT"
