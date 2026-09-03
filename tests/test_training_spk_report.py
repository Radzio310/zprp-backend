# Raport wyników sprawdzianu - kogo liczyć i jak grupować.
#
# Te same reguły co zestawienie w panelu: najlepsze podejście sędziego,
# nauka w aplikacji poza liczbami. Raport okręgowy to ten sam raport na
# mniejszych danych - filtr, nie osobny szablon.

from app.training_spk_report import report_context


def run(judge, score, province="MAZOWIECKIE", mode="video", attempt=1, name=None):
    return {
        "runId": f"{judge}-{attempt}",
        "judgeId": judge,
        "judgeName": name or f"Sędzia {judge}",
        "province": province,
        "attempt": attempt,
        "mode": mode,
        "score": score,
    }


def sample():
    return [
        run("j1", 62.0, attempt=1),
        run("j1", 88.5, attempt=3),
        run("j2", 91.0, province="LUBELSKIE"),
        run("j3", 45.0, province="LUBELSKIE"),
        run("j4", None),
        run("j5", 99.0, mode="guided"),
    ]


class TestZasadyLiczenia:
    def test_liczy_najlepsze_podejscie_sedziego(self):
        ctx = report_context(sample())
        j1 = next(r for r in ctx["ranking"] if r["judgeName"] == "Sędzia j1")
        assert j1["score"] == 88.5
        assert j1["attempt"] == 3

    def test_nauka_w_aplikacji_poza_rankingiem_ale_widoczna(self):
        ctx = report_context(sample())
        assert all(r["mode"] != "nauka w aplikacji" for r in ctx["ranking"])
        assert ctx["guidedAttempts"] == 1

    def test_podejscie_bez_wyniku_nie_istnieje_w_liczbach(self):
        ctx = report_context(sample())
        assert ctx["judges"] == 3

    def test_ranking_od_najlepszego(self):
        ctx = report_context(sample())
        assert [r["place"] for r in ctx["ranking"]] == [1, 2, 3]
        assert ctx["ranking"][0]["score"] == 91.0


class TestOkregi:
    def test_raport_ogolnopolski_ma_tabele_okregow(self):
        ctx = report_context(sample())
        names = [p["province"] for p in ctx["byProvince"]]
        assert set(names) == {"MAZOWIECKIE", "LUBELSKIE"}

    def test_raport_okregowy_filtruje_i_chowa_tabele_okregow(self):
        ctx = report_context(sample(), province="lubelskie")
        assert ctx["judges"] == 2
        assert ctx["byProvince"] == []
        assert ctx["scope"] == "LUBELSKIE"

    def test_srednia_okregu_z_najlepszych_podejsc(self):
        ctx = report_context(sample())
        lub = next(p for p in ctx["byProvince"] if p["province"] == "LUBELSKIE")
        assert lub["avg"] == 68.0
        assert lub["judges"] == 2


class TestRozkladOcen:
    def test_progi_dokladnie_jak_grade(self):
        runs = [run(f"j{i}", s) for i, s in enumerate([96, 90, 72, 55, 30])]
        buckets = {b["label"]: b["count"] for b in report_context(runs)["gradeBuckets"]}
        assert buckets == {
            "wzorowo": 1,
            "bardzo dobrze": 1,
            "dobrze": 1,
            "są braki": 1,
            "do poprawy": 1,
        }

    def test_pusty_zakres_nie_wywraca(self):
        ctx = report_context([], province="OPOLSKIE")
        assert ctx["judges"] == 0
        assert ctx["avg"] is None
        assert ctx["gradeBuckets"] == []
        assert ctx["ranking"] == []
