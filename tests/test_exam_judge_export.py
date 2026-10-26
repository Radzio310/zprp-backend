"""Egzamin - karta jednego sędziego (studio eksportu 26.10.2026): liczby, cztery układy, trzy motywy."""

from datetime import timedelta

import pytest

from app import exam_judge_html as J
from app import exam_print_theme as T
from app import exam_report_html as H
from app import exam_report_rules as R
from app import exam_report_service as RS
from app import exam_service as S
from app.exam_rules import ExamError
from tests.test_exam_service import (  # noqa: F401 - `st` to fiksura
    COMMISSION, CORRECT, DELEGATE, OPEN, PLAIN, answer_all, make, st,
)


async def _done(st):
    exam, _ = await make(st, result_release="immediate", pass_percent=60)
    t = OPEN + timedelta(minutes=5)
    for w, chooser in ((PLAIN, lambda q: [CORRECT[q]]), (DELEGATE, lambda q: ["a"])):
        state = await S.start_attempt(st, w, exam["id"], {}, now=t)
        await answer_all(st, w, state["attempt"]["id"], t, choose=chooser, state=state)
    rep = await RS.build_report(st, COMMISSION, exam["id"])
    return exam, rep


async def test_liczby_karty_z_przegladu_komisji(st):
    exam, rep = await _done(st)
    best, worst = rep["ranking"][0], rep["ranking"][1]
    review = await S.committee_review(st, COMMISSION, exam["id"], worst["attempt_id"])
    f = J.judge_facts(rep, review, None, worst["judge_id"])
    assert f["place"] == 2 and f["ranked"] == 2 and not f["shared"] and f["beaten"] == 0
    assert len(f["map"]) == 3 and f["counts"]["good"] + f["counts"]["bad"] + f["counts"]["partial"] == 3
    assert f["mistakes"] and all(m["correct"] for m in f["mistakes"])
    # Litery to pozycje na karcie zdającego (a-...), nie klucze katalogu.
    assert all(l in "abcdef" for m in f["mistakes"] for l, _ in m["correct"])
    assert f["rules"] and f["weak"] and f["province_avg"] is not None
    top = J.judge_facts(rep, await S.committee_review(st, COMMISSION, exam["id"], best["attempt_id"]), None, best["judge_id"])
    assert top["passed"] and top["mistakes"] == [] and top["beaten"] == 100


async def test_cztery_uklady_i_trzy_motywy(st):
    exam, rep = await _done(st)
    row = rep["ranking"][0]
    review = await S.committee_review(st, COMMISSION, exam["id"], row["attempt_id"])
    seen = []
    for layout in J.LAYOUTS:
        for theme in ("province", "elegant", "premium"):
            opts = R.clean_export_options({"kind": "judge", "format": "html", "theme": theme,
                                           "judge": {"judge_id": row["judge_id"], "attempt_id": row["attempt_id"], "layout": layout}},
                                          national=False)
            html = J.render_judge(rep, review, None, opts, progress=lambda *a: seen.append(a))
            assert html.startswith("<!doctype html>") and row["judge_name"] in html
    assert ("cards", 1, 1, row["judge_name"]) in seen
    sheet = R.clean_export_options({"kind": "judge", "theme": "elegant",
                                    "judge": {"judge_id": "1", "attempt_id": "x", "layout": "sheet"}}, national=False)
    html = J.render_judge(rep, review, None, {**sheet, "judge": {**sheet["judge"], "judge_id": row["judge_id"]}})
    assert "klucz" in html and "Arkusz odpowiedzi" in html


def test_opcje_karty_odrzucaja_zle_wartosci():
    with pytest.raises(ExamError) as err:
        R.clean_export_options({"kind": "judge", "judge": {"judge_id": "1", "attempt_id": "a", "layout": "poster"}}, national=False)
    assert err.value.code == "BAD_EXPORT"
    with pytest.raises(ExamError):
        R.clean_export_options({"kind": "judge", "judge": {"judge_id": "1", "attempt_id": "a", "layout": "player", "blocks": ["answers"]}},
                               national=False)
    ok = R.clean_export_options({"kind": "judge", "judge": {"judge_id": "1", "attempt_id": "a", "layout": "player",
                                                            "blocks": ["map", "photo", "answers"]}}, national=False)
    assert ok["judge"]["blocks"] == ["photo", "map"] and ok["kind"] == "judge"
    assert R.clean_export_options({}, national=False)["kind"] == "exam"


def test_motyw_okregu_z_herbu_czytelny_na_papierze():
    th = T.province_theme("Dolnośląskie")
    # Żółć herbu na białym papierze jest nieczytelna - akcent idzie ku czerni, pas zostaje w barwie herbu.
    assert th["band"] == "#F3C707" and T.contrast(th["accent"], th["bg"]) >= 4.0
    assert T.province_theme(None)["band"] == T.ZPRP_RED
    assert T.theme_for("night", None, H.THEMES)["dark"] is True


async def test_raport_egzaminu_w_nowych_motywach(st):
    exam, _ = await _done(st)
    rep = await RS.build_report(st, COMMISSION, exam["id"], with_scores=True)
    for theme in ("province", "elegant", "premium"):
        options = R.clean_export_options({"format": "html", "theme": theme, "layout": {"cover": True}}, national=False)
        rows = R.select_rows(rep["attempts"], "best")
        html = H.render_report(rep, rows, options)
        assert 'class="band"' in html and "cover" in html
