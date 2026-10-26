"""Strona publiczna wyników egzaminu (26.10.2026): link komisji, poziomy jawności, wyłączenie od razu,
licznik wyświetleń, kosz odfiltrowany, remisy 1, 2, 2, 3 - i JAWNY test, że poziom nie wycieka danych."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import MetaData
from sqlalchemy.schema import CreateTable

from app import exam_public_service as EP
from app import exam_public_rules as P
from app import exam_service as S
from app import exam_trash as T
from app.exam_public_tables import define_tables
from app.exam_rules import ExamError
from test_exam_service import (  # noqa: F401 - fixture `st` i pomocnicze
    ADMIN, COMMISSION, CORRECT, DELEGATE, OPEN, PLAIN, TEACH, answer_all, make, st, who,
)

WRONG = {"q1-1": "b", "q1-2": "a", "q1-3": "a"}
EXTRA = who("5", "Piotr Cichy")


@pytest.fixture
async def links(st):
    (table,) = define_tables(MetaData())
    await st.database.execute(str(CreateTable(table).compile(dialect=st.database._backend._dialect)))
    EP._CACHE.clear()
    return table


async def _results(st):
    """Trzy osoby: PLAIN 100%, DELEGATE 100% (remis), EXTRA 0%. Zdjęcie ma tylko PLAIN."""
    exam, _ = await make(st)
    now = OPEN + timedelta(minutes=1)
    for w, key in ((PLAIN, CORRECT), (DELEGATE, CORRECT), (EXTRA, WRONG)):
        state = await S.start_attempt(st, w, exam["id"], {}, now=now)
        await answer_all(st, w, state["attempt"]["id"], now, choose=lambda q, k=key: [k[q]], state=state)
    return exam, now + timedelta(minutes=10)


async def _photos(st):
    original = st.judges

    async def judges(prov):
        rows = await original(prov)
        for r in rows:
            if r["judge_id"] == PLAIN.judge_id:
                r["photo_url"] = "https://foto.example/jan.jpg"
        return rows

    st.judges = judges


def _all_strings(payload) -> str:
    return json.dumps(payload, ensure_ascii=False)


async def test_komisja_wlacza_zwykly_sedzia_nie(st, links):
    exam, now = await _results(st)
    with pytest.raises(ExamError) as e:
        await EP.set_link(st, links, PLAIN, exam["id"], {"level": "names"}, now=now)
    assert e.value.status == 403
    out = await EP.set_link(st, links, COMMISSION, exam["id"], {"level": "names", "photos": True}, now=now)
    link = out
    assert link["active"] and P.normalize_code(link["code"]) == link["code"]
    assert link["url"].endswith(f"/wyniki/{link['code']}") and link["views"] == 0
    assert (await EP.get_link(st, links, TEACH, exam["id"]))["code"] == link["code"]


async def test_zla_wartosc_to_zdanie_nie_ciche_przyciecie(st, links):
    exam, now = await _results(st)
    empty = await EP.get_link(st, links, COMMISSION, exam["id"])
    assert empty["active"] is False and empty["code"] is None and empty["url"] is None and empty["views"] == 0
    with pytest.raises(ExamError):
        await EP.set_link(st, links, COMMISSION, exam["id"], {"level": "stats", "theme": "neon"}, now=now)
    with pytest.raises(ExamError) as e:
        await EP.set_link(st, links, COMMISSION, exam["id"], {"level": "wszystko"}, now=now)
    assert e.value.status == 400 and "Poziom" in e.value.message


async def test_poziom_nie_wycieka_danych(st, links):
    """Każdy poziom: nic ponad ustawienie. Szukamy nazwisk, zdjęć i procentów w CAŁEJ odpowiedzi."""
    await _photos(st)
    exam, now = await _results(st)
    names = ("Jan Zwykły", "Ola Delegat", "Piotr Cichy")
    photo = "foto.example"

    async def page(level, photos=True, hardest=False):
        out = await EP.set_link(st, links, COMMISSION, exam["id"], {"level": level, "photos": photos, "hardest": hardest}, now=now)
        return await EP.public_results(st, links, out["code"], now=now)

    stats = await page("stats")
    text = _all_strings(stats)
    assert stats["ranking"] is None and not stats["photos"]
    assert not any(n in text for n in names) and photo not in text
    assert all("initials" not in k for k in stats)
    assert stats["dots"] == [100.0, 100.0, 0.0]  # anonimowo, bez osób

    ini = await page("initials")
    text = _all_strings(ini)
    assert not any(n in text for n in names) and photo not in text and not ini["photos"]
    assert ini["dots"] is None and ini["summary"]["best_percent"] is None
    for row in ini["ranking"]:
        assert set(row) == {"place", "passed", "initials"}

    nam = await page("names")
    assert {r["name"] for r in nam["ranking"]} == set(names)
    assert nam["photos"] and any(r.get("photo") for r in nam["ranking"])
    for row in nam["ranking"]:
        assert "percent" not in row and "points" not in row and "max" not in row
    assert nam["dots"] is None

    no_photo = await page("names", photos=False)
    assert photo not in _all_strings(no_photo)

    pts = await page("points")
    assert all("percent" in r and "points" in r for r in pts["ranking"])
    assert pts["dots"] == [100.0, 100.0, 0.0]

    # Nigdy: rzetelność, numery, odpowiedzi osób, nieobecni, okręgi porównania.
    for payload in (stats, ini, nam, pts):
        text = _all_strings(payload)
        for banned in ("integrity", "judge_id", "attempt_id", "missing", "violations", "web_judges", "reminders", "device"):
            assert banned not in text, (payload["level"], banned)


async def test_remisy_gesto_i_kosz_odfiltrowany(st, links):
    exam, now = await _results(st)
    out = await EP.set_link(st, links, COMMISSION, exam["id"], {"level": "points"}, now=now)
    code = out["code"]
    page = await EP.public_results(st, links, code, now=now)
    assert [r["place"] for r in page["ranking"]] == [1, 1, 2]
    await T.delete_result(st, COMMISSION, exam["id"], PLAIN.judge_id, now=now)
    page = await EP.public_results(st, links, code, now=now)
    assert "Jan Zwykły" not in _all_strings(page)
    assert [r["place"] for r in page["ranking"]] == [1, 2] and page["summary"]["people"] == 2


async def test_wylaczenie_od_razu_licznik_i_ten_sam_kod(st, links):
    exam, now = await _results(st)
    code = (await EP.set_link(st, links, COMMISSION, exam["id"], {"level": "stats"}, now=now))["code"]
    first = await EP.public_results(st, links, code.upper())  # wielkość liter bez znaczenia, pamięć podręczna
    assert first["views"] == 1
    preview = await EP.public_results(st, links, code, count=False)
    assert preview["views"] == 1
    bot = await EP.public_results(st, links, code, user_agent="WhatsApp/2.23 A")
    assert bot["views"] == 1
    human = await EP.public_results(st, links, code, user_agent="Mozilla/5.0 (iPhone)")
    assert human["views"] == 2
    await EP.disable_link(st, links, COMMISSION, exam["id"], now=now)
    with pytest.raises(ExamError) as e:
        await EP.public_results(st, links, code)  # mimo świeżej pamięci podręcznej
    assert e.value.status == 410 and e.value.code == "PUBLIC_LINK_DISABLED"
    off = await EP.get_link(st, links, COMMISSION, exam["id"])
    assert off["active"] is False and off["code"] == code and off["disabled_at"]
    again = await EP.set_link(st, links, COMMISSION, exam["id"], {"level": "stats"}, now=now)
    assert again["code"] == code and again["views"] == 2
    fresh = await EP.set_link(st, links, COMMISSION, exam["id"], {"level": "stats", "new_code": True}, now=now)
    assert fresh["code"] != code
    with pytest.raises(ExamError):
        await EP.public_results(st, links, code)


async def test_nieznany_kod_i_egzamin_w_koszu(st, links):
    exam, now = await _results(st)
    for bad in ("", "abc", "zzzzzzzz", "../../etc"):
        with pytest.raises(ExamError) as e:
            await EP.public_results(st, links, bad)
        assert e.value.status == 404
    code = (await EP.set_link(st, links, COMMISSION, exam["id"], {"level": "stats"}, now=now))["code"]
    await S.delete_exam(st, COMMISSION, exam["id"], now=now)
    with pytest.raises(ExamError) as e:
        await EP.public_results(st, links, code, now=now)
    assert e.value.status == 410


async def test_najtrudniejsze_tylko_gdy_wlaczone(st, links):
    exam, now = await _results(st)
    code = (await EP.set_link(st, links, COMMISSION, exam["id"], {"level": "stats"}, now=now))["code"]
    assert (await EP.public_results(st, links, code, now=now))["hardest"] is None
    await EP.set_link(st, links, ADMIN, exam["id"], {"level": "stats", "hardest": True}, now=now)
    hard = (await EP.public_results(st, links, code, now=now))["hardest"]
    assert hard and hard[0]["text"] and "answers" not in hard[0]  # bez klucza i bez rozkładu
    assert hard[0]["correct_rate"] == pytest.approx(2 / 3, abs=0.001)


def test_inicjaly():
    assert P.initials("Jan Zwykły") == "J. Z."
    assert P.initials("  KOWALSKA-NOWAK  Anna ") == "K. A."
    assert P.initials("") == "?"
