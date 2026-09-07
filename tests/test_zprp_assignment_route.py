"""Trasa sędziego - droga do meczu, którego okręg nie ma w terminarzu.

Konto wojewódzkie nie ma meczu ligi centralnej w swoim terminarzu, ale ma go
na liście meczów SĘDZIEGO, a tam na stronie meczu stoi ten sam przycisk
„Sędziowie", co przy meczach własnych. Trasa idzie tą drogą jak obsadowy w
przeglądarce i bierze z przycisku pole `user`.

Trzy rzeczy, których pilnują te testy:

* każdy krok, który zawodzi, ma WŁASNY kod - „nie ma na liście" i „jest, ale
  bez przycisku" to dwie różne wiadomości dla obsadowego,
* formularz idzie z `user` i z Refererem strony meczu, jak z przeglądarki,
* chętny, który stoi już w innym gnieździe tego meczu, nie zostaje zapisany.

Warstwa HTTP jest podmieniona. Sprawdzamy własne czytanie stron, nie ZPRP.
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Tuple

import pytest

from app.zprp import assignments as A

SELECTS = [
    "NrSedzia_pierwszy",
    "NrSedzia_drugi",
    "NrSedzia_delegat",
    "NrSedzia_delegat2",
    "NrSedzia_sekretarz",
    "NrSedzia_czas",
]


def judge_list_html(
    rows: List[Tuple[str, str, str, str, str]],
    selected_season: str = "2026/2027",
    seasons: List[Tuple[str, str]] | None = None,
    name: str = "WITKOWICZ Radosław",
) -> str:
    """Strona „Mecze sędziego" - nagłówek z nazwiskiem, filtr sezonu, wiersze."""
    seasons = seasons or [("195", "2026/2027"), ("194", "2025/2026")]
    parts = [
        '<html><body><table><tr><td colspan="14"><b>',
        name,
        ' <a class="przycisk3" href="?a=sedzia&amp;b=edycja&amp;NrSedzia=5124">EDYTUJ</a></b></td></tr>',
        '<tr><td>Lp.</td><td><form method="get"><select name="Filtr_sezon">',
        '<option value="">---</option>',
    ]
    for value, label in seasons:
        mark = ' selected="selected"' if label == selected_season else ""
        parts.append(f'<option value="{value}"{mark}>{label}</option>')
    parts.append("</select></form></td></tr>")
    for lp, (code, id_zawody, when, host, guest) in enumerate(rows, 1):
        parts.append(
            f"<tr><td>{lp}.</td><td>2026/2027</td>"
            f'<td><a href="?a=zawody&b=protokol&Filtr_sezon=195&IdRozgr=1&IdRundy=2&IdZawody={id_zawody}">{code}</a>'
            '<br /><input type="checkbox" name="ProEl" value="1" /></td>'
            f"<td>{when}</td><td>hala</td><td>0</td><td><big>{host}</big></td><td>:</td>"
            f"<td><big>{guest}</big></td><td>para</td><td>delegat</td><td>tel</td><td>tel</td></tr>"
        )
    parts.append("</table></body></html>")
    return "".join(parts)


def match_page_html(id_zawody: str, user: str = "ks_slzpr", with_form: bool = True) -> str:
    """Strona meczu - przycisk „Sędziowie" tak, jak renderuje go ZPRP."""
    form = (
        '<FORM NAME="UstawSedziow" target="UstawSedziow" action="zawody_UstawSedziow.php" method="post">'
        '<td colspan="2" align="center">'
        f"<INPUT TYPE=\"hidden\" NAME=\"IdZawody\" VALUE='{id_zawody}'>"
        "<INPUT TYPE=\"hidden\" NAME=\"akcja\" VALUE='UstawSedziow'>"
        f"<INPUT TYPE=\"hidden\" NAME=\"user\" VALUE='{user}'>"
        '<button type="submit" class="przycisk3">Sędziowie</button></td></FORM>'
        if with_form
        else ""
    )
    return (
        "<html><body><table><tr><td>Hala:</td><td>Opole</td></tr>"
        f"<tr>{form}</tr><tr><td>Sędziowie:</td><td>WITKOWICZ Krzysztof</td></tr></table></body></html>"
    )


def form_html(selected: Dict[str, str], options: Dict[str, List[Tuple[str, str]]]) -> str:
    parts = ['<html><body><input type="hidden" name="IdZawody" value="207406">']
    for name in SELECTS:
        parts.append(f'<select name="{name}">')
        parts.append('<option value="">--- ---</option>')
        for value, label in options.get(name, []):
            mark = " selected" if selected.get(name) == value else ""
            parts.append(f'<option value="{value}"{mark}>{label}</option>')
        parts.append("</select>")
    parts.append("</body></html>")
    return "".join(parts)


BASE_OPTIONS = {
    name: [("1", "NOWAK Jan"), ("2", "KOWALSKI Piotr"), ("3", "MAZUR Adam")]
    for name in SELECTS
}


class FakeHttp:
    """Podstawka pod `fetch_with_correct_encoding` - strony po początku adresu.

    Dłuższe klucze przed krótszymi, bo lista bez filtra sezonu jest przedrostkiem
    listy z filtrem.
    """

    def __init__(self, pages: List[Tuple[str, str]]):
        self.pages = sorted(pages, key=lambda item: -len(item[0]))
        self.calls: List[Dict[str, Any]] = []

    async def __call__(
        self, client, path, method="GET", data=None, cookies=None, headers=None, **kw
    ):
        self.calls.append(
            {
                "path": path,
                "method": method,
                "data": dict(data or {}),
                "headers": dict(headers or {}),
            }
        )
        for key, page in self.pages:
            if path.startswith(key):
                return None, page
        raise AssertionError(f"nieoczekiwany adres {path}")

    def paths(self) -> List[str]:
        return [c["path"] for c in self.calls]


LIST_PATH = "/index.php?a=statystyki&b=sedzia&NrSedzia=5124"
ROWS = [
    ("IIM4/1", "208137", "", "MKS WiRy Siódemka Mysłowice", "Hutnik Kraków"),
    ("IMD/3", "207406", "2026-09-13 (15:00)", "Gwardia Opole", "SPR Orzeł Przeworsk"),
]


@pytest.fixture
def http(monkeypatch):
    def install(pages: List[Tuple[str, str]]) -> FakeHttp:
        fake = FakeHttp(pages)
        monkeypatch.setattr(A, "fetch_with_correct_encoding", fake)
        return fake

    return install


async def walk(**kw):
    kw.setdefault("judge_id", "5124")
    return await A.walk_judge_route(None, {}, **kw)


# ─────────────────────────── czytanie stron ───────────────────────────


def test_judge_page_gives_name_seasons_and_rows():
    page = A._parse_judge_matches_page(judge_list_html(ROWS))
    assert page["judge_name"] == "WITKOWICZ Radosław"
    assert [s["label"] for s in page["seasons"]] == ["2026/2027", "2025/2026"]
    assert [s["selected"] for s in page["seasons"]] == [True, False]
    assert [r["code"] for r in page["rows"]] == ["IIM4/1", "IMD/3"]
    row = page["rows"][1]
    assert row["id_zawody"] == "207406"
    assert row["href"].startswith("?a=zawody&b=protokol")
    assert row["when"] == "2026-09-13 (15:00)"
    assert row["host"] == "Gwardia Opole"
    assert row["guest"] == "SPR Orzeł Przeworsk"


def test_judge_page_without_matches_is_empty_not_broken():
    page = A._parse_judge_matches_page("<html><body>nic</body></html>")
    assert page == {"judge_name": "", "seasons": [], "rows": []}


def test_crew_form_reads_user_and_respects_the_match_id():
    found = A._find_crew_form(match_page_html("207406"), "207406")
    assert found["present"] is True
    assert found["user"] == "ks_slzpr"
    # Formularz INNEGO meczu na tej stronie nie jest tym, o który pytamy.
    assert A._find_crew_form(match_page_html("999"), "207406")["present"] is False
    assert A._find_crew_form(match_page_html("207406", with_form=False), "207406")["present"] is False


def test_season_label_follows_the_first_of_september():
    utc = datetime.timezone.utc
    assert A.zprp_season_label(datetime.datetime(2026, 9, 7, tzinfo=utc)) == "2026/2027"
    assert A.zprp_season_label(datetime.datetime(2026, 8, 31, tzinfo=utc)) == "2025/2026"


# ─────────────────────────── trasa ───────────────────────────


@pytest.mark.asyncio
async def test_walk_finds_the_match_by_id_and_takes_user_from_the_button(http):
    fake = http(
        [
            (LIST_PATH, judge_list_html(ROWS)),
            ("/index.php?a=zawody", match_page_html("207406")),
        ]
    )
    out = await walk(id_zawody="207406", season_label="2026/2027")

    assert out["ok"] is True
    assert out["reason"] == "OK"
    assert out["user"] == "ks_slzpr"
    assert out["code"] == "IMD/3"
    assert out["judge_name"] == "WITKOWICZ Radosław"
    assert out["season"] == "2026/2027"
    assert out["detail_path"].startswith("/index.php?a=zawody&b=protokol")
    assert "IdZawody=207406" in out["detail_path"]
    assert [s["ok"] for s in out["steps"]] == [True, True]
    # Dwa wejścia: lista i strona meczu; strona meczu z Refererem listy.
    assert fake.paths() == [LIST_PATH, out["detail_path"]]
    assert fake.calls[1]["headers"]["Referer"] == LIST_PATH


@pytest.mark.asyncio
async def test_walk_switches_season_when_the_page_opened_another(http):
    fake = http(
        [
            (LIST_PATH + "&Filtr_sezon=195", judge_list_html(ROWS)),
            (LIST_PATH, judge_list_html([], selected_season="2025/2026")),
            ("/index.php?a=zawody", match_page_html("207406")),
        ]
    )
    out = await walk(id_zawody="207406", season_label="2026/2027")

    assert out["ok"] is True
    assert fake.paths()[:2] == [LIST_PATH, LIST_PATH + "&Filtr_sezon=195"]


@pytest.mark.asyncio
async def test_walk_refuses_when_the_match_is_not_on_the_list(http):
    fake = http([(LIST_PATH, judge_list_html(ROWS))])
    out = await walk(id_zawody="111111", season_label="2026/2027")

    assert out["ok"] is False
    assert out["reason"] == "NOT_ON_LIST"
    assert len(out["message"]) > 30
    assert out["judge_name"] == "WITKOWICZ Radosław"
    assert [s["ok"] for s in out["steps"]] == [False]
    # Po odmowie na liście nie ma po co otwierać strony meczu.
    assert fake.paths() == [LIST_PATH]


@pytest.mark.asyncio
async def test_walk_refuses_when_the_match_page_has_no_button(http):
    http(
        [
            (LIST_PATH, judge_list_html(ROWS)),
            ("/index.php?a=zawody", match_page_html("207406", with_form=False)),
        ]
    )
    out = await walk(id_zawody="207406", season_label="2026/2027")

    assert out["ok"] is False
    assert out["reason"] == "NO_FORM"
    assert out["reason"] != "NOT_ON_LIST"
    assert out["code"] == "IMD/3"
    assert [s["ok"] for s in out["steps"]] == [True, False]


@pytest.mark.asyncio
async def test_walk_finds_by_code_when_the_id_is_unknown(http):
    http(
        [
            (LIST_PATH, judge_list_html(ROWS)),
            ("/index.php?a=zawody", match_page_html("207406")),
        ]
    )
    out = await walk(match_code=" imd/3 ", season_label="2026/2027")

    assert out["ok"] is True
    assert out["id_zawody"] == "207406"


@pytest.mark.asyncio
async def test_walk_without_a_judge_number_refuses_without_the_network(http):
    fake = http([])
    out = await walk(judge_id="", id_zawody="207406")

    assert out["ok"] is False
    assert out["reason"] == "NOT_ON_LIST"
    assert fake.paths() == []


@pytest.mark.asyncio
async def test_walk_shares_the_list_between_matches_of_the_same_judge(http):
    fake = http(
        [
            (LIST_PATH, judge_list_html(ROWS)),
            ("/index.php?a=zawody", match_page_html("207406")),
        ]
    )
    cache: Dict[str, Any] = {}
    await walk(id_zawody="207406", season_label="2026/2027", page_cache=cache)
    await walk(id_zawody="208137", season_label="2026/2027", page_cache=cache)

    # Lista sędziego pobrana RAZ, strony meczów dwa razy.
    assert fake.paths().count(LIST_PATH) == 1
    assert sum(1 for p in fake.paths() if p.startswith("/index.php?a=zawody")) == 2


# ─────────────────────────── formularz jak z przeglądarki ───────────────────────────


@pytest.mark.asyncio
async def test_probe_carries_user_and_referer_like_the_browser(http):
    fake = http([("/zawody_UstawSedziow.php", form_html({}, BASE_OPTIONS))])
    out = await A.probe_assignment_rights(
        None, {}, "207406", user="ks_slzpr", referer="/index.php?a=zawody&IdZawody=207406"
    )

    assert out["assignable"] is True
    assert fake.calls[0]["data"]["user"] == "ks_slzpr"
    assert fake.calls[0]["headers"]["Referer"] == "/index.php?a=zawody&IdZawody=207406"
    # Zestawienie szóstki gniazd - do raportu w panelu.
    assert set(out["slots"]) == {"sedzia1", "sedzia2", "delegat", "delegat2", "sekretarz", "czas"}
    assert out["slots"]["sedzia1"]["options"] == 3


@pytest.mark.asyncio
async def test_apply_refuses_a_taker_who_already_sits_elsewhere(http):
    # Chętny (KOWALSKI) stoi już jako sędzia 2; oddający (NOWAK) oddaje sędziego 1.
    fake = http(
        [
            (
                "/zawody_UstawSedziow.php",
                form_html({"NrSedzia_pierwszy": "1", "NrSedzia_drugi": "2"}, BASE_OPTIONS),
            )
        ]
    )
    out = await A.apply_referee_assignment(
        None,
        {},
        "207406",
        {"NrSedzia_pierwszy": ("", "Piotr KOWALSKI")},
        expect=("NrSedzia_pierwszy", "NOWAK Jan"),
        require_name_match=True,
        forbid_elsewhere="Piotr KOWALSKI",
    )

    assert out["success"] is False
    assert out["code"] == "ALREADY_IN_CREW"
    assert out["role"] == "sedzia2"
    assert "sędzia 2" in out["error"]
    # Formularz wczytany, ale NIE wysłany.
    assert len(fake.calls) == 1
    assert "akcja_edycja" not in fake.calls[0]["data"]


@pytest.mark.asyncio
async def test_apply_ignores_the_slot_being_handed_over_and_the_placeholder(http):
    # Gniazdo, które właśnie przejmuje, nie liczy się jako „już stoi"; tak samo
    # znak pustego gniazda „--- ---" nie jest nikim.
    fake = http(
        [
            (
                "/zawody_UstawSedziow.php",
                form_html({"NrSedzia_pierwszy": "1", "NrSedzia_drugi": ""}, BASE_OPTIONS),
            )
        ]
    )
    out = await A.apply_referee_assignment(
        None,
        {},
        "207406",
        {"NrSedzia_pierwszy": ("", "Piotr KOWALSKI")},
        expect=("NrSedzia_pierwszy", "NOWAK Jan"),
        require_name_match=True,
        forbid_elsewhere="Piotr KOWALSKI",
        user="ks_slzpr",
        referer="/index.php?a=zawody&IdZawody=207406",
    )

    assert out["code"] != "ALREADY_IN_CREW"
    assert len(fake.calls) == 2
    submitted = fake.calls[1]
    assert submitted["data"]["akcja_edycja"] == "ZAPISZ ZMIANY"
    assert submitted["headers"]["Referer"] == "/index.php?a=zawody&IdZawody=207406"
