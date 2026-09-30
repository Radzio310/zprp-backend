"""Serwer przerabia arkusz oceny DOKŁADNIE jak aplikacja.

Oczekiwany wynik (`*.app.json`) to zrzut `parseDelegateEvaluationHtml` z
aplikacji (`utils/delegateEvaluationParser.ts` w BAZA) dla tego samego HTML.
Identyczny JSON = identyczny `content_hash`, więc arkusz zapisany przez serwer
i przez starszą wersję aplikacji to jedna i ta sama wersja oceny.
Drugi arkusz przechodzi przez gałęzie zapasowe parsera.
"""

import json
import pathlib

import pytest

from app.delegate_evaluation_parser import parse_delegate_evaluation_html

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("name", ["delegate_evaluation_ocena2", "delegate_evaluation_ocena2b"])
def test_wynik_jak_w_aplikacji(name):
    html = (FIXTURES / f"{name}.html").read_text(encoding="utf-8")
    expected = json.loads((FIXTURES / f"{name}.app.json").read_text(encoding="utf-8"))
    assert parse_delegate_evaluation_html(html) == expected


def test_pusty_i_obcy_html_nie_wywraca_parsera():
    assert parse_delegate_evaluation_html("") == {"sections": [], "keySituations": [], "priorities": [], "vr": []}
    assert parse_delegate_evaluation_html("<html><b>I. Bez tabeli</b></html>")["sections"] == []
