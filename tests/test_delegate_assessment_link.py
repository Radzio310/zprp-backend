from bs4 import BeautifulSoup

from app.zprp.officials import _parse_delegate_assessment_link


def _cell(html: str):
    return BeautifulSoup(f"<table><tr><td>{html}</td></tr></table>", "html.parser").find("td")


def test_ocena2_wygrywa_ze_starym_pdf_niezaleznie_od_kolejnosci():
    td = _cell(
        '<a href="./statystyki_sedzia_oc_PDF.php?Id=7">PDF</a>'
        '<a href="?a=zawody&b=ocena2&IdZawody=206764">Ocena sedziow</a>'
    )

    assert _parse_delegate_assessment_link(td) == (
        "?a=zawody&b=ocena2&IdZawody=206764"
    )


def test_stary_pdf_zostaje_fallbackiem_gdy_nie_ma_ocena2():
    td = _cell('<a href="./statystyki_sedzia_oc_PDF.php?Id=7">Ocena</a>')
    assert _parse_delegate_assessment_link(td) == "statystyki_sedzia_oc_PDF.php?Id=7"
