from pathlib import Path


TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "templates"


def test_settlement_pdf_templates_are_clean_utf8():
    """Polskie znaki nie moga ponownie trafic do PDF jako mojibake."""
    for name in ("okreg_zestawienie.html", "okreg_przejazdy.html"):
        text = (TEMPLATES / name).read_text(encoding="utf-8")
        assert "Kluby, które nie rozliczają się przez okręg" in text
        assert "Nazwisko i imię" in text
        assert 'class="outside-section"' in text
        assert "page-break-before: always" in text
        assert not any(marker in text for marker in ("Ă", "Ä", "Ĺ", "â€", "�"))
