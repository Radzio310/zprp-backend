import fitz
import pytest
from fastapi import HTTPException

from app.protocol_convert import (
    _pdf_info,
    _render_pdf_page,
    _validated_public_pdf_url,
)


def _two_page_pdf() -> bytes:
    document = fitz.open()
    for label in ("PROTOKOL 1", "PROTOKOL 2"):
        page = document.new_page(width=595, height=842)
        page.insert_text((72, 90), label, fontsize=24)
    data = document.tobytes()
    document.close()
    return data


def test_preview_accepts_only_public_zprp_pdf_directory():
    good = "https://baza.zprp.pl/zawody_zalaczniki/211642_1.pdf"
    assert _validated_public_pdf_url(good) == good
    legacy = "https://baza.zprp.pl/pdf/211642"
    assert _validated_public_pdf_url(legacy) == legacy

    for bad in (
        "http://baza.zprp.pl/zawody_zalaczniki/1.pdf",
        "https://example.com/zawody_zalaczniki/1.pdf",
        "https://baza.zprp.pl/index.php?file=1.pdf",
        "https://user:pass@baza.zprp.pl/zawody_zalaczniki/1.pdf",
    ):
        with pytest.raises(HTTPException):
            _validated_public_pdf_url(bad)


def test_preview_reads_page_count_and_renders_png():
    data = _two_page_pdf()
    assert _pdf_info(data) == {"pages": 2}
    rendered = _render_pdf_page(data, 1, 480)
    assert rendered.startswith(b"\x89PNG\r\n\x1a\n")


def test_preview_rejects_page_outside_document():
    with pytest.raises(HTTPException) as error:
        _render_pdf_page(_two_page_pdf(), 2, 480)
    assert error.value.status_code == 404
