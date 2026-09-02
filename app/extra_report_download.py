"""Pobieranie dodatkowego raportu na telefon - plik pod jednorazowym tokenem.

Ten sam wzorzec co przy protokole PDF (`app/results.py`): gotowy plik leży
chwilę pod tokenem UUID, aplikacja otwiera adres SYSTEMOWO i raport ląduje
w pobranych - a nie w arkuszu udostępniania. Token jest jednorazowy (plik
znika po pobraniu) i krótkotrwały (TTL), dlatego adres może być bez nagłówków
tożsamości: przeglądarka i menedżer pobierania i tak ich nie mają.

Moduł-liść BEZ importu `app.db` - testy jednostkowe muszą go dać radę
zaimportować bez bazy (patrz `tests/test_extra_report_pdf.py`).
"""

from __future__ import annotations

import os
import re
import time
import uuid

DOWNLOAD_DIR = "/tmp/extra_report_downloads"
DOWNLOAD_TTL_SECONDS = 10 * 60  # 10 min - tyle co przy protokole

# Token idzie w ścieżkę pliku, więc przyjmujemy WYŁĄCZNIE kształt UUID -
# cokolwiek innego nie ma prawa dotknąć dysku.
TOKEN_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


def _ensure_download_dir() -> None:
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def _cleanup_expired_downloads() -> None:
    try:
        _ensure_download_dir()
        now = time.time()
        for fn in os.listdir(DOWNLOAD_DIR):
            p = os.path.join(DOWNLOAD_DIR, fn)
            try:
                if now - os.stat(p).st_mtime > DOWNLOAD_TTL_SECONDS:
                    os.remove(p)
            except Exception:
                pass
    except Exception:
        pass


def stash_for_download(pdf: bytes) -> str:
    """Odkłada plik pod tokenem i zwraca token."""
    _cleanup_expired_downloads()
    _ensure_download_dir()
    token = str(uuid.uuid4())
    with open(os.path.join(DOWNLOAD_DIR, f"{token}.pdf"), "wb") as fh:
        fh.write(pdf)
    return token


def download_path_for(token: str) -> str | None:
    """Ścieżka pliku dla tokena albo None, gdy token zły lub plik wygasł."""
    if not TOKEN_RE.fullmatch(token):
        return None
    file_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
    return file_path if os.path.exists(file_path) else None
