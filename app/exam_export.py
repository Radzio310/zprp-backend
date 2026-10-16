"""
Egzamin z przepisów - eksport wyników komisji do HTML/PDF (etap 4, 16.10.2026).

Moduł-liść BEZ importu bazy: zadania eksportu żyją w pamięci procesu (Railway =
jeden proces, jak gniazda trybu na żywo), pliki leżą chwilę pod tokenem UUID
w katalogu tymczasowym - wzorzec `extra_report_download.py`.

  - NAJWYŻEJ 2 zadania składają plik naraz (cały proces); kolejne czekają
    w kolejce ze stanem `queued` - telefon mówi to wprost, nie udaje postępu.
  - Jedna osoba ma najwyżej 2 zadania w toku (trzecie: 429 EXPORT_BUSY ze zdaniem).
  - Postęp jest PRAWDZIWY: etap + licznik + ostatnie nazwiska z wierszy raportu.
  - Plik żyje 30 min i można go pobrać wiele razy (udostępnienie, druga próba);
    token jest jedynym sekretem adresu - przeglądarka nie ma nagłówka tożsamości.
  - Restart procesu gubi zadania w toku: telefon dostaje 404 EXPORT_JOB_GONE
    z prośbą o ponowienie (zero cichych blokad).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Deque, Dict, Optional, Tuple

from app.exam_rules import ExamError

logger = logging.getLogger(__name__)

EXPORT_DIR = os.path.join(tempfile.gettempdir(), "exam_exports")
FILE_TTL_S = 30 * 60
JOB_TTL_S = 60 * 60
MAX_RUNNING = 2
MAX_PER_OWNER = 2
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
MEDIA = {"pdf": "application/pdf", "html": "text/html; charset=utf-8"}

STAGE_LABELS = {
    "queued": "Czeka w kolejce - składamy najwyżej dwa raporty naraz.",
    "collect": "Zbieramy wyniki, statystyki i listę nieobecnych.",
    "rows": "Wpisujemy wyniki na listę.",
    "cards": "Wypełniamy karty zdających.",
    "pdf": "Składamy strony PDF.",
    "seal": "Przybijamy pieczęć i odkładamy plik.",
    "done": "Gotowe.",
}


def pdf_available() -> bool:
    try:
        import weasyprint  # noqa: F401
    except Exception:  # noqa: BLE001 - brak bibliotek systemowych też tu ląduje
        return False
    return True


# ---------------------------------------------------------------------------
# Pliki pod tokenem
# ---------------------------------------------------------------------------


def _cleanup(now: Optional[float] = None) -> None:
    now = now or time.time()
    try:
        os.makedirs(EXPORT_DIR, exist_ok=True)
        for fn in os.listdir(EXPORT_DIR):
            path = os.path.join(EXPORT_DIR, fn)
            try:
                if now - os.stat(path).st_mtime > FILE_TTL_S:
                    os.remove(path)
            except OSError:
                pass
    except OSError:
        pass


def stash(data: bytes, ext: str, name: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Odkłada plik i zwraca opis `{token, url, name, size, expires_at}`."""
    _cleanup()
    os.makedirs(EXPORT_DIR, exist_ok=True)
    token = uuid.uuid4().hex
    with open(os.path.join(EXPORT_DIR, f"{token}.{ext}"), "wb") as fh:
        fh.write(data)
    with open(os.path.join(EXPORT_DIR, f"{token}.json"), "w", encoding="utf-8") as fh:
        json.dump({"name": name, "ext": ext}, fh, ensure_ascii=False)
    expires = (now or datetime.now(timezone.utc)) + timedelta(seconds=FILE_TTL_S)
    return {"token": token, "url": f"/exam-exports/files/{token}", "name": name, "size": len(data),
            "format": ext, "expires_at": expires.isoformat()}


def file_for(token: str) -> Optional[Tuple[str, str, str]]:
    """(ścieżka, nazwa do pobrania, typ) albo None (zły token, plik wygasł)."""
    if not TOKEN_RE.fullmatch(token or ""):
        return None
    meta_path = os.path.join(EXPORT_DIR, f"{token}.json")
    try:
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, ValueError):
        return None
    ext = meta.get("ext") if meta.get("ext") in MEDIA else None
    if not ext:
        return None
    path = os.path.join(EXPORT_DIR, f"{token}.{ext}")
    try:
        if time.time() - os.stat(path).st_mtime > FILE_TTL_S:
            return None
    except OSError:
        return None
    return path, str(meta.get("name") or f"wyniki.{ext}"), MEDIA[ext]


# ---------------------------------------------------------------------------
# Zadania
# ---------------------------------------------------------------------------


@dataclass
class ExportJob:
    id: str
    owner: str
    exam_id: str
    format: str
    status: str = "queued"  # queued | working | ready | error
    stage: str = "queued"
    done: int = 0
    total: int = 0
    names: Deque[str] = field(default_factory=lambda: deque(maxlen=8))
    file: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    code: Optional[str] = None
    created: float = field(default_factory=time.time)
    seq: int = 0

    def view(self) -> Dict[str, Any]:
        return {"job_id": self.id, "exam_id": self.exam_id, "format": self.format, "status": self.status,
                "stage": self.stage, "stage_label": STAGE_LABELS.get(self.stage, ""), "done": self.done,
                "total": self.total, "names": list(self.names), "seq": self.seq, "file": self.file,
                "code": self.code, "message": self.message}


_JOBS: Dict[str, ExportJob] = {}
_RUNNING = 0
_WAKE: Optional[asyncio.Condition] = None
_WAKE_LOOP: Any = None


def _cond() -> asyncio.Condition:
    """Warunek przypięty do bieżącej pętli (testy tworzą nową pętlę na test)."""
    global _WAKE, _WAKE_LOOP, _RUNNING
    loop = asyncio.get_running_loop()
    if _WAKE is None or _WAKE_LOOP is not loop:
        _WAKE, _WAKE_LOOP, _RUNNING = asyncio.Condition(), loop, 0
    return _WAKE


def _prune() -> None:
    now = time.time()
    for jid in [j.id for j in _JOBS.values() if now - j.created > JOB_TTL_S and j.status in ("ready", "error")]:
        _JOBS.pop(jid, None)


def active_for(owner: str) -> int:
    return sum(1 for j in _JOBS.values() if j.owner == owner and j.status in ("queued", "working"))


def new_job(owner: str, exam_id: str, fmt: str) -> ExportJob:
    _prune()
    if active_for(owner) >= MAX_PER_OWNER:
        raise ExamError("EXPORT_BUSY", "Masz już dwa raporty w przygotowaniu. Poczekaj, aż któryś będzie gotowy.", 429)
    job = ExportJob(id=uuid.uuid4().hex, owner=owner, exam_id=exam_id, format=fmt)
    _JOBS[job.id] = job
    return job


def get_job(job_id: str, owner: str) -> ExportJob:
    job = _JOBS.get(job_id)
    if not job or job.owner != owner:
        raise ExamError("EXPORT_JOB_GONE",
                        "Nie ma już tego zadania eksportu (serwer mógł się zrestartować). Zleć eksport jeszcze raz.", 404)
    return job


def running() -> int:
    return _RUNNING


def _progress(job: ExportJob) -> Callable[[str, int, int, Optional[str]], None]:
    def tick(stage: str, done: int, total: int, name: Optional[str]) -> None:
        job.stage, job.done, job.total = stage, done, total
        if name:
            job.names.append(str(name))
        job.seq += 1
    return tick


def render_pdf(html: str) -> bytes:
    import weasyprint

    return weasyprint.HTML(string=html).write_pdf()


async def run(job: ExportJob, compose: Callable[[Callable[[str, int, int, Optional[str]], None]], Awaitable[Tuple[str, str]]]) -> ExportJob:
    """Wykonuje zadanie z limitem 2 naraz. `compose(progress)` zwraca (html, nazwa bez rozszerzenia)."""
    global _RUNNING
    cond = _cond()
    async with cond:
        await cond.wait_for(lambda: _RUNNING < MAX_RUNNING)
        _RUNNING += 1
    try:
        job.status, job.stage = "working", "collect"
        job.seq += 1
        html, base = await compose(_progress(job))
        if job.format == "pdf":
            job.stage, job.seq = "pdf", job.seq + 1
            data = await asyncio.to_thread(render_pdf, html)
        else:
            data = html.encode("utf-8")
        job.stage, job.seq = "seal", job.seq + 1
        job.file = stash(data, job.format, f"{base}.{job.format}")
        job.status, job.stage = "ready", "done"
    except ExamError as error:
        job.status, job.code, job.message = "error", error.code, error.message
    except Exception:  # noqa: BLE001 - zdanie dla człowieka, szczegóły w logu
        logger.exception("egzamin: eksport %s nieudany", job.id)
        job.status, job.code = "error", "EXPORT_FAILED"
        job.message = "Nie udało się złożyć pliku. Spróbuj jeszcze raz albo wybierz HTML."
    finally:
        job.seq += 1
        async with cond:
            _RUNNING -= 1
            cond.notify_all()
    return job
