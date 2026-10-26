# app/exam_public_service.py
"""
Strona publiczna wyników egzaminu - bazapodreka.app/wyniki/<kod> (26.10.2026).

  GET    /exams/{id}/public-link            link egzaminu (albo null) - teczka komisji
  POST   /exams/{id}/public-link            włącz / zmień ustawienia {level, photos, hardest, new_code?}
  DELETE /exams/{id}/public-link            wyłącz (działa od następnego zapytania strony)
  GET    /public/exam-results/{kod}         BEZ logowania: dane przycięte do poziomu (`?preview=1` nie liczy wejścia)

Bramka zarządzania jak odczyt wyników komisji (`_managed_exam(read=True)`): okręgowy - admin,
komisja i Teach Master okręgu; krajowy - admin (całość) albo komisja okręgu (tylko jej okręg,
link pamięta ten wycinek). Przycinanie: `exam_public_rules.public_payload` (lista pól jawna).
Kontrakt: BAZA/docs/egzamin-api.md, sekcja „Strona publiczna wyników”.

Trasy: `app/exam_public.py` (ten moduł nie importuje bazy - testy na SQLite).
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import and_, insert, select, update

from app import exam_public_rules as P
from app import exam_service as S
from app.exam_rules import ExamError

logger = logging.getLogger(__name__)

#: Raport składany dla strony publicznej: kod -> (ważny do, znacznik ustawień, odpowiedź).
#: Krótko, bo wynik w koszu ma zniknąć szybko; stan linku (wyłączenie) czytamy ZAWSZE z bazy.
CACHE_TTL_S = 30.0
_CACHE: Dict[str, Tuple[float, str, Dict[str, Any]]] = {}


# ---------------------------------------------------------------------------
# Serwis (testowany na SQLite; tabela linków podawana wprost)
# ---------------------------------------------------------------------------


def _public_who(cut: Optional[str]) -> S.Who:
    """Tożsamość, z którą strona publiczna składa raport: admin (całość) albo zarządzający okręgiem
    (egzamin krajowy wystawiony przez komisję okręgu - ten sam wycinek, który ona widzi)."""
    if not cut:
        return S.Who(judge_id="public-link", name="", province="", is_admin=True, badges={})

    async def teach(_prov: str) -> bool:
        return True

    return S.Who(judge_id="public-link", name="", province=cut, is_admin=False, badges={}, teach_check=teach)


async def _rows_for(st: S.Store, links: Any, exam_id: str, cut: Optional[str]):
    cond = [links.c.exam_id == exam_id, links.c.cut_province.is_(None) if cut is None else links.c.cut_province == cut]
    return await st.database.fetch_all(select(links).where(and_(*cond)).order_by(links.c.updated_at.desc()))


async def get_link(st: S.Store, links: Any, who: S.Who, exam_id: str) -> Dict[str, Any]:
    exam = await S._managed_exam(st, who, exam_id, read=True)
    rows = [S._row(r) for r in await _rows_for(st, links, exam_id, exam["cut_province"])]
    active = next((r for r in rows if r.get("disabled_at") is None), None)
    return P.link_view(exam_id, active or (rows[0] if rows else None))


async def set_link(st: S.Store, links: Any, who: S.Who, exam_id: str, body: Dict[str, Any], now=None) -> Dict[str, Any]:
    now = now or S.utcnow()
    exam = await S._managed_exam(st, who, exam_id, read=True)
    settings = P.clean_settings(body)
    cut = exam["cut_province"]
    rows = [S._row(r) for r in await _rows_for(st, links, exam_id, cut)]
    active = next((r for r in rows if r.get("disabled_at") is None), None)
    target = active
    if body.get("new_code"):
        if active:
            await st.database.execute(update(links).where(links.c.code == active["code"])
                                      .values(disabled_at=now, disabled_by=who.judge_id, updated_at=now))
        target = None
    elif target is None and rows:
        target = rows[0]  # ponowne włączenie: ten sam kod, wydrukowany QR znów działa
    if target is not None:
        await st.database.execute(update(links).where(links.c.code == target["code"]).values(
            **settings, disabled_at=None, disabled_by=None, updated_at=now))
        code = target["code"]
    else:
        code = await _fresh_code(st, links)
        await st.database.execute(insert(links).values(
            code=code, exam_id=exam_id, cut_province=cut, **settings, views=0, created_by=who.judge_id,
            created_by_name=who.name or None, created_at=now, updated_at=now))
    _CACHE.pop(code, None)
    row = await st.database.fetch_one(select(links).where(links.c.code == code))
    return P.link_view(exam_id, S._row(row))


async def disable_link(st: S.Store, links: Any, who: S.Who, exam_id: str, now=None) -> Dict[str, Any]:
    now = now or S.utcnow()
    exam = await S._managed_exam(st, who, exam_id, read=True)
    rows = [S._row(r) for r in await _rows_for(st, links, exam_id, exam["cut_province"])]
    for r in rows:
        if r.get("disabled_at") is None:
            await st.database.execute(update(links).where(links.c.code == r["code"])
                                      .values(disabled_at=now, disabled_by=who.judge_id, updated_at=now))
        _CACHE.pop(r["code"], None)
    return await get_link(st, links, who, exam_id)


async def _fresh_code(st: S.Store, links: Any) -> str:
    for _ in range(12):
        code = P.new_code()
        if not await st.database.fetch_one(select(links.c.code).where(links.c.code == code)):
            return code
    raise ExamError("PUBLIC_LINK_CODE", "Nie udało się wylosować kodu linku. Spróbuj jeszcze raz.", 503)


_GONE = "Komisja wyłączyła tę stronę wyników. Jeśli jej potrzebujesz, poproś komisję o nowy link."


async def public_results(st: S.Store, links: Any, raw_code: str, *, count: bool = True, now=None,
                         user_agent: Optional[str] = None) -> Dict[str, Any]:
    """Strona bez logowania. Stan linku zawsze świeży z bazy (wyłączenie działa natychmiast)."""
    code = P.normalize_code(raw_code)
    row = await st.database.fetch_one(select(links).where(links.c.code == code)) if code else None
    if not row:
        raise ExamError("PUBLIC_LINK_UNKNOWN", "Pod tym adresem nie ma wyników egzaminu. Sprawdź, czy link jest pełny.", 404)
    link = S._row(row)
    if link.get("disabled_at") is not None:
        raise ExamError("PUBLIC_LINK_DISABLED", _GONE, 410)
    stamp = f"{link['level']}|{link['photos']}|{link['hardest']}|{link.get('theme')}|{link.get('updated_at')}"
    hit = _CACHE.get(code)
    clock = time.monotonic()
    if hit and hit[0] > clock and hit[1] == stamp and now is None:
        payload = hit[2]
    else:
        from app import exam_live_brand as BR
        from app import exam_report_service as RS

        try:
            report = await RS.build_report(st, _public_who(link.get("cut_province")), link["exam_id"], now=now)
        except ExamError as error:
            if error.code == "EXAM_NOT_FOUND":  # egzamin w koszu albo usunięty: strona jest zdjęta
                raise ExamError("PUBLIC_LINK_DISABLED", _GONE, 410)
            raise
        exam = report["exam"]
        palette = BR.palette_for(exam.get("scope"), exam.get("cut_province") or exam.get("province"))
        payload = P.public_payload(report, link, backend_crest=f"/exam-live/assets/img/{BR.crest_name(palette)}")
        _CACHE[code] = (clock + CACHE_TTL_S, stamp, payload)
    views = int(link.get("views") or 0)
    if count and not P.is_bot(user_agent):
        views += 1
        await st.database.execute(update(links).where(links.c.code == code)
                                  .values(views=links.c.views + 1, last_view_at=now or S.utcnow()))
    return {**payload, "views": views}


