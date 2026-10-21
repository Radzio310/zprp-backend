"""
Panel „Mentor" - raporty pary (`docs/mentor-panel.md`, 4.11 i 4.12).

Kreator wysyła zakres (mecz / okres / sezon) i sekcje; serwer składa migawkę
(liczby, mecze, klipy, zestawienia, wątki, arkusze, trendy, priorytety, cele),
a podgląd A4 i PDF rysuje TEN SAM szablon `app/templates/mentor_report.html`
(WeasyPrint w wątku). PDF trafia do R2 (`mentor/<para>/reports/<id>.pdf`),
a bez magazynu powstaje na żądanie z zapisanej migawki.
Publiczny raport (`/public/{token}`) to projekcja bez arkuszy i trendów.
"""

from __future__ import annotations

import asyncio
import base64
import io
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import database, mentor_clips, mentor_compilations, mentor_match_videos, mentor_reports, mentor_threads
from app.mentor_panel_auth import mentor_actor

router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

#: Paleta kategorii w PDF (ekrany biorą tokeny z systemu projektowego).
PALETTE_HEX = {
    "emerald": "#10b981", "rose": "#f43f5e", "amber": "#f59e0b", "sky": "#0ea5e9", "pink": "#ec4899",
    "violet": "#8b5cf6", "indigo": "#6366f1", "teal": "#14b8a6", "lime": "#84cc16", "orange": "#f97316",
    "cyan": "#06b6d4", "slate": "#64748b",
}
SECTION_LABELS = {
    "summary": "Podsumowanie", "matches": "Mecze", "clips": "Klipy", "compilations": "Zestawienia",
    "threads": "Pytania i odpowiedzi", "sheets": "Arkusze ocen", "trends": "Trendy sekcji I-X",
    "priorities": "Priorytety", "goals": "Cele i notatka mentora",
}


class ReportBody(BaseModel):
    scope: Dict[str, Any] = Field(default_factory=dict)
    sections: List[str] = Field(default_factory=list, max_length=20)
    title: Optional[str] = Field(default=None, max_length=400)
    goals: Optional[str] = Field(default=None, max_length=4000)
    publish: bool = False


def _clean(body: ReportBody) -> Dict[str, Any]:
    try:
        return R.clean_report_config(body.model_dump())
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc


def _scope_label(scope: Dict[str, Any], cards: List[Dict[str, Any]]) -> str:
    if scope["kind"] == "match":
        card = cards[0] if cards else {}
        teams = " - ".join(x for x in ((card.get("home") or {}).get("name"), (card.get("away") or {}).get("name")) if x)
        return f"Mecz {card.get('match_code') or ''} {teams}".strip()
    if scope["kind"] == "range":
        return f"Okres {scope['from']} - {scope['to']}"
    return f"Sezon {scope['season']}" if scope.get("season") else "Cała historia pary"


async def _thumbs(clip_rows: List[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    from app.mentor_panel_media import public_video

    ids = sorted({r["video_id"] for r in clip_rows})
    out: Dict[str, Optional[str]] = {}
    if not ids:
        return out
    for video in await C.rows(select(mentor_match_videos).where(mentor_match_videos.c.id.in_(ids))):
        shaped = await public_video(video)
        out[video["id"]] = shaped.get("poster_url") or shaped.get("thumbnail_url") or None
    return out


async def build_snapshot(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    from app.mentor_panel import delegate_sheet_shape, mentor_sheet_shapes
    from app.mentor_panel_library import compilation_summaries

    scope = config["scope"]
    cards = [c for c in await C.enrich_cards(ctx, await C.pair_match_cards(ctx["judge_ids"])) if R.in_scope(c, scope)]
    match_ids = [c["match_id"] for c in cards]
    clip_rows = await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id == ctx["pair_id"])
                             .where(mentor_clips.c.deleted_at.is_(None)).where(mentor_clips.c.match_id.in_(match_ids or [""]))
                             .order_by(mentor_clips.c.created_at.asc()))
    clips = await C.clips_payload(ctx, clip_rows)
    thumbs = await _thumbs(clip_rows)
    categories = {r["id"]: r for r in await C.categories(ctx, seed=False)}
    for clip in clips:
        clip["thumbnail_url"] = thumbs.get(clip["video_id"])
        clip["categories"] = [{k: categories[c].get(k) for k in ("name", "color", "icon")} for c in clip["category_ids"] if c in categories]
    thread_rows = await C.rows(select(mentor_threads).where(mentor_threads.c.pair_id == ctx["pair_id"])
                               .where(mentor_threads.c.match_id.in_(match_ids or [""])).order_by(mentor_threads.c.created_at.asc()))
    threads = await C.threads_payload(ctx, thread_rows)
    comp_rows = await C.rows(select(mentor_compilations).where(mentor_compilations.c.pair_id == ctx["pair_id"])
                             .order_by(mentor_compilations.c.updated_at.desc()))
    compilations = [c for c in await compilation_summaries(ctx, comp_rows) if c["items_count"]]
    delegate = [delegate_sheet_shape(r) for r in await C.delegate_sheet_rows(ctx["judge_ids"], match_ids)
                if R.s(r.get("match_id")) in set(match_ids)]
    mentor = [m for m in await mentor_sheet_shapes(await C.mentor_sheet_rows(ctx["pair_key"])) if R.s(m["match_id"]) in set(match_ids)]
    d_rows = [{"match_id": d["match_id"], "date": d["match_date"], "evaluation": d["evaluation"], "points": d["points"]} for d in delegate]
    m_rows = [{"match_id": m["match_id"], "date": m["match_at"], "evaluation": m["sheet"], "points": m["points"]} for m in mentor]
    trend = R.trends(d_rows, m_rows)
    names = await C.people([*ctx["judge_ids"], *ctx["mentor_ids"]])
    snapshot = {
        "title": config["title"] or "Raport pary",
        "pair": C.pair_people_shape(ctx["pair"], ctx["mentor_ids"], names),
        "scope": scope, "scope_label": _scope_label(scope, cards), "sections": config["sections"],
        "generated_at": C.now(),
        "summary": R.report_summary(cards, clips, threads, d_rows, m_rows),
        "matches": cards, "clips": clips, "compilations": compilations, "threads": threads,
        "delegate_sheets": delegate, "mentor_sheets": mentor,
        "trends": trend, "priorities": trend["priorities"], "goals": config["goals"],
    }
    return R.json_value(C.dumps(snapshot), {})


def _qr(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    try:
        import qrcode

        image = qrcode.make(url, box_size=4, border=1)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
    except Exception:  # noqa: BLE001 - bez kodu QR raport nadal ma link
        return None


def _date(value: Any) -> str:
    text = R.s(value)
    if len(text) >= 10 and text[4] == "-":
        return f"{text[8:10]}.{text[5:7]}.{text[0:4]}"
    return text[:10] or "-"


def _clock(seconds: Any) -> str:
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return "-"
    return f"{total // 3600}:{total % 3600 // 60:02d}:{total % 60:02d}" if total >= 3600 else f"{total // 60}:{total % 60:02d}"


def render_html(snapshot: Dict[str, Any], *, public: bool = False) -> str:
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    env.filters["pldate"] = _date
    env.filters["clock"] = _clock
    env.filters["points"] = R.fmt_points
    env.filters["qr"] = _qr
    env.filters["hex"] = lambda token: PALETTE_HEX.get(R.s(token), "#64748b")
    trends = snapshot.get("trends") or {}
    section_rows = []
    for section in trends.get("sections") or []:
        values = {"delegate": [p["value"] for p in section["points"] if p["source"] == "delegate"],
                  "mentor": [p["value"] for p in section["points"] if p["source"] == "mentor"]}
        avg = {k: (round(sum(v) / len(v), 2) if v else None) for k, v in values.items()}
        section_rows.append({"label": section["label"], "delegate": avg["delegate"], "mentor": avg["mentor"],
                             "samples": len(section["points"])})
    return env.get_template("mentor_report.html").render(
        snap=snapshot, public=public, labels=SECTION_LABELS, section_rows=section_rows,
        form_label=R.FORM_LABELS.get((snapshot.get("summary") or {}).get("form") or "", ""),
        generated=_date(snapshot.get("generated_at")),
    )


def html_to_pdf(html: str) -> bytes:
    """PDF z HTML - wołać w wątku. Obrazki są już osadzone (`inline_images`),
    więc WeasyPrint nie sięga do sieci."""
    import weasyprint

    return weasyprint.HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()


#: Miniatury do PDF tylko z tych hostów (YouTube, Vimeo, nasz R2) - adres
#: z podglądu linku (`og:image`) może wskazywać dowolne miejsce, także wewnątrz sieci.
THUMB_HOSTS = ("i.ytimg.com", "img.youtube.com", "i.vimeocdn.com")
MAX_THUMB_BYTES = 600_000


def _thumb_allowed(url: str) -> bool:
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    if urlparse(url).scheme != "https" or not host:
        return False
    if host in THUMB_HOSTS:
        return True
    try:
        from app.mentor_panel_media import storage_config

        endpoint = (urlparse(storage_config()["endpoint"]).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return False
    return bool(endpoint) and (host == endpoint or host.endswith("." + endpoint))


async def inline_images(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Miniatury klipów jako `data:` (najwyżej 40, 4 s na obrazek); reszta wypada."""
    import httpx

    clips = [c for c in snapshot.get("clips") or [] if c.get("thumbnail_url")]
    if not clips:
        return snapshot

    async def fetch(client: httpx.AsyncClient, url: str) -> Optional[str]:
        if not _thumb_allowed(url):
            return None
        try:
            response = await client.get(url)
        except Exception:  # noqa: BLE001
            return None
        kind = response.headers.get("content-type", "").split(";")[0].strip()
        if response.status_code != 200 or not kind.startswith("image/") or len(response.content) > MAX_THUMB_BYTES:
            return None
        return f"data:{kind};base64," + base64.b64encode(response.content).decode("ascii")

    async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
        found = await asyncio.gather(*(fetch(client, c["thumbnail_url"]) for c in clips[:40]))
    for clip, data in zip(clips, list(found) + [None] * len(clips)):
        clip["thumbnail_url"] = data
    return snapshot


@router.post("/pairs/{pair_id}/reports/preview")
async def preview(pair_id: str, body: ReportBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    snapshot = await build_snapshot(ctx, _clean(body))
    return {"html": await asyncio.to_thread(render_html, snapshot)}


def _pdf_name(snapshot: Dict[str, Any]) -> str:
    return R.safe_filename(snapshot.get("title") or "raport", "pdf")


async def _store_pdf(ctx: Dict[str, Any], report_id: str, pdf: bytes) -> Optional[str]:
    from app.mentor_panel_media import object_key, s3_client, storage_config, storage_ready

    if not storage_ready():
        return None
    key = object_key(ctx["pair_id"], "reports", f"{report_id}.pdf")
    config = storage_config()

    def put() -> None:
        s3_client(config).put_object(Bucket=config["bucket"], Key=key, Body=pdf, ContentType="application/pdf")

    try:
        await asyncio.to_thread(put)
        return key
    except Exception:  # noqa: BLE001 - PDF powstanie wtedy na żądanie
        C.logger.warning("mentor: zapis PDF raportu w R2 nieudany", exc_info=True)
        return None


def _pdf_url(row: Dict[str, Any]) -> str:
    if row.get("pdf_key"):
        from app.mentor_panel_media import presign_get

        found = presign_get(row["pdf_key"], 3600)
        if found:
            return found
    return f"/mentor-panel/reports/{row['id']}/pdf"


def report_shape(row: Dict[str, Any], names: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    return {"id": row["id"], "title": row.get("title"), "created_at": row.get("created_at"),
            "created_by": C.person(names, row.get("created_by")), "config": R.json_value(row.get("config_json"), {}),
            "public_url": R.public_url("report", row.get("public_token")), "pdf_url": _pdf_url(row)}


@router.post("/pairs/{pair_id}/reports")
async def create_report(pair_id: str, body: ReportBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="create")
    config = _clean(body)
    snapshot = await build_snapshot(ctx, config)
    report_id = R.new_id()
    printable = await inline_images(R.json_value(C.dumps(snapshot), {}))
    pdf = await asyncio.to_thread(lambda: html_to_pdf(render_html(printable)))
    pdf_key = await _store_pdf(ctx, report_id, pdf)
    row = {"id": report_id, "pair_id": ctx["pair_id"], "title": snapshot["title"][:120], "config_json": C.dumps(config),
           "snapshot_json": C.dumps(snapshot), "created_by": actor.judge_id, "created_at": C.now(), "pdf_key": pdf_key}
    await database.execute(mentor_reports.insert().values(**row))
    await C.touch(ctx, actor.judge_id, "report_created", "reports", data={"id": report_id})
    public_url = None
    if body.publish:
        from app.mentor_panel_library import publish

        public_url = (await publish("report", report_id, actor, on=True))["public_url"]
    return {"id": report_id, "pdf_url": _pdf_url(row), "public_url": public_url}


@router.get("/pairs/{pair_id}/reports")
async def list_reports(pair_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    found = await C.rows(select(mentor_reports).where(mentor_reports.c.pair_id == ctx["pair_id"])
                         .order_by(mentor_reports.c.created_at.desc()))
    names = await C.people({r.get("created_by") for r in found})
    return {"reports": [report_shape(r, names) for r in found]}


def _pdf_response(pdf: bytes, filename: str) -> Response:
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'inline; filename="{filename}"', "Cache-Control": "no-store"})


@router.get("/reports/{report_id}/pdf")
async def report_pdf(report_id: str, actor: Actor = Depends(mentor_actor)):
    row = await C.one(select(mentor_reports).where(mentor_reports.c.id == report_id))
    if not row:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego raportu.")
    await C.pair_context(row["pair_id"], actor)
    snapshot = await inline_images(R.json_value(row.get("snapshot_json"), {}))
    pdf = await asyncio.to_thread(lambda: html_to_pdf(render_html(snapshot)))
    return _pdf_response(pdf, _pdf_name(snapshot))


@router.post("/reports/{report_id}/publish")
async def publish_report(report_id: str, actor: Actor = Depends(mentor_actor)):
    from app.mentor_panel_library import publish

    return await publish("report", report_id, actor, on=True)


@router.delete("/reports/{report_id}/publish")
async def unpublish_report(report_id: str, actor: Actor = Depends(mentor_actor)):
    from app.mentor_panel_library import publish

    return await publish("report", report_id, actor, on=False)


@router.get("/public/{token}/pdf")
async def public_pdf(token: str):
    row = await C.one(select(mentor_reports).where(mentor_reports.c.public_token == R.s(token)[:64]))
    if not row or len(R.s(token)) < 10:
        raise C.err(404, "NOT_FOUND", "Ten link nie istnieje albo został wyłączony.")
    snapshot = await inline_images(R.public_report(R.json_value(row.get("snapshot_json"), {})))
    pdf = await asyncio.to_thread(lambda: html_to_pdf(render_html(snapshot, public=True)))
    return _pdf_response(pdf, _pdf_name(snapshot))

