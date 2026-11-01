"""Przenoszenie klipów BAZY: trwały plan, potwierdzenie i wznawialne wykonanie.

Nie skanujemy obcych plików. Identyfikatory klipów pochodzą wyłącznie z księgi
pary, a ich rzeczywiste położenie sprawdzamy w Google przed zaplanowaniem ruchu.
"""

import asyncio
import hashlib
import json
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, update

from app import mentor_drive as D
from app.mentor_panel_auth import mentor_actor

router = APIRouter()
ACTIVE = ("preparing", "ready", "queued", "working", "failed")
RUNNABLE = ("preparing", "queued", "working")
RANK = {"reader": 1, "commenter": 2, "writer": 3, "owner": 4}
LEASE = timedelta(minutes=3)


def data_of(conn):
    return D.R.json_value((conn or {}).get("folder_transfer_data"), {}) or {}


def busy(conn):
    return bool(conn and conn.get("folder_transfer_state") in ACTIVE)


def guard(conn):
    if busy(conn):
        raise D.derr(409, "TRANSFER_ACTIVE", "Najpierw zakończ albo anuluj przygotowane przenoszenie Teczki.")


def public(conn):
    d = data_of(conn)
    if not d:
        return None
    people = {}
    for p in d.get("root_people", []) + [p for f in d.get("items", []) for p in f.get("permissions", [])]:
        key = (p["type"], p["emailAddress"].lower())
        old = people.get(key)
        scope = "folder" if p in d.get("root_people", []) else "materials"
        if not old or RANK[p["role"]] > RANK[old["role"]]:
            people[key] = {"email": p["emailAddress"], "role": p["role"], "type": p["type"], "scope": scope}
        elif scope == "folder":
            old["scope"] = scope
    return {"id": d["id"], "state": conn.get("folder_transfer_state"), "source_name": d.get("source_name"),
            "target_name": d.get("target_name"), "target_id": d.get("target_id"), "target_url": d.get("target_url"),
            "scanned": d.get("scan", 0), "candidates": len(d.get("candidates", [])), "total": len(d.get("items", [])),
            "moved": d.get("moved", 0), "skipped": d.get("skipped", []), "people": list(people.values()),
            "destination_people": d.get("destination_people", []), "error": d.get("error"),
            "started": bool(d.get("started")), "can_cancel": not d.get("started")}


def encode(d):
    return json.dumps(d, ensure_ascii=False, separators=(",", ":"))


def signature(perms):
    return sorted([p.get("type", ""), (p.get("emailAddress") or p.get("domain") or "").lower(), p.get("role", ""),
                   p.get("expirationTime") or ""] for p in perms if not p.get("deleted"))


def copyable(perms, *, root=False, own_email=""):
    out = []
    for p in perms:
        if p.get("deleted"):
            continue
        if p.get("expirationTime"):
            raise D.derr(409, "TRANSFER_TEMPORARY_ACCESS", "Ten materiał ma dostęp z datą wygaśnięcia. BAZA nie przeniesie go automatycznie, aby nie zmienić czasu dostępu tej osoby.")
        if p.get("type") not in ("user", "group") or p.get("role") not in RANK or not p.get("emailAddress"):
            raise D.derr(409, "TRANSFER_ACCESS_UNSUPPORTED",
                         "Ten materiał ma dostęp przez link, domenę albo Dysk współdzielony. Przeniesienie z zachowaniem tych zasad nie jest dostępne w BAZIE.")
        if p["role"] == "owner" and (not root or p["emailAddress"].lower() == own_email.lower()):
            continue
        item = {k: p[k] for k in ("type", "emailAddress", "expirationTime") if p.get(k)}
        item["role"] = "writer" if p["role"] == "owner" else p["role"]
        out.append(item)
    return out


async def access(pid, method, *args):
    return await D._google(pid, lambda token: getattr(D.G.api(), method)(token, *args))


async def save(pid, d, state, worker=None):
    query = update(D.CONN).where(D.CONN.c.pair_id == pid)
    if worker:
        query = query.where(D.CONN.c.folder_transfer_worker == worker)
    await D.database.execute(query.values(folder_transfer_data=encode(d), folder_transfer_state=state,
                                          folder_transfer_worker=None, folder_transfer_lease_until=None, updated_at=D.C.now()))


class PlanBody(BaseModel):
    source_folder_id: str = Field(min_length=1, max_length=120)
    file_id: str | None = Field(default=None, max_length=120)
    create: bool = False
    name: str | None = Field(default=None, max_length=120)


@router.get("/pairs/{pair_id}/drive/transfer")
async def get_transfer(pair_id: str, actor: D.Actor = Depends(mentor_actor), response: Response = None):
    if response is not None:
        response.headers["Cache-Control"] = "no-store"
    ctx = await D._context(pair_id, actor)
    conn = await D.get_conn(ctx["pair_id"])
    return {"transfer": public(conn) if conn else None}


@router.post("/pairs/{pair_id}/drive/transfer/plan")
async def plan_transfer(pair_id: str, body: PlanBody, actor: D.Actor = Depends(mentor_actor)):
    ctx = await D._context(pair_id, actor, "video")
    pid = ctx["pair_id"]
    conn = D._require_owner(await D.get_conn(pid), actor, token=True)
    guard(conn)
    if conn.get("folder_id") != body.source_folder_id:
        raise D.derr(409, "TRANSFER_SOURCE_CHANGED", "Folder Teczki zmienił się. Odśwież ustawienia i wybierz nowe miejsce ponownie.")
    if bool(body.file_id) == body.create or (body.file_id and not D._FILE_ID.match(body.file_id)):
        raise D.derr(422, "TRANSFER_TARGET", "Wybierz istniejący folder albo nazwę nowego folderu.")
    if body.file_id == conn["folder_id"]:
        raise D.derr(422, "TRANSFER_SAME_FOLDER", "To już jest obecny folder Teczki.")
    names = await D.C.people(ctx["judge_ids"]) if body.create and not body.name else {}
    title = D.DR.drive_name(body.name) if body.name else D.DR.default_folder_name([D.C.person(names, j)["name"] for j in ctx["judge_ids"]])
    d = {"id": secrets.token_hex(16), "source_id": conn["folder_id"], "source_name": conn.get("folder_name"),
         "target_id": body.file_id, "create": body.create, "target_name": title if body.create else None,
         "scan": 0, "moved": 0, "items": [], "skipped": [], "started": False,
         "actor_id": actor.judge_id, "acted_by": actor.acted_by, "initialized": False}
    # CAS: dwa otwarte okna nie mogą nadpisać aktywnego zadania.
    await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid)
                             .where(D.CONN.c.folder_id == body.source_folder_id)
                             .where(or_(D.CONN.c.folder_transfer_state.is_(None), D.CONN.c.folder_transfer_state.notin_(ACTIVE)))
                             .values(folder_transfer_data=encode(d), folder_transfer_state="preparing",
                                     folder_transfer_worker=None, folder_transfer_lease_until=None))
    again = await D.get_conn(pid)
    if data_of(again).get("id") != d["id"]:
        raise D.derr(409, "TRANSFER_ACTIVE", "Przygotowanie przenoszenia już trwa.")
    D.wake_worker()
    return {"transfer": public(again)}


async def owned_job(pair_id, job_id, actor):
    ctx = await D._context(pair_id, actor, "video")
    conn = D._require_owner(await D.get_conn(ctx["pair_id"]), actor, token=True)
    d = data_of(conn)
    if d.get("id") != job_id:
        raise D.derr(409, "TRANSFER_CHANGED", "To przygotowanie nie jest już aktualne. Odśwież ustawienia.")
    return ctx["pair_id"], conn, d


@router.post("/pairs/{pair_id}/drive/transfer/{job_id}/start")
async def start_transfer(pair_id: str, job_id: str, actor: D.Actor = Depends(mentor_actor)):
    pid, conn, d = await owned_job(pair_id, job_id, actor)
    if d.get("started"):
        return {"transfer": public(conn)}
    if conn["folder_transfer_state"] != "ready":
        raise D.derr(409, "TRANSFER_NOT_READY", "Najpierw poczekaj na sprawdzenie materiałów i dostępów.")
    ready = D.R.aware(datetime.fromisoformat(d["ready_at"]))
    if ready + timedelta(minutes=15) < D.C.now():
        raise D.derr(409, "TRANSFER_EXPIRED", "Podgląd przenoszenia wygasł. Anuluj go i przygotuj ponownie.")
    if conn.get("folder_id") != d["source_id"]:
        raise D.derr(409, "TRANSFER_SOURCE_CHANGED", "Obecny folder zmienił się. Przygotuj przenoszenie ponownie.")
    if signature(await access(pid, "list_permissions", d["source_id"])) != d["source_signature"]:
        raise D.derr(409, "TRANSFER_ACCESS_CHANGED", "Dostępy do starego folderu zmieniły się. Przygotuj podgląd ponownie.")
    if d.get("target_id") and signature(await access(pid, "list_permissions", d["target_id"])) != d["target_signature"]:
        raise D.derr(409, "TRANSFER_ACCESS_CHANGED", "Dostępy do nowego folderu zmieniły się. Przygotuj podgląd ponownie.")
    d["started"], d["error"] = True, None
    # Potwierdzenie i anulowanie wykluczają się również między procesami.
    await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid).where(D.CONN.c.folder_transfer_state == "ready")
                             .where(D.CONN.c.folder_transfer_data == conn["folder_transfer_data"])
                             .values(folder_transfer_data=encode(d), folder_transfer_state="queued"))
    again = await D.get_conn(pid)
    if again["folder_transfer_state"] not in ("queued", "working", "done"):
        raise D.derr(409, "TRANSFER_CHANGED", "Przygotowanie zostało anulowane albo zmienione.")
    D.wake_worker()
    return {"transfer": public(again)}


class CancelBody(BaseModel):
    leave_partial: bool = False


@router.post("/pairs/{pair_id}/drive/transfer/{job_id}/cancel")
async def cancel_transfer(pair_id: str, job_id: str, actor: D.Actor = Depends(mentor_actor), body: CancelBody = None):
    pid, conn, d = await owned_job(pair_id, job_id, actor)
    if d.get("started") and not (conn["folder_transfer_state"] == "failed" and body and body.leave_partial):
        raise D.derr(409, "TRANSFER_STARTED", "Przenoszenie już rozpoczęto. W razie błędu wznów je, aby dokończyć wszystkie materiały.")
    await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid)
                             .where(D.CONN.c.folder_transfer_data == conn["folder_transfer_data"])
                             .values(folder_transfer_state="cancelled", folder_transfer_worker=None, folder_transfer_lease_until=None))
    again = await D.get_conn(pid)
    if not again or again.get("folder_transfer_state") != "cancelled" or data_of(again).get("id") != job_id:
        raise D.derr(409, "TRANSFER_CHANGED", "Stan operacji zmienił się. Odśwież jej szczegóły.")
    D.wake_worker()
    return {"transfer": public(again)}


@router.post("/pairs/{pair_id}/drive/transfer/{job_id}/resume")
async def resume_transfer(pair_id: str, job_id: str, actor: D.Actor = Depends(mentor_actor)):
    pid, conn, d = await owned_job(pair_id, job_id, actor)
    if conn["folder_transfer_state"] != "failed":
        return {"transfer": public(conn)}
    d["error"] = None
    await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid).where(D.CONN.c.folder_transfer_state == "failed")
                             .where(D.CONN.c.folder_transfer_data == conn["folder_transfer_data"])
                             .values(folder_transfer_state="queued" if d.get("started") else "preparing",
                                     folder_transfer_data=encode(d), folder_transfer_worker=None, folder_transfer_lease_until=None))
    D.wake_worker()
    return {"transfer": public(await D.get_conn(pid))}


async def folder(pid, folder_id):
    f = await access(pid, "get_file", folder_id)
    if f.get("trashed") or f.get("mimeType") != D.G.FOLDER_MIME:
        raise D.derr(409, "TRANSFER_FOLDER", "Jeden z folderów przestał być dostępny.")
    if f.get("driveId"):
        raise D.derr(409, "TRANSFER_SHARED_DRIVE", "Przenoszenie Teczki na Dyskach współdzielonych nie jest jeszcze dostępne.")
    return f


async def ancestry(pid, parent, source):
    path, seen = [], set()
    for _ in range(50):
        if parent == source:
            return list(reversed(path))
        if not parent or parent in seen:
            return None
        seen.add(parent)
        try:
            f = await folder(pid, parent)
        except D.HTTPException as exc:
            if getattr(exc, "error_code", "") != "FOLDER_UNAVAILABLE":
                raise
            # drive.file nie daje prawa do dowolnych przodków folderu wybranego w Pickerze.
            # Bez potwierdzenia przynależności plik zostaje pominięty; nie poszerzamy uprawnień.
            return None
        path.append(f.get("name") or "Folder")
        parent = (f.get("parents") or [None])[0]
    raise D.derr(409, "TRANSFER_DEPTH", "Foldery są zbyt głęboko zagnieżdżone, aby bezpiecznie przygotować przenoszenie.")


async def initialize(pid, conn, d):
    await folder(pid, d["source_id"])
    perms = await access(pid, "list_permissions", d["source_id"])
    d["source_signature"] = signature(perms)
    d["root_people"] = copyable(perms, root=True, own_email=conn.get("google_email") or "")
    if d.get("target_id"):
        target = await folder(pid, d["target_id"])
        caps = target.get("capabilities") or {}
        if not caps.get("canAddChildren") or not caps.get("canShare"):
            raise D.derr(409, "TRANSFER_TARGET_ACCESS", "Na nowym folderze potrzebny jest dostęp pozwalający dodawać pliki i nadawać uprawnienia.")
        if await ancestry(pid, d["target_id"], d["source_id"]) is not None:
            raise D.derr(409, "TRANSFER_NESTED", "Nowy folder nie może znajdować się wewnątrz obecnej Teczki.")
        target_perms = await access(pid, "list_permissions", d["target_id"])
        if any(p.get("expirationTime") for p in target_perms):
            raise D.derr(409, "TRANSFER_TEMPORARY_ACCESS", "Nowy folder ma dostęp z datą wygaśnięcia. Wybierz folder bez dostępów czasowych, aby zachować dotychczasowe zasady.")
        # Także publiczny lub domenowy dostęp w celu musi zostać jawnie rozpoznany.
        d["destination_people"] = [{"name": p.get("emailAddress") or p.get("domain") or "Każdy z linkiem",
                                     "role": p.get("role"), "type": p.get("type")} for p in target_perms if not p.get("deleted")]
        d["target_signature"] = signature(target_perms)
        d["target_name"], d["target_url"] = target.get("name"), target.get("webViewLink")
    else:
        d["destination_people"] = []
    d["candidates"] = [{"row_id": r["id"], "file_id": r["drive_file_id"], "name": r["name"]}
                       for r in await D.C.rows(select(D.FILES).where(D.FILES.c.pair_id == pid)
                                                .where(D.FILES.c.state == "done").where(D.FILES.c.drive_file_id.is_not(None))
                                                .order_by(D.FILES.c.id.asc()))]
    d["initialized"] = True


async def prepare_one(pid, d):
    if d["scan"] >= len(d["candidates"]):
        d["ready_at"] = D.C.now().isoformat()
        return "ready"
    item = dict(d["candidates"][d["scan"]])
    try:
        meta = await access(pid, "get_file", item["file_id"])
    except D.HTTPException as exc:
        if getattr(exc, "error_code", "") != "FOLDER_UNAVAILABLE":
            raise
        d["skipped"].append({"name": item["name"], "reason": "Plik nie jest dostępny na Dysku."})
        d["scan"] += 1
        return "preparing"
    parent = (meta.get("parents") or [None])[0]
    paths = d.setdefault("paths", {})
    if parent and parent not in paths and not meta.get("trashed") and not meta.get("driveId"):
        paths[parent] = await ancestry(pid, parent, d["source_id"])
    path = None if meta.get("trashed") or meta.get("driveId") else paths.get(parent)
    if path is None:
        d["skipped"].append({"name": item["name"], "reason": "Plik jest w koszu, poza obecną Teczką albo nie można potwierdzić jego położenia."})
    else:
        caps = meta.get("capabilities") or {}
        if not caps.get("canMoveItemWithinDrive") or not caps.get("canShare"):
            raise D.derr(409, "TRANSFER_FILE_ACCESS", "Brakuje uprawnień do przeniesienia jednego z klipów i zachowania jego dostępów. Sprawdź plik na Dysku.")
        perms = await access(pid, "list_permissions", item["file_id"])
        item.update(source_parent=parent, path=path, permissions=copyable(perms), source_signature=signature(perms))
        d["items"].append(item)
    d["scan"] += 1
    return "preparing"


async def grant(pid, file_id, required):
    current = await access(pid, "list_permissions", file_id)
    for p in required:
        same = next((x for x in current if x.get("type") == p["type"] and
                     (x.get("emailAddress") or "").lower() == p["emailAddress"].lower()), None)
        if same and RANK.get(same.get("role"), 0) >= RANK[p["role"]]:
            if not same.get("expirationTime") or (p.get("expirationTime") and same["expirationTime"] >= p["expirationTime"]):
                continue
        await access(pid, "transfer_permission", file_id, p, same)
        current = await access(pid, "list_permissions", file_id)


async def target_path(pid, d, names):
    parent = d["target_id"]
    for depth, name in enumerate(names):
        # Obcy podfolder o tej samej nazwie może mieć dodatkowe, niepotwierdzone dostępy.
        marker = hashlib.sha256(encode([d["id"], names[:depth + 1]]).encode()).hexdigest()
        found = await access(pid, "find_by_prop", parent, "baza_transfer", marker)
        if not found:
            found = await access(pid, "create_transfer_folder", name, marker, parent)
        memo = await D.C.one(select(D.FOLDERS).where(D.FOLDERS.c.pair_id == pid).where(D.FOLDERS.c.parent_id == parent)
                             .where(D.FOLDERS.c.name == name))
        if not memo:
            await D.database.execute(D.FOLDERS.insert().values(pair_id=pid, parent_id=parent, name=name, folder_id=found["id"], created_at=D.C.now()))
        else:
            await D.database.execute(update(D.FOLDERS).where(D.FOLDERS.c.pair_id == pid)
                                     .where(D.FOLDERS.c.parent_id == parent).where(D.FOLDERS.c.name == name)
                                     .values(folder_id=found["id"]))
        parent = found["id"]
    return parent


async def running_one(pid, conn, d, worker):
    if not d.get("target_id"):
        target = await access(pid, "find_by_prop", "root", "baza_transfer", d["id"])
        if not target:
            target = await access(pid, "create_transfer_folder", d["target_name"], d["id"])
        d["target_id"], d["target_url"] = target["id"], target.get("webViewLink")
        # Utrwalamy ID przed jakimkolwiek ruchem. appProperties pozwala znaleźć folder także po awarii tego zapisu.
        await checkpoint(pid, d, worker)
    if not d.get("root_shared"):
        await grant(pid, d["target_id"], d["root_people"])
        d["root_shared"] = True
        return "working"
    if d["moved"] < len(d["items"]):
        item = d["items"][d["moved"]]
        if not item.get("target_parent"):
            item["target_parent"] = await target_path(pid, d, item["path"])
            await checkpoint(pid, d, worker)
        meta = await access(pid, "get_file", item["file_id"])
        parents = meta.get("parents") or []
        if item["target_parent"] not in parents:
            if meta.get("trashed") or parents != [item["source_parent"]]:
                raise D.derr(409, "TRANSFER_FILE_CHANGED", "Po przygotowaniu zmieniono położenie jednego z plików. Przywróć go do starego miejsca i wznów przenoszenie.")
            if signature(await access(pid, "list_permissions", item["file_id"])) != item["source_signature"]:
                raise D.derr(409, "TRANSFER_FILE_ACCESS_CHANGED", "Dostęp do jednego z plików zmienił się po potwierdzeniu. Przywróć wcześniejsze dostępy i wznów przenoszenie.")
            await access(pid, "move_file", item["file_id"], item["source_parent"], item["target_parent"])
        # Jawne dostępy pliku pozostają przy ID; odtwarzamy także osoby, które wcześniej dziedziczyły dostęp.
        await grant(pid, item["file_id"], item["permissions"])
        d["moved"] += 1
        await D.database.execute(update(D.FILES).where(D.FILES.c.id == item["row_id"]).values(updated_at=D.C.now()))
        return "working"
    current = await access(pid, "list_permissions", d["target_id"])
    partner = (conn.get("partner_email") or "").lower()
    shared = any((p.get("emailAddress") or "").lower() == partner for p in current) if partner else False
    await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid).where(D.CONN.c.folder_id == d["source_id"])
                             .where(D.CONN.c.folder_transfer_worker == worker)
                             .values(folder_id=d["target_id"], folder_name=d["target_name"], folder_url=d.get("target_url"),
                                     folder_problem=None, access_snapshot=None, share_status="ok" if shared else "none",
                                     share_error=None, shared_at=D.C.now() if shared else None, updated_at=D.C.now(),
                                     folder_transfer_state="done", folder_transfer_data=encode(d),
                                     folder_transfer_worker=None, folder_transfer_lease_until=None))
    await D.C.touch(pid, d["actor_id"], "drive_folder_transfer", "drive")
    await D.log_event(pid, "folder_changed", actor_id=d["actor_id"], acted_by=d.get("acted_by"), details={"folder_name": d["target_name"]})
    return "done"


async def checkpoint(pid, d, worker):
    await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid).where(D.CONN.c.folder_transfer_worker == worker)
                             .values(folder_transfer_data=encode(d), folder_transfer_lease_until=D.C.now() + LEASE))


async def heartbeat(pid, worker):
    while True:
        await asyncio.sleep(20)
        await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid).where(D.CONN.c.folder_transfer_worker == worker)
                                 .values(folder_transfer_lease_until=D.C.now() + LEASE))


async def work_once(worker, now=None):
    now = now or D.C.now()
    for conn in await D.C.rows(select(D.CONN).where(D.CONN.c.folder_transfer_state.in_((*RUNNABLE, "ready")))):
        pid, d = conn["pair_id"], data_of(conn)
        if conn["folder_transfer_state"] == "ready":
            if D.R.aware(datetime.fromisoformat(d["ready_at"])) + timedelta(minutes=15) < now:
                await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid).where(D.CONN.c.folder_transfer_state == "ready")
                                         .where(D.CONN.c.folder_transfer_data == conn["folder_transfer_data"])
                                         .values(folder_transfer_state="expired"))
            continue
        held = D.R.aware(conn.get("folder_transfer_lease_until"))
        if held and held > now:
            continue
        # Dajemy już rozpoczętym uploadom skończyć. Nowe claim_next/process zatrzymuje znacznik transferu.
        uploading = await D.C.one(select(D.FILES.c.id).where(D.FILES.c.pair_id == pid).where(D.FILES.c.state == "working")
                                  .where(D.FILES.c.lease_until > now).limit(1))
        if uploading:
            continue
        await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid)
                                 .where(D.CONN.c.folder_transfer_state == conn["folder_transfer_state"])
                                 .where(D.CONN.c.folder_transfer_data == conn["folder_transfer_data"])
                                 .where(or_(D.CONN.c.folder_transfer_lease_until.is_(None), D.CONN.c.folder_transfer_lease_until < now))
                                 .values(folder_transfer_worker=worker, folder_transfer_lease_until=now + LEASE))
        owned = await D.get_conn(pid)
        if owned.get("folder_transfer_worker") != worker:
            continue
        pulse = asyncio.create_task(heartbeat(pid, worker))
        try:
            if conn.get("state") != "connected":
                continue
            if not d.get("initialized"):
                await initialize(pid, conn, d)
                state = "preparing"
            elif not d.get("started"):
                state = await prepare_one(pid, d)
            else:
                state = await running_one(pid, conn, d, worker)
            await save(pid, d, state, worker)
        except Exception as exc:
            # Wyłącznie własny komunikat lub kod; nigdy treść odpowiedzi Google ani token.
            d["error"] = (exc.detail.get("message") if isinstance(exc, D.HTTPException) and isinstance(exc.detail, dict)
                          else None) or "Nie udało się dokończyć operacji na Dysku. Sprawdź połączenie i użyj Wznów."
            await save(pid, d, "failed", worker)
        finally:
            pulse.cancel()
            try:
                await pulse
            except asyncio.CancelledError:
                pass
            await D.database.execute(update(D.CONN).where(D.CONN.c.pair_id == pid).where(D.CONN.c.folder_transfer_worker == worker)
                                     .values(folder_transfer_worker=None, folder_transfer_lease_until=None))
        return True
    return False
