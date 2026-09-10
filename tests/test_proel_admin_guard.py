"""Bramka tras admina z nagłówkami ProEla: dowód numeru, okres przejściowy, odmowa.

`app.proel_admin_guard` sięga do listy adminów i ustawień JWT dopiero w środku
funkcji, więc test podmienia listę i ustawienia - bez Postgresa i bez kompletu
zmiennych Railway. Moduły z trasami (`extra_reports`, `training_spk`,
`proel_users.users`) żądają żywej bazy przy imporcie, więc ich okablowanie
czytamy ze źródła.
"""

from __future__ import annotations

import ast
import pathlib
import sys
import time
from types import ModuleType, SimpleNamespace

import pytest
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import Column, MetaData, String, Table

from app import proel_admin_guard as guard
from app.proel_auth import Actor, proel_actor

SECRET = "test-secret"
ALG = "HS256"
ADMIN = "999"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    """Admin aplikacji to 999, zwykły sędzia to 8."""
    import app.deps

    monkeypatch.setattr(
        app.deps, "get_settings", lambda: SimpleNamespace(SECRET_KEY=SECRET, ALGORITHM=ALG)
    )

    async def claims_admin(judge_id):
        return str(judge_id or "").strip() == ADMIN

    monkeypatch.setattr(guard, "claims_admin", claims_admin)
    monkeypatch.delenv(guard.STRICT_ENV, raising=False)


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setenv(guard.STRICT_ENV, "1")


def baza_jwt(judge_id=ADMIN, *, exp_in=3600, secret=SECRET):
    claims = {
        "sub": "login",
        "judge_id": judge_id,
        "account_type": "judge",
        "exp": int(time.time()) + exp_in,
    }
    return jwt.encode(claims, secret, algorithm=ALG)


def actor(judge_id=ADMIN, *, verified=False, elevated=False):
    return Actor(
        judge_id=judge_id,
        installation_id="obca-instalacja",
        verified=verified,
        elevated=elevated,
    )


async def check(a=None, *, admin_token=None, account_header=False, path="/admin/extra-report/recipients"):
    return await guard.check_proel_admin(
        a or actor(),
        method="PUT",
        path=path,
        admin_token=admin_token,
        account_header=account_header,
    )


# ── dowód numeru ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "a, admin_token, account_header, proof, reason",
    [
        (actor(elevated=True, verified=True), None, False, guard.PROOF_ELEVATION, "ok"),
        (actor(verified=True), None, True, guard.PROOF_ACCOUNT, "ok"),
        (actor(), baza_jwt(), False, guard.PROOF_TOKEN, "ok"),
        (actor(), "Bearer " + baza_jwt(), False, guard.PROOF_TOKEN, "ok"),
        # sam rejestr urządzeń to NIE dowód - identyfikator instalacji bywa czytelny
        (actor(verified=True), None, False, None, "brak_tokenu"),
        (actor(), None, False, None, "brak_tokenu"),
        (actor(), "smieci", False, None, "niewazny_token"),
        (actor(), baza_jwt(secret="cudzy-sekret"), False, None, "niewazny_token"),
        (actor(), baza_jwt(exp_in=-10), False, None, "wygasly_token"),
        # token sędziego 8 nie potwierdza numeru 999 z nagłówka
        (actor(), baza_jwt("8"), False, None, guard.REASON_OTHER_JUDGE),
        # `Authorization` bez potwierdzonego aktora nic nie dowodzi
        (actor(), None, True, None, "brak_tokenu"),
    ],
)
def test_dowod_numeru(a, admin_token, account_header, proof, reason):
    assert guard.identity_proof(a, admin_token=admin_token, account_header=account_header) == (
        proof,
        reason,
    )


# ── rozstrzygnięcia ──────────────────────────────────────────────────────


@pytest.mark.parametrize("strict_value", ["", "1"])
async def test_nie_admin_przechodzi_bez_slowa_odmowe_daje_trasa(monkeypatch, caplog, strict_value):
    # 403 dla zwykłego sędziego zostaje takie, jakie dawała trasa - bramka
    # nie zmienia mu ani kodu, ani komunikatu.
    monkeypatch.setenv(guard.STRICT_ENV, strict_value)
    with caplog.at_level("WARNING"):
        assert await check(actor("8")) is None
    assert not caplog.records


async def test_atak_numerem_admina_w_okresie_przejsciowym_zostawia_slad(caplog):
    # Dokładnie ten atak: numer admina + losowa instalacja, bez tokenu.
    with caplog.at_level("WARNING"):
        assert await check(actor()) is None
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "[proel_admin_guard]" in text
    assert "powod=brak_tokenu" in text
    assert "judge_id=999" in text
    assert "urzadzenie=niepotwierdzone" in text
    assert "tryb=przejsciowy" in text


@pytest.mark.parametrize(
    "admin_token, status, fragment",
    [
        (None, 401, "Zaktualizuj aplikację"),
        ("smieci", 401, "zaloguj się ponownie"),
        (baza_jwt(exp_in=-10), 401, "Sesja administratora wygasła"),
        (baza_jwt("8"), 403, "nie zgadza się"),
    ],
)
async def test_po_zamknieciu_furtki_odmowa_z_powodem(strict, admin_token, status, fragment):
    with pytest.raises(HTTPException) as err:
        await check(actor(), admin_token=admin_token)
    assert err.value.status_code == status
    assert fragment in err.value.detail
    assert "—" not in err.value.detail and "–" not in err.value.detail


async def test_po_zamknieciu_furtki_zarejestrowane_urzadzenie_nie_wystarcza(strict):
    with pytest.raises(HTTPException) as err:
        await check(actor(verified=True))
    assert err.value.status_code == 401


@pytest.mark.parametrize(
    "a, admin_token, account_header, proof",
    [
        (actor(), baza_jwt(), False, guard.PROOF_TOKEN),
        (actor(elevated=True, verified=True), None, False, guard.PROOF_ELEVATION),
        (actor(verified=True), None, True, guard.PROOF_ACCOUNT),
    ],
)
async def test_po_zamknieciu_furtki_dowiedziony_admin_dalej_pracuje(strict, a, admin_token, account_header, proof):
    assert await check(a, admin_token=admin_token, account_header=account_header) == proof


async def test_awaria_listy_adminow_zostawia_decyzje_trasie(monkeypatch, strict):
    # Bez listy nie wiadomo, czy to admin - trasa zapyta o nią sama i odmówi.
    async def broken(judge_id):
        raise RuntimeError("baza lezy")

    monkeypatch.setattr(guard, "claims_admin", broken)
    assert await check(actor()) is None


# ── zależność na routerze + koperta błędu ────────────────────────────────


def _app(*, override_actor=True, a=None) -> FastAPI:
    app = FastAPI()

    @app.exception_handler(HTTPException)
    async def envelope(request: Request, exc: HTTPException):  # jak w main.py
        content = {"error": exc.detail}
        if isinstance(exc.detail, dict):
            content.update({k: v for k, v in exc.detail.items() if k != "error"})
        return JSONResponse(status_code=exc.status_code, content=content)

    router = APIRouter(prefix="/admin/extra-report", dependencies=[Depends(guard.proel_admin_guard)])

    @router.put("/recipients")
    async def save(actor: Actor = Depends(proel_actor)):
        return {"saved_by": actor.judge_id}

    app.include_router(router)
    if override_actor:
        app.dependency_overrides[proel_actor] = lambda: a or actor()
    return app


def test_router_twardy_odbija_w_kopercie_error_i_wpuszcza_z_tokenem(strict):
    client = TestClient(_app())

    res = client.put("/admin/extra-report/recipients")
    assert res.status_code == 401
    body = res.json()
    # Zasada projektu: błąd wraca jako {"error": ...}, nie {"detail": ...}.
    assert "error" in body and "detail" not in body
    assert isinstance(body["error"], str)

    ok = client.put("/admin/extra-report/recipients", headers={guard.ADMIN_TOKEN_HEADER: baza_jwt()})
    assert ok.status_code == 200 and ok.json() == {"saved_by": ADMIN}


def test_router_przejsciowy_nie_zmienia_zachowania_starych_aplikacji():
    client = TestClient(_app())
    assert client.put("/admin/extra-report/recipients").json() == {"saved_by": ADMIN}


def test_awaria_bramki_w_okresie_przejsciowym_nie_psuje_zadania(monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError("bramka pekla")

    monkeypatch.setattr(guard, "check_proel_admin", boom)
    client = TestClient(_app())
    res = client.put("/admin/extra-report/recipients")
    assert res.status_code == 200


@pytest.fixture
def push_tokens_bez_wiersza(monkeypatch):
    """`app.db` bez Postgresa: rejestr urządzeń nie zna żadnej instalacji."""
    table = Table(
        "push_tokens",
        MetaData(),
        Column("installation_id", String),
        Column("judge_id", String),
    )

    async def fetch_one(query):
        return None

    fake = ModuleType("app.db")
    fake.database = SimpleNamespace(fetch_one=fetch_one)
    fake.push_tokens = table
    monkeypatch.setitem(sys.modules, "app.db", fake)


def test_atak_przez_prawdziwy_proel_actor(strict, push_tokens_bez_wiersza):
    # Pełna droga, bez podmiany aktora: numer admina i losowa instalacja, której
    # nie ma w rejestrze. Przed bramką to wystarczało, żeby przepisać adresatów.
    client = TestClient(_app(override_actor=False))
    attack = {"X-Judge-Id": ADMIN, "X-Installation-Id": "losowa-instalacja"}
    assert client.put("/admin/extra-report/recipients", headers=attack).status_code == 401

    # Prawdziwy admin z tokenem BAZY w osobnym nagłówku przechodzi tą samą drogą.
    admin = {**attack, guard.ADMIN_TOKEN_HEADER: baza_jwt()}
    res = client.put("/admin/extra-report/recipients", headers=admin)
    assert res.status_code == 200 and res.json() == {"saved_by": ADMIN}


# ── okablowanie - czytane ze źródła, bo moduły tras żądają żywej bazy ────

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"


def _tree(filename: str) -> ast.Module:
    return ast.parse((APP_DIR / filename).read_text(encoding="utf-8"))


def _router_dependencies(filename: str, name: str) -> str:
    for node in ast.walk(_tree(filename)):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
            and isinstance(node.value, ast.Call)
        ):
            for kw in node.value.keywords:
                if kw.arg == "dependencies":
                    return ast.unparse(kw.value)
    return ""


@pytest.mark.parametrize("filename", ["extra_reports.py", "training_spk.py"])
def test_bramka_wisi_na_calym_routerze_admina(filename):
    # Na routerze, nie na trasach: nowa trasa admina jest chroniona bez
    # pamiętania o tym.
    assert "proel_admin_guard" in _router_dependencies(filename, "admin_router")


def _routes(filename: str):
    """(nazwa routera, metoda, ścieżka, zależności trasy) dla każdego dekoratora."""
    for node in ast.walk(_tree(filename)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and isinstance(dec.func.value, ast.Name)
                and dec.args
                and isinstance(dec.args[0], ast.Constant)
            ):
                continue
            deps = next((ast.unparse(k.value) for k in dec.keywords if k.arg == "dependencies"), "")
            yield dec.func.value.id, dec.func.attr, dec.args[0].value, deps


def test_kazda_trasa_admina_kont_proel_ma_bramke():
    admin_routes = [r for r in _routes("proel_users/users.py") if r[2].startswith("/admin")]
    # list, szczegóły, blokada, reset hasła, usunięcie
    assert len(admin_routes) == 5
    for _router, method, path, deps in admin_routes:
        assert deps == "_ADMIN_GUARD", (method, path)
    source = (APP_DIR / "proel_users" / "users.py").read_text(encoding="utf-8")
    assert "_ADMIN_GUARD = [Depends(proel_admin_guard)]" in source


def test_podpisany_adres_materialu_zostaje_poza_bramka():
    # Menedżer pobierania nie niesie nagłówków - adres podpisany musi zostać
    # na zwykłym routerze, inaczej materiał przestałby się pobierać.
    signed = [r for r in _routes("training_spk.py") if r[1] == "get" and r[2] == "/slides.pdf"]
    assert ("router", "get", "/slides.pdf", "") in signed


# ── uprawnienie admina W MECZU (miękka odmiana) ──────────────────────────
#
# Zatwierdzenie meczu, `POST /proel/patch` i przejęcie prowadzenia to nie są
# trasy admina: administrator tylko ROZSZERZA tam to, co aktor i tak może.
# Niedowiedziony numer ma stracić sam dodatek, nigdy całe żądanie.


@pytest.fixture(autouse=True)
def czysta_pamiec_logu():
    """Log miękkiej bramki jest dławiony w pamięci procesu - test zaczyna od zera."""
    guard._soft_log_seen.clear()
    yield
    guard._soft_log_seen.clear()


def rights(*, admin_token=None, account_header=False, path="/proel/patch"):
    return guard.AdminRights(
        admin_token=admin_token,
        account_header=account_header,
        method="POST",
        path=path,
    )


async def test_zwykly_sedzia_nie_dostaje_dodatku_i_nie_trafia_do_logu(caplog):
    with caplog.at_level("WARNING"):
        assert await rights().granted(actor("8")) is False
    assert not caplog.records


async def test_dowiedziony_admin_ma_uprawnienie_w_obu_trybach(monkeypatch):
    for strict_value in ("", "1"):
        monkeypatch.setenv(guard.STRICT_ENV, strict_value)
        assert await rights(admin_token=baza_jwt()).granted(actor()) is True
        assert await rights().granted(actor(elevated=True, verified=True)) is True
        assert await rights(account_header=True).granted(actor(verified=True)) is True


async def test_w_okresie_przejsciowym_uprawnienie_zostaje_ale_zostawia_slad(caplog):
    with caplog.at_level("WARNING"):
        assert await rights().granted(actor()) is True
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "[proel_admin_guard] uprawnienie admina w meczu niedowiedzione" in text
    assert "powod=brak_tokenu" in text
    assert "judge_id=999" in text
    assert "skutek=uprawnienie_zostaje" in text


async def test_po_zamknieciu_furtki_dodatek_znika_ZAMIAST_odmowy(strict, caplog):
    # Sedno miękkiej odmiany: żadnego wyjątku. Delegat, który przy okazji jest
    # adminem, ma dalej zatwierdzać swój mecz jako delegat, a sędzia z obsady
    # zapisywać pola, do których ma rolę - odmowę (jeśli w ogóle) wystawia
    # trasa, swoim dotychczasowym komunikatem.
    with caplog.at_level("WARNING"):
        assert await rights().granted(actor()) is False
    assert "skutek=role_z_obsady" in " ".join(r.getMessage() for r in caplog.records)


async def test_awaria_listy_adminow_nie_wywraca_zadania(monkeypatch, strict):
    async def broken(judge_id):
        raise RuntimeError("baza lezy")

    monkeypatch.setattr(guard, "claims_admin", broken)
    assert await rights().granted(actor()) is False


async def test_lista_adminow_czytana_RAZ_na_zadanie(monkeypatch):
    # `POST /proel/patch` przechodzi kilkanaście operacji w pętli i każda pyta
    # o uprawnienie - listy adminów nie ma powodu czytać po raz drugi.
    calls = []

    async def counting(judge_id):
        calls.append(judge_id)
        return str(judge_id) == ADMIN

    monkeypatch.setattr(guard, "claims_admin", counting)
    r = rights(admin_token=baza_jwt())
    for _ in range(5):
        assert await r.granted(actor()) is True
    assert len(calls) == 1


async def test_ten_sam_niedowiedziony_admin_nie_zasypuje_logu(caplog):
    # `GET /proel/state` odpytuje co kilka sekund - wpis przy każdym odpytaniu
    # schowałby pod sobą resztę logu Railway.
    r = rights(path="/proel/state")
    with caplog.at_level("WARNING"):
        for _ in range(4):
            assert await r.granted(actor()) is True
    assert len([x for x in caplog.records if "niedowiedzione" in x.getMessage()]) == 1


async def test_po_odczekaniu_wpis_wraca():
    key = ("999", "/proel/state", guard.REASON_NO_TOKEN)
    assert guard._soft_log_due(key, now=0.0) is True
    assert guard._soft_log_due(key, now=guard.SOFT_LOG_EVERY_SECONDS - 1) is False
    assert guard._soft_log_due(key, now=guard.SOFT_LOG_EVERY_SECONDS + 1) is True


def test_zaleznosc_miekka_niczego_nie_czyta_przed_uzyciem():
    # `proel_admin_rights` nie dotyka bazy: gdyby czytała listę adminów przy
    # każdym żądaniu, `GET /proel/state` płaciłby za to co kilka sekund.
    import inspect

    code = inspect.getsource(guard.proel_admin_rights)
    assert "claims_admin" not in code
    assert "Depends(proel_actor)" not in code


# ── okablowanie tras, które zostały bez bramki ───────────────────────────

HARD = "[Depends(proel_admin_guard)]"
SOFT = "Depends(proel_admin_rights)"


def _route(filename: str, method: str, path: str):
    found = [r for r in _routes(filename) if r[1] == method and r[2] == path]
    assert len(found) == 1, (filename, method, path, found)
    return found[0]


@pytest.mark.parametrize(
    "filename, method, path",
    [
        # cudzy protokół kasowany hurtem i pojedynczo
        ("proel.py", "delete", "/{match_number:path}"),
        # podgląd cudzej pracy w toku razem z nazwiskami prowadzących
        ("proel.py", "get", "/live"),
        # dziennik: kto co zmienił w cudzym meczu
        ("proel_journal.py", "get", "/matches"),
        ("proel_journal.py", "get", ""),
        # dziennik protokołów PDF i sprawdzanie plików
        ("results.py", "get", "/judge/results/protocol/audit"),
        ("results.py", "get", "/judge/results/protocol/audit/{code}"),
        ("results.py", "get", "/judge/results/protocol/audit/{code}/state"),
        ("results.py", "post", "/judge/results/protocol/verify"),
        ("results.py", "post", "/judge/results/protocol/verify-file"),
        ("results.py", "post", "/judge/results/protocol/scan"),
    ],
)
def test_trasy_admina_maja_bramke_twarda(filename, method, path):
    assert _route(filename, method, path)[3] == HARD


def test_cale_archiwum_jest_trase_admina():
    # Bramka na routerze, nie na trasach: nowa trasa w archiwum ma być
    # chroniona bez pamiętania o tym.
    assert "proel_admin_guard" in _router_dependencies("proel_archive.py", "router")


def test_zgloszenie_zdarzenia_z_aplikacji_zostaje_poza_bramka():
    # `POST /proel/journal/event` wysyła KAŻDA aplikacja po nieudanej wysyłce
    # do ZPRP - bramka zamieniłaby dziennik awarii w dziennik samych adminów.
    assert _route("proel_journal.py", "post", "/event")[3] == ""


def _route_function(filename: str, method: str, path: str) -> ast.AST:
    """Funkcja trasy - po dekoratorze `@router.<metoda>("<sciezka>")`."""
    for node in ast.walk(_tree(filename)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == method
                and dec.args
                and isinstance(dec.args[0], ast.Constant)
                and dec.args[0].value == path
            ):
                return node
    raise AssertionError((filename, method, path))


@pytest.mark.parametrize(
    "method, path",
    [("get", "/state"), ("post", "/ensure"), ("post", "/patch"), ("post", "/lease")],
)
def test_trasy_meczowe_dostaly_bramke_MIEKKA(method, path):
    # Tu admin tylko rozszerza uprawnienia, więc twarda bramka odbijałaby w
    # hali sędziego z obsady, który przy okazji jest administratorem: żadna z
    # tych tras nie ma `proel_admin_guard`, każda dostaje `AdminRights`.
    assert _route("proel.py", method, path)[3] == ""
    fn = _route_function("proel.py", method, path)
    defaults = ast.unparse(fn.args)
    assert SOFT in defaults, defaults


def test_zapis_meczu_przekazuje_dowod_do_reguly_zatwierdzania():
    # `PUT /proel/{numer}` buduje aktora sam z nagłówków, więc token BAZY musi
    # dojechać do `_may_approve` osobno - inaczej admin traciłby prawo do
    # zatwierdzenia dokładnie tam, gdzie go używa.
    source = (APP_DIR / "proel.py").read_text(encoding="utf-8")
    assert 'x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token")' in source
    assert "rights=admin_rights(" in source
