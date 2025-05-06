# app/edit_judge.py
from fastapi import APIRouter, HTTPException, status
from httpx import AsyncClient
from app.schemas import EditJudgeRequest
from app.utils import fetch_with_correct_encoding
from app.deps import get_settings, Settings

router = APIRouter()

@router.post("/judge/edit")
async def edit_judge(data: EditJudgeRequest, settings: Settings = Depends(get_settings)):
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True) as client:
        # 1) Logowanie
        resp_login, html_login = await fetch_with_correct_encoding(
            client,
            "/login.php",
            method="POST",
            data={
                "login": data.username,
                "haslo": data.password,
                "from": "/index.php?",
            },
        )
        if "/index.php" not in resp_login.url.path:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Logowanie nie powiodło się")

        cookies = dict(resp_login.cookies)

        # 2) Przygotowanie danych do edycji
        form_payload = {
            "NrSedzia": data.judge_id,
            "Imie": data.Imie,
            "Imie2": data.Imie2,
            "Nazwisko": data.Nazwisko,
            "NazwiskoRodowe": data.NazwiskoRodowe,
            "Plec": data.Plec,
            "DataUr": data.DataUr,
            "Ulica": data.Ulica,
            "KodPocztowy": data.KodPocztowy,
            "Miasto": data.Miasto,
            "woj": data.woj,
            "Telefon": data.Telefon,
            "Email": data.Email,
            "CzySedzia": data.CzySedzia,
            "CzyDelegat": data.CzyDelegat,
            "NrSedzia_para": data.NrSedzia_para,
            "Aktywny": data.Aktywny,
            "akcja": "ZAPISZ",
        }

        # 3) Wysłanie POST do zapisu
        path = f"/index.php?a=sedzia&b=edycja&NrSedzia={data.judge_id}"
        resp_edit, html_edit = await fetch_with_correct_encoding(
            client, path, method="POST", data=form_payload, cookies=cookies
        )

        # 4) Sprawdzenie sukcesu: jeżeli w odpowiedzi nie ma formularza edycji, to uznajemy że zapis poszedł
        if "name='edycja'" in html_edit:
            # nadal widzimy form edycji → pewnie błąd walidacji
            # można spróbować wyciągnąć jakiś komunikat z html_edit
            return {"success": False, "error": "Nie udało się zapisać – niezamierzony powrót do formularza."}
        else:
            return {"success": True}
