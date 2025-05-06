# app/schemas.py
from pydantic import BaseModel
from typing import Literal

class EditJudgeRequest(BaseModel):
    username: str
    password: str
    judge_id: str  # NrSedzia
    Imie: str
    Imie2: str
    Nazwisko: str
    NazwiskoRodowe: str
    Plec: Literal["M", "K"]
    DataUr: str      # YYYY-MM-DD
    Ulica: str
    KodPocztowy: str
    Miasto: str
    woj: str         # voivodeshipCode
    Telefon: str
    Email: str
    CzySedzia: str
    CzyDelegat: str
    NrSedzia_para: str
    Aktywny: str
