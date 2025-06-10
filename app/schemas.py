import datetime
from typing import Optional, Literal, List
from pydantic import BaseModel

class EditJudgeRequest(BaseModel):
    username: str
    password: str
    judge_id: str
    Imie: Optional[str] = None
    Nazwisko: Optional[str] = None
    Miasto: Optional[str] = None
    Telefon: Optional[str] = None
    Email: Optional[str] = None
class OffTimeAction(BaseModel):
    type: Literal["create", "update", "delete"]
    IdOffT: Optional[str]   # dla create może być None lub ""
    DataOd: str             # w formacie DD.MM.YYYY
    DataDo: str
    Info: str

class BatchOffTimeRequest(BaseModel):
    username: str     # Base64‑RSA
    password: str
    judge_id: str
    actions: str      # Base64‑RSA całego JSON array

