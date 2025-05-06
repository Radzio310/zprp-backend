from typing import Optional
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
