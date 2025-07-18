from datetime import date, datetime
from typing import Any, Optional, Literal, List
from pydantic import BaseModel, Field

class EditJudgeRequest(BaseModel):
    username: str
    password: str
    judge_id: str
    Imie: Optional[str] = None
    Nazwisko: Optional[str] = None
    Miasto: Optional[str] = None
    Telefon: Optional[str] = None
    Email: Optional[str] = None

class BatchOffTimeRequest(BaseModel):
    username: str     # Base64‑RSA
    password: str
    judge_id: str
    actions: str      # Base64‑RSA całego JSON array

# — wspólny bazowy model uwierzytelniający (wszystko zaszyfrowane Base64-RSA) —
class AuthPayload(BaseModel):
    username: str   # Base64-RSA
    password: str   # Base64-RSA
    judge_id: str   # Base64-RSA

# 1) Żądanie utworzenia ogłoszenia
class CreateAnnouncementRequest(AuthPayload):
    title: str      # zaszyfrowany Base64-RSA
    content: str    # zaszyfrowany Base64-RSA
    image_url: Optional[str] = None  # zaszyfrowany Base64-RSA lub plaintext URL
    priority: int
    link: Optional[str] = None
    full_name: str

# 2) Żądanie aktualizacji ogłoszenia
class UpdateAnnouncementRequest(AuthPayload):
    id: int
    title: Optional[str] = None
    content: Optional[str] = None
    image_url: Optional[str] = None
    priority: Optional[int] = None
    link: Optional[str] = None
    full_name: Optional[str] = None

# 3) Żądanie usunięcia ogłoszenia
class DeleteAnnouncementRequest(AuthPayload):
    id: int

# 4) Odpowiedź pojedynczego ogłoszenia
class AnnouncementResponse(BaseModel):
    id: int
    title: str
    content: str
    link: Optional[str] = None  # może być pusty
    image_url: Optional[str]
    priority: int
    updated_at: datetime
    judge_name: Optional[str] = None

# 5) Odpowiedź listy ogłoszeń
class ListAnnouncementsResponse(BaseModel):
    announcements: List[AnnouncementResponse]

# 6) Odpowiedź z datą ostatniej aktualizacji
class LastUpdateResponse(BaseModel):
    last_update: Optional[datetime] # type: ignore
    

# 7) Żądanie ustawienia / nadpisania niedyspozycji sędziego
class SetOfftimesRequest(BaseModel):
  judge_id: str       # Base64-RSA
  full_name: str      # Base64-RSA
  city: Optional[str] # Base64-RSA  ← jeśli szyfrujemy
  data_json: Any      # Base64-RSA JSON array

class OfftimeRecord(BaseModel):
  judge_id: str
  full_name: str
  city: Optional[str]
  data_json: Any
  updated_at: datetime

class ListOfftimesResponse(BaseModel):
  record: OfftimeRecord

class ListAllOfftimesResponse(BaseModel):
  records: List[OfftimeRecord]


class MatchOfferRequest(AuthPayload):
    full_name: str       # Base64-RSA
    match_data: str      # Base64-RSA JSON

class MatchAssignmentRequest(AuthPayload):
    full_name: str       # Base64-RSA

class ApprovalActionRequest(AuthPayload):
    # ewentualne pola na decyzję (np. komentarz)
    pass

class OfferItem(BaseModel):
    id: int
    judge_id: str
    judge_name: str
    match_data: dict

class ListOffersResponse(BaseModel):
    offers: List[OfferItem]

class ApprovalItem(BaseModel):
    id: int
    original_offer_id: int
    judge_id: str
    judge_name: str
    match_data: dict
    assign_judges: List[str]
    assign_names: List[str]
    requested_at: datetime

class ListApprovalsResponse(BaseModel):
    approvals: List[ApprovalItem]

# PANEL ADMINA
## PIN‑y adminów
class ValidatePinRequest(BaseModel):
    judge_id: str      # plaintext ID sędziego
    pin: str           # plaintext PIN

class ValidatePinResponse(BaseModel):
    valid: bool

class UpdatePinRequest(BaseModel):
    judge_id: str      # plaintext ID sędziego
    new_pin: str       # plaintext nowego PIN-u

## LISTA ADMINÓW

class UpdateAdminsRequest(BaseModel):
    allowed_admins: List[str]

class ListAdminsResponse(BaseModel):
    allowed_admins: List[str]

class GenerateHashRequest(BaseModel):
    pin: str = Field(..., min_length=1, max_length=32, description="Dowolny PIN do zhashowania")

class GenerateHashResponse(BaseModel):
    hash: str = Field(..., description="bcrypt‑owy hash wejściowego PINu")

## BUDUJMY RAZEM BAZĘ
class CreateUserReportRequest(BaseModel):
    judge_id: str
    full_name: str
    phone: str
    email: Optional[str]
    type: Literal["pomysl","awaria","pytanie"]
    content: str

class UserReportItem(BaseModel):
    id: int
    judge_id: str
    full_name: str
    phone: str
    email: Optional[str]
    type: str
    content: str
    created_at: datetime
    is_read: bool

class ListUserReportsResponse(BaseModel):
    reports: List[UserReportItem]

class CreateAdminPostRequest(BaseModel):
    title: str
    content: str
    link: Optional[str]

class AdminPostItem(BaseModel):
    id: int
    title: str
    content: str
    link: Optional[str]
    created_at: datetime

class ListAdminPostsResponse(BaseModel):
    posts: List[AdminPostItem]

# UŻYTKOWNICY
# 1) Żądanie (upsert) rekordu logowania
class CreateLoginRecordRequest(BaseModel):
    judge_id: str
    full_name: str

# 2) Jeden rekord w odpowiedzi
class LoginRecordItem(BaseModel):
    judge_id: str
    full_name: str
    last_login_at: datetime

# 3) Lista rekordów
class ListLoginRecordsResponse(BaseModel):
    records: list[LoginRecordItem]

class SetForcedLogoutRequest(BaseModel):
    logout_at: datetime  # ISO‑8601

class ForcedLogoutResponse(BaseModel):
    logout_at: Optional[datetime]  # może być None, jeśli jeszcze nie ustawiono

# MODUŁ ŚLĄSKI
class ListMastersResponse(BaseModel):
    news: List[str]
    calendar: List[str]
    match: List[str]

class UpdateMastersRequest(BaseModel):
    news: List[str]
    calendar: List[str]
    match: List[str]

# Pliki źródłowe
class JsonFileItem(BaseModel):
    key: str
    content: Any
    enabled: bool
    updated_at: datetime

class GetJsonFileResponse(BaseModel):
    file: JsonFileItem

class ListJsonFilesResponse(BaseModel):
    files: List[JsonFileItem]

class UpsertJsonFileRequest(BaseModel):
    key: str
    content: Any
    enabled: bool

# ---------------------------- HALE ----------------------------
class CreateHallReportRequest(BaseModel):
    Hala_nazwa: str
    Hala_miasto: str
    Hala_ulica: str
    Hala_numer: str
    Druzyny: List[str]

class HallReportItem(BaseModel):
    id: int
    Hala_nazwa: str
    Hala_miasto: str
    Hala_ulica: str
    Hala_numer: str
    Druzyny: List[str]
    created_at: datetime

class ListHallReportsResponse(BaseModel):
    reports: List[HallReportItem]

# ---------------- NIEDYSPOZYCYJNOŚĆ ŚLĄSKA ----------------
# 20) Dodatkowe modele dla rozszerzonego modułu niedyspozycji

class GoogleEvent(BaseModel):
    event_id: str
    summary: str
    start: datetime
    end: datetime

class GoogleSyncRequest(BaseModel):
    username: str
    password: str
    judge_id: str
    # nie szyfrujemy listy, bo zapytanie robimy po zalogowaniu

class OffTimeAction(BaseModel):
    type: Literal["create", "update", "delete"]
    IdOffT: Optional[int]    # id rekordu w silesia_offtimes, do update/delete
    DataOd: date
    DataDo: date
    Info: str

