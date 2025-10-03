from datetime import date, datetime
from typing import Any, Optional, Literal, List
from pydantic import BaseModel, Field, HttpUrl

class EditJudgeRequest(BaseModel):
    username: str
    password: str
    judge_id: str
    Imie: Optional[str] = None
    Nazwisko: Optional[str] = None
    Miasto: Optional[str] = None
    KodPocztowy: Optional[str] = None
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
    app_version: Optional[str] = None
    app_opens: Optional[int] = None
    last_open_at: Optional[datetime] = None

class LoginRecordItem(BaseModel):
    judge_id: str
    full_name: str
    last_login_at: datetime
    app_version: Optional[str] = None
    app_opens: Optional[int] = None
    last_open_at: Optional[datetime] = None

class ListLoginRecordsResponse(BaseModel):
    records: list[LoginRecordItem]

class UpdateLoginRecordRequest(BaseModel):
    full_name: Optional[str] = None
    app_version: Optional[str] = None
    app_opens: Optional[int] = None
    last_open_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None

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

# ---------------- Stawki okręgowe (per-województwo) ----------------
class OkregRateItem(BaseModel):
    province: str          # np. "ŚLĄSKIE"
    content: Any           # dowolny JSON (jak w Twoich plikach z aplikacji)
    enabled: bool
    updated_at: datetime

class GetOkregRateResponse(BaseModel):
    file: OkregRateItem

class ListOkregRatesResponse(BaseModel):
    files: list[OkregRateItem]

class UpsertOkregRateRequest(BaseModel):
    province: str          # musi zgadzać się z path param
    content: Any
    enabled: bool = True

# ====== DISTANCES (okręgowe) ======

class OkregDistanceItem(BaseModel):
    province: str                      # np. "ŚLĄSKIE"
    content: Any                       # dowolny JSON (np. {cities:[], edges:[]})
    enabled: bool
    updated_at: Optional[datetime] = None

class ListOkregDistancesResponse(BaseModel):
    files: List[OkregDistanceItem]

class GetOkregDistanceResponse(BaseModel):
    file: OkregDistanceItem

class UpsertOkregDistanceRequest(BaseModel):
    province: str
    content: Any                       # Twój JSON tabeli odległości
    enabled: bool = True

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

# ------------------------- PROEL SAVED MATCHES -------------------------
class CreateSavedMatchRequest(BaseModel):
    match_number: str
    data_json: Any
    is_finished: Optional[bool] = False

class UpdateSavedMatchRequest(BaseModel):
    data_json: Any
    is_finished: Optional[bool] = None

class MatchItem(BaseModel):
    match_number: str
    updated_at: datetime
    data_json: Any
    is_finished: bool

class ListSavedMatchesResponse(BaseModel):
    matches: List[MatchItem]

# ------------------------- Najbliższe mecze z rozgrywki.zprp.pl -------------------------

class UpcomingMatchItem(BaseModel):
    Id: int = Field(..., description="ID meczu z query param Mecz")
    Id_rozgrywki: int | None = Field(None, description="ID rozgrywek z query param Rozgrywki")
    data_fakt: datetime | None = Field(None, description="Data i (opcjonalnie) czas meczu w strefie Europe/Warsaw")
    ID_zespoly_gosp_ZespolNazwa: str | None = None
    ID_zespoly_gosc_ZespolNazwa: str | None = None
    RozgrywkiCode: str | None = None
    code: str | None = None
    league: str | None = Field(None, description="Nazwa rozgrywek z atrybutu title wiersza")
    href: str | None = Field(None, description="Pełny URL do meczu na rozgrywki.zprp.pl")
    wynik: str | None = Field(None, description="np. '39 : 24' jeśli jest już wynik")

class UpcomingMatchesResponse(BaseModel):
    data: list[UpcomingMatchItem]

PlayersSide = Literal["home", "away", "both"]

class PlayerInfo(BaseModel):
    number: int
    full_name: str
    photo_url: Optional[HttpUrl] = None

class PlayersResponse(BaseModel):
    match_number: str
    home: Optional[List[PlayerInfo]] = None
    away: Optional[List[PlayerInfo]] = None

# --- Contacts (judges) upsert ---
class UpsertContactJudgeRequest(BaseModel):
    name: str = Field(..., description="Imię (pole 'name')")
    surname: str = Field(..., description="Nazwisko (pole 'surname')")
    city: Optional[str] = Field(None, description="Miasto")
    phone: Optional[str] = Field(None, description="Telefon")
    email: Optional[str] = Field(None, description="Email")
    # jeśli kiedyś chcesz wymusić nadpisanie nawet pustą wartością:
    overwrite: bool = Field(False, description="Jeśli True: nadpisuje istniejące pola podanymi wartościami (także pustymi)")

class UpsertContactJudgeResponse(BaseModel):
    success: bool
    action: Literal["created", "updated"]
    matched_index: Optional[int] = None
    matched_by: Optional[str] = None  # "name", "name+city", "none"

    # ---------------------------- APP VERSIONS ----------------------------
class VersionItem(BaseModel):
    id: int
    version: str
    name: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class ListVersionsResponse(BaseModel):
    versions: List[VersionItem]

class CreateVersionRequest(BaseModel):
    version: str  # "X.Y.Z"
    name: str
    description: Optional[str] = None

class UpdateVersionRequest(BaseModel):
    version: Optional[str] = None  # możesz pozwolić zmienić numer
    name: Optional[str] = None
    description: Optional[str] = None

