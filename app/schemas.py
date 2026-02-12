from datetime import date, datetime
from typing import Any, Dict, Optional, Literal, List
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
    title: str
    content: str
    image_url: Optional[str] = None
    priority: int
    link: Optional[str] = None
    full_name: str
    province: str                     # ⬅⬅⬅ NOWE

class UpdateAnnouncementRequest(AuthPayload):
    id: int
    title: Optional[str] = None
    content: Optional[str] = None
    image_url: Optional[str] = None
    priority: Optional[int] = None
    link: Optional[str] = None
    full_name: Optional[str] = None
    province: Optional[str] = None    # ⬅⬅⬅ NOWE


# 3) Żądanie usunięcia ogłoszenia
class DeleteAnnouncementRequest(AuthPayload):
    id: int

# ------------------- REAKCJE I KOMENTARZE (OGŁOSZENIA) -------------------

ReactionType = Literal["like", "love", "haha", "wow", "sad", "angry"]


class ReactionEntry(BaseModel):
    judge_id: str
    full_name: Optional[str] = None
    reaction: ReactionType | str
    created_at: datetime


class CommentEntry(BaseModel):
    id: str
    judge_id: str
    full_name: Optional[str] = None
    text: str
    created_at: datetime
    is_pinned: bool = False

class DeleteCommentRequest(BaseModel):
    judge_id: str
    full_name: Optional[str] = None
    comment_id: str


class ToggleReactionRequest(BaseModel):
    judge_id: str
    full_name: Optional[str] = None
    reaction: ReactionType


class AddCommentRequest(BaseModel):
    judge_id: str
    full_name: Optional[str] = None
    text: str

class PinCommentRequest(BaseModel):
    judge_id: str
    full_name: str
    comment_id: str
    pin: bool

# 4) Odpowiedź pojedynczego ogłoszenia
class AnnouncementResponse(BaseModel):
    id: int
    title: str
    content: str
    link: Optional[str] = None
    image_url: Optional[str] = None
    priority: int
    updated_at: datetime
    judge_name: Optional[str] = None
    province: str
    likes: List[ReactionEntry] = []
    comments: List[CommentEntry] = []


# 5) Odpowiedź listy ogłoszeń
class ListAnnouncementsResponse(BaseModel):
    announcements: List[AnnouncementResponse]

# 6) Odpowiedź z datą ostatniej aktualizacji
class LastUpdateResponse(BaseModel):
    last_update: Optional[datetime] # type: ignore
    

# 7) Żądanie ustawienia / nadpisania niedyspozycji sędziego
class SetOfftimesRequest(BaseModel):
  judge_id: str
  full_name: str
  city: Optional[str]
  data_json: Any
  province: str                  # ⬅⬅⬅ NOWE

class OfftimeRecord(BaseModel):
  judge_id: str
  province: str                  # ⬅⬅⬅ NOWE
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

class TargetFilters(BaseModel):
    judge_ids: Optional[List[str]] = None
    provinces: Optional[List[str]] = None
    versions: Optional[List[str]] = None

class CreateAdminPostRequest(BaseModel):
    title: str
    content: str
    link: Optional[str]
    # ⬇⬇⬇ NOWE ⬇⬇⬇
    button_text: Optional[str] = None
    target_filters: Optional[TargetFilters] = None

class AdminPostItem(BaseModel):
    id: int
    title: str
    content: str
    link: Optional[str]
    # ⬇⬇⬇ NOWE ⬇⬇⬇
    button_text: Optional[str] = None
    target_filters: Optional[TargetFilters] = None
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
    province: Optional[str] = None
    config_json: Optional[Any] = None

class LoginRecordItem(BaseModel):
    judge_id: str
    full_name: str
    last_login_at: datetime
    app_version: Optional[str] = None
    app_opens: Optional[int] = None
    last_open_at: Optional[datetime] = None
    province: Optional[str] = None
    config_json: Any = Field(default_factory=dict)

class ListLoginRecordsResponse(BaseModel):
    records: list[LoginRecordItem]

class UpdateLoginRecordRequest(BaseModel):
    full_name: Optional[str] = None
    app_version: Optional[str] = None
    app_opens: Optional[int] = None
    last_open_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    province: Optional[str] = None
    config_json: Optional[Any] = None

# ------------------------- BAZA VIPs -------------------------

class BazaVipUpsertRequest(BaseModel):
    """
    Wywoływane po udanym logowaniu do baza.zprp.pl, gdy:
    - mamy pewność, że login działa
    - ale nie mamy judge_id (lub mamy i chcemy go zlinkować)
    """
    username: str
    judge_id: Optional[str] = None

    # jeśli już znasz z profilu – wyślij; jeśli nie – zostaw None
    province: Optional[str] = None

    # dowolne dane diagnostyczne: platforma, app_version, itp.
    login_info_json: Optional[Any] = None


class BazaVipItem(BaseModel):
    id: int
    username: str
    judge_id: Optional[str] = None
    province: Optional[str] = None
    permissions_json: Any = Field(default_factory=dict)
    login_info_json: Any = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime


class BazaVipUpsertResponse(BaseModel):
    success: bool
    created: bool
    record: Optional[BazaVipItem] = None


class BazaVipUpdateRequest(BaseModel):
    """
    Do panelu/admina (lub Twojego narzędzia serwisowego):
    ustawienie województwa i/lub uprawnień.
    """
    judge_id: Optional[str] = None
    province: Optional[str] = None
    permissions_json: Optional[Any] = None
    login_info_json: Optional[Any] = None


class ListBazaVipsResponse(BaseModel):
    records: List[BazaVipItem]

class ZprpScheduleScrapeRequest(BaseModel):
    username: str  # RSA+base64
    password: str  # RSA+base64
    season_id: Optional[str] = None


# ------------------------- SĘDZIOWIE PER WOJEWÓDZTWO (BADGES) -------------------------

class CreateProvinceJudgeRequest(BaseModel):
    judge_id: str
    full_name: str
    province: str
    badges: Optional[Any] = None  # domyślnie backend ustawi {}


class UpdateProvinceJudgeRequest(BaseModel):
    full_name: Optional[str] = None
    province: Optional[str] = None
    badges: Optional[Any] = None


class ProvinceJudgeItem(BaseModel):
    judge_id: str
    full_name: str
    province: str
    badges: Any
    updated_at: datetime


class ListProvinceJudgesResponse(BaseModel):
    records: list[ProvinceJudgeItem]

# ---------------------------- BADGES (definicje) ----------------------------

class CreateBadgeRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    meta_json: Any = Field(default_factory=dict, description="Charakterystyka badge'a jako JSON")

class UpdateBadgeRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    meta_json: Optional[Any] = None

class BadgeItem(BaseModel):
    id: int
    name: str
    meta_json: Any
    updated_at: datetime

class ListBadgesResponse(BaseModel):
    badges: List[BadgeItem]


class SetForcedLogoutRequest(BaseModel):
    logout_at: datetime  # ISO‑8601

class ForcedLogoutResponse(BaseModel):
    logout_at: Optional[datetime]  # może być None, jeśli jeszcze nie ustawiono

class ForcedLogoutRuleItem(BaseModel):
    id: int
    logout_at: datetime
    filters: Optional[TargetFilters] = None
    created_at: datetime

class CreateForcedLogoutRuleRequest(BaseModel):
    logout_at: datetime
    filters: Optional[TargetFilters] = None

class ListForcedLogoutRulesResponse(BaseModel):
    rules: List[ForcedLogoutRuleItem]


# MODUŁ OKRĘOWY - MASTERS
# Klucz = PROVINCE (np. "ŚLĄSKIE"), wartość = lista ID sędziów
MastersMap = Dict[str, List[str]]

class ListMastersResponse(BaseModel):
    news: MastersMap
    calendar: MastersMap
    match: MastersMap
    teach: MastersMap   # ⬅⬅⬅ NOWE – Teach Masters w tym samym formacie

class UpdateMastersRequest(BaseModel):
    news: MastersMap
    calendar: MastersMap
    match: MastersMap
    teach: MastersMap   # ⬅⬅⬅ NOWE – Teach Masters w tym samym formacie

# ---------------- ZPRP MASTERS ----------------
class ListZprpMastersResponse(BaseModel):
    masters: List[str]

class UpdateZprpMastersRequest(BaseModel):
    masters: List[str]

# ---------------- Aktywne okręgi ----------------
class ActiveProvinceItem(BaseModel):
    province: str
    enabled: bool
    updated_at: datetime

class GetActiveProvinceResponse(BaseModel):
    file: ActiveProvinceItem

class ListActiveProvincesResponse(BaseModel):
    files: List[ActiveProvinceItem]

class UpsertActiveProvinceRequest(BaseModel):
    province: str
    enabled: bool = True


# ---------------- Kluby rozliczane ----------------
class SettlementClubsItem(BaseModel):
    province: str
    clubs: Any                                # np. lista słowników lub mapa {club_id: {...}}
    updated_at: Optional[datetime] = None

class GetSettlementClubsResponse(BaseModel):
    file: SettlementClubsItem

class ListSettlementClubsResponse(BaseModel):
    files: List[SettlementClubsItem]

class UpsertSettlementClubsRequest(BaseModel):
    province: str
    clubs: Any                                # pełny JSON, który chcesz przechowywać


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

# ---------------- Stawki okręgowe (per-województwo) - WERSJONOWANE ----------------

class OkregRateItem(BaseModel):
    # NOWE (ale opcjonalne => zgodność wsteczna)
    id: Optional[int] = None
    valid_from: Optional[date] = None
    valid_to: Optional[date] = None

    province: str
    content: Any
    enabled: bool
    updated_at: datetime


class GetOkregRateResponse(BaseModel):
    file: OkregRateItem


class ListOkregRatesResponse(BaseModel):
    files: List[OkregRateItem]


class UpsertOkregRateRequest(BaseModel):
    """
    Backward compatible:
    - stare klienty wysyłają: province, content, enabled
    - nowe mogą dodać: id, valid_from, valid_to
    """
    province: str
    content: Any
    enabled: bool = True

    # NOWE (opcjonalne)
    id: Optional[int] = None
    valid_from: Optional[date] = None
    valid_to: Optional[date] = None


# --- Nowe modele do zarządzania wieloma wersjami (CRUD) ---

class ListOkregRateVersionsResponse(BaseModel):
    files: List[OkregRateItem]


class CreateOkregRateVersionRequest(BaseModel):
    province: str
    content: Any
    enabled: bool = True
    valid_from: Optional[date] = None
    valid_to: Optional[date] = None


class UpdateOkregRateVersionRequest(BaseModel):
    # province trzymamy w path; tu same pola modyfikowalne
    content: Optional[Any] = None
    enabled: Optional[bool] = None
    valid_from: Optional[date] = None
    valid_to: Optional[date] = None

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


# ---------------------------------
# MŁODZI SĘDZIOWIE – SCHEMAS
# ---------------------------------

class CreateYoungRefereeRequest(BaseModel):
    full_name: str
    base_judge_id: Optional[str] = None
    province: str                        # np. "ŚLĄSKIE"
    is_active: bool = True


class UpdateYoungRefereeRequest(BaseModel):
    full_name: Optional[str] = None
    base_judge_id: Optional[str] = None
    province: Optional[str] = None
    is_active: Optional[bool] = None


class YoungRefereeItem(BaseModel):
    id: int
    full_name: str
    base_judge_id: Optional[str] = None
    province: str
    is_active: bool


class ListYoungRefereesResponse(BaseModel):
    records: List[YoungRefereeItem]


class CreateYoungRefereeRatingRequest(BaseModel):
    rating_date: Optional[datetime] = None  # jeśli None – backend może ustawić "teraz"
    province: str
    mentor_name: str
    young_referee_name: str
    young_referee_id: int
    young_referee2_name: Optional[str] = None
    young_referee2_id: Optional[int] = None
    rating: Any                              # JSON z oceną


class UpdateYoungRefereeRatingRequest(BaseModel):
    rating_date: Optional[datetime] = None
    province: Optional[str] = None
    mentor_name: Optional[str] = None
    young_referee_name: Optional[str] = None
    young_referee_id: Optional[int] = None
    young_referee2_name: Optional[Optional[str]] = None
    young_referee2_id: Optional[Optional[int]] = None
    rating: Optional[Any] = None


class YoungRefereeRatingItem(BaseModel):
    id: int
    rating_date: datetime
    province: str
    mentor_name: str
    young_referee_name: str
    young_referee_id: int
    young_referee2_name: Optional[str] = None
    young_referee2_id: Optional[int] = None
    rating: Any


class ListYoungRefereeRatingsResponse(BaseModel):
    records: List[YoungRefereeRatingItem]

class YoungRefereeRatingTemplateOut(BaseModel):
    id: int
    province: str
    template: Any = Field(..., description="JSON szablonu oceny")
    updated_at: datetime

class YoungRefereeRatingTemplateUpsert(BaseModel):
    province: str
    template: Any = Field(..., description="JSON szablonu oceny")

# ---------------------------------
# MŁODZI SĘDZIOWIE – WIDOCZNOŚĆ OCEN (per województwo)
# ---------------------------------

class YoungRefereeRatingsVisibilityItem(BaseModel):
    province: str
    enabled: bool
    updated_at: datetime

class UpsertYoungRefereeRatingsVisibilityRequest(BaseModel):
    province: str
    enabled: bool = True


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
    to_show: bool = False
    created_at: datetime
    updated_at: datetime


class ListVersionsResponse(BaseModel):
    versions: List[VersionItem]


class CreateVersionRequest(BaseModel):
    version: str  # "X.Y.Z"
    name: str
    description: Optional[str] = None
    to_show: Optional[bool] = False


class UpdateVersionRequest(BaseModel):
    version: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    to_show: Optional[bool] = None


# ---------------------------- Niedyspozcyje partnera ----------------------------
class PartnerOfftimeBase(BaseModel):
    judge_id: str
    full_name: str
    partner_id: Optional[str] = None
    data_json: Any


class CreatePartnerOfftimeRequest(PartnerOfftimeBase):
    pass


class UpdatePartnerOfftimeRequest(BaseModel):
    full_name: Optional[str] = None
    partner_id: Optional[str] = None
    data_json: Optional[Any] = None


class PartnerOfftimeItem(PartnerOfftimeBase):
    updated_at: datetime

    class Config:
        orm_mode = True


class ListPartnerOfftimesResponse(BaseModel):
    records: List[PartnerOfftimeItem]


class GetPartnerOfftimeResponse(BaseModel):
    record: PartnerOfftimeItem

# ------------------------- Rejestr "wyniku skróconego" -------------------------

class CreateShortResultRecordRequest(BaseModel):
    match_number: str
    author_id: str
    author_name: Optional[str] = None
    payload: Any

class ShortResultRecordItem(BaseModel):
    id: int
    created_at: datetime
    match_number: str
    author_id: str
    author_name: Optional[str] = None
    payload: Any

class ListShortResultRecordsResponse(BaseModel):
    records: List[ShortResultRecordItem]
