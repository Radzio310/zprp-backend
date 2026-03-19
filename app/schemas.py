from datetime import date, datetime
from typing import Any, Dict, Optional, Literal, List
from pydantic import BaseModel, Field, HttpUrl, validator

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
    photo_url: Optional[str] = None  # ✅ NOWE
    config_json: Optional[Any] = None

class LoginRecordItem(BaseModel):
    judge_id: str
    full_name: str
    last_login_at: datetime
    app_version: Optional[str] = None
    app_opens: Optional[int] = None
    last_open_at: Optional[datetime] = None
    province: Optional[str] = None
    photo_url: str = ""  # ✅ NOWE (spójne z DB default "")
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
    photo_url: Optional[str] = None  # ✅ NOWE
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
    username: str
    password: str
    judge_id: Optional[str] = None
    # sezon
    season_id: Optional[str] = None
    # NOWE: ograniczenia pobierania
    filtr_kategoria: Optional[str] = None   # np. "1|M" (w URL: 1%7CM)
    id_rozgr: Optional[str] = None          # np. "11625"



# ------------------------- SĘDZIOWIE PER WOJEWÓDZTWO (BADGES) -------------------------

class CreateProvinceJudgeRequest(BaseModel):
    judge_id: str
    full_name: str
    province: str
    photo_url: Optional[str] = None  # ✅ NOWE: domyślnie backend ustawi ""
    badges: Optional[Any] = None     # domyślnie backend ustawi {}


class UpdateProvinceJudgeRequest(BaseModel):
    full_name: Optional[str] = None
    province: Optional[str] = None
    photo_url: Optional[str] = None  # ✅ NOWE
    badges: Optional[Any] = None


class ProvinceJudgeItem(BaseModel):
    judge_id: str
    full_name: str
    province: str
    photo_url: str  # ✅ NOWE
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

# ---------------------------- WYDARZENIA OKRĘGOWE ----------------------------

class ProvinceEventTarget(BaseModel):
    """
    Targetowanie zaproszeń:
    - include_badges: zaproś tylko tych, którzy mają przynajmniej jeden z badge’y
    - exclude_badges: wyklucz tych, którzy mają którykolwiek z badge’y
    - include_all: jeśli True, ignoruje include_badges (ale nadal respektuje exclude_badges)
    """
    include_badges: List[str] = Field(default_factory=list)
    exclude_badges: List[str] = Field(default_factory=list)
    include_all: bool = False


class ProvinceEventData(BaseModel):
    """
    Dowolny JSON. Trzymamy ustandaryzowane klucze,
    ale backend nie ogranicza dodatkowych pól.
    """
    target: ProvinceEventTarget = Field(default_factory=ProvinceEventTarget)

    # zapisujemy listę zaproszonych (wyliczoną lub ręcznie nadpisaną)
    invited_ids: List[str] = Field(default_factory=list)

    # obecność
    present_ids: List[str] = Field(default_factory=list)

    # opcjonalnie cache nazw/mini-profili (app może to uzupełniać)
    invited_cache: Optional[Any] = None


class CreateProvinceEventRequest(BaseModel):
    province: str
    event_date: datetime
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    data_json: Optional[Any] = None   # przyjmujemy dowolne, backend znormalizuje do ProvinceEventData


class UpdateProvinceEventRequest(BaseModel):
    province: Optional[str] = None
    event_date: Optional[datetime] = None
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[Optional[str]] = None
    data_json: Optional[Any] = None


class UpdateProvinceEventAttendanceRequest(BaseModel):
    """
    Aktualizacja obecności: wysyłasz pełną listę present_ids (prościej i stabilniej).
    """
    present_ids: List[str] = Field(default_factory=list)


class ProvinceEventItem(BaseModel):
    id: int
    province: str
    event_date: datetime
    name: str
    description: Optional[str] = None
    data_json: Any = Field(default_factory=dict)
    updated_at: datetime

    # computed (backend dopina dla wygody UI)
    invited_total: int = 0
    present_total: int = 0
    user_invited: bool = False
    user_present: bool = False


class ListProvinceEventsResponse(BaseModel):
    events: List[ProvinceEventItem]


# ---------------------------- PROVINCE TRAVEL (przejazdy) ----------------------------

class ProvinceTravelUpsertAllRequest(BaseModel):
    judge_id: str
    full_name: str
    province: str
    data_json: Any  # pełny JSON z przejazdami (np. {"seasons": {...}})

class ProvinceTravelUpsertSeasonRequest(BaseModel):
    judge_id: str
    full_name: str
    province: str
    season_key: str            # np. "2024/2025"
    season_json: Any           # JSON tylko dla danego sezonu (dowolna struktura)
    season_updated_at: Optional[datetime] = None  # opcjonalnie z klienta

class ProvinceTravelItem(BaseModel):
    judge_id: str
    full_name: str
    province: str
    data_json: Any
    updated_at: datetime

class GetProvinceTravelResponse(BaseModel):
    record: Optional[ProvinceTravelItem] = None

class ListProvinceTravelResponse(BaseModel):
    records: List[ProvinceTravelItem]

# ---------------------------- MENTOR GRADES (rated/pending counters) ----------------------------

class MentorGradesPayload(BaseModel):
    rated: int = 0
    pending: int = 0
    total: Optional[int] = None
    season: Optional[str] = None  # opcjonalnie, jeśli chcesz dopinać po stronie appki


class MentorGradesUpsertRequest(BaseModel):
    judge_id: str
    full_name: str
    province: str
    grades_json: Any  # np. {"rated": 10, "pending": 3, "total": 13, "season": "2025/2026"}


class MentorGradesPatchRequest(BaseModel):
    full_name: Optional[str] = None
    province: Optional[str] = None
    grades_json: Optional[Any] = None


class MentorGradesItem(BaseModel):
    judge_id: str
    full_name: str
    province: str
    grades_json: Any
    updated_at: datetime


class GetMentorGradesResponse(BaseModel):
    record: Optional[MentorGradesItem] = None


class ListMentorGradesResponse(BaseModel):
    records: List[MentorGradesItem]

# ---------------------------- FORCED LOGOUT (wymuszone wylogowanie) ----------------------------

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


# =====================================================================
# BEACH (nowa aplikacja) — SCHEMAS
# =====================================================================

from typing import Any, Optional, List, Dict, Literal
from datetime import datetime

from pydantic import BaseModel, Field


# ---------------------------- BADGES (BEACH) ----------------------------

class BeachBadgeCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    config_json: Any = Field(default_factory=dict)

class BeachBadgeUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    config_json: Optional[Any] = None

class BeachBadgeItem(BaseModel):
    id: int
    name: str
    config_json: Any = Field(default_factory=dict)
    updated_at: datetime

class BeachBadgesListResponse(BaseModel):
    badges: List[BeachBadgeItem]


# ---------------------------- USERS (BEACH) ----------------------------

class BeachUserCreateRequest(BaseModel):
    judge_id: Optional[str] = None
    person_id: Optional[int] = None
    player_id: Optional[int] = None

    full_name: str = Field(..., min_length=1, max_length=220)   # "NAZWISKO Imię"
    province: Optional[str] = None
    city: Optional[str] = None

    login: str = Field(..., min_length=1, max_length=120)

    # analogicznie jak w Twojej appce: jedno z poniższych
    password: Optional[str] = None
    password_encrypted: Optional[str] = None

    # np. ["judge", "player"] albo [{type:"companion", role:"TRENER"}]
    roles: Optional[Any] = None

    badges: Optional[Any] = None
    app_version: Optional[str] = None
    device_ids: Optional[List[str]] = None


class BeachUserUpdateRequest(BaseModel):
    judge_id: Optional[str] = None
    person_id: Optional[int] = None
    player_id: Optional[int] = None

    full_name: Optional[str] = Field(None, min_length=1, max_length=220)
    province: Optional[str] = None
    city: Optional[str] = None

    login: Optional[str] = Field(None, min_length=1, max_length=120)

    password: Optional[str] = None
    password_encrypted: Optional[str] = None

    roles: Optional[Any] = None

    badges: Optional[Any] = None
    app_version: Optional[str] = None
    device_ids: Optional[List[str]] = None


class BeachUserItem(BaseModel):
    id: int

    judge_id: Optional[str] = None
    person_id: Optional[int] = None
    player_id: Optional[int] = None

    full_name: str
    province: Optional[str] = None
    city: Optional[str] = None

    login: str

    roles: Any = Field(default_factory=list)
    badges: Any = Field(default_factory=dict)

    last_login_at: Optional[datetime] = None
    app_opens: int = 0
    app_version: Optional[str] = None

    device_ids: List[str] = Field(default_factory=list)

    created_at: datetime
    updated_at: datetime

    is_admin: bool = False


class BeachUsersListResponse(BaseModel):
    users: List[BeachUserItem]


class BeachLoginRequest(BaseModel):
    login: str
    password: Optional[str] = None
    password_encrypted: Optional[str] = None

    # opcjonalnie dopinamy urządzenie / wersję przy logowaniu
    device_id: Optional[str] = None
    app_version: Optional[str] = None


class BeachLoginResponse(BaseModel):
    user: BeachUserItem
    token: str


# ---------------------------- Verification (BEACH) ----------------------------

class BeachVerificationCreateRequest(BaseModel):
    role: str  # "judge" | "coach" | "player"
    meta: Optional[Any] = None  # np. {team_id, person_id, license_number}

class BeachVerificationItem(BaseModel):
    id: int
    user_id: int
    role: str
    status: str
    meta: Any = Field(default_factory=dict)
    admin_note: Optional[str] = None
    reviewed_by_user_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime

class BeachVerificationPatchRequest(BaseModel):
    status: str                     # "approved" | "rejected"
    admin_note: Optional[str] = None
    judge_id: Optional[str] = None  # wypełnia admin przy approve sędziego
    person_id: Optional[int] = None # wypełnia admin przy approve trenera
    player_id: Optional[int] = None # wypełnia admin przy approve zawodnika

class BeachVerificationsListResponse(BaseModel):
    requests: List[BeachVerificationItem]
    total: int
    pending_count: int


# ---------------------------- ADMINS (BEACH) ----------------------------

class BeachAdminUpsertRequest(BaseModel):
    user_id: int

class BeachAdminItem(BaseModel):
    user_id: int
    judge_id: Optional[str] = None
    full_name: str
    province: Optional[str] = None
    created_at: datetime

class BeachAdminsListResponse(BaseModel):
    admins: List[BeachAdminItem]

# ---------------------------- AVAILABILITY (BEACH) ----------------------------
import re as _re

_DATE_RE = _re.compile(r"^\\d{4}-\\d{2}-\\d{2}$")
_VALID_AVAIL = {"available", "unavailable"}


class BeachJudgeAvailabilityUpsertRequest(BaseModel):
    """
    availability_json: maps "YYYY-MM-DD" → "available" | "unavailable".
    Dates absent from the dict mean the judge has not set their status for that day.
    """
    availability_json: Dict[str, str] = Field(default_factory=dict)

    @validator("availability_json")
    def validate_availability(cls, v: Dict[str, str]) -> Dict[str, str]:
        cleaned: Dict[str, str] = {}
        for k, val in v.items():
            if not isinstance(k, str) or not _DATE_RE.match(k):
                raise ValueError(
                    f"Invalid date key {k!r}. Expected YYYY-MM-DD."
                )
            if val not in _VALID_AVAIL:
                raise ValueError(
                    f"Invalid value {val!r} for key {k}. "
                    "Expected 'available' or 'unavailable'."
                )
            cleaned[k] = val
        return cleaned


class BeachJudgeAvailabilityItem(BaseModel):
    user_id: int
    full_name: str
    judge_id: Optional[str] = None
    availability_json: Dict[str, str] = Field(default_factory=dict)
    updated_at: datetime


class BeachJudgeAvailabilityListResponse(BaseModel):
    items: List[BeachJudgeAvailabilityItem]


# ---------------------------- TOURNAMENTS (BEACH) ----------------------------

VALID_CATEGORIES = {
    "Senior", "Junior", "Junior mł.", "Młodzik", "Dzieci"
}


class BeachTournamentTarget(BaseModel):
    badge: Optional[str] = None
    include_all: bool = False


class BeachTournamentData(BaseModel):
    target: BeachTournamentTarget = Field(default_factory=BeachTournamentTarget)
    invited_ids: List[str] = Field(default_factory=list)
    present_ids: List[str] = Field(default_factory=list)
    invited_cache: Optional[Any] = None


class CreateBeachTournamentRequest(BaseModel):
    badge: Optional[str] = None
    event_date: datetime
    end_date: Optional[datetime] = None          # NEW — last day of multi-day event
    name: str = Field(..., min_length=1, max_length=220)
    description: Optional[str] = None
    location: Optional[str] = None               # NEW — city / venue
    category: Optional[str] = None               # NEW — Senior | Junior | ...
    data_json: Optional[Any] = None

    @validator("end_date")
    def end_date_not_before_start(
        cls, v: Optional[datetime], values: dict
    ) -> Optional[datetime]:
        if v is not None and "event_date" in values and values["event_date"] is not None:
            if v.date() < values["event_date"].date():
                raise ValueError("end_date cannot be before event_date")
        return v

    @validator("category")
    def validate_category(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category {v!r}. Must be one of: {VALID_CATEGORIES}"
            )
        return v


class UpdateBeachTournamentRequest(BaseModel):
    badge: Optional[Optional[str]] = None
    event_date: Optional[datetime] = None
    end_date: Optional[Optional[datetime]] = None   # NEW
    name: Optional[str] = Field(None, min_length=1, max_length=220)
    description: Optional[Optional[str]] = None
    location: Optional[Optional[str]] = None        # NEW
    category: Optional[Optional[str]] = None        # NEW
    data_json: Optional[Any] = None

    @validator("category")
    def validate_category(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category {v!r}. Must be one of: {VALID_CATEGORIES}"
            )
        return v


class UpdateBeachTournamentAttendanceRequest(BaseModel):
    present_ids: List[str] = Field(default_factory=list)


class BeachTournamentItem(BaseModel):
    id: int
    badge: Optional[str] = None
    event_date: datetime
    end_date: Optional[datetime] = None             # NEW
    name: str
    description: Optional[str] = None
    location: Optional[str] = None                  # NEW
    category: Optional[str] = None                  # NEW
    data_json: Any = Field(default_factory=dict)
    updated_at: datetime

    invited_total: int = 0
    present_total: int = 0
    user_invited: bool = False
    user_present: bool = False


class BeachTournamentsListResponse(BaseModel):
    tournaments: List[BeachTournamentItem]

# ---------------------------- APP VERSIONS (BEACH) ----------------------------

class BeachVersionItem(BaseModel):
    id: int
    version: str
    name: str
    description: Optional[str] = None
    to_show: bool = False
    created_at: datetime
    updated_at: datetime


class BeachListVersionsResponse(BaseModel):
    versions: List[BeachVersionItem]


class BeachCreateVersionRequest(BaseModel):
    version: str  # "X.Y.Z"
    name: str
    description: Optional[str] = None
    to_show: Optional[bool] = False


class BeachUpdateVersionRequest(BaseModel):
    version: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    to_show: Optional[bool] = None

# ---------------------------- TEAMS (BEACH) ----------------------------

class BeachTeamContact(BaseModel):
    address: Optional[str] = None
    postal_code: Optional[str] = None
    city: Optional[str] = None
    phone: Optional[str] = None
    phone2: Optional[str] = None
    email: Optional[str] = None
    notes: Optional[str] = None
    website: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)


class BeachFilterOption(BaseModel):
    id: str
    label: str
    selected: bool = False


class BeachFilterGroup(BaseModel):
    selected_id: Optional[str] = None
    selected_label: Optional[str] = None
    options: List[BeachFilterOption] = Field(default_factory=list)


class BeachTeamsFiltersResponse(BaseModel):
    seasons: BeachFilterGroup = Field(default_factory=BeachFilterGroup)
    provinces: BeachFilterGroup = Field(default_factory=BeachFilterGroup)
    categories: BeachFilterGroup = Field(default_factory=BeachFilterGroup)
    clubs: BeachFilterGroup = Field(default_factory=BeachFilterGroup)
    genders: BeachFilterGroup = Field(default_factory=BeachFilterGroup)


class BeachTeamItem(BaseModel):
    id: int
    team_name: str

    gender: Optional[str] = None
    gender_label: Optional[str] = None

    category_id: Optional[str] = None
    category: Optional[str] = None

    club_id: Optional[str] = None
    club: Optional[str] = None

    province_id: Optional[str] = None
    province: Optional[str] = None

    season_id: Optional[str] = None
    season: Optional[str] = None

    contact: BeachTeamContact = Field(default_factory=BeachTeamContact)
    squad_url: Optional[str] = None

    source: str = "zprp"
    last_synced_at: Optional[datetime] = None

    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class BeachTeamsListResponse(BaseModel):
    teams: List[BeachTeamItem]


class BeachTeamCreateRequest(BaseModel):
    id: int
    team_name: str = Field(..., min_length=1, max_length=255)

    gender: Optional[str] = Field(None, max_length=10)
    gender_label: Optional[str] = Field(None, max_length=100)

    category_id: Optional[str] = Field(None, max_length=50)
    category: Optional[str] = Field(None, max_length=120)

    club_id: Optional[str] = Field(None, max_length=50)
    club: Optional[str] = Field(None, max_length=255)

    province_id: Optional[str] = Field(None, max_length=50)
    province: Optional[str] = Field(None, max_length=50)

    season_id: Optional[str] = Field(None, max_length=50)
    season: Optional[str] = Field(None, max_length=50)

    contact: Optional[BeachTeamContact] = None
    squad_url: Optional[str] = None

    source: Optional[str] = "manual"


class BeachTeamUpdateRequest(BaseModel):
    team_name: Optional[str] = Field(None, min_length=1, max_length=255)

    gender: Optional[str] = Field(None, max_length=10)
    gender_label: Optional[str] = Field(None, max_length=100)

    category_id: Optional[str] = Field(None, max_length=50)
    category: Optional[str] = Field(None, max_length=120)

    club_id: Optional[str] = Field(None, max_length=50)
    club: Optional[str] = Field(None, max_length=255)

    province_id: Optional[str] = Field(None, max_length=50)
    province: Optional[str] = Field(None, max_length=50)

    season_id: Optional[str] = Field(None, max_length=50)
    season: Optional[str] = Field(None, max_length=50)

    contact: Optional[BeachTeamContact] = None
    squad_url: Optional[str] = None

    source: Optional[str] = None


class BeachTeamPutRequest(BaseModel):
    team_name: str = Field(..., min_length=1, max_length=255)

    gender: Optional[str] = Field(None, max_length=10)
    gender_label: Optional[str] = Field(None, max_length=100)

    category_id: Optional[str] = Field(None, max_length=50)
    category: Optional[str] = Field(None, max_length=120)

    club_id: Optional[str] = Field(None, max_length=50)
    club: Optional[str] = Field(None, max_length=255)

    province_id: Optional[str] = Field(None, max_length=50)
    province: Optional[str] = Field(None, max_length=50)

    season_id: Optional[str] = Field(None, max_length=50)
    season: Optional[str] = Field(None, max_length=50)

    contact: BeachTeamContact = Field(default_factory=BeachTeamContact)
    squad_url: Optional[str] = None

    source: Optional[str] = "manual"


class BeachTeamsSyncRequest(BaseModel):
    season_id: Optional[str] = None
    province_id: Optional[str] = None
    gender: Optional[str] = None
    category_id: Optional[str] = None
    club_id: Optional[str] = None
    name: Optional[str] = None
    sort: Optional[str] = None


class BeachTeamsSyncFilters(BaseModel):
    season_id: Optional[str] = None
    province_id: Optional[str] = None
    gender: Optional[str] = None
    category_id: Optional[str] = None
    club_id: Optional[str] = None
    name: Optional[str] = None
    sort: Optional[str] = None
    include_squads: bool = False
    db_squad_columns: Dict[str, bool] = Field(default_factory=dict)


class BeachTeamsSyncResponse(BaseModel):
    success: bool = True
    fetched: int = 0
    upserted: int = 0
    filters: BeachTeamsSyncFilters = Field(default_factory=BeachTeamsSyncFilters) # akceptuje boola