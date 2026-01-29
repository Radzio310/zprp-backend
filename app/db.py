# app/db.py
from datetime import datetime
import os
from sqlalchemy import (
    ARRAY,
    JSON,
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    MetaData,
    Table,
    Text,
    create_engine,
    func,
    text,
    inspect,
    Index
)
from databases import Database
from sqlalchemy.dialects.postgresql import JSONB

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./local.db")

# Połączenie do bazy
database = Database(DATABASE_URL)
metadata = MetaData()

# -------------------------
# Tabele
# -------------------------

# 1) Tabela tokenów kalendarza
calendar_tokens = Table(
    "calendar_tokens",
    metadata,
    Column("user_login", String, primary_key=True),
    Column("access_token", String, nullable=False),
    Column("refresh_token", String, nullable=False),
    Column("expires_at", String, nullable=False),
)

# 2) Tabela CSRF state dla OAuth2
oauth_states = Table(
    "oauth_states",
    metadata,
    Column("user_login", String, primary_key=True),
    Column("state", String, nullable=False),
)

# 3) Mappings between your match_id and calendar event_id
event_mappings = Table(
    "event_mappings",
    metadata,
    Column("user_login", String, primary_key=True),
    Column("match_id", String, primary_key=True),
    Column("event_id", String, nullable=False),
)

# 4) Tabela ogłoszeń (Silesia)
announcements = Table(
    "announcements",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("judge_id", String, nullable=False, index=True),
    Column("judge_name", String, nullable=True),
    Column("title", String, nullable=False),
    Column("content", Text, nullable=False),
    Column("image_url", String, nullable=True),
    Column("priority", Integer, nullable=False, default=0),
    Column("link", String, nullable=True),
    Column("province", String, nullable=False, index=True),
    # lista reakcji: [{judge_id, full_name?, reaction, created_at}, ...]
    Column("likes", JSON, nullable=False, server_default="[]"),
    # lista komentarzy: [{id, judge_id, full_name?, text, created_at}, ...]
    Column("comments", JSON, nullable=False, server_default="[]"),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    ),
)


# 5) Tabela “kalendarz niedyspozycji” okręgowej
silesia_offtimes = Table(
  "silesia_offtimes",
  metadata,
  Column("judge_id", String, primary_key=True),
  Column("province", String, primary_key=True),     # ⬅⬅⬅ NOWE (PK cz. 2)
  Column("full_name", String, nullable=False),
  Column("city", String, nullable=True),
  Column("data_json", JSON, nullable=False),
  Column("updated_at", DateTime(timezone=True),
         server_default=func.now(), onupdate=func.now())
)

# (6) Mecze do oddania
matches_to_offer = Table(
    "matches_to_offer",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("judge_id", String, nullable=False, index=True),
    Column("judge_name", String, nullable=False),
    Column("match_data", Text, nullable=False),           # JSON jako tekst
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
)

# (7) Mecze oczekujące na akceptację
matches_to_approve = Table(
    "matches_to_approve",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("original_offer_id", Integer, nullable=False, index=True),
    Column("judge_id", String, nullable=False, index=True),
    Column("judge_name", String, nullable=False),
    Column("match_data", Text, nullable=False),
    Column("assign_judges", ARRAY(String), nullable=False),  # lista ID
    Column("assign_names", ARRAY(String), nullable=False),   # lista imion
    Column("requested_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
)

# (8) Historia zdarzeń przy meczu
matches_events = Table(
    "matches_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_type", String, nullable=False),           # np. "offer","assign","approve","reject","delete"
    Column("event_time", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("match_id", Integer, nullable=False, index=True), # odniesienie do offer_id
    Column("owner_judge_id", String, nullable=False),        # kto dodał ofertę
    Column("acting_judge_id", String, nullable=True),        # kto wykonał akcję
)

#9) Tabela admin PIN per‑judge
admin_pins = Table(
  "admin_pins",
  metadata,
  Column("judge_id", String, primary_key=True),      # teraz klucz główny
  Column("pin_hash", String, nullable=False),
)

# (10) Tabela listy adminów
admin_settings = Table(
    "admin_settings",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("allowed_admins", ARRAY(String), nullable=False, default=[]),
)

# 11) Zgłoszenia od userów
user_reports = Table(
  "user_reports", metadata,
  Column("id", Integer, primary_key=True, autoincrement=True),
  Column("judge_id", String, nullable=False, index=True),
  Column("full_name", String, nullable=False),
  Column("phone", String, nullable=False),
  Column("email", String, nullable=True),
  Column("type", String, nullable=False),       # "pomysl", "awaria", "pytanie"
  Column("content", Text, nullable=False),
    Column(
    "created_at",
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False
  ),
  Column(
    "is_read",
    Boolean,
    nullable=False,
    server_default=text("false")    # ← to dodaj
  ),
)
# 12) Wpisy admina
admin_posts = Table(
  "admin_posts", metadata,
  Column("id", Integer, primary_key=True, autoincrement=True),
  Column("title", String, nullable=False),
  Column("content", Text, nullable=False),
  Column("link", String, nullable=True),
  # ⬇⬇⬇ NOWE ⬇⬇⬇
  Column("button_text", String, nullable=True),  # tekst przycisku w appce
  Column("target_filters", JSON, nullable=True), # jak w forced_logout_rules.filters
  Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

# (13) Tabela do zapisu ostatniego logowania
login_records = Table(
  "login_records",
  metadata,
  Column("judge_id", String, primary_key=True),
  Column("full_name", String, nullable=False),
  Column("last_login_at", DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False),

  # ⬇⬇⬇ DODAJ TO ⬇⬇⬇
  Column("app_version", String, nullable=True),            # np. "1.4.0"
  Column("app_opens", Integer, nullable=True),             # licznik wejść
  Column("last_open_at", DateTime(timezone=True), nullable=True),  # data ostatniego wejścia
  Column("province", String, nullable=True),
    # ✅ NOWE: JSON z konfiguracją użytkownika (np. dane urządzenia / ustawienia)
  Column(
      "config_json",
      JSONB,
      nullable=False,
      server_default=text("'{}'::jsonb"),
  ),
)

# (13.1) Tabela sędziów per-województwo (z badge'ami)
province_judges = Table(
  "province_judges",
  metadata,
  Column("judge_id", String, primary_key=True),            # ID sędziego
  Column("full_name", String, nullable=False),             # Imię i nazwisko
  Column("province", String, nullable=False, index=True),  # Województwo
  Column("badges", JSON, nullable=False, server_default="{}"),  # NOWE: JSON z badge'ami
  Column(
      "updated_at",
      DateTime(timezone=True),
      server_default=func.now(),
      onupdate=func.now(),
      nullable=False,
  ),
)

# 13.2) Badge sędziów okręgowych
badges = Table(
    "badges",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("name", String, nullable=False, unique=True, index=True),
    Column("meta_json", JSONB, nullable=False, server_default="{}"),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

# (14) Jednopolowa tabela z terminu wymuszonego wylogowania
forced_logout = Table(
    "forced_logout",
    metadata,
    # pojedynczy wiersz o id=1
    Column("id", Integer, primary_key=True, default=1),
    Column(
        "logout_at",
        DateTime(timezone=True),
        nullable=False,
        comment="Globalny termin wymuszonego wylogowania"
    ),
)

# 14.1) Wiele reguł wymuszonego wylogowania (targetowane)
forced_logout_rules = Table(
    "forced_logout_rules",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("logout_at", DateTime(timezone=True), nullable=False),
    # JSON z opcjonalnymi filtrami:
    # {"judge_ids": ["123","456"], "provinces": ["ŚLĄSKIE","MAZOWIECKIE"], "versions": ["1.23.14","1.24.0"]}
    Column("filters", JSON, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

# 15) News Masters – listy per województwo
news_masters = Table(
    "news_masters", metadata,
    Column("province", String, primary_key=True),   # Np. "ŚLĄSKIE"
    Column("judges", JSONB, nullable=False, server_default="[]")  # lista ID-ów sędziów
)

# 16) Calendar Masters – listy per województwo
calendar_masters = Table(
    "calendar_masters", metadata,
    Column("province", String, primary_key=True),
    Column("judges", JSONB, nullable=False, server_default="[]")
)

# 17) Match Masters – listy per województwo
match_masters = Table(
    "match_masters", metadata,
    Column("province", String, primary_key=True),
    Column("judges", JSONB, nullable=False, server_default="[]")
)

# 17.4) Teach Masters – listy per województwo
teach_masters = Table(
    "teach_masters",
    metadata,
    Column("province", String, primary_key=True),                 # np. "ŚLĄSKIE"
    Column("judges", JSONB, nullable=False, server_default="[]"), # lista ID sędziów
)

# 17.1) ZPRP Master – uprawnieni do funkcji ZPRP
zprp_masters = Table(
    "zprp_masters",
    metadata,
    Column("judge_id", String, primary_key=True),
)

# 17.2) Aktywne okręgi (proste włącz/wyłącz per województwo)
active_provinces = Table(
    "active_provinces",
    metadata,
    Column("province", String, primary_key=True),                 # np. "ŚLĄSKIE"
    Column("enabled", Boolean, nullable=False, server_default=text("false")),
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), onupdate=func.now()),
)

# 17.3) Kluby rozliczane (lista/JSON klubów per województwo)
settlement_clubs = Table(
    "settlement_clubs",
    metadata,
    Column("province", String, primary_key=True),                 # np. "ŚLĄSKIE"
    Column("clubs", JSONB, nullable=False, server_default="[]"),  # dowolny JSON; domyślnie []
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), onupdate=func.now()),
)


# 18) Pliki źródłowe
json_files = Table(
  "json_files", metadata,
  Column("key", String, primary_key=True),
  Column("content", JSON, nullable=False),            
  Column("enabled", Boolean, nullable=False, default=False),
  Column("updated_at", DateTime(timezone=True),
         server_default=func.now(), onupdate=func.now()),
)

# 18.1) Stawki okręgowe per województwo (WERSJONOWANE)
okreg_rates = Table(
    "okreg_rates",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),  # NOWE PK
    Column("province", String, nullable=False, index=True),       # już nie PK
    Column("content", JSON, nullable=False),
    # zachowujemy "enabled" jako aktywność (zgodność wsteczna)
    Column("enabled", Boolean, nullable=False, server_default=text("false")),
    # NOWE: okres obowiązywania
    Column("valid_from", Date, nullable=True),
    Column("valid_to", Date, nullable=True),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    ),
)

# 18.2) Tabele odległości okręgowych per województwo
okreg_distances = Table(
    "okreg_distances",
    metadata,
    Column("province", String, primary_key=True),  # np. "ŚLĄSKIE"
    Column("content", JSON, nullable=False),       # pełny JSON tabeli odległości dla okręgu
    Column("enabled", Boolean, nullable=False, server_default=text("false")),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    ),
)

# 18.3) Młodzi sędziowie (per województwo)
young_referees = Table(
    "young_referees",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("full_name", String, nullable=False),          # imię i nazwisko młodego sędziego
    Column("base_judge_id", String, nullable=True),       # ID bazowe (np. z systemu głównego)
    Column("is_active", Boolean, nullable=False, server_default=text("true")),
    Column("province", String, nullable=False, index=True)  # województwo jak w innych tabelach
)

# 18.4) Oceny młodych sędziów
young_referee_ratings = Table(
    "young_referee_ratings",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("rating_date", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("province", String, nullable=False, index=True),      # województwo
    Column("mentor_name", String, nullable=False),               # imię i nazwisko mentora
    Column("young_referee_name", String, nullable=False),        # imię i nazwisko młodego sędziego (kopią)
    Column("young_referee_id", Integer, nullable=False, index=True),  # ID z tabeli young_referees
    Column("young_referee2_name", String, nullable=True),
    Column("young_referee2_id", Integer, nullable=True, index=True),
    Column("rating_json", JSON, nullable=False),                 # JSON z oceną
)

# 18.5) Szablony ocen młodych sędziów per województwo
young_referee_rating_templates = Table(
    "young_referee_rating_templates",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("province", String, nullable=False, unique=True, index=True),
    Column("template_json", JSON, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

Index("ix_yrrt_province", young_referee_rating_templates.c.province)

# 18.6) Widoczność ocen dla młodych sędziów (per województwo)
young_referee_ratings_visibility = Table(
    "young_referee_ratings_visibility",
    metadata,
    Column("province", String, primary_key=True),  # np. "ŚLĄSKIE"
    Column("enabled", Boolean, nullable=False, server_default=text("false")),  # czy młodzi widzą oceny
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

Index("ix_yrrv_province", young_referee_ratings_visibility.c.province)

# 19) Hale
hall_reports = Table(
    "hall_reports",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("Hala_nazwa", String, nullable=False),
    Column("Hala_miasto", String, nullable=False),
    Column("Hala_ulica", String, nullable=False),
    Column("Hala_numer", String, nullable=False),
    Column("Druzyny", ARRAY(String), nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    # jeżeli chcesz śledzić, które zgłoszenia już przerobiłeś:
    Column("is_processed", Boolean, nullable=False, server_default=text("false")),
)

# 19.1) Hale odrzucone – żeby blokować ponowne zgłoszenia
rejected_halls = Table(
    "rejected_halls",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("Hala_nazwa", String, nullable=False),
    Column("Hala_miasto", String, nullable=False),
    Column("Hala_ulica", String, nullable=False),
    Column("Hala_numer", String, nullable=False),
    # klucz normalizowany do szybkiego porównania (bez znaków diakrytycznych/spacji/znaków specjalnych)
    Column("norm_key", String, nullable=False, unique=True, index=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)


# 20) Kalendarzowe wydarzenia Google (opcjonalnie rozbijemy później)
calendar_events = Table(
    "calendar_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("judge_id", String, nullable=False, index=True),
    Column("event_id", String, nullable=False),       # Google Calendar event ID
    Column("summary", String, nullable=False),        # tytuł wydarzenia
    Column("start", DateTime(timezone=True), nullable=False),
    Column("end", DateTime(timezone=True), nullable=False),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
)

# 21) ProEl - zapisane mecze stolikowe
saved_matches = Table(
    "proel_matches", metadata,
    Column("match_number", String, primary_key=True, index=True),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False),
    Column("data_json", JSON, nullable=False),
    Column("is_finished", Boolean, nullable=False, server_default=text("false")),
)

# 22) Wersje aplikacji / bazy
app_versions = Table(
    "app_versions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("version", String, nullable=False, unique=True, index=True),  # np. "1.23.14"
    Column("name", String, nullable=False),                              # nazwa wersji
    Column("description", Text, nullable=True),                          # opis zmian
    Column("to_show", Boolean, nullable=False, server_default="false"),   # czy pokazywać w aplikacji
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False),
)

# 23) Niedyspozycje partnera
partner_offtimes = Table(
    "partner_offtimes",
    metadata,
    Column("judge_id", String, primary_key=True),      # ID sędziego (unikatowy)
    Column("full_name", String, nullable=False),       # Imię i nazwisko
    Column("partner_id", String, nullable=True),       # ID partnera (opcjonalne)
    Column("data_json", JSON, nullable=False),         # JSON z niedyspozycjami
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), onupdate=func.now())
)

# 24) Rejestr wysyłek "wyniku skróconego"
short_result_records = Table(
    "short_result_records",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("match_number", String, nullable=False, index=True),
    Column("author_id", String, nullable=False, index=True),      # ID osoby wpisującej (np. judge_id)
    Column("author_name", String, nullable=True),                 # Imię i nazwisko (opcjonalnie)
    Column("payload", JSON, nullable=False),                      # Pełny JSON wysyłany na serwer
)

# 25) Dokumenty agenta 
agent_documents = Table(
    "agent_documents",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String(255), nullable=False),
    Column("source_type", String(50), nullable=False, default="pdf"),  # 'pdf', 'note', etc.
    Column("source_path", String(1024), nullable=True),  # np. ścieżka do pliku w storage
    Column("created_at", DateTime, default=datetime.utcnow, nullable=False),
    Column("updated_at", DateTime, default=datetime.utcnow, nullable=False),
)

# 26) Fragmenty dokumentów agenta z embeddingami
agent_document_chunks = Table(
    "agent_document_chunks",
    metadata,
    Column("id", Integer, primary_key=True),
    Column(
        "document_id",
        Integer,
        ForeignKey("agent_documents.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("chunk_index", Integer, nullable=False),
    Column("content", Text, nullable=False),
    Column("embedding", Text, nullable=False),  # JSON-owy string listy floatów
    Column("created_at", DateTime, default=datetime.utcnow, nullable=False),
)

# -------------------------
# NEW: Push (tokens + schedules)
# -------------------------

push_tokens = Table(
    "push_tokens",
    metadata,
    Column("installation_id", String, primary_key=True),
    Column("token_type", String, nullable=False),  # device_fcm | device_apns | unknown
    Column("token", Text, nullable=False),
    Column("platform", String, nullable=True),     # ios | android | web
    Column("app_variant", String, nullable=True),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False),
)

push_schedules = Table(
    "push_schedules",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("installation_id", String, nullable=False, index=True),
    Column("send_at_utc", DateTime(timezone=True), nullable=False, index=True),
    Column("send_hour_utc", Integer, nullable=False, index=True),  # floor(timestamp/3600)
    Column("title", String, nullable=False),
    Column("body", Text, nullable=False),
    Column("data_json", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("status", String, nullable=False, server_default=text("'pending'")),  # pending|sent|failed
    Column("attempts", Integer, nullable=False, server_default=text("0")),
    Column("last_error", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False),
)

Index("ix_push_sched_install_hour", push_schedules.c.installation_id, push_schedules.c.send_hour_utc)

engine = create_engine(DATABASE_URL)
metadata.create_all(engine)