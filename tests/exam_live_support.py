"""Wspólne pomoce testów egzaminu na żywo (nie jest testem): sklep na SQLite i uczestnicy."""

from datetime import datetime, timezone

from databases import Database
from sqlalchemy import JSON, Column, DateTime, Integer, MetaData, String, Table, Text, create_engine

from app import exam_live_service as V
from app import exam_service as S
from app.exam_live_tables import define_tables as define_live
from app.exam_tables import define_tables

UTC = timezone.utc
T0 = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
SINGLES = ["q1-1", "q1-2", "q1-3"]  # poprawne: a, b, c
CORRECT = {"q1-1": "a", "q1-2": "b", "q1-3": "c"}


def make_store(path) -> V.LiveStore:
    """Sklep z tabelami egzaminu i sesji na żywo na pliku SQLite; połączenie otwiera wołający."""
    meta = MetaData()
    banks, bq, defs, attempts, answers, events, reminders = define_tables(meta)
    sessions, participants, live_answers = define_live(meta)
    pe = Table("province_events", meta,
               Column("id", Integer, primary_key=True, autoincrement=True), Column("province", String),
               Column("event_date", DateTime(timezone=True)), Column("end_date", DateTime(timezone=True)),
               Column("name", String), Column("description", Text), Column("event_type", String),
               Column("data_json", JSON), Column("created_by", String), Column("created_by_name", String),
               Column("created_at", DateTime(timezone=True)), Column("updated_at", DateTime(timezone=True)),
               Column("deleted_at", DateTime(timezone=True)))
    engine = create_engine(f"sqlite:///{path}")
    meta.create_all(engine)
    engine.dispose()
    db = Database(f"sqlite+aiosqlite:///{path}")

    async def judges(province):
        # Sędzia 101 ma zdjęcie na liście okręgu; reszta jedzie na inicjałach.
        return [{"judge_id": "101", "photo_url": "https://zdjecia.example/101.jpg"}]

    async def push(ids, title, body, data):
        return None

    exam = S.Store(database=db, t=S.Tables(banks, bq, defs, attempts, answers, events, reminders, pe),
                   judges=judges, push=push, secret="sekret")
    S._BANK_CACHE.clear()
    return V.LiveStore(exam=exam, t=V.LiveTables(sessions, participants, live_answers))


def who(jid, name, *, admin=False, badges=None, province="ŚLĄSKIE", teach=False):
    async def teach_check(_prov):
        return teach

    return S.Who(judge_id=jid, name=name, province=province, is_admin=admin, badges=badges or {}, teach_check=teach_check)


ADMIN = who("1", "Anna Admin", admin=True)
HOST = who("2", "Kasia Komisja", badges={"Komisja sędziowska": True})
PLAIN = who("3", "Jan Zwykły")
OTHER = who("4", "Ola Delegat", badges={"Delegaci": True})
TEACH = who("5", "Piotr Cichy", teach=True)
OPOLE = who("8", "Opole Komisja", badges={"Komisja sędziowska": True}, province="OPOLSKIE")
PLAYERS = [who(str(100 + i), f"Sędzia {i}") for i in range(1, 6)]


def create_body(**over):
    body = {"scope": "province", "province": "ŚLĄSKIE", "title": "Quiz testowy", "question_ids": list(SINGLES)}
    body.update(over)
    return body
