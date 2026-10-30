"""Automat nagrań w dniu meczu (30.10.2026) - schematy. Kontrakt: `docs/mentor-panel.md`, § "Automat nagrań".

Jeden wiersz na mecz pary (`mentor_auto_found`): ślad prób (start / +30 min / +2 h), wynik (dodane samo albo sugestie),
odrzucone klucze i znacznik wysłanego pusha. `mentor_auto_found_seen` to "widziałem" per użytkownik (podświetlenie
meczu i efektowne odsłonięcie "Co znaleźliśmy" pokazujemy do pierwszego wejścia).
"""

from sqlalchemy import Boolean, Column, DateTime, String, Table, Text, func, text


def define_tables(metadata):
    found = Table(
        "mentor_auto_found",
        metadata,
        Column("pair_id", String, primary_key=True),
        Column("match_id", String, primary_key=True),
        #: Godzina startu meczu z obsady ZPRP (UTC) - od niej liczone próby.
        Column("start_at", DateTime(timezone=True), nullable=False),
        #: `searching` | `added` | `suggested` | `none`.
        Column("state", String, nullable=False, server_default=text("'searching'")),
        Column("found_at", DateTime(timezone=True), nullable=True),
        #: [{at, slot, result}] - slot 0/1/2 = start / +30 min / +2 h; wynik: added|suggested|none|missed|error.
        Column("attempts_json", Text, nullable=False, server_default=text("'[]'")),
        #: {video_id, source, title, thumbnail_url, candidate} gdy nagranie dodał automat.
        Column("added_json", Text, nullable=True),
        Column("candidates_json", Text, nullable=False, server_default=text("'[]'")),
        Column("dismissed_json", Text, nullable=False, server_default=text("'[]'")),
        Column("bastion_error", String, nullable=True),
        #: Człowiek zdecydował (przyjął / odrzucił / cofnął): automat niczego już sam nie dodaje.
        Column("locked", Boolean, nullable=False, server_default=text("false")),
        Column("finished", Boolean, nullable=False, server_default=text("false")),
        Column("pushed_at", DateTime(timezone=True), nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    seen = Table(
        "mentor_auto_found_seen",
        metadata,
        Column("pair_id", String, primary_key=True),
        Column("match_id", String, primary_key=True),
        Column("judge_id", String, primary_key=True),
        Column("seen_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return found, seen
