"""Zapisane stany zakładek „Raporty i podsumowania ZPRP" (10.11.2026) - sam schemat.

Jeden wiersz = okręg + rodzaj danych + klucz parametrów. `payload` to odpowiedź
trasy `/zprp/*` jako JSON spakowany gzipem (pełny terminarz sezonu ma kilka MB).
Reguły: `app/zprp_report_snapshot_rules.py`, trasy: `app/zprp_report_snapshots.py`.
"""

from sqlalchemy import Column, DateTime, Integer, LargeBinary, String, Table


def define_tables(metadata):
    snapshots = Table(
        "zprp_report_snapshots",
        metadata,
        #: Okręg bez ogonków, wielkimi literami (`zprp_accounts.normalize_province`).
        Column("province", String, primary_key=True),
        Column("kind", String, primary_key=True),
        Column("key", String, primary_key=True),
        Column("payload_gz", LargeBinary, nullable=False),
        Column("size", Integer, nullable=False),
        Column("fetched_at", DateTime(timezone=True), nullable=False),
        #: auto | manual
        Column("source", String, nullable=False),
        #: Login konta, które pobrało ręcznie; „serwer" dla automatu.
        Column("fetched_by", String, nullable=True),
    )
    return (snapshots,)
