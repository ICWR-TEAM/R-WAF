import logging
import os
import time
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


class PostgresStorage:
    def __init__(self, database_url=None):
        self.database_url = database_url or os.environ.get(
            "DATABASE_URL",
            "postgresql://rwaf:rwaf@postgres:5432/rwaf",
        )
        self.initialize_schema()

    @contextmanager
    def connection(self):
        conn = psycopg2.connect(self.database_url)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def cursor(self):
        with self.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                yield cur

    def initialize_schema(self):
        statements = [
            """
            CREATE TABLE IF NOT EXISTS bans (
                ip TEXT PRIMARY KEY,
                until TIMESTAMPTZ NOT NULL,
                reason TEXT NOT NULL DEFAULT 'banned',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS whitelist (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id BIGSERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                module TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                ip TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                matched_rule TEXT NOT NULL DEFAULT '',
                status_code INTEGER
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id BIGSERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                ip TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                status_code INTEGER,
                module TEXT NOT NULL DEFAULT '',
                matched_rule TEXT NOT NULL DEFAULT ''
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS reverse_proxies (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL DEFAULT '',
                path_prefix TEXT NOT NULL DEFAULT '/',
                upstream_scheme TEXT NOT NULL DEFAULT 'http',
                upstream_host TEXT NOT NULL,
                upstream_port INTEGER NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (host, path_prefix)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts (ip)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs (timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_ip ON traffic_logs (ip)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_action ON traffic_logs (action)",
            "CREATE INDEX IF NOT EXISTS idx_reverse_proxies_lookup ON reverse_proxies (enabled, host, path_prefix)",
        ]

        last_error = None
        for attempt in range(1, 11):
            try:
                with self.connection() as conn:
                    with conn.cursor() as cur:
                        for statement in statements:
                            cur.execute(statement)
                logger.info("PostgreSQL schema initialized")
                return
            except psycopg2.OperationalError as exc:
                last_error = exc
                logger.warning(f"PostgreSQL not ready, retrying schema init ({attempt}/10)")
                time.sleep(2)

        raise last_error
