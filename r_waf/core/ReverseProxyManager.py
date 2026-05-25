import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ReverseProxyManager:
    def __init__(self, storage):
        self.storage = storage

    def _normalize_path_prefix(self, path_prefix):
        path_prefix = (path_prefix or "/").strip()
        if not path_prefix.startswith("/"):
            path_prefix = "/" + path_prefix
        return path_prefix.rstrip("/") or "/"

    def _parse_upstream(self, data):
        upstream_url = (data.get("upstream_url") or "").strip()
        if upstream_url:
            parsed = urlparse(upstream_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("upstream_url must be a valid http:// or https:// URL")
            return {
                "scheme": parsed.scheme,
                "host": parsed.hostname,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            }

        scheme = (data.get("upstream_scheme") or "http").strip().lower()
        host = (data.get("upstream_host") or "").strip()
        port = int(data.get("upstream_port") or (443 if scheme == "https" else 80))
        if scheme not in {"http", "https"}:
            raise ValueError("upstream_scheme must be http or https")
        if not host:
            raise ValueError("upstream_host is required")
        if port < 1 or port > 65535:
            raise ValueError("upstream_port must be between 1 and 65535")
        return {"scheme": scheme, "host": host, "port": port}

    def _row_to_proxy(self, row):
        return {
            "id": row["id"],
            "name": row["name"],
            "host": row["host"],
            "path_prefix": row["path_prefix"],
            "upstream_scheme": row["upstream_scheme"],
            "upstream_host": row["upstream_host"],
            "upstream_port": row["upstream_port"],
            "upstream_url": f"{row['upstream_scheme']}://{row['upstream_host']}:{row['upstream_port']}",
            "enabled": row["enabled"],
            "created_at": row["created_at"].isoformat(),
            "updated_at": row["updated_at"].isoformat(),
        }

    def list_proxies(self):
        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, host, path_prefix, upstream_scheme, upstream_host,
                       upstream_port, enabled, created_at, updated_at
                FROM reverse_proxies
                ORDER BY host ASC, path_prefix ASC, id ASC
                """
            )
            return [self._row_to_proxy(row) for row in cur.fetchall()]

    def create_proxy(self, data):
        upstream = self._parse_upstream(data)
        name = (data.get("name") or "").strip() or upstream["host"]
        host = (data.get("host") or "").strip().lower()
        path_prefix = self._normalize_path_prefix(data.get("path_prefix"))
        enabled = bool(data.get("enabled", True))

        with self.storage.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reverse_proxies (
                    name, host, path_prefix, upstream_scheme, upstream_host,
                    upstream_port, enabled
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id, name, host, path_prefix, upstream_scheme, upstream_host,
                          upstream_port, enabled, created_at, updated_at
                """,
                (name, host, path_prefix, upstream["scheme"], upstream["host"], upstream["port"], enabled),
            )
            return self._row_to_proxy(cur.fetchone())

    def update_proxy(self, proxy_id, data):
        upstream = self._parse_upstream(data)
        name = (data.get("name") or "").strip() or upstream["host"]
        host = (data.get("host") or "").strip().lower()
        path_prefix = self._normalize_path_prefix(data.get("path_prefix"))
        enabled = bool(data.get("enabled", True))

        with self.storage.cursor() as cur:
            cur.execute(
                """
                UPDATE reverse_proxies
                SET name = %s,
                    host = %s,
                    path_prefix = %s,
                    upstream_scheme = %s,
                    upstream_host = %s,
                    upstream_port = %s,
                    enabled = %s,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id, name, host, path_prefix, upstream_scheme, upstream_host,
                          upstream_port, enabled, created_at, updated_at
                """,
                (name, host, path_prefix, upstream["scheme"], upstream["host"], upstream["port"], enabled, proxy_id),
            )
            row = cur.fetchone()

        if not row:
            return None
        return self._row_to_proxy(row)

    def delete_proxy(self, proxy_id):
        with self.storage.cursor() as cur:
            cur.execute("DELETE FROM reverse_proxies WHERE id = %s", (proxy_id,))
            return cur.rowcount > 0

    def resolve(self, host, path):
        host = (host or "").split(":")[0].lower()
        path = path or "/"

        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT upstream_scheme, upstream_host, upstream_port
                FROM reverse_proxies
                WHERE enabled = TRUE
                  AND (host = %s OR host = '')
                  AND (%s = path_prefix OR %s LIKE path_prefix || '/%%' OR path_prefix = '/')
                ORDER BY
                  CASE WHEN host = %s THEN 0 ELSE 1 END,
                  LENGTH(path_prefix) DESC,
                  id ASC
                LIMIT 1
                """,
                (host, path, path, host),
            )
            row = cur.fetchone()

        if row:
            return {
                "scheme": row["upstream_scheme"],
                "host": row["upstream_host"],
                "port": row["upstream_port"],
                "upstream": f"{row['upstream_scheme']}://{row['upstream_host']}:{row['upstream_port']}",
            }

        return None
