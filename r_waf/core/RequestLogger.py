import base64
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def _parse_range(start_date=None, end_date=None, default_days=7):
    if start_date:
        try:
            if "T" in start_date:
                start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
            else:
                start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            start_dt = datetime.now(timezone.utc) - timedelta(days=default_days)
    else:
        start_dt = datetime.now(timezone.utc) - timedelta(days=default_days)

    if end_date:
        try:
            if "T" in end_date:
                end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
            else:
                end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(
                    hour=23, minute=59, second=59, tzinfo=timezone.utc
                )
        except Exception:
            end_dt = datetime.now(timezone.utc)
    else:
        end_dt = datetime.now(timezone.utc)

    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=timezone.utc)
    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=timezone.utc)
    return start_dt, end_dt


class RequestLogger:
    def __init__(self, storage):
        self.storage = storage

    def log_request(self, ip, method, path, user_agent="", action="allow", reason="",
                    status_code=None, module="", matched_rule=""):
        try:
            decoded_path = base64.b64decode(path.encode()).decode() if path else ""
        except Exception:
            decoded_path = path or ""

        with self.storage.cursor() as cur:
            cur.execute(
                """
                INSERT INTO traffic_logs (
                    timestamp, ip, method, path, user_agent, action, reason,
                    status_code, module, matched_rule
                )
                VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    ip,
                    method or "",
                    decoded_path[:500] if decoded_path else "",
                    (user_agent or "")[:200],
                    action,
                    reason or "",
                    status_code,
                    module or "",
                    str(matched_rule)[:200] if matched_rule else "",
                ),
            )

    def _rows_to_logs(self, rows):
        return [
            {
                "timestamp": row["timestamp"].isoformat(),
                "ip": row["ip"],
                "method": row["method"],
                "path": row["path"],
                "user_agent": row["user_agent"],
                "action": row["action"],
                "reason": row["reason"],
                "status_code": row["status_code"],
                "module": row["module"],
                "matched_rule": row["matched_rule"],
            }
            for row in rows
        ]

    def get_logs_paginated(self, page=1, per_page=50, start_date=None, end_date=None,
                          keyword=None, action_filter=None):
        start_dt, end_dt = _parse_range(start_date, end_date)
        where = ["timestamp BETWEEN %s AND %s"]
        params = [start_dt, end_dt]

        if action_filter:
            where.append("action = %s")
            params.append(action_filter)

        if keyword:
            where.append("(ip ILIKE %s OR path ILIKE %s OR reason ILIKE %s OR method ILIKE %s OR module ILIKE %s)")
            like = f"%{keyword}%"
            params.extend([like, like, like, like, like])

        where_sql = " AND ".join(where)
        offset = max(page - 1, 0) * per_page

        with self.storage.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS total FROM traffic_logs WHERE {where_sql}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
                SELECT timestamp, ip, method, path, user_agent, action, reason,
                       status_code, module, matched_rule
                FROM traffic_logs
                WHERE {where_sql}
                ORDER BY timestamp DESC
                LIMIT %s OFFSET %s
                """,
                params + [per_page, offset],
            )
            rows = cur.fetchall()

        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        return {
            "logs": self._rows_to_logs(rows),
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
        }

    def get_stats(self, start_date=None, end_date=None):
        start_dt, end_dt = _parse_range(start_date, end_date)

        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) AS total_requests,
                    COUNT(*) FILTER (WHERE action = 'allow') AS allowed_requests,
                    COUNT(*) FILTER (WHERE action = 'block') AS blocked_requests,
                    COUNT(DISTINCT ip) AS unique_ips
                FROM traffic_logs
                WHERE timestamp BETWEEN %s AND %s
                """,
                (start_dt, end_dt),
            )
            totals = cur.fetchone()

            cur.execute(
                """
                SELECT method, COUNT(*) AS count
                FROM traffic_logs
                WHERE timestamp BETWEEN %s AND %s
                GROUP BY method
                ORDER BY count DESC
                """,
                (start_dt, end_dt),
            )
            method_counts = {row["method"]: row["count"] for row in cur.fetchall()}

            cur.execute(
                """
                SELECT ip, COUNT(*) AS count
                FROM traffic_logs
                WHERE timestamp BETWEEN %s AND %s AND action = 'block'
                GROUP BY ip
                ORDER BY count DESC
                LIMIT 10
                """,
                (start_dt, end_dt),
            )
            top_blocked_ips = [{"ip": row["ip"], "count": row["count"]} for row in cur.fetchall()]

        return {
            "total_requests": totals["total_requests"],
            "allowed_requests": totals["allowed_requests"],
            "blocked_requests": totals["blocked_requests"],
            "unique_ips": totals["unique_ips"],
            "method_counts": method_counts,
            "top_blocked_ips": top_blocked_ips,
        }

    def get_timeline_data(self, start_date=None, end_date=None, granularity="hour"):
        start_dt, end_dt = _parse_range(start_date, end_date)
        bucket = "day" if granularity == "day" else "hour"

        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT
                    date_trunc(%s, timestamp) AS bucket,
                    COUNT(*) FILTER (WHERE action = 'allow') AS allowed,
                    COUNT(*) FILTER (WHERE action = 'block') AS blocked
                FROM traffic_logs
                WHERE timestamp BETWEEN %s AND %s
                GROUP BY bucket
                ORDER BY bucket
                """,
                (bucket, start_dt, end_dt),
            )
            rows = cur.fetchall()

        fmt = "%Y-%m-%d" if bucket == "day" else "%Y-%m-%d %H:00"
        return {
            "labels": [row["bucket"].strftime(fmt) for row in rows],
            "allowed": [row["allowed"] for row in rows],
            "blocked": [row["blocked"] for row in rows],
        }

    def clear_logs(self, date_str=None):
        with self.storage.cursor() as cur:
            if date_str:
                start_dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                end_dt = start_dt.replace(hour=23, minute=59, second=59)
                cur.execute("DELETE FROM traffic_logs WHERE timestamp BETWEEN %s AND %s", (start_dt, end_dt))
            else:
                cur.execute("DELETE FROM traffic_logs")
        logger.info("Cleared traffic logs from PostgreSQL")
        return True
