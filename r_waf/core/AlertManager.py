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


class AlertManager:
    def __init__(self, storage):
        self.storage = storage

    def log_alert(self, module_name, action, reason, ip, method="", path="", user_agent="", matched_rule="", status_code=None):
        try:
            decoded_path = base64.b64decode(path.encode()).decode() if path else ""
        except Exception:
            decoded_path = path or ""

        with self.storage.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (
                    timestamp, module, action, reason, ip, method, path,
                    user_agent, matched_rule, status_code
                )
                VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    module_name,
                    action,
                    reason,
                    ip,
                    method or "",
                    decoded_path,
                    (user_agent or "")[:100],
                    str(matched_rule)[:200] if matched_rule else "",
                    status_code,
                ),
            )

        logger.warning(f"[ALERT] {module_name} | {action} | {reason} | IP: {ip}")

    def _rows_to_alerts(self, rows):
        return [
            {
                "timestamp": row["timestamp"].isoformat(),
                "module": row["module"],
                "action": row["action"],
                "reason": row["reason"],
                "ip": row["ip"],
                "method": row["method"],
                "path": row["path"],
                "user_agent": row["user_agent"],
                "matched_rule": row["matched_rule"],
                "status_code": row["status_code"],
            }
            for row in rows
        ]

    def get_alerts(self, limit=100):
        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT timestamp, module, action, reason, ip, method, path,
                       user_agent, matched_rule, status_code
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return self._rows_to_alerts(rows)

    def get_alerts_by_ip(self, ip, limit=50):
        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT timestamp, module, action, reason, ip, method, path,
                       user_agent, matched_rule, status_code
                FROM alerts
                WHERE ip = %s
                ORDER BY timestamp DESC
                LIMIT %s
                """,
                (ip, limit),
            )
            rows = cur.fetchall()
        return self._rows_to_alerts(rows)

    def clear_alerts(self):
        with self.storage.cursor() as cur:
            cur.execute("DELETE FROM alerts")
        logger.info("Cleared alerts from PostgreSQL")
        return True

    def get_alerts_paginated(self, page=1, per_page=50, start_date=None, end_date=None, keyword=None):
        start_dt, end_dt = _parse_range(start_date, end_date)
        where = ["timestamp BETWEEN %s AND %s"]
        params = [start_dt, end_dt]

        if keyword:
            where.append("(ip ILIKE %s OR path ILIKE %s OR reason ILIKE %s OR module ILIKE %s)")
            like = f"%{keyword}%"
            params.extend([like, like, like, like])

        where_sql = " AND ".join(where)
        offset = max(page - 1, 0) * per_page

        with self.storage.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS total FROM alerts WHERE {where_sql}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"""
                SELECT timestamp, module, action, reason, ip, method, path,
                       user_agent, matched_rule, status_code
                FROM alerts
                WHERE {where_sql}
                ORDER BY timestamp DESC
                LIMIT %s OFFSET %s
                """,
                params + [per_page, offset],
            )
            rows = cur.fetchall()

        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        return {
            "alerts": self._rows_to_alerts(rows),
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
        }

    def get_stats(self):
        start_dt = datetime.now(timezone.utc) - timedelta(days=7)

        with self.storage.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS total FROM alerts WHERE timestamp >= %s", (start_dt,))
            total_alerts = cur.fetchone()["total"]
            cur.execute(
                """
                SELECT COUNT(DISTINCT ip) AS blocked_ips
                FROM alerts
                WHERE timestamp >= %s AND action = 'block'
                """,
                (start_dt,),
            )
            blocked_ips = cur.fetchone()["blocked_ips"]
            cur.execute(
                """
                SELECT module, COUNT(*) AS count
                FROM alerts
                WHERE timestamp >= %s
                GROUP BY module
                ORDER BY count DESC
                """,
                (start_dt,),
            )
            module_counts = {row["module"]: row["count"] for row in cur.fetchall()}
            cur.execute(
                """
                SELECT timestamp, module, action, reason, ip, method, path,
                       user_agent, matched_rule, status_code
                FROM alerts
                WHERE timestamp >= %s
                ORDER BY timestamp DESC
                LIMIT 10
                """,
                (start_dt,),
            )
            recent_alerts = self._rows_to_alerts(cur.fetchall())

        return {
            "total_alerts": total_alerts,
            "blocked_ips": blocked_ips,
            "module_counts": module_counts,
            "recent_alerts": recent_alerts,
        }

    def get_timeline_data(self, start_date=None, end_date=None, granularity="hour"):
        start_dt, end_dt = _parse_range(start_date, end_date)
        bucket = "day" if granularity == "day" else "hour"

        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT date_trunc(%s, timestamp) AS bucket, COUNT(*) AS count
                FROM alerts
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
            "data": [row["count"] for row in rows],
        }
