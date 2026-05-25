import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


class BanManager:
    def __init__(self, storage, delay_ban_minutes=15):
        self.storage = storage
        self.delay_ban_minutes = delay_ban_minutes
        self.bans = {}
        self.whitelist = set()
        self.load_bans()
        self.load_whitelist()

    def normalize_ip(self, ip):
        ip = str(ip or "").strip()
        if "," in ip:
            ip = ip.split(",", 1)[0].strip()
        if ip.startswith("[") and "]" in ip:
            ip = ip[1:ip.index("]")]
        elif ":" in ip and ip.count(":") == 1:
            host, port = ip.rsplit(":", 1)
            if port.isdigit():
                ip = host
        return ip

    def load_bans(self):
        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT ip, until, reason
                FROM bans
                WHERE until > NOW()
                ORDER BY until DESC
                """
            )
            self.bans = {
                self.normalize_ip(row["ip"]): {"until": row["until"], "reason": row["reason"]}
                for row in cur.fetchall()
            }
        logger.info("Loaded active bans from PostgreSQL")

    def save_bans(self):
        self.load_bans()

    def load_whitelist(self):
        with self.storage.cursor() as cur:
            cur.execute("SELECT ip FROM whitelist")
            self.whitelist = {self.normalize_ip(row["ip"]) for row in cur.fetchall()}
        logger.info("Loaded whitelist from PostgreSQL")

    def is_banned(self, ip):
        ip = self.normalize_ip(ip)
        if ip in self.whitelist:
            return False, None

        with self.storage.cursor() as cur:
            cur.execute(
                "SELECT until, reason FROM bans WHERE ip = %s",
                (ip,),
            )
            row = cur.fetchone()

            if not row:
                self.bans.pop(ip, None)
                return False, None

            if datetime.now(timezone.utc) >= row["until"]:
                cur.execute("DELETE FROM bans WHERE ip = %s", (ip,))
                self.bans.pop(ip, None)
                return False, None

            self.bans[ip] = {"until": row["until"], "reason": row["reason"]}
            return True, row["reason"]

    def add_ban(self, ip, minutes=None, reason="manual ban"):
        ip = self.normalize_ip(ip)
        if not ip:
            logger.warning("Attempt to ban empty IP ignored.")
            return False

        self.load_whitelist()
        if ip in self.whitelist:
            logger.info(f"Attempt to ban whitelisted IP {ip} ignored.")
            return False

        if minutes is None:
            minutes = self.delay_ban_minutes
        expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)

        with self.storage.cursor() as cur:
            cur.execute(
                """
                INSERT INTO bans (ip, until, reason)
                VALUES (%s, %s, %s)
                ON CONFLICT (ip)
                DO UPDATE SET
                    until = EXCLUDED.until,
                    reason = EXCLUDED.reason,
                    updated_at = NOW()
                """,
                (ip, expire, reason),
            )

        self.bans[ip] = {"until": expire, "reason": reason}
        logger.info(f"Added ban for IP {ip} until {expire.isoformat()} Reason: {reason}")
        return True

    def delete_ban(self, ip):
        ip = self.normalize_ip(ip)
        with self.storage.cursor() as cur:
            cur.execute("DELETE FROM bans WHERE ip = %s", (ip,))
            deleted = cur.rowcount > 0

        self.bans.pop(ip, None)
        if deleted:
            logger.info(f"Deleted ban for IP {ip}")
        return deleted

    def get_active_bans(self):
        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT ip, until, reason
                FROM bans
                WHERE until > NOW()
                ORDER BY until DESC
                """
            )
            rows = cur.fetchall()

        return {
            row["ip"]: {
                "until": row["until"].isoformat(),
                "reason": row["reason"],
            }
            for row in rows
        }

    def get_all_bans_list(self):
        with self.storage.cursor() as cur:
            cur.execute(
                """
                SELECT ip, until, reason, until > NOW() AS active
                FROM bans
                ORDER BY until DESC
                """
            )
            rows = cur.fetchall()

        return [
            {
                "ip": row["ip"],
                "until": row["until"].isoformat(),
                "reason": row["reason"],
                "active": row["active"],
            }
            for row in rows
        ]
