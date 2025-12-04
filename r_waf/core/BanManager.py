import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BanManager:
    def __init__(self, bans_file, whitelist_file, delay_ban_minutes=15):
        self.bans_file = bans_file
        self.whitelist_file = whitelist_file
        self.delay_ban_minutes = delay_ban_minutes
        self.bans = {}
        self.whitelist = set()
        self._lock = threading.Lock()
        self._cache = {}
        self._cache_ttl = 5
        
        self.load_bans()
        self.load_whitelist()
    
    def load_bans(self):
        self.bans = {}
        try:
            with open(self.bans_file, encoding="utf-8") as f:
                raw = json.load(f)
                for ip, info in raw.items():
                    until = datetime.fromisoformat(info["until"].replace("Z", "+00:00"))
                    self.bans[ip] = {"until": until, "reason": info.get("reason", "banned")}
            logger.info(f"Loaded bans from {self.bans_file}")
        except FileNotFoundError:
            logger.info(f"No bans file found at '{self.bans_file}', starting fresh.")
        except Exception as e:
            logger.error(f"Failed to load bans: {e}")
    
    def save_bans(self):
        with self._lock:
            raw = {
                ip: {
                    "until": info["until"].isoformat() + "Z",
                    "reason": info["reason"]
                } for ip, info in self.bans.items()
            }
            temp_file = self.bans_file + ".tmp"
            try:
                with open(temp_file, "w", encoding="utf-8") as f:
                    json.dump(raw, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp_file, self.bans_file)
                logger.debug(f"Saved bans to {self.bans_file}")
            except Exception as e:
                logger.error(f"Failed to save bans: {e}")
                if os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except:
                        pass
    
    def load_whitelist(self):
        self.whitelist = set()
        if os.path.exists(self.whitelist_file):
            try:
                with open(self.whitelist_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.whitelist = set(data)
                    logger.info(f"Loaded whitelist from {self.whitelist_file}")
            except Exception as e:
                logger.error(f"Failed to load whitelist: {e}")
        else:
            with open(self.whitelist_file, "w") as f:
                json.dump([], f)
            logger.info(f"Created empty whitelist file at {self.whitelist_file}")
    
    def is_banned(self, ip):
        if ip in self.whitelist:
            return False, None
        
        now = time.time()
        if ip in self._cache:
            result, expire_time = self._cache[ip]
            if now < expire_time:
                return result
        
        with self._lock:
            info = self.bans.get(ip)
            if not info:
                result = (False, None)
                self._cache[ip] = (result, now + self._cache_ttl)
                return result
            if datetime.now(timezone.utc) >= info["until"]:
                del self.bans[ip]
                self.save_bans()
                result = (False, None)
                self._cache[ip] = (result, now + self._cache_ttl)
                return result
            result = (True, info["reason"])
            self._cache[ip] = (result, now + self._cache_ttl)
            return result
    
    def add_ban(self, ip, minutes=None, reason="manual ban"):
        if ip in self.whitelist:
            logger.info(f"Attempt to ban whitelisted IP {ip} ignored.")
            return False
        if minutes is None:
            minutes = self.delay_ban_minutes
        expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        
        with self._lock:
            self.bans[ip] = {"until": expire, "reason": reason}
            if ip in self._cache:
                del self._cache[ip]
            self.save_bans()
        
        logger.info(f"Added ban for IP {ip} until {expire.isoformat()} Reason: {reason}")
        return True
    
    def delete_ban(self, ip):
        with self._lock:
            if ip in self.bans:
                del self.bans[ip]
                self.save_bans()
                logger.info(f"Deleted ban for IP {ip}")
                return True
        return False
    
    def get_active_bans(self):
        now = datetime.now(timezone.utc)
        with self._lock:
            return {
                ip: {
                    "until": info["until"].isoformat(),
                    "reason": info["reason"]
                }
                for ip, info in self.bans.items()
                if now < info["until"]
            }
    
    def get_all_bans_list(self):
        bans_list = []
        now = datetime.now(timezone.utc)
        
        with self._lock:
            for ip, info in self.bans.items():
                is_active = now < info["until"]
                bans_list.append({
                    "ip": ip,
                    "until": info["until"].isoformat(),
                    "reason": info.get("reason", ""),
                    "active": is_active
                })
        
        bans_list.sort(key=lambda x: x["until"], reverse=True)
        return bans_list
