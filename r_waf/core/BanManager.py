import json
import logging
import os
import threading
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
        self._dirty = False
        self._last_save = 0
        
        self.load_bans()
        self.load_whitelist()
        
        self._start_auto_save()
    
    def _start_auto_save(self):
        def auto_save():
            import time
            while True:
                time.sleep(5)
                if self._dirty:
                    self._flush_to_disk()
        
        t = threading.Thread(target=auto_save, daemon=True)
        t.start()
    
    def _flush_to_disk(self):
        with self._lock:
            if not self._dirty:
                return
            
            raw = {
                ip: {
                    "until": info["until"].isoformat() + "Z",
                    "reason": info["reason"]
                } for ip, info in self.bans.items()
            }
            try:
                temp_file = self.bans_file + ".tmp"
                with open(temp_file, "w", encoding="utf-8") as f:
                    json.dump(raw, f, indent=2)
                os.replace(temp_file, self.bans_file)
                self._dirty = False
            except Exception as e:
                logger.error(f"Failed to auto-save bans: {e}")
    
    def load_bans(self):
        with self._lock:
            self.bans = {}
            try:
                with open(self.bans_file, encoding="utf-8") as f:
                    raw = json.load(f)
                    for ip, info in raw.items():
                        until_str = info["until"]
                        if until_str.endswith('Z'):
                            until_str = until_str[:-1] + '+00:00'
                        until = datetime.fromisoformat(until_str)
                        self.bans[ip] = {"until": until, "reason": info.get("reason", "banned")}
                logger.info(f"Loaded bans from {self.bans_file}")
            except FileNotFoundError:
                logger.info(f"No bans file found at '{self.bans_file}', starting fresh.")
            except Exception as e:
                logger.error(f"Failed to load bans: {e}")
    
    def save_bans(self):
        self._dirty = True
    
    def load_whitelist(self):
        with self._lock:
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
        
        with self._lock:
            info = self.bans.get(ip)
            if not info:
                return False, None
            if datetime.now(timezone.utc) >= info["until"]:
                del self.bans[ip]
                return False, None
            return True, info["reason"]
    
    def add_ban(self, ip, minutes=None, reason="manual ban"):
        if ip in self.whitelist:
            logger.info(f"Attempt to ban whitelisted IP {ip} ignored.")
            return False
        
        with self._lock:
            if minutes is None:
                minutes = self.delay_ban_minutes
            expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
            self.bans[ip] = {"until": expire, "reason": reason}
            self._dirty = True
            
            logger.info(f"Added ban for IP {ip} until {expire.isoformat()} Reason: {reason}")
            return True
    
    def delete_ban(self, ip):
        with self._lock:
            if ip in self.bans:
                del self.bans[ip]
                self._dirty = True
                logger.info(f"Deleted ban for IP {ip}")
                return True
            return False
    
    def get_active_bans(self):
        with self._lock:
            now = datetime.now(timezone.utc)
            return {
                ip: {
                    "until": info["until"].isoformat(),
                    "reason": info["reason"]
                }
                for ip, info in self.bans.items()
                if now < info["until"]
            }
    
    def get_all_bans_list(self):
        with self._lock:
            bans_list = []
            now = datetime.now(timezone.utc)
            
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
