import os
import json
import logging
import base64
import threading
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, alerts_dir="data/alerts"):
        self.alerts_dir = alerts_dir
        os.makedirs(self.alerts_dir, exist_ok=True)
        self._file_lock = threading.Lock()
        self._pending_alerts = {}
        self._pending_lock = threading.Lock()
        
        self._start_auto_flush()
    
    def _start_auto_flush(self):
        def auto_flush():
            import time
            while True:
                time.sleep(2)
                self._flush_pending_alerts()
        
        t = threading.Thread(target=auto_flush, daemon=True)
        t.start()
    
    def _flush_pending_alerts(self):
        with self._pending_lock:
            if not self._pending_alerts:
                return
            
            pending_copy = dict(self._pending_alerts)
            self._pending_alerts.clear()
        
        for date_str, alerts_to_add in pending_copy.items():
            if not alerts_to_add:
                continue
            
            with self._file_lock:
                existing_alerts = self._load_alerts_unsafe(date_str)
                existing_alerts.extend(alerts_to_add)
                self._save_alerts_unsafe(existing_alerts, date_str)
    
    def get_alert_file(self, date_str=None):
        if date_str:
            return os.path.join(self.alerts_dir, f"{date_str}-alerts.json")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return os.path.join(self.alerts_dir, f"{today}-alerts.json")
    
    def _load_alerts_unsafe(self, date_str=None):
        alert_file = self.get_alert_file(date_str)
        if not os.path.exists(alert_file):
            return []
        
        try:
            with open(alert_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load alerts from {alert_file}: {e}")
            return []
    
    def load_alerts(self):
        return self._load_alerts_unsafe()
    
    def _save_alerts_unsafe(self, alerts, date_str=None):
        if date_str is None:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        alert_file = os.path.join(self.alerts_dir, f"{date_str}-alerts.json")
        
        try:
            temp_file = alert_file + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(alerts, f, indent=2, ensure_ascii=False)
            os.replace(temp_file, alert_file)
        except Exception as e:
            logger.error(f"Failed to save alerts to {alert_file}: {e}")
    
    def save_alerts(self, alerts, date_str=None):
        if date_str is None:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        with self._file_lock:
            self._save_alerts_unsafe(alerts, date_str)
    
    def log_alert(self, module_name, action, reason, ip, method="", path="", user_agent="", matched_rule="", status_code=None):
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "module": module_name,
            "action": action,
            "reason": reason,
            "ip": ip,
            "method": method,
            "path": base64.b64decode(path.encode()).decode() if path else "",
            "user_agent": user_agent[:100] if user_agent else "",
            "matched_rule": str(matched_rule)[:200] if matched_rule else "",
            "status_code": status_code
        }
        
        with self._pending_lock:
            if date_str not in self._pending_alerts:
                self._pending_alerts[date_str] = []
            self._pending_alerts[date_str].append(alert)
        
        logger.warning(f"[ALERT] {module_name} | {action} | {reason} | IP: {ip}")
    
    def get_alerts(self, limit=100):
        alerts = self.load_alerts()
        return alerts[-limit:] if len(alerts) > limit else alerts
    
    def get_alerts_by_ip(self, ip, limit=50):
        alerts = self.load_alerts()
        filtered = [a for a in alerts if a.get("ip") == ip]
        return filtered[-limit:] if len(filtered) > limit else filtered
    
    def clear_alerts(self):
        alert_file = self.get_alert_file()
        if os.path.exists(alert_file):
            try:
                os.remove(alert_file)
                logger.info(f"Cleared alerts file: {alert_file}")
                return True
            except Exception as e:
                logger.error(f"Failed to clear alerts: {e}")
                return False
        return True
    
    def get_alerts_paginated(self, page=1, per_page=50, start_date=None, end_date=None, keyword=None):
        all_alerts = []
        
        if start_date and end_date:
            current_date = datetime.strptime(start_date, "%Y-%m-%d")
            end = datetime.strptime(end_date, "%Y-%m-%d")
        else:
            end = datetime.now(timezone.utc)
            current_date = end - timedelta(days=7)
        
        while current_date <= end:
            date_str = current_date.strftime("%Y-%m-%d")
            alert_file = self.get_alert_file(date_str)
            
            if os.path.exists(alert_file):
                try:
                    with open(alert_file, "r", encoding="utf-8") as f:
                        alerts = json.load(f)
                        all_alerts.extend(alerts)
                except Exception as e:
                    logger.error(f"Failed to load {alert_file}: {e}")
            
            current_date += timedelta(days=1)
        
        if keyword:
            keyword_lower = keyword.lower()
            all_alerts = [
                a for a in all_alerts 
                if keyword_lower in str(a.get("ip", "")).lower() 
                or keyword_lower in str(a.get("path", "")).lower()
                or keyword_lower in str(a.get("reason", "")).lower()
                or keyword_lower in str(a.get("module", "")).lower()
            ]
        
        all_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        total = len(all_alerts)
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        return {
            "alerts": all_alerts[start_idx:end_idx],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages
        }
    
    def get_stats(self):
        all_alerts = []
        
        end = datetime.now(timezone.utc)
        current_date = end - timedelta(days=7)
        
        while current_date <= end:
            date_str = current_date.strftime("%Y-%m-%d")
            alert_file = self.get_alert_file(date_str)
            
            if os.path.exists(alert_file):
                try:
                    with open(alert_file, "r", encoding="utf-8") as f:
                        alerts = json.load(f)
                        all_alerts.extend(alerts)
                except Exception as e:
                    logger.error(f"Failed to load {alert_file}: {e}")
            
            current_date += timedelta(days=1)
        
        total_alerts = len(all_alerts)
        blocked_ips = len(set(a.get("ip") for a in all_alerts if a.get("action") == "block"))
        
        module_counts = {}
        for alert in all_alerts:
            module = alert.get("module", "unknown")
            module_counts[module] = module_counts.get(module, 0) + 1
        
        return {
            "total_alerts": total_alerts,
            "blocked_ips": blocked_ips,
            "module_counts": module_counts,
            "recent_alerts": all_alerts[-10:] if len(all_alerts) > 10 else all_alerts
        }
    
    def get_timeline_data(self, start_date=None, end_date=None, granularity="hour"):
        all_alerts = []
        
        if start_date and end_date:
            current_date = datetime.strptime(start_date, "%Y-%m-%d")
            end = datetime.strptime(end_date, "%Y-%m-%d")
        else:
            end = datetime.now(timezone.utc)
            current_date = end - timedelta(days=7)
        
        while current_date <= end:
            date_str = current_date.strftime("%Y-%m-%d")
            alert_file = self.get_alert_file(date_str)
            
            if os.path.exists(alert_file):
                try:
                    with open(alert_file, "r", encoding="utf-8") as f:
                        alerts = json.load(f)
                        all_alerts.extend(alerts)
                except Exception as e:
                    logger.error(f"Failed to load {alert_file}: {e}")
            
            current_date += timedelta(days=1)
        
        timeline = {}
        for alert in all_alerts:
            timestamp = alert.get("timestamp", "")
            if not timestamp:
                continue
            
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                
                if granularity == "hour":
                    key = dt.strftime("%Y-%m-%d %H:00")
                elif granularity == "day":
                    key = dt.strftime("%Y-%m-%d")
                else:
                    key = dt.strftime("%Y-%m-%d %H:00")
                
                timeline[key] = timeline.get(key, 0) + 1
            except Exception as e:
                logger.error(f"Failed to parse timestamp {timestamp}: {e}")
                continue
        
        sorted_timeline = sorted(timeline.items())
        
        return {
            "labels": [item[0] for item in sorted_timeline],
            "data": [item[1] for item in sorted_timeline]
        }
