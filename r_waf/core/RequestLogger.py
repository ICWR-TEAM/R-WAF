import os
import json
import logging
import base64
import threading
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

class RequestLogger:
    
    def __init__(self, logs_dir="data/traffic"):
        self.logs_dir = logs_dir
        os.makedirs(self.logs_dir, exist_ok=True)
        self._file_lock = threading.Lock()
        self._pending_logs = {}
        self._pending_lock = threading.Lock()
        
        self._start_auto_flush()
    
    def _start_auto_flush(self):
        def auto_flush():
            import time
            while True:
                time.sleep(2)
                self._flush_pending_logs()
        
        t = threading.Thread(target=auto_flush, daemon=True)
        t.start()
    
    def _flush_pending_logs(self):
        with self._pending_lock:
            if not self._pending_logs:
                return
            
            pending_copy = dict(self._pending_logs)
            self._pending_logs.clear()
        
        for date_str, logs_to_add in pending_copy.items():
            if not logs_to_add:
                continue
            
            with self._file_lock:
                existing_logs = self._load_logs_unsafe(date_str)
                existing_logs.extend(logs_to_add)
                self._save_logs_unsafe(existing_logs, date_str)
    
    def get_log_file(self, date_str=None):
        if date_str:
            return os.path.join(self.logs_dir, f"{date_str}-traffic.json")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return os.path.join(self.logs_dir, f"{today}-traffic.json")
    
    def _load_logs_unsafe(self, date_str=None):
        log_file = self.get_log_file(date_str)
        if not os.path.exists(log_file):
            return []
        
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load traffic logs from {log_file}: {e}")
            return []
    
    def load_logs(self):
        return self._load_logs_unsafe()
    
    def _save_logs_unsafe(self, logs, date_str=None):
        if date_str is None:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        log_file = os.path.join(self.logs_dir, f"{date_str}-traffic.json")
        
        try:
            temp_file = log_file + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
            os.replace(temp_file, log_file)
        except Exception as e:
            logger.error(f"Failed to save traffic logs to {log_file}: {e}")
    
    def save_logs(self, logs, date_str=None):
        if date_str is None:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        with self._file_lock:
            self._save_logs_unsafe(logs, date_str)
    
    def log_request(self, ip, method, path, user_agent="", action="allow", reason="", 
                    status_code=None, module="", matched_rule=""):
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        try:
            if path and len(path) > 0:
                decoded_path = base64.b64decode(path.encode()).decode() if path else ""
            else:
                decoded_path = path
        except:
            decoded_path = path
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip,
            "method": method,
            "path": decoded_path[:500] if decoded_path else "",  # Limit path length
            "user_agent": user_agent[:200] if user_agent else "",
            "action": action,
            "reason": reason if reason else "",
            "status_code": status_code,
            "module": module if module else "",
            "matched_rule": str(matched_rule)[:200] if matched_rule else ""
        }
        
        with self._pending_lock:
            if date_str not in self._pending_logs:
                self._pending_logs[date_str] = []
            self._pending_logs[date_str].append(log_entry)
    
    def get_logs_paginated(self, page=1, per_page=50, start_date=None, end_date=None, 
                          keyword=None, action_filter=None):
        all_logs = []
        
        if start_date:
            try:
                if 'T' in start_date:
                    start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                else:
                    start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except:
                start_dt = datetime.now(timezone.utc) - timedelta(days=7)
        else:
            start_dt = datetime.now(timezone.utc) - timedelta(days=7)
        
        if end_date:
            try:
                if 'T' in end_date:
                    end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                else:
                    end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            except:
                end_dt = datetime.now(timezone.utc)
        else:
            end_dt = datetime.now(timezone.utc)
        
        current_date = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        end_day = end_dt.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        while current_date <= end_day:
            date_str = current_date.strftime("%Y-%m-%d")
            log_file = self.get_log_file(date_str)
            
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                        for log in logs:
                            try:
                                log_time = datetime.fromisoformat(log.get("timestamp", "").replace('Z', '+00:00'))
                                if start_dt <= log_time <= end_dt:
                                    all_logs.append(log)
                            except:
                                all_logs.append(log)
                except Exception as e:
                    logger.error(f"Failed to load {log_file}: {e}")
            
            current_date += timedelta(days=1)
        
        if action_filter:
            all_logs = [log for log in all_logs if log.get("action") == action_filter]
        
        if keyword:
            keyword_lower = keyword.lower()
            all_logs = [
                log for log in all_logs 
                if keyword_lower in str(log.get("ip", "")).lower() 
                or keyword_lower in str(log.get("path", "")).lower()
                or keyword_lower in str(log.get("reason", "")).lower()
                or keyword_lower in str(log.get("method", "")).lower()
                or keyword_lower in str(log.get("module", "")).lower()
            ]
        
        all_logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        total = len(all_logs)
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        return {
            "logs": all_logs[start_idx:end_idx],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages
        }
    
    def get_stats(self, start_date=None, end_date=None):
        all_logs = []
        
        if start_date and end_date:
            try:
                if 'T' in start_date:
                    start_dt = datetime.fromisoformat(start_date)
                    if start_dt.tzinfo is None:
                        start_dt = start_dt.replace(tzinfo=timezone.utc)
                else:
                    start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                
                if 'T' in end_date:
                    end_dt = datetime.fromisoformat(end_date)
                    if end_dt.tzinfo is None:
                        end_dt = end_dt.replace(tzinfo=timezone.utc)
                else:
                    end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            except:
                end_dt = datetime.now(timezone.utc)
                start_dt = end_dt - timedelta(days=7)
        else:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(days=7)
        
        current_date = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        end_day = end_dt.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        while current_date <= end_day:
            date_str = current_date.strftime("%Y-%m-%d")
            log_file = self.get_log_file(date_str)
            
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                        for log in logs:
                            try:
                                log_time = datetime.fromisoformat(log.get("timestamp", "").replace('Z', '+00:00'))
                                if start_dt <= log_time <= end_dt:
                                    all_logs.append(log)
                            except:
                                pass
                except Exception as e:
                    logger.error(f"Failed to load {log_file}: {e}")
            
            current_date += timedelta(days=1)
        
        total_requests = len(all_logs)
        allowed_requests = len([log for log in all_logs if log.get("action") == "allow"])
        blocked_requests = len([log for log in all_logs if log.get("action") == "block"])
        unique_ips = len(set(log.get("ip") for log in all_logs))
        
        method_counts = {}
        for log in all_logs:
            method = log.get("method", "UNKNOWN")
            method_counts[method] = method_counts.get(method, 0) + 1
        
        blocked_ip_counts = {}
        for log in all_logs:
            if log.get("action") == "block":
                ip = log.get("ip")
                blocked_ip_counts[ip] = blocked_ip_counts.get(ip, 0) + 1
        
        top_blocked_ips = sorted(
            blocked_ip_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return {
            "total_requests": total_requests,
            "allowed_requests": allowed_requests,
            "blocked_requests": blocked_requests,
            "unique_ips": unique_ips,
            "method_counts": method_counts,
            "top_blocked_ips": [{"ip": ip, "count": count} for ip, count in top_blocked_ips]
        }
    
    def get_timeline_data(self, start_date=None, end_date=None, granularity="hour"):
        all_logs = []
        
        if start_date and end_date:
            try:
                if 'T' in start_date:
                    start_dt = datetime.fromisoformat(start_date)
                    if start_dt.tzinfo is None:
                        start_dt = start_dt.replace(tzinfo=timezone.utc)
                else:
                    start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                
                if 'T' in end_date:
                    end_dt = datetime.fromisoformat(end_date)
                    if end_dt.tzinfo is None:
                        end_dt = end_dt.replace(tzinfo=timezone.utc)
                else:
                    end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            except:
                end_dt = datetime.now(timezone.utc)
                start_dt = end_dt - timedelta(days=7)
        else:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(days=7)
        
        current_date = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        end_day = end_dt.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        while current_date <= end_day:
            date_str = current_date.strftime("%Y-%m-%d")
            log_file = self.get_log_file(date_str)
            
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                        for log in logs:
                            try:
                                log_time = datetime.fromisoformat(log.get("timestamp", "").replace('Z', '+00:00'))
                                if start_dt <= log_time <= end_dt:
                                    all_logs.append(log)
                            except:
                                pass
                except Exception as e:
                    logger.error(f"Failed to load {log_file}: {e}")
            
            current_date += timedelta(days=1)
        
        timeline_allowed = {}
        timeline_blocked = {}
        
        for log in all_logs:
            timestamp = log.get("timestamp", "")
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
                
                action = log.get("action", "allow")
                if action == "block":
                    timeline_blocked[key] = timeline_blocked.get(key, 0) + 1
                else:
                    timeline_allowed[key] = timeline_allowed.get(key, 0) + 1
                    
            except Exception as e:
                logger.error(f"Failed to parse timestamp {timestamp}: {e}")
                continue
        
        # Get all unique keys and sort
        all_keys = sorted(set(list(timeline_allowed.keys()) + list(timeline_blocked.keys())))
        
        # Build arrays with 0 for missing values
        allowed_data = [timeline_allowed.get(key, 0) for key in all_keys]
        blocked_data = [timeline_blocked.get(key, 0) for key in all_keys]
        
        return {
            "labels": all_keys,
            "allowed": allowed_data,
            "blocked": blocked_data
        }
    
    def clear_logs(self, date_str=None):
        log_file = self.get_log_file(date_str)
        if os.path.exists(log_file):
            try:
                os.remove(log_file)
                logger.info(f"Cleared traffic logs: {log_file}")
                return True
            except Exception as e:
                logger.error(f"Failed to clear logs: {e}")
                return False
        return True
