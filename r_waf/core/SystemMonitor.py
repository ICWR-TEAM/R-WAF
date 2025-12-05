import psutil
import logging
from datetime import datetime, timezone, timedelta
import threading
import json

logger = logging.getLogger(__name__)

class SystemMonitor:
    def __init__(self):
        self._history = []
        self._history_lock = threading.Lock()
        self._max_history = 1440
        self._last_net_io = None
        self._start_collection()
    
    def _start_collection(self):
        def collect():
            import time
            while True:
                try:
                    cpu_percent = psutil.cpu_percent(interval=1)
                    memory = psutil.virtual_memory()
                    net_io = psutil.net_io_counters()
                    
                    upload_speed = 0
                    download_speed = 0
                    if self._last_net_io:
                        time_diff = 60
                        upload_speed = (net_io.bytes_sent - self._last_net_io.bytes_sent) / time_diff
                        download_speed = (net_io.bytes_recv - self._last_net_io.bytes_recv) / time_diff
                    
                    self._last_net_io = net_io
                    
                    entry = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory.percent,
                        "memory_used": memory.used,
                        "memory_total": memory.total,
                        "upload_speed": upload_speed,
                        "download_speed": download_speed
                    }
                    
                    with self._history_lock:
                        self._history.append(entry)
                        if len(self._history) > self._max_history:
                            self._history.pop(0)
                    
                except Exception as e:
                    logger.error(f"Error collecting system metrics: {e}")
                
                time.sleep(60)
        
        t = threading.Thread(target=collect, daemon=True)
        t.start()
    
    def get_current(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            upload_speed = 0
            download_speed = 0
            with self._history_lock:
                if self._history:
                    latest = self._history[-1]
                    upload_speed = latest.get("upload_speed", 0)
                    download_speed = latest.get("download_speed", 0)
            
            return {
                "cpu_percent": round(cpu_percent, 2),
                "memory_percent": round(memory.percent, 2),
                "memory_used_mb": round(memory.used / 1024 / 1024, 2),
                "memory_total_mb": round(memory.total / 1024 / 1024, 2),
                "disk_percent": round(disk.percent, 2),
                "disk_used_gb": round(disk.used / 1024 / 1024 / 1024, 2),
                "disk_total_gb": round(disk.total / 1024 / 1024 / 1024, 2),
                "upload_speed_mbps": round(upload_speed / 1024 / 1024, 2),
                "download_speed_mbps": round(download_speed / 1024 / 1024, 2)
            }
        except Exception as e:
            logger.error(f"Error getting current metrics: {e}")
            return {
                "cpu_percent": 0,
                "memory_percent": 0,
                "memory_used_mb": 0,
                "memory_total_mb": 0,
                "disk_percent": 0,
                "disk_used_gb": 0,
                "disk_total_gb": 0,
                "upload_speed_mbps": 0,
                "download_speed_mbps": 0
            }
    
    def get_history(self, hours=24, start_date=None, end_date=None):
        with self._history_lock:
            if not self._history:
                return {
                    "labels": [],
                    "cpu": [],
                    "memory": [],
                    "upload": [],
                    "download": []
                }
            
            if start_date and end_date:
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
                
                filtered = [
                    h for h in self._history 
                    if start_dt <= datetime.fromisoformat(h["timestamp"].replace("Z", "+00:00")) <= end_dt
                ]
            else:
                cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
                filtered = [
                    h for h in self._history 
                    if datetime.fromisoformat(h["timestamp"].replace("Z", "+00:00")) >= cutoff
                ]
            
            return {
                "labels": [h["timestamp"] for h in filtered],
                "cpu": [h["cpu_percent"] for h in filtered],
                "memory": [h["memory_percent"] for h in filtered],
                "upload": [round(h.get("upload_speed", 0) / 1024 / 1024, 2) for h in filtered],
                "download": [round(h.get("download_speed", 0) / 1024 / 1024, 2) for h in filtered]
            }
