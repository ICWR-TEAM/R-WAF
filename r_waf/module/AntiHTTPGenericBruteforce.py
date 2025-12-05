import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AntiHTTPGenericBruteforce:
    def __init__(self, data):
        self.data = data
        self.state = self.data["data_module"]
        self.response_hits = self.state.setdefault("response_hits", {})
        self.window = self.data["config"]["window_seconds"]
        self.limit = self.data["config"]["window_max_requests"]

    def run(self):
        if not self.data['config']['anti_http_generic_bf']:
            return {"action": "allow", "result": "module_disabled"}
        
        if "status_code" not in self.data or self.data["status_code"] is None:
            return {"action": "allow", "result": "skipped_request_phase"}
        
        now = datetime.now(timezone.utc)
        ip = self.data["ip"]
        status_code = self.data["status_code"]
        
        suspicious_codes = [401, 403, 429]
        
        if status_code not in suspicious_codes:
            return {"action": "allow", "result": {"response_pattern": "normal"}}
        
        buf = self.response_hits.get(ip, [])
        buf = [t for t in buf if (now - t).total_seconds() <= self.window]
        buf.append(now)
        self.response_hits[ip] = buf
        
        if len(buf) > self.limit:
            logger.info(f"Blocked {ip} by response pattern: {len(buf)} x {status_code} in {self.window}s")
            return {
                "action": "block", 
                "reason": f"Suspicious response pattern: {len(buf)} x {status_code}",
                "result": {"response_hits": len(buf), "status_code": status_code}
            }
        
        return {
            "action": "allow", 
            "result": {"response_hits": len(buf), "status_code": status_code}
        }

def run(data):
    return AntiHTTPGenericBruteforce(data).run()

