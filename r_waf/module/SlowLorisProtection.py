import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SlowLorisProtection:
    def __init__(self, data):
        self.data = data
        self.state = self.data["data_module"]
        self.connection_tracker = self.state.setdefault("connection_tracker", {})
        self.slow_requests = self.state.setdefault("slow_requests", {})
        self.max_concurrent_connections = 15
        self.max_slow_requests = 5
        self.slow_threshold_seconds = 30

    def run(self):
        if "status_code" in self.data and self.data["status_code"] is not None:
            return {"action": "allow", "result": "skipped_response_phase"}
        
        now = datetime.now(timezone.utc)
        ip = self.data["ip"]
        method = self.data.get("method", "")
        
        if method.upper() not in ["POST", "PUT", "PATCH"]:
            return {"action": "allow", "result": "not_applicable"}
        
        connections = self.connection_tracker.get(ip, [])
        connections = [t for t in connections if (now - t).total_seconds() <= 60]
        connections.append(now)
        self.connection_tracker[ip] = connections
        
        if len(connections) > self.max_concurrent_connections:
            logger.warning(f"Slow Loris attack detected from {ip}: {len(connections)} concurrent connections")
            return {
                "action": "block",
                "reason": f"Too many concurrent connections: {len(connections)}",
                "result": {
                    "concurrent_connections": len(connections),
                    "limit": self.max_concurrent_connections
                }
            }
        
        slow_reqs = self.slow_requests.get(ip, [])
        slow_reqs = [t for t in slow_reqs if (now - t).total_seconds() <= 300]
        
        body = self.data.get("body", "")
        try:
            import base64
            body_decoded = base64.b64decode(body.encode()).decode() if body else ""
        except:
            body_decoded = ""
        
        if len(body_decoded) > 0 and len(body_decoded) < 10:
            slow_reqs.append(now)
            self.slow_requests[ip] = slow_reqs
            
            if len(slow_reqs) > self.max_slow_requests:
                logger.warning(f"Slow POST attack detected from {ip}: {len(slow_reqs)} slow requests")
                return {
                    "action": "block",
                    "reason": f"Slow HTTP attack pattern detected",
                    "result": {
                        "slow_requests": len(slow_reqs),
                        "pattern": "incomplete_post"
                    }
                }
        
        return {
            "action": "allow",
            "result": {
                "concurrent_connections": len(connections),
                "slow_requests": len(slow_reqs)
            }
        }

def run(data):
    return SlowLorisProtection(data).run()
