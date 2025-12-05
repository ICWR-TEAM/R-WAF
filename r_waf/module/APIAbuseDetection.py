import logging
import json
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APIAbuseDetection:
    def __init__(self, data):
        self.data = data
        self.max_payload_size = 1 * 1024 * 1024
        self.max_array_length = 1000
        self.max_json_depth = 10

    def run(self):
        if "status_code" in self.data and self.data["status_code"] is not None:
            return {"action": "allow", "result": "skipped_response_phase"}
        
        path = self.data.get("path", "")
        try:
            import base64
            path_decoded = base64.b64decode(path.encode()).decode() if path else ""
        except:
            path_decoded = ""
        
        if not ("/api" in path_decoded.lower() or path_decoded.endswith(".json")):
            return {"action": "allow", "result": "not_api_endpoint"}
        
        ip = self.data["ip"]
        header = self.data.get("header", "")
        try:
            import base64
            header_decoded = base64.b64decode(header.encode()).decode() if header else ""
        except:
            header_decoded = ""
        
        method = self.data.get("method", "")
        if method.upper() in ["POST", "PUT", "PATCH"]:
            if "application/json" not in header_decoded.lower():
                logger.warning(f"Non-JSON content type in API request from {ip}")
                return {
                    "action": "block",
                    "reason": "Invalid Content-Type for API endpoint",
                    "result": {"expected": "application/json"}
                }
            
            body = self.data.get("body", "")
            try:
                import base64
                body_decoded = base64.b64decode(body.encode()).decode() if body else ""
            except:
                body_decoded = ""
            
            if len(body_decoded) > self.max_payload_size:
                logger.warning(f"Oversized API payload from {ip}: {len(body_decoded)} bytes")
                return {
                    "action": "block",
                    "reason": f"API payload too large: {len(body_decoded)} bytes",
                    "result": {"size": len(body_decoded), "limit": self.max_payload_size}
                }
            
            if body_decoded:
                try:
                    json_data = json.loads(body_decoded)
                    
                    def get_json_depth(obj, depth=0):
                        if depth > self.max_json_depth:
                            return depth
                        if isinstance(obj, dict):
                            return max([get_json_depth(v, depth + 1) for v in obj.values()] or [depth])
                        elif isinstance(obj, list):
                            return max([get_json_depth(item, depth + 1) for item in obj] or [depth])
                        return depth
                    
                    depth = get_json_depth(json_data)
                    if depth > self.max_json_depth:
                        logger.warning(f"Deeply nested JSON from {ip}: depth {depth}")
                        return {
                            "action": "block",
                            "reason": f"JSON too deeply nested: {depth} levels",
                            "result": {"depth": depth, "limit": self.max_json_depth}
                        }
                    
                    def count_arrays(obj):
                        count = 0
                        if isinstance(obj, list):
                            if len(obj) > self.max_array_length:
                                return 999999
                            for item in obj:
                                count += count_arrays(item)
                        elif isinstance(obj, dict):
                            for v in obj.values():
                                count += count_arrays(v)
                        return count
                    
                    if isinstance(json_data, list) and len(json_data) > self.max_array_length:
                        logger.warning(f"Oversized JSON array from {ip}: {len(json_data)} elements")
                        return {
                            "action": "block",
                            "reason": f"JSON array too large: {len(json_data)} elements",
                            "result": {"array_size": len(json_data), "limit": self.max_array_length}
                        }
                    
                    json_str = json.dumps(json_data)
                    injection_patterns = [
                        r'<script', r'javascript:', r'onerror=', r'onload=',
                        r'\$\(', r'eval\(', r'function\s*\('
                    ]
                    for pattern in injection_patterns:
                        if re.search(pattern, json_str, re.IGNORECASE):
                            logger.warning(f"Injection attempt in JSON from {ip}")
                            return {
                                "action": "block",
                                "reason": "Code injection detected in JSON payload",
                                "result": {"matched_pattern": pattern}
                            }
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"Malformed JSON from {ip}: {str(e)}")
                    return {
                        "action": "block",
                        "reason": "Malformed JSON payload",
                        "result": {"error": str(e)[:100]}
                    }
                except Exception as e:
                    logger.error(f"JSON validation error from {ip}: {str(e)}")
        
        suspicious_params = ["__proto__", "constructor", "prototype", "$where", "$ne"]
        for param in suspicious_params:
            if param in path_decoded:
                logger.warning(f"Suspicious API parameter from {ip}: {param}")
                return {
                    "action": "block",
                    "reason": f"Suspicious API parameter detected: {param}",
                    "result": {"parameter": param}
                }
        
        return {"action": "allow", "result": {"validation": "passed"}}

def run(data):
    return APIAbuseDetection(data).run()
