import logging
import base64
import json
import re
from urllib.parse import unquote_plus
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BasicAttackRules:
    def __init__(self, data):
        self.data = data
        self.config = self.data["config"]
        self.rules = self.load_rules()
        
    def load_rules(self):
        rules = {}
        rules_dir = self.config.get("rules_dir", "./data/rules")
        if not Path(rules_dir).exists():
            return rules
        
        for f in Path(rules_dir).iterdir():
            if f.suffix == ".json":
                try:
                    with open(f, encoding="utf-8") as fp:
                        rules[f.name] = json.load(fp)
                except Exception as e:
                    logger.error(f"Failed to load rules file {f}: {e}")
        return rules
    
    def try_base64_decode(self, s):
        try:
            decoded = base64.b64decode(s, validate=True)
            return decoded.decode('utf-8', errors='ignore')
        except Exception:
            return s
    
    def pattern_check(self, pattern, string):
        try:
            variants = [
                string,
                unquote_plus(string),
                self.try_base64_decode(string)
            ]
            return any(re.search(pattern.lower(), v.lower()) for v in variants)
        except Exception as e:
            logger.info(f"Error: {e}")
        return False

    def run(self):
        if "status_code" in self.data and self.data["status_code"] is not None:
            return {"action": "allow", "result": "skipped_response_phase"}
        
        ip = self.data.get("ip", "")
        user_agent = self.data.get("user_agent", "")
        header = self.data.get("header", "")
        path = self.data.get("path", "")
        body = self.data.get("body", "")
        
        decode = lambda v: base64.b64decode(v).decode('utf-8') if v else ""
        header = "\r\n".join(f"{k.title()}: {v}" for k, v in json.loads(decode(header.decode() if isinstance(header, bytes) else header)).items())
        path = decode(path)
        body = decode(body)
        
        targets = {
            "ip_blocklist": ip,
            "user_agents": user_agent.lower(),
            "headers": header,
            "paths": path,
            "body": body,
        }

        for rule_type, target in targets.items():
            for fname in filter(lambda f: rule_type in f, self.rules):
                for rule in self.rules.get(fname, []):
                    if rule_type == "ip_blocklist" and ip == rule:
                        logger.info(f"Blocked IP by ip_blocklist: {ip}")
                        return {"action": "block", "reason": "ip_blocklist", "result": {"matched_rule": rule}}
                    if rule_type == "user_agents" and rule.lower() in target:
                        logger.info(f"Blocked IP {ip} by bad user-agent: {user_agent}")
                        return {"action": "block", "reason": "bad_user_agent", "result": {"matched_rule": rule}}
                    if rule_type in {"headers", "paths", "body"} and self.pattern_check(rule, target):
                        logger.info(f"Blocked IP {ip} by {rule_type} pattern: {rule}")
                        return {"action": "block", "reason": f"{rule_type}_blocked", "result": {"matched_rule": rule}}
        
        return {"action": "allow", "result": "no_match"}

def run(data):
    return BasicAttackRules(data).run()
