import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BotDetection:
    def __init__(self, data):
        self.data = data
        self.user_agent = self.data.get("user_agent", "").lower()
        
        self.malicious_bots = [
            r"sqlmap", r"nikto", r"nmap", r"masscan", r"nessus", 
            r"acunetix", r"metasploit", r"burpsuite", r"w3af",
            r"dirbuster", r"gobuster", r"wfuzz", r"commix",
            r"havij", r"pangolin", r"jsql", r"sqlninja",
            r"grabber", r"paros", r"webscarab", r"vega",
            r"httrack", r"wget", r"curl.*bot", r"python-requests",
            r"zgrab", r"masscan", r"shodan", r"censys",
            r"nuclei", r"subfinder", r"amass", r"ffuf"
        ]
        
        self.suspicious_patterns = [
            r"bot.*scan", r"exploit", r"hack", r"inject",
            r"attack", r"vulnerability", r"penetration"
        ]
        
        self.scanner_signatures = [
            r"^-$",
            r"^$", 
            r"^mozilla/4\.0$",
            r"^java/",
            r"^libwww-perl",
            r"^python-",
            r"^go-http-client"
        ]

    def run(self):
        if "status_code" in self.data and self.data["status_code"] is not None:
            return {"action": "allow", "result": "skipped_response_phase"}
        
        if not self.user_agent:
            logger.warning(f"Empty User-Agent from IP {self.data['ip']}")
            return {
                "action": "block",
                "reason": "Missing User-Agent (possible bot)",
                "result": {"matched_rule": "empty_user_agent"}
            }
        
        for pattern in self.malicious_bots:
            if re.search(pattern, self.user_agent, re.IGNORECASE):
                logger.warning(f"Malicious bot detected from {self.data['ip']}: {self.user_agent}")
                return {
                    "action": "block",
                    "reason": f"Malicious bot/scanner detected",
                    "result": {"matched_rule": pattern, "user_agent": self.user_agent[:100]}
                }
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, self.user_agent, re.IGNORECASE):
                logger.warning(f"Suspicious User-Agent from {self.data['ip']}: {self.user_agent}")
                return {
                    "action": "block",
                    "reason": "Suspicious bot pattern detected",
                    "result": {"matched_rule": pattern, "user_agent": self.user_agent[:100]}
                }
        
        for pattern in self.scanner_signatures:
            if re.match(pattern, self.user_agent, re.IGNORECASE):
                logger.warning(f"Scanner signature detected from {self.data['ip']}: {self.user_agent}")
                return {
                    "action": "block",
                    "reason": "Scanner signature detected",
                    "result": {"matched_rule": pattern, "user_agent": self.user_agent[:100]}
                }
        
        return {"action": "allow", "result": {"user_agent_check": "passed"}}

def run(data):
    return BotDetection(data).run()
