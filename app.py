print(r"""
 /$$$$$$$          /$$      /$$  /$$$$$$  /$$$$$$$$
| $$__  $$        | $$  /$ | $$ /$$__  $$| $$_____/
| $$  \ $$        | $$ /$$$| $$| $$  \ $$| $$      
| $$$$$$$/ /$$$$$$| $$/$$ $$ $$| $$$$$$$$| $$$$$   
| $$__  $$|______/| $$$$_  $$$$| $$__  $$| $$__/   
| $$  \ $$        | $$$/ \  $$$| $$  | $$| $$      
| $$  | $$        | $$/   \  $$| $$  | $$| $$      
|__/  |__/        |__/     \__/|__/  |__/|__/      
===================================================
[*] R-WAF (Rusher WAF) - R&D incrustwerush.org
===================================================
""")

import argparse
import base64
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import unquote_plus
from functools import lru_cache

from flask import Flask, request, jsonify

BASE_DIR = "./rwaf"
RULES_DIR = os.path.join(BASE_DIR, "rules")
BANS_DIR = os.path.join(BASE_DIR, "bans")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
BANS_FILE_DEFAULT = os.path.join(BANS_DIR, "bans.json")
WHITELIST_FILE_DEFAULT = os.path.join(BANS_DIR, "whitelist.json")
CACHE_MAXSIZE = 32

DEFAULT_CONFIG = {
    "rules_dir": RULES_DIR,
    "bans_file": BANS_FILE_DEFAULT,
    "whitelist_file": WHITELIST_FILE_DEFAULT,
    "banned_page_file": os.path.join(BASE_DIR, "banned.html"),
    "api_key": "incrustwerush.org",
    "host": "0.0.0.0",
    "port": 5000,
    "debug": False,
    "delay_ban_minutes": 3,
    "cache_maxsize": CACHE_MAXSIZE,
    "base_dir": BASE_DIR
}

logger = None

def ensure_dirs_and_files(config):
    os.makedirs(config["rules_dir"], exist_ok=True)
    os.makedirs(os.path.dirname(config["bans_file"]), exist_ok=True)

    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)

    if not os.path.exists(config["bans_file"]):
        with open(config["bans_file"], "w") as f:
            f.write("{}")

    if not os.path.exists(config["whitelist_file"]):
        with open(config["whitelist_file"], "w") as f:
            json.dump([], f)

    default_rules = {
        "ip_blocklist.json": [
            "192.168.1.100",
            "10.0.0.2"
        ],
        "headers_patterns.json": [
            r"(?i)union\s+select",
            r"(?i)or\s+1=1",
            r"(?i)drop\s+table",
            r"<\?php",
            r"base64_decode"
        ],
        "user_agents.json": [
            "sqlmap",
            "nikto",
            "fuzz",
            "curl"
        ],
        "paths.json": [
            r"/wp-admin",
            r"/phpmyadmin",
            r"/\.env",
            r"../etc/passwd",
            r"<script>",
            r"<\?php",
            r"eval\(",
            r"(?i)union\s+select",
            r"(?i)or\s+1=1",
            r"(?i)drop\s+table",
            r"/\.git",
            r".*\.bak"
        ],
        "body_patterns.json": [
            r"(?i)union\s+select",
            r"(?i)or\s+1=1",
            r"(?i)drop\s+table",
            r"<script>",
            r"<\?php",
            r"base64_decode"
        ]
    }

    for filename, rules in default_rules.items():
        rule_path = os.path.join(config["rules_dir"], filename)
        if not os.path.exists(rule_path):
            with open(rule_path, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2)

    banned_html_path = os.path.join(config["base_dir"], "banned.html")
    if not os.path.exists(banned_html_path):
        banned_html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Access Denied</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <link rel="icon" href="https://incrustwerush.org/img/site/icon.ico" />
  <style>
    html, body {
      margin: 0;
      padding: 0;
      height: 100%;
      background-color: #000;
      color: #fff;
      font-family: monospace;
      display: flex;
      justify-content: center;
      align-items: center;
      text-align: center;
    }

    .container {
      max-width: 100%;
    }
  </style>
</head>
<body>
  <div class="container">
    <div style="margin-bottom: 20px;">
        <span style="font-size: 30px; font-weight: bold;">Access Denied</span>
    </div>
    <div style="margin-bottom: 20px;">
        <span style="font-size: 20px; font-weight: bold;">Your IP has been blocked by the R-WAF</span>
    </div>
    <div>
        <span>R-WAF | R&D incrustwerush.org</span>
    </div>
  </div>
</body>
</html>
"""
        with open(banned_html_path, "w", encoding="utf-8") as f:
            f.write(banned_html_content.strip())

def setup_logger(base_dir):
    global logger
    os.makedirs(base_dir, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(base_dir, "waf.log")),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)


class WAFApp:
    def __init__(self, config):
        self.config = config
        self.rules_dir = config["rules_dir"]
        self.bans_file = config["bans_file"]
        self.whitelist_file = config["whitelist_file"]
        self.api_key = config["api_key"]
        self.banned_page_file = config["banned_page_file"]
        self.delay_ban_minutes = config["delay_ban_minutes"]
        self.cache_maxsize = config['cache_maxsize']
        global CACHE_MAXSIZE
        CACHE_MAXSIZE = self.cache_maxsize

        self.rules = {}
        self.bans = {}
        self.whitelist = set()

        self.load_rules()
        self.load_bans()
        self.load_whitelist()

        self.app = Flask(__name__)
        self.setup_routes()

    @staticmethod
    def cached_wrapper(method):
        @lru_cache(maxsize=CACHE_MAXSIZE)
        def wrapper(self, *args):
            return method(self, *args)
        return wrapper
    
    @cached_wrapper
    def check_request_cached(self, ip, header, user_agent, path, body=""):
        return self.check_request(ip, header, user_agent, path, body)

    def load_rules(self):
        self.rules = {}
        if not os.path.exists(self.rules_dir):
            logger.warning(f"Rules directory '{self.rules_dir}' does not exist.")
            return
        for f in os.listdir(self.rules_dir):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(self.rules_dir, f), encoding="utf-8") as fp:
                        self.rules[f] = json.load(fp)
                    logger.info(f"Loaded rules from {f}")
                except Exception as e:
                    logger.error(f"Failed to load rules file {f}: {e}")

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
        raw = {
            ip: {
                "until": info["until"].isoformat() + "Z",
                "reason": info["reason"]
            } for ip, info in self.bans.items()
        }
        try:
            with open(self.bans_file, "w", encoding="utf-8") as f:
                json.dump(raw, f, indent=2)
            logger.info(f"Saved bans to {self.bans_file}")
        except Exception as e:
            logger.error(f"Failed to save bans: {e}")

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
        info = self.bans.get(ip)
        if not info:
            return False, None
        if datetime.now(timezone.utc) >= info["until"]:
            del self.bans[ip]
            self.save_bans()
            return False, None
        return True, info["reason"]
    
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

    def check_request(self, ip, header, user_agent, path, body=""):
        try:
            banned, reason = self.is_banned(ip)
            
            decode = lambda v: base64.b64decode(v).decode('utf-8') if v else ""
            header = "\r\n".join( f"{k.title()}: {v}" for k, v in json.loads( decode(header.decode() if isinstance(header, bytes) else header) ).items() )
            path = decode(path)
            body = decode(body)

            if banned:
                logger.info(f"Blocked banned IP {ip}: {reason}")
                return {"action": "block", "reason": f"banned: {reason}"}

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
                            self.add_ban(ip, reason="ip_blocklist")
                            return {"action": "block", "reason": "ip_blocklist"}
                        if rule_type == "user_agents" and rule.lower() in target:
                            logger.info(f"Blocked IP {ip} by bad user-agent: {user_agent}")
                            self.add_ban(ip, reason="bad_user_agent")
                            return {"action": "block", "reason": "bad_user_agent"}
                        if rule_type in {"headers", "paths", "body"} and self.pattern_check(rule, target):
                            logger.info(f"Blocked IP {ip} by {rule_type} pattern: {rule}")
                            self.add_ban(ip, reason=f"{rule_type}_blocked")
                            return {"action": "block", "reason": f"{rule_type}_blocked"}

        except Exception as e:
            logger.exception(f"Exception during check_request: {e}")
        return {"action": "allow"}

    def add_ban(self, ip, minutes=None, reason="manual ban"):
        if ip in self.whitelist:
            logger.info(f"Attempt to ban whitelisted IP {ip} ignored.")
            return False
        if minutes is None:
            minutes = self.delay_ban_minutes
        expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        self.bans[ip] = {"until": expire, "reason": reason}
        self.save_bans()
        logger.info(f"Added ban for IP {ip} until {expire.isoformat()} Reason: {reason}")
        return True

    def delete_ban(self, ip):
        if ip in self.bans:
            del self.bans[ip]
            self.save_bans()
            logger.info(f"Deleted ban for IP {ip}")
            return True
        return False

    def get_active_bans(self):
        now = datetime.now(timezone.utc)
        return {
            ip: {
                "until": info["until"].isoformat(),
                "reason": info["reason"]
            }
            for ip, info in self.bans.items()
            if now < info["until"]
        }

    def require_api_key(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            key = request.headers.get("X-API-Key")
            if not key or key != self.api_key:
                logger.warning("Unauthorized API access attempt")
                return jsonify({"error": "Invalid API Key"}), 401
            return f(*args, **kwargs)
        return decorated_function

    def setup_routes(self):
        @self.app.route("/reload", methods=["GET"])
        def reload_all():
            self.load_rules()
            self.load_bans()
            self.load_whitelist()
            return jsonify({"status": "reloaded"})

        @self.app.route("/check", methods=["POST"])
        def check():
            data = request.json or {}
            ip = data.get("ip", "")
            ua = data.get("user_agent", "")
            path = data.get("path", "")
            header = data.get("header", "")
            body_raw = data.get("body_raw_b64", "")
            #return jsonify(self.check_request(ip, header, ua, path, body_raw))
            return jsonify(self.check_request_cached(ip, header, ua, path, body_raw))

        @self.app.route("/ban/list", methods=["GET"])
        @self.require_api_key
        def ban_list():
            return jsonify(self.get_active_bans())

        @self.app.route("/ban/add", methods=["GET"])
        @self.require_api_key
        def ban_add():
            ip = request.args.get("ip")
            if not ip:
                return jsonify({"error": "ip param required"}), 400
            minutes = request.args.get("minutes")
            reason = request.args.get("reason", "manual ban")
            try:
                minutes = int(minutes) if minutes else None
            except Exception:
                return jsonify({"error": "minutes param invalid"}), 400

            success = self.add_ban(ip, minutes, reason)
            if not success:
                return jsonify({"status": "ignored", "reason": "IP in whitelist"}), 200
            expire = self.bans[ip]["until"]
            return jsonify({"status": "banned", "ip": ip, "until": expire.isoformat()})

        @self.app.route("/ban/delete", methods=["GET"])
        @self.require_api_key
        def ban_delete():
            ip = request.args.get("ip")
            if not ip:
                return jsonify({"error": "ip param required"}), 400
            success = self.delete_ban(ip)
            if success:
                return jsonify({"status": "deleted", "ip": ip})
            return jsonify({"status": "not found", "ip": ip}), 404

        @self.app.route("/banned_page", methods=["GET"])
        def banned_page():
            try:
                with open(self.banned_page_file, "r", encoding="utf-8") as f:
                    return f.read(), 200, {"Content-Type": "text/html"}
            except Exception as e:
                logger.error(f"Failed to load banned page from {self.banned_page_file}: {e}")
                return "<h1>Access Denied</h1><p>Blocked by WAF</p>", 500, {"Content-Type": "text/html"}


def load_config(path):
    if not os.path.exists(path):
        return DEFAULT_CONFIG.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            conf = json.load(f)
        merged = DEFAULT_CONFIG.copy()
        merged.update(conf)
        return merged
    except Exception:
        return DEFAULT_CONFIG.copy()


def main():
    parser = argparse.ArgumentParser(description="Python Flask WAF API")
    parser.add_argument("--config", type=str, default=CONFIG_PATH, help="Path to config JSON file")
    args = parser.parse_args()

    config = load_config(args.config)

    ensure_dirs_and_files(config)

    setup_logger(config.get("base_dir", BASE_DIR))

    logger.info("Starting WAF app...")

    waf = WAFApp(config)
    waf.app.run(host=config["host"], port=config["port"], debug=config["debug"])


if __name__ == "__main__":
    main()
