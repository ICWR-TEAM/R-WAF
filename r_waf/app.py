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
import importlib.util
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify

sys.dont_write_bytecode = True

BASE_DIR = "./data"
RULES_DIR = os.path.join(BASE_DIR, "rules")
BANS_DIR = os.path.join(BASE_DIR, "bans")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
BANS_FILE_DEFAULT = os.path.join(BANS_DIR, "bans.json")
WHITELIST_FILE_DEFAULT = os.path.join(BANS_DIR, "whitelist.json")

DEFAULT_CONFIG = {
    "rules_dir": RULES_DIR,
    "bans_file": BANS_FILE_DEFAULT,
    "whitelist_file": WHITELIST_FILE_DEFAULT,
    "banned_page_file": "ban.html",
    "module_threads": 10,
    "api_key": "incrustwerush.org",
    "host": "0.0.0.0",
    "port": 5000,
    "debug": False,
    "delay_ban_minutes": 15,
    "anti_http_generic_bf": True,
    "window_seconds": 10,
    "window_max_requests": 5,
    "cache_maxsize": 32,
    "enable_response_filter": True,
    "enable_request_body_check": True,
    "enable_response_body_check": False,
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
    
    from core.InitializeDefaultRules import initialize_default_rules
    initialize_default_rules(config["rules_dir"])

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
        self.api_key = config["api_key"]
        self.data_module = {}
        self.banned_page_file = config["banned_page_file"]
        self.module_threads = config['module_threads']

        self.rules = {}
        
        from core.BanManager import BanManager
        from core.CacheManager import CacheManager
        from core.AlertManager import AlertManager
        from core.RequestLogger import RequestLogger
        from core.SystemMonitor import SystemMonitor
        
        self.ban_manager = BanManager(
            config["bans_file"],
            config["whitelist_file"],
            config["delay_ban_minutes"]
        )
        
        self.cache_manager = CacheManager(maxsize=config['cache_maxsize'])
        
        self.alert_manager = AlertManager(alerts_dir=os.path.join(config['base_dir'], 'alerts'))
        
        self.request_logger = RequestLogger(logs_dir=os.path.join(config['base_dir'], 'traffic'))
        
        self.system_monitor = SystemMonitor()
        
        self._cached_check_request = self.cache_manager.cached(self._check_request_impl)

        self.load_rules()

        self.app = Flask(__name__)
        from routes.route import setup_routes
        setup_routes(self.app, self)
    
    def _check_request_impl(self, ip, method, header, user_agent, path, body):
        return self.check_request(ip, method, header, user_agent, path, body)
    
    def check_request_cached(self, ip, method, header, user_agent, path, body=""):
        return self._cached_check_request(ip, method, header, user_agent, path, body)

    def discover_modules(self):
        return sorted([f for f in Path("module/").rglob("*.py") if not f.name.startswith("__")])
    
    def load_module(self, file_path):
        name = file_path.stem
        spec = importlib.util.spec_from_file_location(name, str(file_path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return name, mod
    
    def run_module(self, file_path, data):
        name, mod = self.load_module(file_path)
        if hasattr(mod, "run"):
            try:
                res = mod.run(data)
                if isinstance(res, dict):
                    if res.get("action") == "block":
                        self.alert_manager.log_alert(
                            module_name=name,
                            action="block",
                            reason=res.get("reason", "unknown"),
                            ip=data.get("ip", "unknown"),
                            method=data.get("method", ""),
                            path=data.get("path", ""),
                            user_agent=data.get("user_agent", ""),
                            matched_rule=res.get("result", {}).get("matched_rule", ""),
                            status_code=data.get("status_code")
                        )
                    return {name: res}
            except Exception as e:
                logger.error(f"Module {name} error {e}")
        return None

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

    def check_request(self, ip, method, header, user_agent, path, body=""):
        try:
            banned, reason = self.ban_manager.is_banned(ip)
            if banned:
                logger.info(f"Blocked banned IP {ip}: {reason}")
                return {"action": "block", "reason": f"banned: {reason}"}
            
            modules = self.discover_modules()
            futures = {}
            with ThreadPoolExecutor(max_workers=self.module_threads) as ex:
                for module_path in modules:
                    mod_name = module_path.stem
                    self.data_module.setdefault(mod_name, {})
                    self.data_module[mod_name].setdefault('result', {})
                    data = {
                        "ip": ip,
                        "method": method,
                        "user_agent": user_agent,
                        "header": header,
                        "path": path,
                        "body": body,
                        "config": self.config,
                        "data_module": self.data_module[mod_name]
                    }
                    fut = ex.submit(self.run_module, module_path, data)
                    futures[fut] = mod_name

            for fut, mod_name in futures.items():
                result = fut.result()
                if result:
                    for key, res in result.items():
                        self.data_module[key]['result'] = res['result']
                        if res["action"] == "block":
                            self.ban_manager.add_ban(ip, reason=res.get("reason"))
                            self.request_logger.log_request(
                                ip=ip,
                                method=method,
                                path=path,
                                user_agent=user_agent,
                                action="block",
                                reason=res.get("reason", ""),
                                module=key,
                                matched_rule=res.get("result", {}).get("matched_rule", "")
                            )
                            return res

        except Exception as e:
            logger.exception(f"Exception during check_request: {e}")
        
        self.request_logger.log_request(
            ip=ip,
            method=method,
            path=path,
            user_agent=user_agent,
            action="allow"
        )
        return {"action": "allow"}

    def check_response(self, ip, method, status_code, header="", body=""):
        if not self.config.get("enable_response_filter", True):
            return {"action": "allow"}
        
        banned, reason = self.ban_manager.is_banned(ip)
        if banned:
            return {"action": "allow"}
        
        try:
            modules = self.discover_modules()
            futures = {}
            with ThreadPoolExecutor(max_workers=self.module_threads) as ex:
                for module_path in modules:
                    mod_name = module_path.stem
                    self.data_module.setdefault(mod_name, {})
                    self.data_module[mod_name].setdefault('result', {})
                    data = {
                        "ip": ip,
                        "method": method,
                        "status_code": status_code,
                        "header": header,
                        "body": body,
                        "config": self.config,
                        "data_module": self.data_module[mod_name]
                    }
                    fut = ex.submit(self.run_module, module_path, data)
                    futures[fut] = mod_name

            for fut, mod_name in futures.items():
                result = fut.result()
                if result:
                    for key, res in result.items():
                        self.data_module[key]['result'] = res['result']
                        if res["action"] == "block":
                            self.ban_manager.add_ban(ip, reason=res.get("reason"))
                            logger.info(f"Response filtering blocked IP {ip}: {res.get('reason')}")
                            self.request_logger.log_request(
                                ip=ip,
                                method=method,
                                path="",
                                user_agent="",
                                action="block",
                                reason=res.get("reason", ""),
                                status_code=status_code,
                                module=key,
                                matched_rule=res.get("result", {}).get("matched_rule", "")
                            )
                            return res

        except Exception as e:
            logger.exception(f"Exception during check_response: {e}")
        
        self.request_logger.log_request(
            ip=ip,
            method=method,
            path="",
            user_agent="",
            action="allow",
            status_code=status_code
        )
        return {"action": "allow"}

    def require_api_key(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            key = request.headers.get("X-API-Key")
            if not key or key != self.api_key:
                logger.warning("Unauthorized API access attempt")
                return jsonify({"error": "Invalid API Key"}), 401
            return f(*args, **kwargs)
        return decorated_function

def load_config(path):
    try:
        if not os.path.exists(path):
            return DEFAULT_CONFIG
        else:
            with open(path, "r", encoding="utf-8") as f:
                conf = json.load(f)
            return conf
    except Exception:
        return DEFAULT_CONFIG.copy()

def main():
    parser = argparse.ArgumentParser(description="Python Flask WAF API")
    parser.add_argument("--config", type=str, default=CONFIG_PATH, help="Path to config JSON file")
    args = parser.parse_args()

    config_path = args.config if args.config else CONFIG_PATH
    config = load_config(config_path)
    
    api_key_env = os.environ.get('RWAF_API_KEY')
    if api_key_env:
        config['api_key'] = api_key_env
        logger_temp = logging.getLogger(__name__)
        logger_temp.info("API Key loaded from environment variable")
    
    enable_dashboard = os.environ.get('ENABLE_DASHBOARD', 'false').lower() == 'true'
    dashboard_port = int(os.environ.get('DASHBOARD_PORT', '1337'))
    
    ensure_dirs_and_files(config)

    setup_logger(config.get("base_dir", BASE_DIR))
    logger.info("Starting WAF app...")

    waf = WAFApp(config)
    
    from threading import Thread
    waf_thread = Thread(target=lambda: waf.app.run(
        host=config["host"], 
        port=config["port"], 
        debug=False,
        use_reloader=False
    ))
    waf_thread.daemon = True
    waf_thread.start()
    logger.info(f"WAF API running on {config['host']}:{config['port']}")
    
    if enable_dashboard:
        from flask import Flask
        from routes.dashboard import init_dashboard
        
        dashboard_app = Flask(__name__, template_folder='templates', static_folder='static')
        
        @dashboard_app.route('/')
        def root_redirect():
            from flask import redirect, url_for
            return redirect('/dashboard')
        
        dashboard_bp = init_dashboard(
            waf.alert_manager, 
            waf.ban_manager,
            waf.request_logger,
            waf.system_monitor,
            config['api_key']
        )
        dashboard_app.register_blueprint(dashboard_bp)
        
        logger.info(f"Dashboard enabled on {config['host']}:{dashboard_port}")
        dashboard_app.run(
            host=config["host"], 
            port=dashboard_port, 
            debug=False
        )
    else:
        logger.info("Dashboard disabled. Set ENABLE_DASHBOARD=true to enable.")
        waf_thread.join()


if __name__ == "__main__":
    main()
