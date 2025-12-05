from flask import request, jsonify
from html import escape
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


def setup_routes(app, waf_instance):
    @app.route("/config", methods=["GET"])
    def get_config():
        return jsonify({
            "enable_request_body_check": waf_instance.config.get("enable_request_body_check", True),
            "enable_response_body_check": waf_instance.config.get("enable_response_body_check", False),
            "enable_response_filter": waf_instance.config.get("enable_response_filter", True)
        })
    
    @app.route("/reload", methods=["GET"])
    def reload_all():
        waf_instance.load_rules()
        waf_instance.ban_manager.load_bans()
        waf_instance.ban_manager.load_whitelist()
        waf_instance.cache_manager.clear_all()
        return jsonify({"status": "reloaded"})
    
    @app.route("/cache/stats", methods=["GET"])
    @waf_instance.require_api_key
    def cache_stats():
        return jsonify({
            "summary": waf_instance.cache_manager.get_summary(),
            "details": waf_instance.cache_manager.get_stats()
        })
    
    @app.route("/cache/clear", methods=["POST"])
    @waf_instance.require_api_key
    def cache_clear():
        cleared = waf_instance.cache_manager.clear_all()
        return jsonify({"status": "cleared", "functions": cleared})

    @app.route("/check", methods=["POST"])
    def check():
        data = request.json or {}
        ip = data.get("ip", "")
        method = data.get("method", "")
        ua = data.get("user_agent", "")
        path = data.get("path", "")
        header = data.get("header", "")
        body_raw = data.get("body_raw_b64", "")
        status_code = data.get("status_code")
        
        if status_code is not None:
            return jsonify(waf_instance.check_response(ip, method, status_code, header, body_raw))
        else:
            return jsonify(waf_instance.check_request_cached(ip, method, header, ua, path, body_raw))

    @app.route("/ban/list", methods=["GET"])
    @waf_instance.require_api_key
    def ban_list():
        return jsonify(waf_instance.ban_manager.get_active_bans())

    @app.route("/ban/add", methods=["GET"])
    @waf_instance.require_api_key
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

        success = waf_instance.ban_manager.add_ban(ip, minutes, reason)
        if not success:
            return jsonify({"status": "ignored", "reason": "IP in whitelist"}), 200
        expire = waf_instance.ban_manager.bans[ip]["until"]
        return jsonify({"status": "banned", "ip": ip, "until": expire.isoformat()})

    @app.route("/ban/delete", methods=["GET"])
    @waf_instance.require_api_key
    def ban_delete():
        ip = request.args.get("ip")
        if not ip:
            return jsonify({"error": "ip param required"}), 400
        success = waf_instance.ban_manager.delete_ban(ip)
        if success:
            return jsonify({"status": "deleted", "ip": ip})
        return jsonify({"status": "not found", "ip": ip}), 404

    @app.route("/banned_page", methods=["GET", "POST"])
    def banned_page():
        try:
            data = request.json or {}
            ip = request.args.get("ip") or data.get("ip", "")
            ip_escaped = escape(ip)

            expiry_ts = 0
            remaining = 0
            reason = "Unknown"
            info = waf_instance.ban_manager.bans.get(ip)
            if info:
                expiry_ts = int(info["until"].timestamp() * 1000)
                remaining = int((info["until"] - datetime.now(timezone.utc)).total_seconds())
                if remaining < 0:
                    remaining = 0
                reason = escape(info.get("reason", "Unknown"))

            with open(waf_instance.banned_page_file, "r", encoding="utf-8") as f:
                content = f.read()

            content = content.replace("$IP", ip_escaped).replace("{{IP}}", ip_escaped)
            content = content.replace("$EXPIRY", str(expiry_ts)).replace("{{EXPIRY}}", str(expiry_ts))
            content = content.replace("$REMAIN", str(remaining)).replace("{{REMAIN}}", str(remaining))
            content = content.replace("{{REASON}}", reason)

            return content, 200, {"Content-Type": "text/html"}
        except Exception as e:
            logger.error(f"Failed to load banned page from {waf_instance.banned_page_file}: {e}")
            return "<h1>Access Denied</h1><p>Blocked by WAF</p>", 500, {"Content-Type": "text/html"}
    
    @app.route("/alerts", methods=["GET"])
    @waf_instance.require_api_key
    def get_alerts():
        limit = request.args.get("limit", 100, type=int)
        ip = request.args.get("ip")
        
        if ip:
            alerts = waf_instance.alert_manager.get_alerts_by_ip(ip, limit)
        else:
            alerts = waf_instance.alert_manager.get_alerts(limit)
        
        return jsonify({
            "total": len(alerts),
            "alerts": alerts
        })
    
    @app.route("/alerts/clear", methods=["POST"])
    @waf_instance.require_api_key
    def clear_alerts():
        success = waf_instance.alert_manager.clear_alerts()
        return jsonify({"status": "cleared" if success else "failed"})
