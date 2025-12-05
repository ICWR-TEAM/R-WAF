from flask import Blueprint, render_template, jsonify, request, redirect, url_for, send_from_directory
from functools import wraps
import logging
import os

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

def init_dashboard(alert_manager, ban_manager, request_logger, system_monitor, api_key):
    dashboard_bp.alert_manager = alert_manager
    dashboard_bp.ban_manager = ban_manager
    dashboard_bp.request_logger = request_logger
    dashboard_bp.system_monitor = system_monitor
    dashboard_bp.api_key = api_key
    return dashboard_bp

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key or api_key != dashboard_bp.api_key:
            return jsonify({"error": "Invalid or missing API key"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

@dashboard_bp.route('/')
def index():
    return render_template('dashboard.html')

@dashboard_bp.route('/login')
def login():
    return render_template('login.html')

@dashboard_bp.route('/api/stats')
@require_api_key
def get_stats():
    try:
        alert_stats = dashboard_bp.alert_manager.get_stats()
        bans = dashboard_bp.ban_manager.get_all_bans_list()
        active_bans = len([b for b in bans if b.get('active', False)])
        
        return jsonify({
            "total_alerts": alert_stats.get("total_alerts", 0),
            "blocked_ips": alert_stats.get("blocked_ips", 0),
            "active_bans": active_bans,
            "module_counts": alert_stats.get("module_counts", {})
        })
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/alerts')
@require_api_key
def get_alerts():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        keyword = request.args.get('keyword')
        
        result = dashboard_bp.alert_manager.get_alerts_paginated(
            page=page,
            per_page=per_page,
            start_date=start_date,
            end_date=end_date,
            keyword=keyword
        )
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/bans', methods=['GET'])
@require_api_key
def get_bans():
    try:
        bans = dashboard_bp.ban_manager.get_all_bans_list()
        return jsonify({"bans": bans})
    except Exception as e:
        logger.error(f"Error getting bans: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/bans', methods=['POST'])
@require_api_key
def add_ban():
    try:
        data = request.get_json()
        ip = data.get('ip')
        reason = data.get('reason', 'Manual ban from dashboard')
        minutes = data.get('minutes', 15)
        
        if not ip:
            return jsonify({"error": "IP address is required"}), 400
        
        success = dashboard_bp.ban_manager.add_ban(ip, minutes=minutes, reason=reason)
        
        if success:
            return jsonify({"message": f"IP {ip} banned successfully"})
        else:
            return jsonify({"error": "Failed to ban IP (might be whitelisted)"}), 400
    except Exception as e:
        logger.error(f"Error adding ban: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/bans/<ip>', methods=['DELETE'])
@require_api_key
def delete_ban(ip):
    try:
        success = dashboard_bp.ban_manager.delete_ban(ip)
        
        if success:
            return jsonify({"message": f"IP {ip} unbanned successfully"})
        else:
            return jsonify({"error": "IP not found in ban list"}), 404
    except Exception as e:
        logger.error(f"Error deleting ban: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/timeline')
@require_api_key
def get_timeline():
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        granularity = request.args.get('granularity', 'hour')
        
        timeline_data = dashboard_bp.alert_manager.get_timeline_data(
            start_date=start_date,
            end_date=end_date,
            granularity=granularity
        )
        
        return jsonify(timeline_data)
    except Exception as e:
        logger.error(f"Error getting timeline: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/traffic')
@require_api_key
def get_traffic():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        keyword = request.args.get('keyword')
        action_filter = request.args.get('action')  # 'allow', 'block', or None for all
        
        result = dashboard_bp.request_logger.get_logs_paginated(
            page=page,
            per_page=per_page,
            start_date=start_date,
            end_date=end_date,
            keyword=keyword,
            action_filter=action_filter
        )
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting traffic: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/traffic/stats')
@require_api_key
def get_traffic_stats():
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        stats = dashboard_bp.request_logger.get_stats(
            start_date=start_date,
            end_date=end_date
        )
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting traffic stats: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/traffic/timeline')
@require_api_key
def get_traffic_timeline():
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        granularity = request.args.get('granularity', 'hour')
        
        timeline_data = dashboard_bp.request_logger.get_timeline_data(
            start_date=start_date,
            end_date=end_date,
            granularity=granularity
        )
        
        return jsonify(timeline_data)
    except Exception as e:
        logger.error(f"Error getting traffic timeline: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/system/current')
@require_api_key
def get_system_current():
    try:
        current = dashboard_bp.system_monitor.get_current()
        return jsonify(current)
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/system/history')
@require_api_key
def get_system_history():
    try:
        hours = int(request.args.get('hours', 24))
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        history = dashboard_bp.system_monitor.get_history(
            hours=hours,
            start_date=start_date,
            end_date=end_date
        )
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error getting system history: {e}")
        return jsonify({"error": str(e)}), 500
