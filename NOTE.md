# R-WAF Project Notes

## Overview

R-WAF, or Rusher WAF, is a modular Web Application Firewall built with Python Flask, OpenResty/Nginx, and PostgreSQL. OpenResty sits in front of protected backends and calls the Flask WAF API to decide whether requests should be allowed or blocked. The Python service also provides a dashboard on port `1337` for alerts, bans, traffic logs, reverse proxy routes, and system metrics.

## Main Architecture

- `openresty` receives inbound HTTP traffic on port `80`.
- `nginx/lua/rwaf.lua` performs request checks in the Nginx access phase.
- The Lua layer sends request metadata and optional request bodies to the Flask WAF API at `r-waf:5000/check`.
- If the WAF returns `block`, OpenResty fetches `/banned_page` and responds with HTTP `403`.
- Response filtering is also supported: the Lua body/log phases can capture response metadata and asynchronously send status/body data back to `/check`.
- The Python WAF service runs detection modules concurrently with `ThreadPoolExecutor`.
- Runtime data is stored in PostgreSQL through a dedicated storage layer.
- Reverse proxy routing is managed from the dashboard and resolved dynamically by OpenResty through the WAF API. There is no environment-variable backend fallback.
- Rules remain JSON files under `data/rules/` so rule editing stays simple and file-based.
- Dashboard routes are served by a separate Flask app when `ENABLE_DASHBOARD=true`.

## Key Files

- `compose.yaml`: Docker Compose setup for the `r-waf` Flask service and `openresty` proxy.
- `postgres`: PostgreSQL service in Compose used for bans, whitelist, alerts, and traffic logs.
- `Dockerfile.rwaf`: Builds the Python WAF container.
- `Dockerfile.openresty`: Builds the OpenResty/Nginx container with Lua dependencies.
- `nginx/nginx.conf`: Nginx/OpenResty configuration.
- `nginx/lua/rwaf.lua`: Lua integration that calls the WAF API during request and response phases.
- `r_waf/app.py`: Main WAF application, config loading, module execution, ban/cache/log initialization, and dashboard startup.
- `r_waf/routes/route.py`: Core API routes such as `/check`, `/reload`, `/ban/*`, `/alerts`, `/cache/*`, and `/banned_page`.
- `r_waf/routes/dashboard.py`: Dashboard UI and dashboard API routes.
- `r_waf/storage/postgres.py`: PostgreSQL connection, schema initialization, and shared cursor helpers.
- `r_waf/core/ReverseProxyManager.py`: CRUD and runtime lookup logic for OpenResty reverse proxy routes.
- `r_waf/templates/`: Dashboard and login HTML templates.
- `r_waf/ban.html`: HTML shown to blocked clients.

## Detection Modules

Modules live in `r_waf/module/` and are auto-discovered from Python files that expose a `run(data)` function.

- `BasicAttackRules.py`: Loads JSON rules from `data/rules/` and checks IP blocklists, user agents, headers, paths, and bodies for attack patterns.
- `AntiHTTPGenericBruteforce.py`: Response-phase module that bans IPs after repeated `401`, `403`, or `429` responses within a configured time window.
- `APIAbuseDetection.py`: Checks API endpoints for malformed JSON, oversized payloads, deeply nested JSON, suspicious parameters, and JSON injection patterns.
- `BotDetection.py`: Blocks empty or suspicious user agents and known scanner/bot signatures.
- `FileUploadProtection.py`: Checks multipart uploads for dangerous extensions, path traversal filenames, oversized uploads, double extensions, and web shell signatures.
- `SlowLorisProtection.py`: Tracks request timing/volume patterns to detect slow or abusive clients.

## Core Components

- `BanManager.py`: Manages ban expiry, whitelist handling, and active ban lookups through PostgreSQL.
- `AlertManager.py`: Stores and retrieves security alerts through PostgreSQL, including pagination, filtering, statistics, and timeline data.
- `RequestLogger.py`: Writes and queries allow/block traffic logs through PostgreSQL.
- `CacheManager.py`: Adds LRU caching around request checks and exposes cache statistics.
- `InitializeDefaultRules.py`: Creates default rule JSON files with common SQLi, XSS, LFI, RFI, RCE, scanner, and sensitive-path patterns.
- `SystemMonitor.py`: Collects CPU, memory, disk, and network metrics for the dashboard.
- `ReverseProxyManager.py`: Manages dashboard-created proxy routes and resolves the best upstream for a request host/path.
- `storage/PostgresStorage`: Owns database connectivity and creates required tables/indexes at startup.

## Runtime Data

The application still creates and uses a `data/` directory for local config, rules, and logs:

- `data/config.json`: WAF configuration.
- `data/rules/*.json`: Rule files used by `BasicAttackRules`.
- `data/waf.log`: Application log file.

The following runtime data is now stored in PostgreSQL:

- `bans`: Active and historical IP bans.
- `whitelist`: IPs that should not be banned.
- `alerts`: Security alerts emitted by detection modules.
- `traffic_logs`: Allow/block request and response log entries.
- `reverse_proxies`: Dashboard-managed OpenResty routing rules.

## Important Configuration

Default config is defined in `r_waf/app.py`.

- `api_key`: Default is `incrustwerush.org`.
- `database_url`: Default is `postgresql://rwaf:rwaf@postgres:5432/rwaf`.
- `host`: Default `0.0.0.0`.
- `port`: WAF API default `5000`.
- `delay_ban_minutes`: Default ban duration, `15`.
- `module_threads`: Concurrent module workers, default `10`.
- `window_seconds`: Brute-force detection window.
- `window_max_requests`: Maximum suspicious responses in that window.
- `enable_request_body_check`: Enables request body inspection.
- `enable_response_filter`: Enables response-phase checks.
- `enable_response_body_check`: Controls response body capture and inspection.

Environment variables used by the Docker setup include:

- `RWAF_API_KEY`: Overrides the configured API key in `app.py`.
- `DATABASE_URL`: PostgreSQL connection string.
- `ENABLE_DASHBOARD`: Enables the dashboard Flask app.
- `DASHBOARD_PORT`: Dashboard port, default `1337`.

Compose now sets `RWAF_API_KEY`, matching the variable read by `app.py`.

## PostgreSQL Schema

`r_waf/storage/postgres.py` initializes these tables automatically on startup:

- `bans(ip, until, reason, created_at, updated_at)`
- `whitelist(ip, reason, created_at)`
- `alerts(id, timestamp, module, action, reason, ip, method, path, user_agent, matched_rule, status_code)`
- `traffic_logs(id, timestamp, ip, method, path, user_agent, action, reason, status_code, module, matched_rule)`
- `reverse_proxies(id, name, host, path_prefix, upstream_scheme, upstream_host, upstream_port, enabled, created_at, updated_at)`

Indexes are created for alert timestamps/IPs, traffic timestamps/IPs/actions, and reverse proxy lookup fields.

## Reverse Proxy Management

Reverse proxy routes are managed from the dashboard's Reverse Proxy page.

- Routes can match a specific host, or an empty host as a wildcard/default.
- Routes match by `path_prefix`; the longest matching path wins.
- Upstreams are stored as scheme, host, and port, and displayed as URLs such as `http://backend:8080`.
- OpenResty calls `GET /proxy/resolve?host=...&path=...` before proxying each request.
- If no database route matches, OpenResty returns `502 Bad Gateway` and R-WAF records a reverse proxy alert/traffic block.
- A no-match reverse proxy request also adds the client IP to the ban list.
- Reverse proxy traffic still passes through request filtering, ban checks, alert logging, response filtering, and response-based ban logic.

## Core API Endpoints

- `GET /config`: Returns filtering feature flags for the Lua layer.
- `POST /check`: Main request/response decision endpoint.
- `GET /reload`: Reloads rules, bans, whitelist, and cache.
- `GET /ban/list`: Lists active bans. Requires `X-API-Key`.
- `GET /ban/add?ip=...&minutes=...&reason=...`: Adds a ban. Requires `X-API-Key`.
- `GET /ban/delete?ip=...`: Removes a ban. Requires `X-API-Key`.
- `GET|POST /banned_page`: Returns the block page HTML.
- `GET /alerts`: Returns recent alerts. Requires `X-API-Key`.
- `POST /alerts/clear`: Clears alerts. Requires `X-API-Key`.
- `GET /cache/stats`: Returns cache statistics. Requires `X-API-Key`.
- `POST /cache/clear`: Clears cache stats. Requires `X-API-Key`.
- `GET /proxy/resolve`: Internal OpenResty route resolver.
- `GET /dashboard/api/reverse-proxies`: Lists reverse proxy routes. Requires `X-API-Key`.
- `POST /dashboard/api/reverse-proxies`: Creates a reverse proxy route. Requires `X-API-Key`.
- `PUT /dashboard/api/reverse-proxies/<id>`: Updates a reverse proxy route. Requires `X-API-Key`.
- `DELETE /dashboard/api/reverse-proxies/<id>`: Deletes a reverse proxy route. Requires `X-API-Key`.

## Dashboard

The dashboard is available at `http://localhost:1337/` when enabled. It uses API-key authentication and exposes:

- Alert statistics and module counts.
- Paginated and searchable alert views.
- Ban list, manual ban, and unban actions.
- Reverse proxy route CRUD for OpenResty upstream routing.
- Traffic log views and traffic timelines.
- Current and historical system metrics.

Dashboard API routes live under `/dashboard/api/*`.

## Running

Docker Compose:

```bash
docker compose up -d --build
```

Local development:

```bash
pip install flask psutil psycopg2-binary
export DATABASE_URL=postgresql://rwaf:rwaf@localhost:5432/rwaf
cd r_waf
python app.py --config data/config.json
```

For local development, PostgreSQL must be running and reachable through `DATABASE_URL`. Depending on the environment, OpenResty Lua support requires `lua-resty-http` and `cjson`.

## Extension Model

To add a detection module:

1. Add a Python file under `r_waf/module/`.
2. Implement `run(data)`.
3. Return a dictionary such as `{"action": "allow", "result": ...}` or `{"action": "block", "reason": "...", "result": ...}`.
4. The module will be discovered automatically on each check.

Request-phase modules should ignore response checks when `status_code` is present. Response-phase modules should ignore request checks when `status_code` is absent.

## Observations

- Persistence is now split behind `r_waf/storage/`, which keeps database setup out of the WAF/domain managers.
- Rules are intentionally still JSON-file based; bans, whitelist, alerts, and traffic logs are PostgreSQL-backed.
- Reverse proxy routes are PostgreSQL-backed and read dynamically by OpenResty, so route changes do not require rebuilding containers or setting backend env vars.
- Ban checks are always read live before request filtering, so a previously cached allow decision cannot bypass a new ban.
- Request and response checks share the same `/check` endpoint and are distinguished by the presence of `status_code`.
- Module state is kept in memory through `data_module`, so some detections reset on service restart.
- `CacheManager.clear_all()` clears tracked stats but does not currently call each wrapped function's `cache_clear()`, so actual cached entries may remain.
- Some management actions use `GET` for state changes, such as `/ban/add` and `/ban/delete`.
- The WAF API itself is not API-key protected for `/check`, `/config`, `/reload`, or `/banned_page`; this is acceptable only if the API is isolated behind Docker/private networking or otherwise protected.
