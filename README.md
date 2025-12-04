# R-WAF (Rusher WAF)

R-WAF is a **modular Web Application Firewall** powered by Python + Flask + OpenResty/Nginx. It provides comprehensive protection against common web attacks with both **request and response filtering** capabilities, plus a real-time monitoring **dashboard**.

---

## Key Features

### Core Protection

* **Request Filtering** - Block malicious requests before they reach your backend
* **Response Filtering** - Detect attack patterns in response behavior (e.g., auth bruteforce)
* **200+ Attack Patterns** - SQLi, XSS, LFI, RFI, RCE, XXE, SSRF, and more
* **Modular Architecture** - Easily extend with custom detection modules
* **Concurrent Processing** - ThreadPoolExecutor for high-performance module execution

### Dashboard & Monitoring

* **Real-time Dashboard** - Web-based monitoring interface on port 1337
* **Alert Management** - View, filter, and search security alerts with pagination
* **Ban Management** - Manual IP ban/unban with duration control
* **Statistics** - Total alerts, blocked IPs, active bans tracking
* **Date Range Filters** - Search alerts by date range and keywords
* **API Key Authentication** - Secure dashboard access

### Detection Modules

* **BasicAttackRules** - Pattern-based detection for common attacks
* **AntiHTTPGenericBruteforce** - Response-based authentication bruteforce detection
* **Custom Modules** - Drop any Python module into `module/` directory

### Performance & Management

* **Alert Logging** - JSON-based daily alert logs in `data/alerts/`
* **LRU Caching** - Smart caching with hit/miss statistics
* **Ban Management** - Auto-expiry bans with whitelist support
* **API Key Authentication** - Secure management endpoints
* **Real-time Reload** - Hot-reload rules without restart
* **Docker-Ready** - Full Docker Compose setup included

---

## Architecture

```
                     ┌─────────────────────┐
                     │      Internet       │
                     └─────────┬───────────┘
                               │
                               ▼
                     ┌─────────────────────┐
                     │  OpenResty/Nginx    │
                     │  ┌──────────────┐   │
                     │  │ Lua Modules  │   │
                     │  │ - rwaf.lua   │   │
                     │  └──────────────┘   │
                     │  3 Phase Filtering: │
                     │  1. access_by_lua   │  ← Request Check
                     │  2. body_filter     │  ← Response Capture
                     │  3. log_by_lua      │  ← Async Response Check
                     └─────────┬───────────┘
                               │
              ┌────────────────┴───────────────┐
              │                                │
              ▼                                ▼
    ┌────────────────────┐             ┌───────────────────┐
    │      R-WAF API     │             │   Backend Web App │
    │  (Flask + Python)  │             │  (Your Server)    │
    │                    │             └───────────────────┘
    │ ┌────────────────┐ │
    │ │ core/          │ │
    │ │ - BanManager   │ │
    │ │ - CacheManager │ │
    │ │ - DefaultRules │ │
    │ └────────────────┘ │
    │ ┌────────────────┐ │
    │ │ module/        │ │
    │ │ - BasicAttack  │ │
    │ │ - AntiBrute    │ │
    │ └────────────────┘ │
    │ ┌────────────────┐ │
    │ │ routes/        │ │
    │ │ - API Endpoints│ │
    │ └────────────────┘ │
    └─────────┬──────────┘
              │
  ┌───────────┴────────────┐
  │    Data Storage        │
  │ ┌───────────────────┐  │
  │ │ data/rules/       │  │
  │ │ data/bans/        │  │
  │ │ Runtime Cache     │  │
  │ └───────────────────┘  │
  └────────────────────────┘
```

---

## Project Structure

```
R-WAF/
├── compose.yaml                    # Docker Compose configuration
├── Dockerfile.rwaf                 # R-WAF Python service
├── Dockerfile.openresty            # OpenResty service
├── .gitignore                      # Git ignore rules
├── nginx/
│   ├── nginx.conf                  # Nginx configuration
│   └── lua/
│       └── rwaf.lua                # Lua WAF integration (3 phases)
└── r_waf/
    ├── app.py                      # Main WAF application (dual-port support)
    ├── ban.html                    # Blocked IP page template
    ├── static/                     # Static assets
    │   └── icwr-logo.png           # Dashboard logo
    ├── templates/                  # HTML templates
    │   ├── dashboard.html          # Main dashboard UI
    │   └── login.html              # Dashboard login page
    ├── core/                       # Core functionality
    │   ├── __init__.py
    │   ├── AlertManager.py         # Alert logging and retrieval
    │   ├── BanManager.py           # Ban/whitelist management
    │   ├── CacheManager.py         # LRU cache with statistics
    │   └── InitializeDefaultRules.py # 200+ default attack patterns
    ├── module/                     # Detection modules (auto-discovery)
    │   ├── __init__.py
    │   ├── AntiHTTPGenericBruteforce.py  # Response-based bruteforce detection
    │   └── BasicAttackRules.py     # Request-based pattern matching
    └── routes/
        ├── __init__.py
        ├── dashboard.py            # Dashboard API routes
        └── route.py                # WAF API endpoints
```

---

## Installation & Running

### Quick Start with Docker Compose

```bash
git clone https://github.com/icwr-tEAM/R-WAF.git
cd R-WAF

docker-compose up -d --build

docker-compose logs -f r-waf

docker-compose down
```

**Access:**

- WAF API: `http://localhost:5000`
- Dashboard: `http://localhost:1337` (login with API key)
- Backend: `http://localhost:80` (proxied through OpenResty)

### Local Development

```bash
pip install flask

cd r_waf
python app.py --config data/config.json
```

---

## Dashboard

### Access Dashboard

**URL:** `http://localhost:1337/`

**Login:** Use your API key (default: `incrustwerush.org`)

### Dashboard Features

- **Real-time Statistics**

  - Total alerts count
  - Blocked IPs count
  - Active bans count
- **Alert Monitoring**

  - View all security alerts
  - Filter by date range
  - Keyword search (IP, path, reason, module)
  - Pagination (20 alerts per page)
  - Auto-refresh every 30 seconds
- **Ban Management**

  - View all banned IPs with status (active/expired)
  - Manual IP ban with custom reason and duration
  - Unban IPs instantly
  - Ban expiry countdown
- **Dark Theme UI**

  - Background: `#000`
  - Text: `#fff`
  - ICWR logo integration

### Dashboard API Endpoints

All dashboard endpoints require `X-API-Key` header authentication.

**GET `/dashboard/api/stats`** - Get statistics

```json
{
  "total_alerts": 150,
  "blocked_ips": 45,
  "active_bans": 12
}
```

**GET `/dashboard/api/alerts`** - Get alerts (supports filters)

```
?page=1&per_page=20&start_date=2025-12-01&end_date=2025-12-04&keyword=sqli
```

**GET `/dashboard/api/bans`** - Get all bans

**POST `/dashboard/api/bans`** - Add manual ban

```json
{
  "ip": "1.2.3.4",
  "reason": "Suspicious activity",
  "minutes": 60
}
```

**DELETE `/dashboard/api/bans/<ip>`** - Unban IP

---

## Alert Logging

All security events are automatically logged to daily JSON files.

### Alert Storage

**Location:** `r_waf/data/alerts/YYYY-MM-DD-alerts.json`

**Format:**

```json
[
  {
    "timestamp": "2025-12-04T14:22:33.123456+00:00",
    "module": "BasicAttackRules",
    "action": "block",
    "reason": "SQLi attempt detected",
    "ip": "1.2.3.4",
    "method": "GET",
    "path": "/admin.php?id=1' OR '1'='1",
    "user_agent": "curl/7.85.0",
    "matched_rule": "' OR ",
    "status_code": null
  }
]
```

### Alert Fields

| Field            | Type     | Description                                     |
| ---------------- | -------- | ----------------------------------------------- |
| `timestamp`    | ISO 8601 | UTC timestamp of the alert                      |
| `module`       | string   | Detection module name                           |
| `action`       | string   | Action taken (block/allow)                      |
| `reason`       | string   | Detection reason                                |
| `ip`           | string   | Source IP address                               |
| `method`       | string   | HTTP method                                     |
| `path`         | string   | Request path (decoded)                          |
| `user_agent`   | string   | User agent (truncated to 100 chars)             |
| `matched_rule` | string   | Pattern that triggered (truncated to 200 chars) |
| `status_code`  | int/null | HTTP status code (response phase only)          |

### Alert Retrieval

Alerts are automatically loaded by AlertManager and available via:

- Dashboard UI
- Dashboard API endpoints
- WAF API `/alerts` endpoint

---

## Configuration

Configuration file: `r_waf/data/config.json`

```json
{
  "rules_dir": "data/rules",
  "bans_file": "data/bans/bans.json",
  "whitelist_file": "data/bans/whitelist.json",
  "banned_page_file": "ban.html",
  "module_threads": 10,
  "api_key": "your-secret-api-key",
  "host": "0.0.0.0",
  "port": 5000,
  "debug": false,
  "delay_ban_minutes": 15,
  "anti_http_generic_bf": true,
  "window_seconds": 10,
  "window_max_requests": 5,
  "cache_maxsize": 32,
  "enable_response_filter": true,
  "base_dir": "data"
}
```

### Environment Variables

Set in `compose.yaml`:

```yaml
environment:
  - RWAF_API_KEY=your-secret-api-key
  - ENABLE_DASHBOARD=true
  - DASHBOARD_PORT=1337
```

| Variable             | Default               | Description                |
| -------------------- | --------------------- | -------------------------- |
| `RWAF_API_KEY`     | `incrustwerush.org` | API key for authentication |
| `ENABLE_DASHBOARD` | `true`              | Enable/disable dashboard   |
| `DASHBOARD_PORT`   | `1337`              | Dashboard port             |

### Configuration Options

| Parameter                  | Type   | Default                      | Description                        |
| -------------------------- | ------ | ---------------------------- | ---------------------------------- |
| `rules_dir`              | string | `data/rules`               | Directory for attack pattern rules |
| `bans_file`              | string | `data/bans/bans.json`      | Ban list storage                   |
| `whitelist_file`         | string | `data/bans/whitelist.json` | Whitelist storage                  |
| `banned_page_file`       | string | `ban.html`                 | Template for blocked page          |
| `module_threads`         | int    | `10`                       | ThreadPoolExecutor worker count    |
| `api_key`                | string | `incrustwerush.org`        | API authentication key             |
| `host`                   | string | `0.0.0.0`                  | Flask bind address                 |
| `port`                   | int    | `5000`                     | Flask port                         |
| `debug`                  | bool   | `false`                    | Flask debug mode                   |
| `delay_ban_minutes`      | int    | `15`                       | Default ban duration               |
| `anti_http_generic_bf`   | bool   | `true`                     | Enable bruteforce detection        |
| `window_seconds`         | int    | `10`                       | Bruteforce detection window        |
| `window_max_requests`    | int    | `5`                        | Max auth failures in window        |
| `cache_maxsize`          | int    | `32`                       | LRU cache size                     |
| `enable_response_filter` | bool   | `true`                     | Enable/disable response filtering  |
| `base_dir`               | string | `data`                     | Base directory for all data        |

---

## Detection Modules

### 1. BasicAttackRules (Request Phase)

**File:** `r_waf/module/BasicAttackRules.py`

**Triggers:** `access_by_lua_block` (before request reaches backend)

**Detection Categories:**

- **IP Blocklist** - Known malicious IPs
- **User-Agent Patterns** - Malicious bots, scanners, scrapers
- **Header Patterns** - Attack signatures in headers
- **Path Patterns** - Suspicious URLs and payloads
- **Body Patterns** - POST/PUT body attack detection

**Attack Patterns (200+):**

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Remote Code Execution (RCE)
- XML External Entity (XXE)
- Server-Side Request Forgery (SSRF)
- Command Injection
- Path Traversal
- Log4Shell
- Template Injection

**Features:**

- URL decode + Base64 decode for evasion detection
- Pattern matching with regex
- Multiple encoding bypass detection

### 2. AntiHTTPGenericBruteforce (Response Phase)

**File:** `r_waf/module/AntiHTTPGenericBruteforce.py`

**Triggers:** `log_by_lua_block` (after response received)

**Detection Logic:**

- Monitors HTTP status codes: `401`, `403`, `429`
- Tracks failed auth attempts in sliding window
- Auto-ban when threshold exceeded

**Configuration:**

- `window_seconds`: Time window for tracking (default: 10s)
- `window_max_requests`: Max failures allowed (default: 5)

**Example:** IP banned after 5 failed login attempts in 10 seconds

---

## Nginx + Lua Integration

### Three-Phase Filtering

**File:** `nginx/lua/rwaf.lua`

#### Phase 1: Request Filtering (access_by_lua_block)

```lua
function _M.check_request()
    -- Capture: IP, method, headers, user-agent, path, body
    -- POST to /check endpoint (without status_code)
    -- If action=block → return 403 + banned_page
end
```

#### Phase 2: Response Body Capture (body_filter_by_lua_block)

```lua
function _M.accumulate_response_body()
    -- Accumulate response body chunks
    -- Store in ngx.ctx.response_body
    -- Store status_code in ngx.ctx.response_status_code
end
```

#### Phase 3: Async Response Check (log_by_lua_block)

```lua
function _M.check_response_async()
    -- Use ngx.timer.at for async execution
    -- POST to /check endpoint (with status_code)
    -- Ban IP if bruteforce detected
end
```

---

## R-WAF API Endpoints

## R-WAF API Endpoints

All endpoints return JSON, except `/banned_page`.

### 1. Check Request/Response (Dual Mode)

**URL:** `/check`

**Method:** `POST`

**Authentication:** None (internal use by Nginx)

**Request Body:**

```json
{
  "ip": "1.2.3.4",
  "method": "GET",
  "user_agent": "Mozilla/5.0...",
  "path": "/admin/login",
  "header": "<base64-encoded headers JSON>",
  "body_raw_b64": "<base64-encoded body>",
  "status_code": 401
}
```

**Behavior:**

- **Without `status_code`** → Request filtering (BasicAttackRules)
- **With `status_code`** → Response filtering (AntiHTTPGenericBruteforce)

**Response:**

```json
{
  "action": "allow" | "block",
  "reason": "SQLi attempt detected | Anti HTTP Generic Bruteforce | banned: manual ban"
}
```

**Example CURL (Request Check):**

```bash
curl -X POST http://localhost:5000/check \
-H "Content-Type: application/json" \
-d '{
  "ip": "1.2.3.4",
  "method": "GET",
  "user_agent": "curl/7.85.0",
  "path": "/admin.php",
  "header": "e30=",
  "body_raw_b64": ""
}'
```

**Example CURL (Response Check):**

```bash
curl -X POST http://localhost:5000/check \
-H "Content-Type: application/json" \
-d '{
  "ip": "1.2.3.4",
  "method": "POST",
  "status_code": 401
}'
```

---

### 2. Reload Rules & Bans

**URL:** `/reload`

**Method:** `GET`

**Authentication:** None

**Response:**

```json
{"status": "reloaded"}
```

**CURL:**

```bash
curl http://localhost:5000/reload
```

---

### 3. Cache Statistics

**URL:** `/cache/stats`

**Method:** `GET`

**Authentication:** `X-API-Key` header required

**Response:**

```json
{
  "summary": {
    "total_calls": 150,
    "cache_hits": 120,
    "cache_misses": 30,
    "hit_rate": "80.00%"
  },
  "details": {
    "_check_request_impl": {
      "hits": 120,
      "misses": 30,
      "hit_rate": "80.00%"
    }
  }
}
```

**CURL:**

```bash
curl -H "X-API-Key: your-secret-api-key" \
http://localhost:5000/cache/stats
```

---

### 4. Clear Cache

**URL:** `/cache/clear`

**Method:** `POST`

**Authentication:** `X-API-Key` header required

**Response:**

```json
{
  "status": "cleared",
  "functions": ["_check_request_impl"]
}
```

**CURL:**

```bash
curl -X POST \
-H "X-API-Key: your-secret-api-key" \
http://localhost:5000/cache/clear
```

---

### 5. List Active Bans

**URL:** `/ban/list`

**Method:** `GET`

**Authentication:** `X-API-Key` header required

**Response:**

```json
{
  "1.2.3.4": {
    "until": "2025-12-04T14:22:00+00:00",
    "reason": "SQLi attempt detected"
  },
  "5.6.7.8": {
    "until": "2025-12-04T15:30:00+00:00",
    "reason": "Anti HTTP Generic Bruteforce"
  }
}
```

**CURL:**

```bash
curl -H "X-API-Key: your-secret-api-key" \
http://localhost:5000/ban/list
```

---

### 6. Add Ban

**URL:** `/ban/add`

**Method:** `GET`

**Authentication:** `X-API-Key` header required

**Query Parameters:**

| Parameter   | Required | Description                         |
| ----------- | -------- | ----------------------------------- |
| `ip`      | Yes      | IP address to ban                   |
| `minutes` | No       | Ban duration (default: from config) |
| `reason`  | No       | Ban reason (default: "manual ban")  |

**Response:**

```json
{
  "status": "banned",
  "ip": "1.2.3.4",
  "until": "2025-12-04T14:22:00+00:00"
}
```

**CURL:**

```bash
curl -G http://localhost:5000/ban/add \
-H "X-API-Key: your-secret-api-key" \
--data-urlencode "ip=1.2.3.4" \
--data-urlencode "minutes=60" \
--data-urlencode "reason=Suspicious activity"
```

---

### 7. Delete Ban

**URL:** `/ban/delete`

**Method:** `GET`

**Authentication:** `X-API-Key` header required

**Query Parameters:**

| Parameter | Required | Description         |
| --------- | -------- | ------------------- |
| `ip`    | Yes      | IP address to unban |

**Response (Success):**

```json
{
  "status": "deleted",
  "ip": "1.2.3.4"
}
```

**Response (Not Found):**

```json
{
  "status": "not found",
  "ip": "1.2.3.4"
}
```

**CURL:**

```bash
curl -G http://localhost:5000/ban/delete \
-H "X-API-Key: your-secret-api-key" \
--data-urlencode "ip=1.2.3.4"
```

---

### 8. Banned Page

**URL:** `/banned_page`

**Method:** `GET` or `POST`

**Authentication:** None

**Query/Body Parameters:**

| Parameter | Required | Description                 |
| --------- | -------- | --------------------------- |
| `ip`    | Yes      | IP address to show ban info |

**Response:** HTML page with:

- Blocked IP address
- Ban reason
- Remaining ban time (live countdown)

**CURL:**

```bash
curl "http://localhost:5000/banned_page?ip=1.2.3.4"
```

---

## Creating Custom Modules

### Module Template

Create a new file in `r_waf/module/YourModule.py`:

```python
def run(data):
    ip = data.get("ip")
    method = data.get("method")
    status_code = data.get("status_code")
    config = data.get("config", {})
    data_module = data.get("data_module", {})
  
    # Request-phase detection
    if status_code is None:
        if "attack" in data.get("path", ""):
            return {
                "action": "block",
                "reason": "Custom attack detected",
                "result": {"detected": True}
            }
  
    # Response-phase detection
    else:
        if status_code == 500:
            return {
                "action": "block",
                "reason": "Server error detected",
                "result": {"detected": True}
            }
  
    return {
        "action": "allow",
        "reason": "",
        "result": {}
    }
```

### Module Discovery

Modules are **auto-discovered** from `r_waf/module/` directory:

- Any `.py` file (except `__*.py`)
- Must have `run(data)` function
- Return dict with `action`, `reason`, `result`

### Data Structure

**Input `data` dict:**

```python
{
    "ip": "1.2.3.4",
    "method": "GET|POST|PUT|DELETE",
    "user_agent": "Mozilla/5.0...",
    "header": "base64-encoded JSON",
    "path": "/admin/login",
    "body": "base64-encoded body",
    "status_code": 401,  # Only in response phase
    "config": {...},     # Full config dict
    "data_module": {...} # Persistent module data
}
```

**Output dict:**

```python
{
    "action": "allow" | "block",
    "reason": "Description of detection",
    "result": {
        # Custom data to store in data_module
    }
}
```

---

## Whitelist Management

### Add to Whitelist

Edit `r_waf/data/bans/whitelist.json`:

```json
[
  "127.0.0.1",
  "192.168.1.100",
  "10.0.0.0/8"
]
```

**Reload after edit:**

```bash
curl http://localhost:5000/reload
```

### Whitelist Behavior

- Whitelisted IPs **never get banned**
- `BanManager.add_ban()` returns `False` for whitelisted IPs
- Existing bans are ignored for whitelisted IPs

---

## Attack Pattern Management

### Default Rules

**Auto-generated on first run:** `r_waf/core/InitializeDefaultRules.py`

**Files created in `data/rules/`:**

- `ip_blocklist.json` - Known malicious IPs
- `user_agents.json` - Malicious user-agent patterns
- `headers_patterns.json` - Attack signatures in headers
- `paths.json` - Suspicious URL patterns
- `body_patterns.json` - POST/PUT body attack patterns

### Custom Rules

Add custom patterns to any rule file:

**Example: `data/rules/paths.json`**

```json
[
  "/wp-admin",
  "/phpmyadmin",
  "/admin.php",
  "/.env",
  "/custom-blocked-path"
]
```

**Reload after edit:**

```bash
curl http://localhost:5000/reload
```

---

## Performance Optimization

### LRU Caching

Request filtering uses `functools.lru_cache`:

- Cache key: `(ip, method, header, user_agent, path, body)`
- Default maxsize: `32` (configurable)
- Monitor via `/cache/stats` endpoint

### Cache Statistics

```bash
curl -H "X-API-Key: your-key" http://localhost:5000/cache/stats
```

**Response:**

```json
{
  "summary": {
    "total_calls": 1000,
    "cache_hits": 850,
    "cache_misses": 150,
    "hit_rate": "85.00%"
  }
}
```

### Clear Cache

```bash
curl -X POST -H "X-API-Key: your-key" \
http://localhost:5000/cache/clear
```

---

## Environment Variables

### Nginx/OpenResty

Set in `compose.yaml`:

```yaml
environment:
  - WEB_SERVER_HOST=your-backend-host
  - WEB_SERVER_PORT=8080
```

### R-WAF

Set in `compose.yaml`:

```yaml
environment:
  - PYTHONUNBUFFERED=1
  - PYTHONDONTWRITEBYTECODE=1
```

---

## Logging

### Log Location

- **Container:** `/app/data/waf.log`
- **Host (via volume):** `r_waf/data/waf.log`

### Log Format

```
2025-12-04 14:22:33,123 [INFO] Loaded rules from paths.json
2025-12-04 14:22:45,456 [INFO] Blocked banned IP 1.2.3.4: SQLi attempt detected
2025-12-04 14:23:01,789 [INFO] Response filtering blocked IP 5.6.7.8: Anti HTTP Generic Bruteforce
```

### View Logs

```bash
# Docker logs
docker-compose logs -f r-waf

# File logs
tail -f r_waf/data/waf.log
```

---

## Troubleshooting

### Issue: Response filtering not working

**Solution:**

1. Check config: `"enable_response_filter": true`
2. Verify nginx phases in `nginx.conf`:
   - `access_by_lua_block`
   - `body_filter_by_lua_block`
   - `log_by_lua_block`
3. Check logs for errors

### Issue: All requests blocked

**Solution:**

1. Check if IP is banned: `curl http://localhost:5000/ban/list`
2. Remove ban: `curl -G http://localhost:5000/ban/delete --data-urlencode "ip=YOUR_IP"`
3. Add to whitelist: Edit `data/bans/whitelist.json`

### Issue: Cache not working

**Solution:**

1. Check cache stats: `curl http://localhost:5000/cache/stats`
2. Clear cache: `curl -X POST http://localhost:5000/cache/clear`
3. Increase cache size in config: `"cache_maxsize": 128`

### Issue: Custom module not loading

**Solution:**

1. Check file location: `r_waf/module/YourModule.py`
2. Verify `run(data)` function exists
3. Check logs for module errors
4. Restart container: `docker-compose restart r-waf`

---

## Security Best Practices

1. **Change Default API Key**

   ```json
   {
     "api_key": "your-strong-random-key-here"
   }
   ```
2. **Use HTTPS in Production**

   - Configure SSL/TLS in nginx
   - Use Let's Encrypt for free certificates
3. **Restrict API Access**

   - Use firewall rules
   - Limit `/ban/*` and `/cache/*` endpoints to admin IPs
4. **Regular Updates**

   - Update attack patterns regularly
   - Monitor security advisories
5. **Monitor Logs**

   - Set up log aggregation
   - Alert on unusual patterns

---

## Technical Notes

* **Base64 encoding** used for headers/body to prevent corruption
* **UTC timestamps** for all ban expiry times
* **Concurrent module execution** via ThreadPoolExecutor
* **Async response checking** via `ngx.timer.at` (non-blocking)
* **Auto-expiring bans** cleaned on each check
* **Module isolation** - each module has separate data_module dict

---

## License

MIT License - R&D incrustwerush.org

---

## Credits

Developed by **ICWR-TEAM** (incrustwerush.org)

- GitHub: https://github.com/icwr-tEAM/R-WAF
- Website: https://incrustwerush.org

---

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch
3. Commit your changes
4. Push to branch
5. Create Pull Request

---

## Changelog

### v2.1.0 (Current)

- ✅ Real-time monitoring dashboard (port 1337)
- ✅ Alert logging system (daily JSON files)
- ✅ Dashboard authentication with API key
- ✅ Alert filtering (date range, keyword search)
- ✅ Alert pagination (20 per page)
- ✅ Manual ban management via dashboard
- ✅ Statistics dashboard (total alerts, blocked IPs, active bans)
- ✅ Dark theme UI (#000 background, #fff text)
- ✅ ICWR logo integration
- ✅ Auto-refresh dashboard (30s interval)
- ✅ Dual-port Flask setup (5000 + 1337)
- ✅ Environment variable support (RWAF_API_KEY, ENABLE_DASHBOARD)

### v2.0.0

- ✅ Modular architecture (core/, routes/, module/)
- ✅ Response filtering support
- ✅ 200+ default attack patterns
- ✅ LRU caching with statistics
- ✅ Ban management with whitelist
- ✅ AntiHTTPGenericBruteforce module
- ✅ BasicAttackRules module
- ✅ Cache management API
- ✅ Config toggle for response filter
- ✅ Docker optimization (no __pycache__)

### v1.0.0

- ✅ Initial release
- ✅ Basic request filtering
- ✅ JSON-based rules
- ✅ IP ban system
