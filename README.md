# R-WAF (Rusher WAF)

R-WAF is a Python + Flask-based Web Application Firewall that protects against common web attacks, including SQL Injection, LFI, XSS, and simple DDOS attacks. The system uses JSON-based rules, IP bans/whitelists, and a management API.

---

## Key Features

* Rule-based protection for IP, User-Agent, Header, Path, and Body.
* Basic anti-DDOS protection via per-IP rate-limiting.
* Configurable ban system with expiry.
* API for request checks, listing banned IPs, adding/removing bans.
* Cached request checks for performance.
* Flask + Docker for easy deployment.

---

## Architecture

```
                     ┌─────────────────────┐
                     │      Internet       │
                     └─────────┬───────────┘
                               │
                               ▼
                     ┌─────────────────────┐
                     │    OpenResty/Nginx  │
                     │  (Reverse Proxy /   │
                     │   Lua Integration)  │
                     └─────────┬───────────┘
                               │
              ┌────────────────┴───────────────┐
              │                                │
              ▼                                ▼
    ┌───────────────────┐             ┌───────────────────┐
    │     R-WAF API     │             │   Backend Web App │
    │ (Flask + Python)  │             │   (Example App)   │
    └─────────┬─────────┘             └───────────────────┘
              │
  ┌───────────┴────────────┐
  │       Data Storage     │
  │ ┌───────────────────┐  │
  │ │ Rules JSON Files  │  │
  │ │ Bans / Whitelist  │  │
  │ │ Cached Requests   │  │
  │ └───────────────────┘  │
  └────────────────────────┘

```

---

## Docker Compose Structure

```yaml
services:
  r-waf:
    build:
      context: .
      dockerfile: Dockerfile.rwaf
    volumes:
      - ./r_waf/:/app/
    ports:
      - "5000:5000"
    environment:
      - PYTHONUNBUFFERED=1

  openresty:
    build:
      context: .
      dockerfile: Dockerfile.openresty
    environment:
      - WEB_SERVER_HOST=10.10.1.2
      - WEB_SERVER_PORT=8080
    depends_on:
      - r-waf
    ports:
      - "80:80"
    volumes:
      - ./nginx/lua:/etc/nginx/lua:ro
```

* `r-waf` runs the Python WAF API on port `5000`.
* `openresty` runs the web server which can integrate with WAF via Lua scripting.

---

## Important Directories & Files

* `./data/rules/` → stores JSON rules (`ip_blocklist.json`, `paths.json`, etc.).
* `./data/bans/` → stores `bans.json` and `whitelist.json`.
* `ban.html` → page displayed when IP is blocked.
* `app.py` → WAF API implementation.

---

## Installation & Running

```bash
# Build Docker containers
docker-compose build

# Run containers
docker-compose up -d

# View logs
docker-compose logs -f r-waf
```

Or run locally for development:

```bash
pip install -r requirements.txt
python app.py --config ./data/config.json
```

---

## R-WAF API

All endpoints return JSON, except the banned page.

### 1. Check Request

**URL:** `/check`

**Method:** `POST`

**Body JSON:**

```json
{
  "ip": "1.2.3.4",
  "user_agent": "curl/7.85.0",
  "path": "/index.php",
  "header": "<base64-encoded headers JSON>",
  "body_raw_b64": "<base64-encoded body>"
}
```

**Response:**

```json
{
  "action": "allow" | "block",
  "reason": "ip_blocklist | bad_user_agent | headers_blocked | paths_blocked | body_blocked | ddos | banned:manual ban"
}
```

**Example CURL:**

```bash
curl -X POST http://localhost:5000/check \
-H "Content-Type: application/json" \
-d '{"ip":"1.2.3.4","user_agent":"curl/7.85.0","path":"L2luZGV4LnBocA==","header":"e30=","body_raw_b64":""}'
```

---

### 2. Reload Rules & Bans

**URL:** `/reload`

**Method:** `GET`

**Response:**

```json
{"status":"reloaded"}
```

**CURL:**

```bash
curl http://localhost:5000/reload
```

---

### 3. List Active Bans

**URL:** `/ban/list`

**Method:** `GET`

**Headers:** `X-API-Key: incrustwerush.org`

**Response:**

```json
{
  "1.2.3.4": {"until": "2025-11-27T14:22:00+00:00","reason":"ip_blocklist"}
}
```

**CURL:**

```bash
curl -H "X-API-Key: incrustwerush.org" http://localhost:5000/ban/list
```

---

### 4. Add Ban

**URL:** `/ban/add`

**Method:** `GET`

**Headers:** `X-API-Key: incrustwerush.org`

**Query Params:**

* `ip` → IP to ban
* `minutes` → ban duration (optional)
* `reason` → reason for ban (optional)

**Response:**

```json
{"status":"banned","ip":"1.2.3.4","until":"2025-11-27T14:22:00+00:00"}
```

**CURL:**

```bash
curl -G http://localhost:5000/ban/add \
-H "X-API-Key: incrustwerush.org" \
--data-urlencode "ip=1.2.3.4" \
--data-urlencode "minutes=60" \
--data-urlencode "reason=manual ban"
```

---

### 5. Delete Ban

**URL:** `/ban/delete`

**Method:** `GET`

**Headers:** `X-API-Key: incrustwerush.org`

**Query Params:** `ip` → IP to remove from ban

**Response:**

```json
{"status":"deleted","ip":"1.2.3.4"}
```

**CURL:**

```bash
curl -G http://localhost:5000/ban/delete \
-H "X-API-Key: incrustwerush.org" \
--data-urlencode "ip=1.2.3.4"
```

---

### 6. Banned Page

**URL:** `/banned_page`

**Method:** `GET`

Displays the HTML page for blocked IPs.

**CURL:**

```bash
curl http://localhost:5000/banned_page
```

---

## Technical Notes

* JSON rules can be extended as needed.
* Base64 is used for headers and body to avoid character corruption.
* `anti_ddos` is active by default, limiting 100 requests per 10 seconds per IP.
* All timestamps are UTC.
* Cache uses `functools.lru_cache` with default `maxsize=32`.
