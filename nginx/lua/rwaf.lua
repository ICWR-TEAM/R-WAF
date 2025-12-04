local http = require "resty.http"
local cjson = require "cjson"

local _M = {}

local WAF_HOST = "http://r-waf:5000"
local config_cache = nil
local config_cache_time = 0
local ban_cache = ngx.shared.ban_cache
local waf_cache = ngx.shared.waf_cache

local httpc_pool = {
    keepalive_timeout = 60000,
    keepalive_pool = 10
}

local function get_client_ip()
    local ip = ngx.var.http_x_forwarded_for or ngx.var.http_cf_connecting_ip or ngx.var.remote_addr
    if not ip then return nil end
    local pos = ip:find(",", 1, true)
    if pos then
        return ip:sub(1, pos - 1)
    end
    return ip
end

function _M.get_config()
    local now = ngx.time()
    if config_cache and (now - config_cache_time) < 60 then
        return config_cache
    end
    
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(WAF_HOST .. "/config", {
        method = "GET",
        keepalive_timeout = httpc_pool.keepalive_timeout,
        keepalive_pool = httpc_pool.keepalive_pool
    })
    
    if res and res.status == 200 then
        config_cache = cjson.decode(res.body)
        config_cache_time = now
        return config_cache
    end
    
    return {
        enable_request_body_check = true,
        enable_response_body_check = false,
        enable_response_filter = true
    }
end

function _M.check_request()
    local config = _M.get_config()
    local client_ip = get_client_ip()
    
    if not client_ip then
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    
    local cache_key = "ban:" .. client_ip
    local cached_ban = ban_cache:get(cache_key)
    if cached_ban == "1" then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/html"
        ngx.say("<h1>Access Denied</h1>")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    
    local header = cjson.encode(ngx.req.get_headers())
    local user_agent = ngx.var.http_user_agent or ""
    local request_path = ngx.var.request_uri or ""
    local request_method = ngx.req.get_method()
    local request_body = ""

    if config.enable_request_body_check and (request_method == "POST" or request_method == "PUT") then
        ngx.req.read_body()
        request_body = ngx.req.get_body_data() or ""
    end

    local httpc = http.new()
    httpc:set_timeout(10000)
    local res, err = httpc:request_uri(WAF_HOST .. "/check", {
        method = "POST",
        body = cjson.encode({
            ip = client_ip,
            method = request_method,
            header = ngx.encode_base64(header),
            user_agent = user_agent,
            path = ngx.encode_base64(request_path),
            body_raw_b64 = ngx.encode_base64(request_body)
        }),
        headers = {
            ["Content-Type"] = "application/json"
        },
        keepalive_timeout = httpc_pool.keepalive_timeout,
        keepalive_pool = httpc_pool.keepalive_pool
    })

    if not res then
        ngx.log(ngx.ERR, "WAF check failed: ", err)
        local fail_count_key = "fail:" .. client_ip
        local fails = (ban_cache:get(fail_count_key) or 0) + 1
        ban_cache:set(fail_count_key, fails, 60)
        if fails >= 3 then
            ban_cache:set(cache_key, "1", 300)
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.say("<h1>Access Denied</h1><p>Too many errors</p>")
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
        return
    end

    local waf_response = cjson.decode(res.body)

    if waf_response["action"] == "block" then
        ban_cache:set(cache_key, "1", 300)
        
        local ban_page_res, ban_err = httpc:request_uri(WAF_HOST .. "/banned_page", {
            method = "POST",
            body = cjson.encode({
                ip = client_ip
            }),
            headers = {
                ["Content-Type"] = "application/json"
            },
            keepalive_timeout = httpc_pool.keepalive_timeout,
            keepalive_pool = httpc_pool.keepalive_pool
        })

        if not ban_page_res then
            ngx.say("<h1>Access Denied</h1>")
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/html"
        ngx.say(ban_page_res.body)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

function _M.accumulate_response_body()
    local ctx = ngx.ctx
    
    local config = _M.get_config()
    if not config.enable_response_filter then
        return
    end
    
    if not ctx.response_body then
        ctx.response_body = {}
    end
    
    if config.enable_response_body_check then
        local chunk = ngx.arg[1]
        if chunk then
            table.insert(ctx.response_body, chunk)
        end
    end
    
    if not ctx.response_status then
        ctx.response_status = ngx.status
        ctx.response_method = ngx.var.request_method
        ctx.response_ip = get_client_ip()
        ctx.response_headers = cjson.encode(ngx.resp.get_headers())
    end
end

function _M.check_response_async()
    local ctx = ngx.ctx
    
    local config = _M.get_config()
    if not config.enable_response_filter then
        return
    end
    
    if not ctx.response_status then
        return
    end
    
    local ip = ctx.response_ip
    local method = ctx.response_method
    local status_code = ctx.response_status
    local body_chunks = ctx.response_body or {}
    local response_headers = ctx.response_headers or "{}"
    
    local body = ""
    local body_b64 = ""
    
    if config.enable_response_body_check and #body_chunks > 0 then
        body = table.concat(body_chunks)
        body_b64 = ngx.encode_base64(body)
    end
    
    local ok, err = ngx.timer.at(0, function(premature)
        if premature then
            return
        end
        
        local httpc = http.new()
        httpc:set_timeout(5000)
        
        local payload = cjson.encode({
            ip = ip,
            method = method,
            status_code = status_code,
            header = ngx.encode_base64(response_headers),
            body_raw_b64 = body_b64
        })
        
        local res, err = httpc:request_uri(WAF_HOST .. "/check", {
            method = "POST",
            body = payload,
            headers = {
                ["Content-Type"] = "application/json",
            },
            ssl_verify = false,
            keepalive_timeout = httpc_pool.keepalive_timeout,
            keepalive_pool = httpc_pool.keepalive_pool
        })
        
        if not res then
            ngx.log(ngx.ERR, "WAF response check failed: ", err)
            return
        end
        
        local waf_response = cjson.decode(res.body)
        if waf_response.action == "block" then
            ban_cache:set("ban:" .. ip, "1", 300)
            ngx.log(ngx.WARN, "IP ", ip, " banned due to response pattern: ", waf_response.reason or "unknown")
        end
    end)
    
    if not ok then
        ngx.log(ngx.ERR, "Failed to create timer for response check: ", err)
    end
end

return _M
