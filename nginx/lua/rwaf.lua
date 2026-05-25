local http = require "resty.http"
local cjson = require "cjson"

local _M = {}

local WAF_HOST = "http://r-waf:5000"
local config_cache = nil
local config_cache_time = 0

function _M.get_client_ip()
    local client_ip = ngx.var.remote_addr or ngx.var.http_cf_connecting_ip or ngx.var.http_x_real_ip or ngx.var.http_x_forwarded_for or ""
    if ngx.var.http_cf_connecting_ip and ngx.var.http_cf_connecting_ip ~= "" then
        client_ip = ngx.var.http_cf_connecting_ip
    end
    if client_ip and client_ip ~= "" then
        client_ip = client_ip:match("([^,]+)")
        client_ip = client_ip:gsub("^%s+", ""):gsub("%s+$", "")
    end
    return client_ip
end

function _M.get_config()
    local now = ngx.time()
    if config_cache and (now - config_cache_time) < 60 then
        return config_cache
    end
    
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(WAF_HOST .. "/config", {
        method = "GET"
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
    local client_ip = _M.get_client_ip()
    
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
            ["Content-Type"] = "application/json",
            ["X-Real-IP"] = client_ip,
            ["X-Forwarded-For"] = client_ip,
            ["CF-Connecting-IP"] = client_ip
        }
    })

    if not res then
        ngx.log(ngx.ERR, "WAF check failed: ", err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local waf_response = cjson.decode(res.body)

    if waf_response["action"] == "block" then
        local ban_page_res, ban_err = httpc:request_uri(WAF_HOST .. "/banned_page", {
            method = "POST",
            body = cjson.encode({
                ip = client_ip
            }),
            headers = {
                ["Content-Type"] = "application/json"
            }
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

function _M.resolve_proxy()
    local host = ngx.var.host or ""
    local path = ngx.var.request_uri or "/"
    local client_ip = _M.get_client_ip()

    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(WAF_HOST .. "/proxy/resolve", {
        method = "GET",
        query = {
            host = host,
            path = path
        },
        headers = {
            ["X-Real-IP"] = client_ip,
            ["X-Forwarded-For"] = client_ip,
            ["CF-Connecting-IP"] = client_ip,
            ["User-Agent"] = ngx.var.http_user_agent or ""
        }
    })

    if not res or res.status ~= 200 then
        ngx.log(ngx.ERR, "Proxy resolve failed: ", err or (res and res.status) or "unknown")
        ngx.status = ngx.HTTP_BAD_GATEWAY
        ngx.header.content_type = "text/html"
        ngx.say("<h1>Bad Gateway</h1><p>No reverse proxy route configured.</p>")
        return ngx.exit(ngx.HTTP_BAD_GATEWAY)
    end

    local ok, proxy_config = pcall(cjson.decode, res.body)
    if not ok or not proxy_config["upstream"] then
        ngx.log(ngx.ERR, "Invalid proxy resolve response")
        ngx.status = ngx.HTTP_BAD_GATEWAY
        ngx.header.content_type = "text/html"
        ngx.say("<h1>Bad Gateway</h1><p>Invalid reverse proxy route.</p>")
        return ngx.exit(ngx.HTTP_BAD_GATEWAY)
    end

    return proxy_config["upstream"]
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
        ctx.response_ip = _M.get_client_ip()
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
            ssl_verify = false
        })
        
        if not res then
            ngx.log(ngx.ERR, "WAF response check failed: ", err)
            return
        end
        
        local waf_response = cjson.decode(res.body)
        if waf_response.action == "block" then
            ngx.log(ngx.WARN, "IP ", ip, " banned due to response pattern: ", waf_response.reason or "unknown")
        end
    end)
    
    if not ok then
        ngx.log(ngx.ERR, "Failed to create timer for response check: ", err)
    end
end

return _M
