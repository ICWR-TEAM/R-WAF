local http = require "resty.http"
local cjson = require "cjson"
local base64 = ngx.encode_base64

local waf_host = "http://r-waf:5000"

local client_ip = ngx.var.remote_addr
local header = cjson.encode(ngx.req.get_headers())
local user_agent = ngx.var.http_user_agent or ""
local request_path = ngx.var.request_uri or ""
local request_method = ngx.req.get_method()
local request_body = ""

if request_method == "POST" or request_method == "PUT" then
    ngx.req.read_body()
    request_body = ngx.req.get_body_data() or ""
end

local httpc = http.new()
local res, err = httpc:request_uri(waf_host .. "/check", {
    method = "POST",
    body = cjson.encode({
        ip = client_ip,
        header = base64(header),
        user_agent = user_agent,
        path = base64(request_path),
        body_raw_b64 = base64(request_body)
    }),
    headers = {
        ["Content-Type"] = "application/json"
    }
})

if not res then
    ngx.log(ngx.ERR, "WAF check failed: ", err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local waf_response = cjson.decode(res.body)

if waf_response["action"] == "block" then
    local ban_page_res, ban_err = httpc:request_uri(waf_host .. "/banned_page", {
        method = "GET"
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
