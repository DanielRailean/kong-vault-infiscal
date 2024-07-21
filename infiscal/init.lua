local kong_meta                   = require "kong.meta"
local ffi                         = require "ffi"
local http                        = require "resty.http"
local json                        = require "cjson"

local type                        = type
local gsub                        = string.gsub
local upper                       = string.upper
local find                        = string.find
local sub                         = string.sub
local str                         = ffi.string
local kong                        = kong
local ngx                         = ngx
-- local http  = require "resty.http"
local DEFAULT_HTTP_CLINET_TIMEOUT = 1000

local function dump(o)
  if type(o) == 'table' then
    local s = '{ '
    for k, v in pairs(o) do
      if type(k) ~= 'number' then k = '"' .. k .. '"' end
      s = s .. '[' .. k .. '] = ' .. dump(v) .. ','
    end
    return s .. '} '
  else
    return tostring(o)
  end
end

local ENV = {}

ffi.cdef [[
  extern char **environ;
]]

local function init()
 kong.log.notice("warmup of infiscal vault!")
end

local function echo_value(value)
  return value
end

local function get_auth_token(url, body, timeout)
  local client = http:new()
  client:set_timeout(timeout)
  local res, err = client:request_uri(url, {
    method = "POST",
    body = json.encode(body),
    headers = {
      ["content-type"] = "application/json"
    }
  })
  if err then
    local err_s = json.encode({
      message = 'got err',
      error   = tostring(err)
    })
    error(err_s)
  end

  if res.status ~= 200 then
    local err_s = json.encode({
      message    = 'got err',
      sts_status = res.status,
      sts_body   = json.decode(res.body)
    })
    error(err_s)
  end
  local token_body =
      json.decode(res.body)
  local access_token = token_body.accessToken

  return { token = access_token, ttl = token_body.expiresIn - 60 }
end

local path_secret = "/api/v3/secrets/raw/"
local path_auth = "/api/v1/auth/universal-auth/login"
local cache_key = "infiscal-token"

local function get(conf, resource, version)
  kong.log.notice("get called on infiscal vault!")
  -- kong.log.err(dump({conf = conf, resource = resource, version = version}))
  -- if true then
  --   return "yes"
  -- end
  local base_url = conf.connection.base_url
  local token_res, err = kong.cache:get(cache_key, nil, get_auth_token, base_url .. path_auth, conf.auth,
    conf.connection.timeouts.auth)

  if token_res.ttl then
    -- setting a proper ttl for the token
    kong.cache:renew(cache_key, { ttl = token_res.ttl }, echo_value, { token = token_res.token })
    kong.log.notice("token for '" .. conf.auth.clientId .. "' clientId will expire in " .. token_res.ttl .. "s")
  end

  local client = http:new()
  -- https://github.com/ledgetech/lua-resty-http?tab=readme-ov-file#usage
  client:set_timeout(conf.connection.timeouts.get)
  local res, err = client:request_uri(base_url .. path_secret .. resource, {
    method = "GET",
    headers = {
      authorization =
          "Bearer " .. token_res.token
    },
    ssl_verify = true,
    query = conf.query
  })

  if err then
    local err_s = json.encode({
      message = 'got err',
      error   = tostring(err)
    })
    return nil, err_s
  end

  if res.status ~= 200 then
    local err_s = json.encode({
      message    = 'got err',
      sts_status = res.status,
      sts_body   = json.decode(res.body)
    })
    return nil, err_s
  end

  local credentials, err = json.decode(res.body)
  if err then
    error(err)
  end
  local value = credentials.secret.secretValue
  -- kong.log.err(value)
  return value
end


return {
  VERSION = kong_meta.version,
  init = init,
  get = get,
}
