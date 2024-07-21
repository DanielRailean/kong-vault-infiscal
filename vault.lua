---
-- Vault module
--
-- This module can be used to resolve, parse and verify vault references.
--
-- @module kong.vault

local require = require

local constants = require "kong.constants"
local arguments = require "kong.api.arguments"
local isempty = require "table.isempty"
local buffer = require "string.buffer"
local clone = require "table.clone"
local cjson = require("cjson.safe").new()


local yield = require("kong.tools.yield").yield
local get_updated_now_ms = require("kong.tools.time").get_updated_now_ms
local replace_dashes = require("kong.tools.string").replace_dashes

local function log_not_implemented(function_name)
  kong.log.notice(function_name .. " called, not implemented!")
end

local kong = kong

local ngx = ngx
local get_phase = ngx.get_phase
local max = math.max
local min = math.min
local fmt = string.format
local sub = string.sub
local byte = string.byte
local type = type
local sort = table.sort
local pcall = pcall
local lower = string.lower
local pairs = pairs
local ipairs = ipairs
local concat = table.concat
local md5_bin = ngx.md5_bin
local tostring = tostring
local tonumber = tonumber
local decode_args = ngx.decode_args
local unescape_uri = ngx.unescape_uri
local parse_url = require("socket.url").parse
local parse_path = require("socket.url").parse_path
local encode_base64url = require("ngx.base64").encode_base64url
local decode_json = cjson.decode

-- local ROTATION_INTERVAL = tonumber(os.getenv("KONG_VAULT_ROTATION_INTERVAL") or "60", 10)
local ROTATION_INTERVAL = 60

local VAULT_QUERY_OPTS = { workspace = ngx.null }


---
-- Checks if the passed in reference looks like a reference.
-- Valid references start with '{vault://' and end with '}'.
--
-- @local
-- @function is_reference
-- @tparam string reference reference to check
-- @treturn boolean `true` is the passed in reference looks like a reference, otherwise `false`
local function is_reference(reference)
  local BRACE_START = byte("{")
  local BRACE_END = byte("}")
  local COLON = byte(":")
  local SLASH = byte("/")

  return type(reference) == "string"
      and byte(reference, 1) == BRACE_START
      and byte(reference, -1) == BRACE_END
      and byte(reference, 7) == COLON
      and byte(reference, 8) == SLASH
      and byte(reference, 9) == SLASH
      and sub(reference, 2, 6) == "vault"
end


---
-- Parses and decodes the passed in reference and returns a table
-- containing its components.
--
-- Given a following resource:
-- ```lua
-- "{vault://env/cert/key?prefix=SSL_#1}"
-- ```
--
-- This function will return following table:
--
-- ```lua
-- {
--   name     = "env",  -- name of the Vault entity or Vault strategy
--   resource = "cert", -- resource where secret is stored
--   key      = "key",  -- key to lookup if the resource is secret object
--   config   = {       -- if there are any config options specified
--     prefix = "SSL_"
--   },
--   version  = 1       -- if the version is specified
-- }
-- ```
--
-- @local
-- @function parse_reference
-- @tparam string reference reference to parse
-- @treturn table|nil a table containing each component of the reference, or `nil` on error
-- @treturn string|nil error message on failure, otherwise `nil`
local function parse_reference(reference)
  if not is_reference(reference) then
    return nil, fmt("not a reference [%s]", tostring(reference))
  end

  local url, err = parse_url(sub(reference, 2, -2))
  if not url then
    return nil, fmt("reference is not url (%s) [%s]", err, reference)
  end

  local name = url.host
  if not name then
    return nil, fmt("reference url is missing host [%s]", reference)
  end

  local path = url.path
  if not path then
    return nil, fmt("reference url is missing path [%s]", reference)
  end

  local resource = sub(path, 2)
  if resource == "" then
    return nil, fmt("reference url has empty path [%s]", reference)
  end

  local version = url.fragment
  if version then
    version = tonumber(version, 10)
    if not version then
      return nil, fmt("reference url has invalid version [%s]", reference)
    end
  end

  local key
  local parts = parse_path(resource)
  local count = #parts
  if count == 1 then
    resource = unescape_uri(parts[1])
  else
    resource = unescape_uri(concat(parts, "/", 1, count - 1))
    if parts[count] ~= "" then
      key = unescape_uri(parts[count])
    end
  end

  if resource == "" then
    return nil, fmt("reference url has invalid path [%s]", reference)
  end

  local config
  local query = url.query
  if query and query ~= "" then
    config = decode_args(query)
  end

  return {
    name = url.host,
    resource = resource,
    key = key,
    config = config,
    version = version,
  }
end


---
-- Create a instance of PDK Vault module
--
-- @local
-- @function new
-- @tparam table self a PDK instance
-- @treturn table a new instance of Vault
local function new(self)
  -- Don't put this onto the top level of the file unless you're prepared for a surprise
  local Schema = require "kong.db.schema"

  local STRATEGIES = {}
  local SCHEMAS = {}
  local CONFIGS = {}

  local BUNDLED_VAULTS = constants.BUNDLED_VAULTS
  local VAULT_NAMES
  do
    local vaults = self and self.configuration and self.configuration.loaded_vaults
    if vaults then
      VAULT_NAMES = {}

      for name in pairs(vaults) do
        VAULT_NAMES[name] = true
      end
    else
      VAULT_NAMES = BUNDLED_VAULTS and clone(BUNDLED_VAULTS) or {}
    end
  end


  ---
  -- Calculates hash for a string.
  --
  -- @local
  -- @function calculate_hash
  -- @tparam string str a string to hash
  -- @treturn string md5 hash as base64url encoded string
  local function calculate_hash(str)
    return encode_base64url(md5_bin(str))
  end


  ---
  -- Builds cache key from reference and configuration hash.
  --
  -- @local
  -- @function build_cache_key
  -- @tparam string reference the vault reference string
  -- @tparam string config_hash the configuration hash
  -- @treturn string the cache key for shared dictionary cache
  local function build_cache_key(reference, config_hash)
    return config_hash .. "." .. reference
  end

  ---
  -- This function extracts a key and returns its value from a JSON object.
  --
  -- It first decodes the JSON string into a Lua table, then checks for the presence and type of a specific key.
  --
  -- @local
  -- @function extract_key_from_json_string
  -- @tparam string json_string the JSON string to be parsed and decoded
  -- @tparam string key the specific subfield to be searched for within the JSON object
  -- @treturn string|nil the value associated with the specified key in the JSON object
  -- @treturn string|nil a string describing an error if there was one
  local function extract_key_from_json_string(json_string, key)
    -- Note that this function will only find keys in flat maps.
    -- Deeper nested structures are not supported.
    local json, err = decode_json(json_string)
    if type(json) ~= "table" then
      return nil, fmt("unable to json decode value (%s): %s", json, err)
    end

    json_string = json[key]
    if json_string == nil then
      return nil, fmt("subfield %s not found in JSON secret", key)
    elseif type(json_string) ~= "string" then
      return nil, fmt("unexpected %s value in JSON secret for subfield %s", type(json_string), key)
    end

    return json_string
  end

  ---
  -- Build schema aware configuration out of base configuration and the configuration overrides
  -- (e.g. configuration parameters stored in a vault reference).
  --
  -- It infers and validates configuration fields, and only returns validated fields
  -- in the returned config. It also calculates a deterministic configuration hash
  -- that will can used to build  shared dictionary's cache key.
  --
  -- @local
  -- @function get_vault_config_and_hash
  -- @tparam string name the name of vault strategy
  -- @tparam table schema the scheme of vault strategy
  -- @tparam table base_config the base configuration
  -- @tparam table|nil config_overrides the configuration overrides
  -- @treturn table validated and merged configuration from base configuration and config overrides
  -- @treturn string calculated hash of the configuration
  --
  -- @usage
  -- local config, hash = get_vault_config_and_hash("env", schema, { prefix = "DEFAULT_" },
  --                                                               { prefix = "MY_PREFIX_" })
  local get_vault_config_and_hash
  do
    local CONFIG_HASH_BUFFER = buffer.new(100)
    get_vault_config_and_hash = function(name, schema, base_config, config_overrides)
      CONFIG_HASH_BUFFER:reset():putf("%s;", name)
      local config = {}
      config_overrides = config_overrides or config
      for k, f in schema:each_field() do
        local v = config_overrides[k] or base_config[k]
        v = arguments.infer_value(v, f)
        if v ~= nil and schema:validate_field(f, v) then
          config[k] = v
          CONFIG_HASH_BUFFER:putf("%s=%s;", k, v)
        end
      end
      return config, calculate_hash(CONFIG_HASH_BUFFER:get())
    end
  end


  ---
  -- Fetches the strategy and schema for a given vault.
  --
  -- This function fetches the associated strategy and schema from the `STRATEGIES` and `SCHEMAS` tables,
  -- respectively. If the strategy or schema isn't found in the tables, it attempts to initialize them
  -- from the Lua modules.
  --
  -- @local
  -- @function get_vault_strategy_and_schema
  -- @tparam string name the name of the vault to fetch the strategy and schema for
  -- @treturn table|nil the fetched or required strategy for the given vault
  -- @treturn string|nil an error message, if an error occurred while fetching or requiring the strategy or schema
  -- @treturn table|nil the vault strategy's configuration schema.
  local function get_vault_strategy_and_schema(name)
    local strategy = STRATEGIES[name]
    local schema = SCHEMAS[name]

    if strategy then
      return strategy, nil, schema
    end

    local vaults = self and (self.db and self.db.vaults)
    if vaults and vaults.strategies then
      strategy = vaults.strategies[name]
      if not strategy then
        return nil, fmt("could not find vault (%s)", name)
      end

      schema = vaults.schema.subschemas[name]
      if not schema then
        return nil, fmt("could not find vault schema (%s): %s", name, strategy)
      end

      schema = Schema.new(schema.fields.config)
    else
      local ok
      ok, strategy = pcall(require, fmt("kong.vaults.%s", name))
      if not ok then
        return nil, fmt("could not find vault (%s): %s", name, strategy)
      end

      local def
      ok, def = pcall(require, fmt("kong.vaults.%s.schema", name))
      if not ok then
        return nil, fmt("could not find vault schema (%s): %s", name, def)
      end

      schema = Schema.new(require("kong.db.schema.entities.vaults"))

      local err
      ok, err = schema:new_subschema(name, def)
      if not ok then
        return nil, fmt("could not load vault sub-schema (%s): %s", name, err)
      end

      schema = schema.subschemas[name]
      if not schema then
        return nil, fmt("could not find vault sub-schema (%s)", name)
      end

      if type(strategy.init) == "function" then
        strategy.init()
      end

      schema = Schema.new(schema.fields.config)
    end

    STRATEGIES[name] = strategy
    SCHEMAS[name] = schema

    return strategy, nil, schema
  end


  ---
  -- This function retrieves the base configuration for the default vault
  -- using the vault strategy name.
  --
  -- The vault configuration is stored in Kong configuration from which this
  -- function derives the default base configuration for the vault strategy.
  --
  -- @local
  -- @function get_vault_name_and_config_by_name
  -- @tparam string name The unique name of the vault strategy
  -- @treturn string name of the vault strategy (same as the input string)
  -- @treturn nil this never fails so it always returns `nil`
  -- @treturn table|nil the vault strategy's base config derived from Kong configuration
  --
  -- @usage
  -- local name, err, base_config = get_vault_name_and_config_by_name("env")
  local function get_vault_name_and_config_by_name(name)
    -- base config stays the same so we can cache it
    local base_config = CONFIGS[name]
    if not base_config then
      base_config = {}
      if self and self.configuration then
        local configuration = self.configuration
        local env_name = replace_dashes(name)
        local _, err, schema = get_vault_strategy_and_schema(name)
        if not schema then
          return nil, err
        end
        for k, f in schema:each_field() do
          -- n is the entry in the kong.configuration table, for example
          -- KONG_VAULT_ENV_PREFIX will be found in kong.configuration
          -- with a key "vault_env_prefix". Environment variables are
          -- thus turned to lowercase and we just treat any "-" in them
          -- as "_". For example if your custom vault was called "my-vault"
          -- then you would configure it with KONG_VAULT_MY_VAULT_<setting>
          -- or in kong.conf, where it would be called
          -- "vault_my_vault_<setting>".
          local n = lower(fmt("vault_%s_%s", env_name, replace_dashes(k)))
          local v = configuration[n]
          v = arguments.infer_value(v, f)
          -- TODO: should we be more visible with validation errors?
          -- In general it would be better to check the references
          -- and not just a format when they are stored with admin
          -- API, or in case of process secrets, when the kong is
          -- started. So this is a note to remind future us.
          -- Because current validations are less strict, it is fine
          -- to ignore it here.
          if v ~= nil and schema:validate_field(f, v) then
            base_config[k] = v
          elseif f.required and f.default ~= nil then
            base_config[k] = f.default
          end
        end
        CONFIGS[name] = base_config
      end
    end

    return name, nil, base_config
  end


  ---
  -- This function retrieves a vault entity by its prefix from configuration
  -- database, and returns the strategy name and the base configuration.
  --
  -- It either fetches the vault from a cache or directly from a configuration
  -- database. The vault entity is expected to be found in a database (db) or
  -- cache. If not found, an error message is returned.
  --
  -- @local
  -- @function get_vault_name_and_config_by_prefix
  -- @tparam string prefix the unique identifier of the vault entity to be retrieved
  -- @treturn string|nil name of the vault strategy
  -- @treturn string|nil a string describing an error if there was one
  -- @treturn table|nil the vault entity config
  --
  -- @usage
  -- local name, err, base_config = get_vault_name_and_config_by_prefix("my-vault")
  local function get_vault_name_and_config_by_prefix(prefix)
    if not (self and self.db) then
      return nil, "unable to retrieve config from db"
    end

    -- find a vault - it can be either a named vault that needs to be loaded from the cache, or the
    -- vault type accessed by name
    local cache = self.core_cache
    local vaults = self.db.vaults
    local vault, err

    if cache then
      local vault_cache_key = vaults:cache_key(prefix)
      vault, err = cache:get(vault_cache_key, nil, vaults.select_by_prefix, vaults, prefix, VAULT_QUERY_OPTS)
    else
      vault, err = vaults:select_by_prefix(prefix, VAULT_QUERY_OPTS)
    end

    if not vault then
      if err then
        return nil, fmt("could not find vault (%s): %s", prefix, err)
      end

      return nil, fmt("could not find vault (%s)", prefix)
    end

    return vault.name, nil, vault.config
  end


  ---
  -- Function `get_vault_name_and_base_config` retrieves name of the strategy
  -- and its base configuration using name (for default vaults) or prefix for
  -- database stored vault entities.
  --
  -- @local
  -- @function get_vault_name_and_base_config
  -- @tparam string name_or_prefix name of the vault strategy or prefix of the vault entity
  -- @treturn string|nil name of the vault strategy
  -- @treturn string|nil a string describing an error if there was one
  -- @treturn table|nil the base configuration
  --
  -- @usage
  -- local name, err, base_config = get_vault_name_and_base_config("env")
  local function get_vault_name_and_base_config(name_or_prefix)
    if VAULT_NAMES[name_or_prefix] then
      return get_vault_name_and_config_by_name(name_or_prefix)
    end

    return get_vault_name_and_config_by_prefix(name_or_prefix)
  end


  ---
  -- Function `get_strategy` processes a reference to retrieve a strategy and configuration settings.
  --
  -- The function first parses the reference. Then, it gets the strategy, the schema, and the base configuration
  -- settings for the vault based on the parsed reference. It checks the license type if required by the strategy.
  -- Finally, it gets the configuration and the cache key of the reference.
  --
  -- @local
  -- @function get_strategy
  -- @tparam string reference the reference to be used to load strategy and its settings.
  -- @tparam table|nil strategy the strategy used to fetch the secret
  -- @treturn string|nil a string describing an error if there was one
  -- @treturn table|nil the vault configuration for the reference
  -- @treturn string|nil the cache key for shared dictionary for the reference
  -- @treturn table|nil the parsed reference
  --
  -- @usage
  -- local strategy, err, config, cache_key, parsed_reference = get_strategy(reference)
  local function get_strategy(reference)
    local parsed_reference, err = parse_reference(reference)
    if not parsed_reference then
      return nil, err
    end

    local name, err, base_config = get_vault_name_and_base_config(parsed_reference.name)
    if not name then
      return nil, err
    end

    local strategy, err, schema = get_vault_strategy_and_schema(name)
    if not strategy then
      return nil, err
    end

    if strategy.license_required and self.licensing and self.licensing:license_type() == "free" then
      return nil, "vault " .. name .. " requires a license to be used"
    end

    local config, config_hash = get_vault_config_and_hash(name, schema, base_config, parsed_reference.config)
    local cache_key = build_cache_key(reference, config_hash)

    return strategy, nil, config, cache_key, parsed_reference, config_hash
  end

  ---
  -- Function `get` retrieves a value by calling the vault's get handler
  -- and then caches the value for a default time or for the time provided by the vault
  --
  -- If the value is not found in these caches and `cache_only` is not `truthy`,
  -- it attempts to retrieve the value from a vault.
  --
  -- On init worker phase the resolving of the secrets is postponed to a timer,
  -- and in this case the function returns `""` when it fails to find a value
  -- in a cache. This is because of current limitations in platform that disallows
  -- using cosockets/coroutines in that phase.
  --
  -- @local
  -- @function get
  -- @tparam string reference the reference key to lookup
  -- @tparam[opt] boolean cache_only optional boolean flag (if set to `true`,
  -- the function will not attempt to retrieve the value from the vault)
  -- @treturn string the retrieved value corresponding to the provided reference,
  -- or `nil` (when found negatively cached, or in case of an error)
  -- @treturn string a string describing an error if there was one
  --
  -- @usage
  -- local value, err = get(reference, cache_only)

  local default_ttl = 5 * 60
  local default_neg_ttl = 5
  local default_ress_ttl = 60
  local return_empty_on_get_fail = true

  local function get(reference)
    if get_phase() == "init_worker" then
      -- this is so the init does not complain
      -- https://github.com/Kong/kong/blob/c17190251247b8e5f16a18a6b67ba943cdfd4615/kong/db/schema/init.lua#L1653
      return true
    end

    local ot = kong.tracing.start_span("kong.vaults.get." .. reference)

    local strategy, err, config, cache_key, parsed_reference = get_strategy(reference)
    if err then
      kong.log.err(err)
      return
    end
    if not strategy then
      kong.log.err("vault strategy is null")
      return
    end
    if not parsed_reference then
      kong.log.err("vault reference is null")
      return
    end
    if not config then
      kong.log.err("vault config is null")
      return
    end
    local value, err = kong.cache:get(cache_key, {
        ttl = config.ttl or default_ttl,
        neg_ttl = config.neg_ttl or default_neg_ttl,
        resurrect_ttl = 60 or default_ress_ttl
      },
      strategy.get, config, parsed_reference.resource)
    if err then
      kong.log.err(err)
      ot:finish()
      if return_empty_on_get_fail then
        return ""
      end
      kong.response.exit(500, { message = "Failed to get '" .. reference .. "' secret key reference", detail = err })
    end
    -- local res = strategy.get(config, parsed_reference.resource)
    if value then
      local key = parsed_reference.key
      if key then
        value, err = extract_key_from_json_string(value, key)
        if not value then
          kong.log.err("could not get subfield value: %s", err)
        end
      end

      ot:finish()
      return value
    end
  end


  ---
  -- In place updates record's field from a cached reference.
  --
  -- @local
  -- @function update_from_cache
  -- @tparam string reference reference to look from the caches
  -- @tparam table record record which field is updated from caches
  -- @tparam string field name of the field
  --
  -- @usage
  -- local record = { field = "old-value" }
  -- update_from_cache("{vault://env/example}", record, "field" })
  local function update_from_cache(reference, record, field)
    local value, err = get(reference)
    if err then
      self.log.warn("error updating secret reference ", reference, ": ", err)
    end

    record[field] = value or ""
  end


  ---
  -- Recurse over config and calls the callback for each found reference.
  --
  -- @local
  -- @function recurse_config_refs
  -- @tparam table config config table to recurse.
  -- @tparam function callback callback to call on each reference.
  -- @treturn table config that might have been updated, depending on callback.
  local function recurse_config_refs(config, callback)
    -- silently ignores other than tables
    if type(config) ~= "table" then
      return config
    end

    for key, value in pairs(config) do
      if key ~= "$refs" and type(value) == "table" then
        recurse_config_refs(value, callback)
      end
    end

    local references = config["$refs"]
    if type(references) ~= "table" or isempty(references) then
      return config
    end

    for name, reference in pairs(references) do
      if type(reference) == "string" then    -- a string reference
        callback(reference, config, name)
      elseif type(reference) == "table" then -- array, set or map of references
        for key, ref in pairs(reference) do
          callback(ref, config[name], key)
        end
      end
    end

    return config
  end


  ---
  -- Function `update` recursively updates a configuration table.
  --
  -- This function recursively in-place updates a configuration table by
  -- replacing reference fields with values fetched from a cache. The references
  -- are specified in a `$refs` field.
  --
  -- If a reference cannot be fetched from the cache, the corresponding field is
  -- set to nil and an warning is logged.
  --
  -- @local
  -- @function update
  -- @tparam table config a table representing the configuration to update (if `config`
  -- is not a table, the function immediately returns it without any modifications)
  -- @treturn table the config table (with possibly updated values).
  --
  -- @usage
  -- local config = update(config)
  -- OR
  -- update(config)
  local function update(config)
    return recurse_config_refs(config, update_from_cache)
  end

  local function try(callback, options)
    kong.log.err("Try called, but not implemented")
  end

  ---
  -- Initializes vault, not implemented
  --
  -- @local
  -- @function init_worker
  local function init_worker()
    log_not_implemented("init_worker")
  end

  ---
  -- Called on `init` phase, and stores value in secrets cache.
  --
  -- @local
  -- @function init_in_cache_from_value
  -- @tparam string reference a vault reference.
  -- @tparan value string value that is stored in secrets cache.
  local function init_in_cache_from_value(reference, value)
    log_not_implemented("init_in_cache_from_value")
  end


  ---
  -- Called on `init` phase, and used to warmup secrets cache.
  --
  -- @local
  -- @function init_in_cache
  -- @tparam string reference a vault reference.
  -- @tparan table record a table that is a container for de-referenced value.
  -- @tparam field string field name in a record to which to store the de-referenced value.
  local function init_in_cache(reference, record, field)
    local value, err = init_in_cache_from_value(reference, record[field])
    if not value then
      self.log.warn("error caching secret reference ", reference, ": ", err)
    end
  end


  ---
  -- Called on `init` phase, and used to warmup secrets cache.
  -- @local
  -- @function init
  local function init()
    recurse_config_refs(self.configuration, init_in_cache)
  end


  local _VAULT = {} -- the public PDK interfaces


  ---
  -- Flush vault LRU cache and start a timer to rotate secrets.
  --
  -- @local
  -- @function kong.vault.flush
  --
  -- @usage
  -- kong.vault.flush()
  function _VAULT.flush()
    -- LRU:flush_all()

    -- -- refresh all the secrets
    -- local _, err = self.timer:named_at("secret-rotation-on-flush", 0, rotate_secrets_timer)
    -- if err then
    --   self.log.err("could not schedule timer to rotate vault secret references: ", err)
    -- end
  end

  ---
  -- Checks if the passed in reference looks like a reference.
  -- Valid references start with '{vault://' and end with '}'.
  --
  -- If you need more thorough validation,
  -- use `kong.vault.parse_reference`.
  --
  -- @function kong.vault.is_reference
  -- @tparam string reference reference to check
  -- @treturn boolean `true` is the passed in reference looks like a reference, otherwise `false`
  --
  -- @usage
  -- kong.vault.is_reference("{vault://env/key}") -- true
  -- kong.vault.is_reference("not a reference")   -- false
  function _VAULT.is_reference(reference)
    return is_reference(reference)
  end

  ---
  -- Parses and decodes the passed in reference and returns a table
  -- containing its components.
  --
  -- Given a following resource:
  -- ```lua
  -- "{vault://env/cert/key?prefix=SSL_#1}"
  -- ```
  --
  -- This function will return following table:
  --
  -- ```lua
  -- {
  --   name     = "env",  -- name of the Vault entity or Vault strategy
  --   resource = "cert", -- resource where secret is stored
  --   key      = "key",  -- key to lookup if the resource is secret object
  --   config   = {       -- if there are any config options specified
  --     prefix = "SSL_"
  --   },
  --   version  = 1       -- if the version is specified
  -- }
  -- ```
  --
  -- @function kong.vault.parse_reference
  -- @tparam string reference reference to parse
  -- @treturn table|nil a table containing each component of the reference, or `nil` on error
  -- @treturn string|nil error message on failure, otherwise `nil`
  --
  -- @usage
  -- local ref, err = kong.vault.parse_reference("{vault://env/cert/key?prefix=SSL_#1}") -- table
  function _VAULT.parse_reference(reference)
    return parse_reference(reference)
  end

  ---
  -- Resolves the passed in reference and returns the value of it.
  --
  -- @function kong.vault.get
  -- @tparam string reference  reference to resolve
  -- @treturn string|nil resolved value of the reference
  -- @treturn string|nil error message on failure, otherwise `nil`
  --
  -- @usage
  -- local value, err = kong.vault.get("{vault://env/cert/key}")
  function _VAULT.get(reference)
    return get(reference)
  end

  ---
  -- Helper function for secret rotation based on TTLs. Currently experimental.
  --
  -- @function kong.vault.update
  -- @tparam table options options containing secrets and references (this function modifies the input options)
  -- @treturn table options with updated secret values
  --
  -- @usage
  -- local options = kong.vault.update({
  --   cert = "-----BEGIN CERTIFICATE-----...",
  --   key = "-----BEGIN RSA PRIVATE KEY-----...",
  --   cert_alt = "-----BEGIN CERTIFICATE-----...",
  --   key_alt = "-----BEGIN EC PRIVATE KEY-----...",
  --   ["$refs"] = {
  --     cert = "{vault://aws/cert}",
  --     key = "{vault://aws/key}",
  --     cert_alt = "{vault://aws/cert-alt}",
  --     key_alt = "{vault://aws/key-alt}",
  --   }
  -- })
  --
  -- -- or
  --
  -- local options = {
  --   cert = "-----BEGIN CERTIFICATE-----...",
  --   key = "-----BEGIN RSA PRIVATE KEY-----...",
  --   cert_alt = "-----BEGIN CERTIFICATE-----...",
  --   key_alt = "-----BEGIN EC PRIVATE KEY-----...",
  --   ["$refs"] = {
  --     cert = "{vault://aws/cert}",
  --     key = "{vault://aws/key}",
  --     cert_alt = "{vault://aws/cert-alt}",
  --     key_alt = "{vault://aws/key-alt}",
  --   }
  -- }
  -- kong.vault.update(options)
  function _VAULT.update(options)
    return update(options)
  end

  ---
  -- Helper function for automatic secret rotation. Currently experimental.
  --
  -- @function kong.vault.try
  -- @tparam function callback callback function
  -- @tparam table options options containing credentials and references
  -- @treturn string|nil return value of the callback function
  -- @treturn string|nil error message on failure, otherwise `nil`
  --
  -- @usage
  -- local function connect(options)
  --   return database_connect(options)
  -- end
  --
  -- local connection, err = kong.vault.try(connect, {
  --   username = "john",
  --   password = "doe",
  --   ["$refs"] = {
  --     username = "{vault://aws/database-username}",
  --     password = "{vault://aws/database-password}",
  --   }
  -- })
  function _VAULT.try(callback, options)
    return try(callback, options)
  end

  ---
  -- Initializes vault.
  --
  -- Registers event handlers (on non-dbless nodes) and starts a recurring secrets
  -- rotation timer. Does nothing on control planes.
  --
  -- @local
  -- @function kong.vault.init_worker
  function _VAULT.init_worker()
    init_worker()
  end

  ---
  -- Warmups vault caches from config.
  --
  -- @local
  -- @function kong.vault.warmup
  function _VAULT.warmup(input)
    kong.log.notice("warmup called in ", get_phase())
    for k, v in pairs(input) do
      local kt = type(k)
      if kt == "table" then
        _VAULT.warmup(k)
      elseif kt == "string" and is_reference(k) then
        get(k)
      end
      local vt = type(v)
      if vt == "table" then
        _VAULT.warmup(v)
      elseif vt == "string" and is_reference(v) then
        get(v)
      end
    end
  end

  if get_phase() == "init" then
    init()
  end

  return _VAULT
end

-- modified by Daniel Railean

return {
  new = new,
  is_reference = is_reference,
  parse_reference = parse_reference,
}
