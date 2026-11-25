#!/usr/bin/env lua
-- conformance.lua
-- Length-prefixed stdin/stdout TIER_BLIND conformance adapter for omnibuf_wire.lua.
-- Works directly with omnibuf-go's cross-language conformance-runner:
--   conformance-runner -tier blind lua /path/to/conformance.lua

local function load_wire_module()
  local info = debug.getinfo(1, "S")
  local src = info and info.source or ""
  if src:sub(1, 1) == "@" then
    local dir = src:sub(2):match("^(.*)[/\\]")
    if dir and dir ~= "" then
      local ok, mod = pcall(dofile, dir .. "/omnibuf_wire.lua")
      if ok and type(mod) == "table" then
        return mod
      end
    end
  end
  return require("omnibuf_wire")
end

local wire = load_wire_module()

local MAX_FRAME_BYTES = 16 * 1024 * 1024
local WIRE_FORMAT_JSON = 2
local TIER_BLIND = 4

local function read_exact(n)
  if n == 0 then
    return ""
  end
  local data = io.stdin:read(n)
  if data == nil or #data < n then
    return nil
  end
  return data
end

local function handle_request(req_bytes)
  local decoded, derr = wire.decode_message(req_bytes)
  if derr then
    return wire.encode_string_field(3, "decode request error: " .. tostring(derr))
  end

  local tier = 0
  local requested_output_format = 0
  local omnibuf_payload = ""

  for _, f in ipairs(decoded.fields) do
    if f.field_num == 3 then
      tier = f.value
    elseif f.field_num == 4 then
      requested_output_format = f.value
    elseif f.field_num == 5 then
      omnibuf_payload = f.value
    end
  end

  if tier ~= TIER_BLIND then
    return wire.encode_string_field(4, "omnibuf-wireshark Lua core only implements TIER_BLIND")
  end

  if requested_output_format == WIRE_FORMAT_JSON then
    local json_str, err = wire.decode_blind_json(omnibuf_payload)
    if err then
      return wire.encode_string_field(1, tostring(err))
    end
    return wire.encode_string_field(6, json_str)
  end

  local _, err = wire.decode_message(omnibuf_payload)
  if err then
    return wire.encode_string_field(1, tostring(err))
  end
  return ""
end

while true do
  local hdr = io.stdin:read(4)
  if hdr == nil or #hdr == 0 then
    os.exit(0)
  end
  if #hdr < 4 then
    io.stderr:write("conformance.lua: truncated frame length prefix\n")
    os.exit(1)
  end
  local size = string.unpack("<I4", hdr)
  if size > MAX_FRAME_BYTES then
    io.stderr:write(string.format("conformance.lua: frame size %d exceeds limit\n", size))
    os.exit(1)
  end
  local payload = read_exact(size)
  if payload == nil then
    io.stderr:write("conformance.lua: unexpected EOF reading frame payload\n")
    os.exit(1)
  end

  local resp_bytes = handle_request(payload)
  io.stdout:write(string.pack("<I4", #resp_bytes))
  if #resp_bytes > 0 then
    io.stdout:write(resp_bytes)
  end
  io.stdout:flush()
end
