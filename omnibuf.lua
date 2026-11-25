-- omnibuf.lua
-- Wireshark / tshark / termshark Lua 5.4 dissector for OmniBuf wire payloads.
-- Supports:
--   * Media types: application/omnibuf, application/x-omnibuf,
--     application/connect+omnibuf, application/connect+x-omnibuf,
--     application/grpc+omnibuf, application/grpc+x-omnibuf
--   * 5-byte Connect/gRPC streaming envelopes ([1B flags][4B BE length])
--   * Decode As... on TCP (with DESEGMENT_ONE_MORE_SEGMENT) and UDP
--   * Inline Field #0 (SchemaMeta) + optional JSON schema file overlay

-- Resolve omnibuf_wire.lua relative to this script so `-X lua_script:/path/to/omnibuf.lua`
-- works from any working directory.
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

local omnibuf_proto = Proto("omnibuf", "OmniBuf")

-- Core display-filterable ProtoFields
local f_frame       = ProtoField.string("omnibuf.frame", "Frame")
local f_field       = ProtoField.string("omnibuf.field", "Field")
local f_field_num   = ProtoField.uint32("omnibuf.field_num", "Field Number", base.DEC)
local f_field_name  = ProtoField.string("omnibuf.field_name", "Field Name")
local f_wire_type   = ProtoField.uint8("omnibuf.wire_type", "Wire Type", base.DEC, wire.WIRE_TYPE_NAMES)
local f_type_name   = ProtoField.string("omnibuf.type_name", "Message Type")
local f_val_uint    = ProtoField.uint64("omnibuf.uint", "Uint Value", base.DEC)
local f_val_sint    = ProtoField.int64("omnibuf.sint", "Sint Value", base.DEC)
local f_val_bool    = ProtoField.bool("omnibuf.bool", "Bool Value")
local f_val_f32     = ProtoField.float("omnibuf.float32", "Float32 Value")
local f_val_f64     = ProtoField.double("omnibuf.float64", "Float64 Value")
local f_val_string  = ProtoField.string("omnibuf.string", "String Value")
local f_val_bytes   = ProtoField.bytes("omnibuf.bytes", "Bytes Value")
local f_enum_label  = ProtoField.string("omnibuf.enum", "Enum Label")
local f_env_flags   = ProtoField.uint8("omnibuf.envelope.flags", "Envelope Flags", base.HEX)
local f_env_length  = ProtoField.uint32("omnibuf.envelope.length", "Envelope Length", base.DEC)
local f_error       = ProtoField.string("omnibuf.error", "Decode Error")

omnibuf_proto.fields = {
  f_frame,
  f_field,
  f_field_num,
  f_field_name,
  f_wire_type,
  f_type_name,
  f_val_uint,
  f_val_sint,
  f_val_bool,
  f_val_f32,
  f_val_f64,
  f_val_string,
  f_val_bytes,
  f_enum_label,
  f_env_flags,
  f_env_length,
  f_error,
}

-- Plugin preferences
omnibuf_proto.prefs.schema_path = Pref.string(
  "Schema JSON path",
  "",
  "Optional path to an OmniBuf JSON schema or Protobuf FileDescriptorSet JSON file"
)
omnibuf_proto.prefs.root_message = Pref.string(
  "Root message name",
  "",
  "Optional fully-qualified root message name (defaults to schema root or Field #0 type_name)"
)

local cached_schema_path = nil
local cached_schema = nil
local cached_schema_err = nil

local function get_schema()
  local path = omnibuf_proto.prefs.schema_path or ""
  if path ~= cached_schema_path then
    cached_schema_path = path
    cached_schema = nil
    cached_schema_err = nil
    if path ~= "" then
      local s, err = wire.load_schema_file(path)
      cached_schema = s
      cached_schema_err = err
    end
  end
  return cached_schema, cached_schema_err
end

function omnibuf_proto.prefs_changed()
  cached_schema_path = nil
  get_schema()
end

local function short_hex(s, max_bytes)
  max_bytes = max_bytes or 16
  local n = #s
  local show = n < max_bytes and n or max_bytes
  local parts = {}
  for i = 1, show do
    parts[i] = string.format("%02x", string.byte(s, i))
  end
  if n > max_bytes then
    return table.concat(parts) .. "..."
  end
  return table.concat(parts)
end

local function format_scalar(wt, val, enum_table)
  if wt == wire.WIRE_UINT or wt == wire.WIRE_FIXED32 or wt == wire.WIRE_FIXED64 then
    local s = wire.format_uint64(val)
    if enum_table and enum_table[val] then
      return string.format("%s (%s)", enum_table[val], s)
    end
    return s
  elseif wt == wire.WIRE_SINT or wt == wire.WIRE_SFIXED32 or wt == wire.WIRE_SFIXED64 then
    local s = tostring(val)
    if enum_table and enum_table[val] then
      return string.format("%s (%s)", enum_table[val], s)
    end
    return s
  elseif wt == wire.WIRE_BOOL_FALSE or wt == wire.WIRE_BOOL_TRUE then
    return val and "true" or "false"
  elseif wt == wire.WIRE_FLOAT32 or wt == wire.WIRE_FLOAT64 then
    return string.format("%.9g", val)
  elseif wt == wire.WIRE_STRING then
    if #val > 64 then
      return string.format("%q (%dB)", val:sub(1, 61) .. "...", #val)
    end
    return string.format("%q", val)
  elseif wt == wire.WIRE_BYTES then
    return string.format("0x%s (%dB)", short_hex(val, 16), #val)
  elseif type(val) == "table" and val.kind == "extended" then
    return string.format("ext(0x%02x, %dB)", val.subtype, #val.payload)
  end
  return tostring(val)
end

local function add_scalar_protofield(node, tvb_range, wt, val, enum_table)
  if wt == wire.WIRE_UINT or wt == wire.WIRE_FIXED32 or wt == wire.WIRE_FIXED64 then
    node:add(f_val_uint, tvb_range, UInt64.new(val & 0xFFFFFFFF, (val >> 32) & 0xFFFFFFFF))
    if enum_table and enum_table[val] then
      node:add(f_enum_label, tvb_range, enum_table[val]):set_generated()
    end
  elseif wt == wire.WIRE_SINT or wt == wire.WIRE_SFIXED32 or wt == wire.WIRE_SFIXED64 then
    node:add(f_val_sint, tvb_range, Int64.new(val & 0xFFFFFFFF, (val >> 32) & 0xFFFFFFFF))
    if enum_table and enum_table[val] then
      node:add(f_enum_label, tvb_range, enum_table[val]):set_generated()
    end
  elseif wt == wire.WIRE_BOOL_FALSE or wt == wire.WIRE_BOOL_TRUE then
    node:add(f_val_bool, tvb_range, val)
  elseif wt == wire.WIRE_FLOAT32 then
    node:add(f_val_f32, tvb_range, val)
  elseif wt == wire.WIRE_FLOAT64 then
    node:add(f_val_f64, tvb_range, val)
  elseif wt == wire.WIRE_STRING then
    node:add(f_val_string, tvb_range, val)
  elseif wt == wire.WIRE_BYTES then
    node:add(f_val_bytes, tvb_range)
  end
end

-- Helper to slice a tvb using 1-based inclusive [start_pos, end_pos] offsets
-- relative to base_offset (0-based offset within tvb).
local function tvb_slice(tvb, base_offset, start_pos, end_pos)
  local offset = base_offset + (start_pos - 1)
  local len = end_pos - start_pos + 1
  if len < 0 then
    len = 0
  end
  return tvb(offset, len)
end

local add_message_fields

local function add_value_node(parent_tree, tvb, base_offset, label, start_pos, end_pos, wt, val, schema, msg_name, field_meta_child, enum_table)
  local range = tvb_slice(tvb, base_offset, start_pos, end_pos)

  if type(val) == "table" and val.kind == "submsg" then
    local child_msg_name = msg_name
    if (not child_msg_name or child_msg_name == "") and val.schema_meta and val.schema_meta.type_name ~= "" then
      child_msg_name = val.schema_meta.type_name
    end
    local nfields = #val.fields
    local field_word = nfields == 1 and "field" or "fields"
    local summary = string.format("%s: {%d %s}", label, nfields, field_word)
    if child_msg_name and child_msg_name ~= "" then
      summary = string.format("%s: %s {%d %s}", label, child_msg_name, nfields, field_word)
    end
    local sub_tree = parent_tree:add(f_field, range, summary)
    local eff_meta = wire.merge_schema_meta(field_meta_child, val.schema_meta)
    add_message_fields(sub_tree, tvb, base_offset, val.fields, schema, child_msg_name, eff_meta)
    return sub_tree

  elseif type(val) == "table" and val.kind == "array" then
    local summary = string.format("%s: [%d x %s]", label, val.count, wire.wire_type_name(val.elem_wire_type))
    local arr_tree = parent_tree:add(f_field, range, summary)
    for i, item in ipairs(val.items) do
      add_value_node(
        arr_tree, tvb, base_offset,
        string.format("[%d]", i - 1),
        item.start_pos, item.end_pos,
        val.elem_wire_type, item.value,
        schema, msg_name, field_meta_child, enum_table
      )
    end
    return arr_tree

  elseif type(val) == "table" and val.kind == "map" then
    local summary = string.format(
      "%s: map<%s, %s> (%d)",
      label,
      wire.wire_type_name(val.key_wire_type),
      wire.wire_type_name(val.val_wire_type),
      val.count
    )
    local map_tree = parent_tree:add(f_field, range, summary)
    for _, entry in ipairs(val.entries) do
      local key_str = format_scalar(val.key_wire_type, entry.key, nil)
      add_value_node(
        map_tree, tvb, base_offset,
        key_str,
        entry.start_pos, entry.end_pos,
        val.val_wire_type, entry.value,
        schema, msg_name, field_meta_child, enum_table
      )
    end
    return map_tree

  elseif type(val) == "table" and val.kind == "schema_meta" then
    local meta = val.meta
    local summary = "#0 SchemaMeta"
    if meta.type_name ~= "" then
      summary = string.format("#0 SchemaMeta (%s)", meta.type_name)
    end
    local meta_tree = parent_tree:add(f_field, range, summary)
    if meta.type_name ~= "" then
      meta_tree:add(f_type_name, range, meta.type_name):set_generated()
    end
    for fnum, fname in pairs(meta.fields) do
      meta_tree:add(f_field, range, string.format("#%d -> %s", fnum, fname)):set_generated()
    end
    return meta_tree

  else
    local formatted = format_scalar(wt, val, enum_table)
    local node = parent_tree:add(f_field, range, string.format("%s: %s", label, formatted))
    add_scalar_protofield(node, range, wt, val, enum_table)
    return node
  end
end

add_message_fields = function(tree, tvb, base_offset, fields, schema, msg_name, schema_meta)
  local msg_fields = schema and msg_name and schema.messages and schema.messages[msg_name] or nil

  for _, f in ipairs(fields) do
    local fnum = f.field_num
    local wt = f.wire_type
    local range = tvb_slice(tvb, base_offset, f.start_pos, f.end_pos)

    if fnum == 0 then
      local node = add_value_node(tree, tvb, base_offset, "#0", f.start_pos, f.end_pos, wt, f.value, schema, nil, nil, nil)
      node:add(f_field_num, range, 0):set_generated()
      node:add(f_wire_type, range, wt):set_generated()
    else
      local schema_fdef = msg_fields and msg_fields[fnum] or nil
      local raw_meta_name = schema_meta and schema_meta.fields and schema_meta.fields[fnum] or nil
      local fname = (schema_fdef and schema_fdef.name and schema_fdef.name ~= "" and schema_fdef.name)
        or (raw_meta_name and raw_meta_name ~= "" and raw_meta_name)
        or nil
      local label = fname and string.format("#%d %s", fnum, fname) or string.format("#%d", fnum)
      local child_msg = schema_fdef and schema_fdef.message or nil
      local child_meta = schema_meta and schema_meta.children and schema_meta.children[fnum] or nil
      local enum_table = schema and schema_fdef and schema_fdef.enum and schema.enums and schema.enums[schema_fdef.enum] or nil

      local node = add_value_node(
        tree, tvb, base_offset, label,
        f.start_pos, f.end_pos, wt, f.value,
        schema, child_msg, child_meta, enum_table
      )
      node:add(f_field_num, range, fnum):set_generated()
      node:add(f_wire_type, range, wt):set_generated()
      if fname then
        node:add(f_field_name, range, fname):set_generated()
      end
    end
  end
end

--- Checks if the buffer looks like a valid 5-byte Connect/gRPC envelope stream.
local function looks_like_envelope(raw)
  local n = #raw
  if n < 5 then
    return false
  end
  local pos = 1
  local frames = 0
  while pos <= n do
    if pos + 4 > n then
      return false
    end
    local flags, plen = string.unpack(">BI4", raw, pos)
    if (flags & 0xFC) ~= 0 or plen > n - (pos + 4) then
      return false
    end
    pos = pos + 5 + plen
    frames = frames + 1
  end
  return pos == n + 1 and frames > 0
end

local function dissect_omnibuf_message(tvb, base_offset, raw, tree, schema, root_name)
  local decoded, err = wire.decode_message(raw, 1, #raw)
  if err then
    tree:add(f_error, tvb(base_offset, #raw), err)
    return false, err
  end

  local msg_name = root_name
  if (not msg_name or msg_name == "") and decoded.schema_meta and decoded.schema_meta.type_name ~= "" then
    msg_name = decoded.schema_meta.type_name
  end
  if (not msg_name or msg_name == "") and schema and schema.root then
    msg_name = schema.root
  end

  if msg_name and msg_name ~= "" then
    tree:add(f_type_name, tvb(base_offset, #raw), msg_name):set_generated()
  end

  add_message_fields(tree, tvb, base_offset, decoded.fields, schema, msg_name, decoded.schema_meta)
  return true, #decoded.fields
end

--- Main Wireshark dissector entrypoint.
function omnibuf_proto.dissector(tvb, pinfo, tree)
  local total_len = tvb:len()
  if total_len == 0 then
    return 0
  end

  -- Support TCP reassembly when a 5-byte envelope frame is split across TCP segments.
  if pinfo.port_type == 2 and total_len >= 5 then -- 2 == PT_TCP
    local flags = tvb(0, 1):uint()
    local frame_len = tvb(1, 4):uint()
    if (flags & 0xFC) == 0 and frame_len > 0 and frame_len <= 67108864 then
      local needed = 5 + frame_len
      if total_len < needed then
        pinfo.desegment_offset = 0
        pinfo.desegment_len = needed - total_len
        return total_len
      end
    end
  end

  local raw = tvb:raw(0, total_len)
  local schema, schema_err = get_schema()
  local root_name = omnibuf_proto.prefs.root_message or ""

  pinfo.cols.protocol = "OmniBuf"
  local subtree = tree:add(omnibuf_proto, tvb(0, total_len), string.format("OmniBuf (%d bytes)", total_len))

  if schema_err then
    subtree:add(f_error, tvb(0, 0), "Schema load error: " .. tostring(schema_err)):set_generated()
  end

  -- Check if payload is Connect/gRPC 5-byte length-prefixed envelope framed.
  -- First try raw OmniBuf unless it matches a clean 5-byte envelope stream.
  local is_envelope = false
  local media_type_field = pinfo.private and pinfo.private["media_type"] or nil
  if type(media_type_field) == "string" and (media_type_field:find("connect%+", 1) or media_type_field:find("grpc%+", 1)) then
    is_envelope = true
  elseif looks_like_envelope(raw) then
    -- Verify whether decoding as raw message fails or envelope frames decode cleanly
    local raw_ok = wire.decode_message(raw, 1, #raw)
    if not raw_ok then
      is_envelope = true
    end
  end

  if is_envelope then
    local frames, ferr = wire.decode_envelope_frames(raw, 1, #raw)
    if not frames then
      subtree:add(f_error, tvb(0, total_len), ferr)
      pinfo.cols.info = "OmniBuf (envelope error)"
      return total_len
    end
    pinfo.cols.info = string.format("OmniBuf Stream (%d frame%s)", #frames, #frames == 1 and "" or "s")
    for i, frame in ipairs(frames) do
      local f_range = tvb(frame.header_start - 1, 5 + frame.length)
      local f_label = string.format(
        "Frame #%d (flags=0x%02x, %dB%s%s)",
        i,
        frame.flags,
        frame.length,
        frame.compressed and ", compressed" or "",
        frame.end_stream and ", end-stream" or ""
      )
      local f_tree = subtree:add(f_frame, f_range, f_label)
      f_tree:add(f_env_flags, tvb(frame.header_start - 1, 1), frame.flags)
      f_tree:add(f_env_length, tvb(frame.header_start, 4), frame.length)
      if frame.length > 0 then
        if frame.compressed then
          f_tree:add(f_val_bytes, tvb(frame.payload_start - 1, frame.length))
        elseif frame.end_stream then
          -- Connect end-stream frame carries JSON trailers/status
          f_tree:add(f_val_string, tvb(frame.payload_start - 1, frame.length), frame.payload)
        else
          dissect_omnibuf_message(tvb, frame.payload_start - 1, frame.payload, f_tree, schema, root_name)
        end
      end
    end
    return total_len
  end

  local ok, count_or_err = dissect_omnibuf_message(tvb, 0, raw, subtree, schema, root_name)
  if ok then
    pinfo.cols.info = string.format("OmniBuf (%d field%s, %dB)", count_or_err, count_or_err == 1 and "" or "s", total_len)
  else
    pinfo.cols.info = "OmniBuf (malformed)"
  end
  return total_len
end

-- Register media types for HTTP/1.1, HTTP/2, HTTP/3, Connect, and gRPC
local media_table = DissectorTable.get("media_type")
if media_table then
  local media_types = {
    "application/omnibuf",
    "application/x-omnibuf",
    "application/connect+omnibuf",
    "application/connect+x-omnibuf",
    "application/grpc+omnibuf",
    "application/grpc+x-omnibuf",
  }
  for _, mt in ipairs(media_types) do
    media_table:add(mt, omnibuf_proto)
  end
end

-- Register for "Decode As..." on TCP and UDP
local tcp_table = DissectorTable.get("tcp.port")
if tcp_table then
  tcp_table:add_for_decode_as(omnibuf_proto)
end
local udp_table = DissectorTable.get("udp.port")
if udp_table then
  udp_table:add_for_decode_as(omnibuf_proto)
end
