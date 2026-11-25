-- omnibuf_wire.lua
-- Pure Lua 5.4 OmniBuf v1 DRAFT-1 wire decoder and cursor.
-- Decoupled from Wireshark's API so unit tests and conformance vectors
-- run directly with a standard `lua` 5.4 binary.

local M = {}

M.WIRE_UINT = 0
M.WIRE_SINT = 1
M.WIRE_BOOL_FALSE = 2
M.WIRE_BOOL_TRUE = 3
M.WIRE_FIXED32 = 4
M.WIRE_FIXED64 = 5
M.WIRE_SFIXED32 = 6
M.WIRE_SFIXED64 = 7
M.WIRE_FLOAT32 = 8
M.WIRE_FLOAT64 = 9
M.WIRE_STRING = 10
M.WIRE_BYTES = 11
M.WIRE_SUB_MSG = 12
M.WIRE_ARRAY = 13
M.WIRE_MAP = 14
M.WIRE_EXTENDED = 15

M.WIRE_TYPE_NAMES = {
  [0] = "WireUint",
  [1] = "WireSint",
  [2] = "WireBoolFalse",
  [3] = "WireBoolTrue",
  [4] = "WireFixed32",
  [5] = "WireFixed64",
  [6] = "WireSfixed32",
  [7] = "WireSfixed64",
  [8] = "WireFloat32",
  [9] = "WireFloat64",
  [10] = "WireString",
  [11] = "WireBytes",
  [12] = "WireSubMsg",
  [13] = "WireArray",
  [14] = "WireMap",
  [15] = "WireExtended",
}

M.MAX_CONTAINER_DEPTH = 32
M.MAX_FIELD_NUMBER = 536870911 -- (1 << 29) - 1
M.FIELD0_TAG = 0x19

local VALID_MAP_KEY_TYPES = {
  [0] = true,  -- WireUint
  [1] = true,  -- WireSint
  [2] = true,  -- WireBoolFalse
  [4] = true,  -- WireFixed32
  [5] = true,  -- WireFixed64
  [6] = true,  -- WireSfixed32
  [7] = true,  -- WireSfixed64
  [10] = true, -- WireString
}

local str_byte = string.byte
local str_sub = string.sub
local str_unpack = string.unpack
local str_format = string.format
local math_ult = math.ult
local utf8_len = utf8.len

--- Returns the canonical wire type name for a 4-bit wire type tag.
function M.wire_type_name(wt)
  return M.WIRE_TYPE_NAMES[wt] or str_format("WireUnknown(%d)", wt)
end

--- Formats a 64-bit Lua integer as an unsigned decimal string.
function M.format_uint64(val)
  return str_format("%u", val)
end

--- Decodes an unsigned 64-bit ZigZag value into a signed 64-bit integer.
function M.decode_zigzag(u)
  return (u >> 1) ~ -(u & 1)
end

--- Strictly validates UTF-8 (rejects invalid sequences, overlong forms, and surrogates).
function M.is_valid_utf8(s)
  return utf8_len(s) ~= nil
end

--- Decodes a Prefix-Varint from buf starting at 1-based pos up to inclusive end_pos.
--- Returns (value, next_pos) on success, or (nil, err_msg) on failure.
function M.decode_varint(buf, pos, end_pos)
  end_pos = end_pos or #buf
  if pos > end_pos then
    return nil, str_format("truncated varint at offset %d", pos - 1)
  end
  local b0 = str_byte(buf, pos)
  if (b0 & 1) ~= 0 then
    return b0 >> 1, pos + 1
  elseif (b0 & 2) ~= 0 then
    if pos + 1 > end_pos then
      return nil, str_format("truncated 2-byte varint at offset %d", pos - 1)
    end
    local u16 = str_unpack("<I2", buf, pos)
    return u16 >> 2, pos + 2
  elseif (b0 & 4) ~= 0 then
    if pos + 3 > end_pos then
      return nil, str_format("truncated 4-byte varint at offset %d", pos - 1)
    end
    local u32 = str_unpack("<I4", buf, pos)
    return u32 >> 3, pos + 4
  elseif b0 == 0 then
    if pos + 8 > end_pos then
      return nil, str_format("truncated 9-byte varint at offset %d", pos - 1)
    end
    local u64 = str_unpack("<I8", buf, pos + 1)
    return u64, pos + 9
  else
    return nil, str_format("reserved varint marker 0x%02x at offset %d", b0, pos - 1)
  end
end

--- Decodes a field tag at 1-based pos.
--- Returns (field_num, wire_type, next_pos) or (nil, nil, err_msg).
function M.decode_tag(buf, pos, end_pos)
  local tag, next_pos = M.decode_varint(buf, pos, end_pos)
  if tag == nil then
    return nil, nil, next_pos
  end
  local field_num = tag >> 4
  local wire_type = tag & 0x0F
  if math_ult(M.MAX_FIELD_NUMBER, field_num) then
    return nil, nil, str_format("field number out of range at offset %d", pos - 1)
  end
  if field_num == 0 and wire_type ~= M.WIRE_SUB_MSG then
    return nil, nil, str_format("Field #0 requires WireSubMsg, got %d at offset %d", wire_type, pos - 1)
  end
  return field_num, wire_type, next_pos
end

--- Reads a length-prefixed slice [ByteLen (Prefix-Varint)][Payload].
--- Returns (body_start, body_end, next_pos) or (nil, nil, err_msg).
--- For zero-length payloads, body_end = body_start - 1.
local function read_len_range(buf, pos, end_pos, min_len)
  min_len = min_len or 0
  local byte_len, payload_start = M.decode_varint(buf, pos, end_pos)
  if byte_len == nil then
    return nil, nil, payload_start
  end
  local remaining = end_pos - payload_start + 1
  if math_ult(byte_len, min_len) or math_ult(remaining, byte_len) then
    return nil, nil, str_format("invalid length %s (remaining %d) at offset %d", M.format_uint64(byte_len), remaining, pos - 1)
  end
  local body_end = payload_start + byte_len - 1
  return payload_start, body_end, body_end + 1
end

local decode_value
local decode_message_fields

--- Decodes a Field #0 SchemaMeta payload in buf[start_pos..end_pos].
--- Returns (schema_meta_table, nil) or (nil, err_msg).
function M.decode_schema_meta(buf, start_pos, end_pos, depth, max_depth)
  depth = depth or 1
  max_depth = max_depth or M.MAX_CONTAINER_DEPTH
  if depth > max_depth then
    return nil, str_format("SchemaMeta nesting depth %d exceeds limit %d", depth, max_depth)
  end

  local meta = {
    type_name = "",
    fields = {},
    children = {},
  }
  local pos = start_pos

  while pos <= end_pos do
    local fnum, wt, after_tag = M.decode_tag(buf, pos, end_pos)
    if fnum == nil then
      return nil, wt
    end
    pos = after_tag

    if fnum == 0 then
      return nil, str_format("invalid nested Field #0 inside SchemaMeta at offset %d", pos - 1)
    elseif fnum == 1 then
      if wt ~= M.WIRE_STRING then
        return nil, str_format("SchemaMeta field #1 (type_name) must be WireString, got %d", wt)
      end
      local s_start, s_end, next_pos = read_len_range(buf, pos, end_pos, 0)
      if s_start == nil then
        return nil, next_pos
      end
      local s = str_sub(buf, s_start, s_end)
      if not M.is_valid_utf8(s) then
        return nil, str_format("invalid UTF-8 in SchemaMeta type_name at offset %d", s_start - 1)
      end
      meta.type_name = s
      pos = next_pos
    elseif fnum == 2 then
      if wt ~= M.WIRE_MAP then
        return nil, str_format("SchemaMeta field #2 (fields) must be WireMap, got %d", wt)
      end
      if depth + 1 > max_depth then
        return nil, str_format("SchemaMeta fields map depth %d exceeds limit %d", depth + 1, max_depth)
      end
      local body_start, body_end, next_pos = read_len_range(buf, pos, end_pos, 3)
      if body_start == nil then
        return nil, next_pos
      end
      local key_wt = str_byte(buf, body_start)
      local val_wt = str_byte(buf, body_start + 1)
      if key_wt ~= M.WIRE_UINT or val_wt ~= M.WIRE_STRING then
        return nil, "invalid SchemaMeta fields map header"
      end
      local count, p = M.decode_varint(buf, body_start + 2, body_end)
      if count == nil then
        return nil, p
      end
      local rem = body_end - p + 1
      if (count == 0 and rem ~= 0) or (count ~= 0 and math_ult(rem >> 1, count)) then
        return nil, "invalid SchemaMeta fields map count"
      end
      for _ = 1, count do
        local k, kp = M.decode_varint(buf, p, body_end)
        if k == nil then
          return nil, kp
        end
        if k == 0 or math_ult(M.MAX_FIELD_NUMBER, k) then
          return nil, str_format("invalid SchemaMeta field number %s", M.format_uint64(k))
        end
        local v_start, v_end, vp = read_len_range(buf, kp, body_end, 0)
        if v_start == nil then
          return nil, vp
        end
        local name = str_sub(buf, v_start, v_end)
        if not M.is_valid_utf8(name) then
          return nil, str_format("invalid UTF-8 in SchemaMeta field name at offset %d", v_start - 1)
        end
        meta.fields[k] = name
        p = vp
      end
      if p ~= body_end + 1 then
        return nil, "trailing bytes in SchemaMeta fields map"
      end
      pos = next_pos
    elseif fnum == 3 then
      if wt ~= M.WIRE_MAP then
        return nil, str_format("SchemaMeta field #3 (children) must be WireMap, got %d", wt)
      end
      if depth + 1 > max_depth then
        return nil, str_format("SchemaMeta children map depth %d exceeds limit %d", depth + 1, max_depth)
      end
      local body_start, body_end, next_pos = read_len_range(buf, pos, end_pos, 3)
      if body_start == nil then
        return nil, next_pos
      end
      local key_wt = str_byte(buf, body_start)
      local val_wt = str_byte(buf, body_start + 1)
      if key_wt ~= M.WIRE_UINT or val_wt ~= M.WIRE_SUB_MSG then
        return nil, "invalid SchemaMeta children map header"
      end
      local count, p = M.decode_varint(buf, body_start + 2, body_end)
      if count == nil then
        return nil, p
      end
      local rem = body_end - p + 1
      if (count == 0 and rem ~= 0) or (count ~= 0 and math_ult(rem >> 1, count)) then
        return nil, "invalid SchemaMeta children map count"
      end
      local local_children = {}
      for _ = 1, count do
        local k, kp = M.decode_varint(buf, p, body_end)
        if k == nil then
          return nil, kp
        end
        if k == 0 or math_ult(M.MAX_FIELD_NUMBER, k) then
          return nil, str_format("invalid SchemaMeta child field number %s", M.format_uint64(k))
        end
        local c_start, c_end, vp = read_len_range(buf, kp, body_end, 0)
        if c_start == nil then
          return nil, vp
        end
        local child_meta, cerr = M.decode_schema_meta(buf, c_start, c_end, depth + 2, max_depth)
        if child_meta == nil then
          return nil, cerr
        end
        local_children[k] = child_meta
        p = vp
      end
      if p ~= body_end + 1 then
        return nil, "trailing bytes in SchemaMeta children map"
      end
      for k, child_meta in pairs(local_children) do
        meta.children[k] = M.merge_schema_meta(meta.children[k], child_meta)
      end
      pos = next_pos
    else
      local _, next_pos, err = decode_value(buf, pos, end_pos, wt, depth, max_depth, false)
      if err then
        return nil, err
      end
      pos = next_pos
    end
  end

  return meta, nil
end

--- Merges two SchemaMeta tables (overlay on top of base) without mutating overlay.
function M.merge_schema_meta(base, overlay)
  if overlay == nil then
    return base
  end
  local out = {
    type_name = (base and base.type_name) or "",
    fields = {},
    children = {},
  }
  if base then
    for k, v in pairs(base.fields) do
      out.fields[k] = v
    end
    for k, v in pairs(base.children) do
      out.children[k] = v
    end
  end
  if overlay.type_name and overlay.type_name ~= "" then
    out.type_name = overlay.type_name
  end
  if overlay.fields then
    for k, v in pairs(overlay.fields) do
      out.fields[k] = v
    end
  end
  if overlay.children then
    for k, v in pairs(overlay.children) do
      out.children[k] = M.merge_schema_meta(out.children[k], v)
    end
  end
  return out
end

--- Decodes a single wire value (either top-level field value or container element).
--- Returns (value, next_pos, nil) on success, or (nil, nil, err_msg) on error.
decode_value = function(buf, pos, end_pos, wt, depth, max_depth, is_elem)
  if wt == M.WIRE_UINT then
    local val, next_pos = M.decode_varint(buf, pos, end_pos)
    if val == nil then
      return nil, nil, next_pos
    end
    return val, next_pos, nil

  elseif wt == M.WIRE_SINT then
    local raw, next_pos = M.decode_varint(buf, pos, end_pos)
    if raw == nil then
      return nil, nil, next_pos
    end
    return M.decode_zigzag(raw), next_pos, nil

  elseif wt == M.WIRE_BOOL_FALSE then
    if is_elem then
      if pos > end_pos then
        return nil, nil, str_format("truncated bool element at offset %d", pos - 1)
      end
      local b = str_byte(buf, pos)
      if b > 1 then
        return nil, nil, str_format("invalid bool byte 0x%02x at offset %d", b, pos - 1)
      end
      return b == 1, pos + 1, nil
    end
    return false, pos, nil

  elseif wt == M.WIRE_BOOL_TRUE then
    if is_elem then
      return nil, nil, str_format("WireBoolTrue is invalid as container element type at offset %d", pos - 1)
    end
    return true, pos, nil

  elseif wt == M.WIRE_FIXED32 then
    if pos + 3 > end_pos then
      return nil, nil, str_format("truncated fixed32 at offset %d", pos - 1)
    end
    return str_unpack("<I4", buf, pos), pos + 4, nil

  elseif wt == M.WIRE_FIXED64 then
    if pos + 7 > end_pos then
      return nil, nil, str_format("truncated fixed64 at offset %d", pos - 1)
    end
    return str_unpack("<I8", buf, pos), pos + 8, nil

  elseif wt == M.WIRE_SFIXED32 then
    if pos + 3 > end_pos then
      return nil, nil, str_format("truncated sfixed32 at offset %d", pos - 1)
    end
    return str_unpack("<i4", buf, pos), pos + 4, nil

  elseif wt == M.WIRE_SFIXED64 then
    if pos + 7 > end_pos then
      return nil, nil, str_format("truncated sfixed64 at offset %d", pos - 1)
    end
    return str_unpack("<i8", buf, pos), pos + 8, nil

  elseif wt == M.WIRE_FLOAT32 then
    if pos + 3 > end_pos then
      return nil, nil, str_format("truncated float32 at offset %d", pos - 1)
    end
    return str_unpack("<f", buf, pos), pos + 4, nil

  elseif wt == M.WIRE_FLOAT64 then
    if pos + 7 > end_pos then
      return nil, nil, str_format("truncated float64 at offset %d", pos - 1)
    end
    return str_unpack("<d", buf, pos), pos + 8, nil

  elseif wt == M.WIRE_STRING then
    local s_start, s_end, next_pos = read_len_range(buf, pos, end_pos, 0)
    if s_start == nil then
      return nil, nil, next_pos
    end
    local s = str_sub(buf, s_start, s_end)
    if not M.is_valid_utf8(s) then
      return nil, nil, str_format("invalid UTF-8 string at offset %d", s_start - 1)
    end
    return s, next_pos, nil

  elseif wt == M.WIRE_BYTES then
    local b_start, b_end, next_pos = read_len_range(buf, pos, end_pos, 0)
    if b_start == nil then
      return nil, nil, next_pos
    end
    return str_sub(buf, b_start, b_end), next_pos, nil

  elseif wt == M.WIRE_SUB_MSG then
    if depth + 1 > max_depth then
      return nil, nil, str_format("nesting depth %d exceeds limit %d", depth + 1, max_depth)
    end
    local body_start, body_end, next_pos = read_len_range(buf, pos, end_pos, 0)
    if body_start == nil then
      return nil, nil, next_pos
    end
    local sub_fields, sub_meta, err = decode_message_fields(buf, body_start, body_end, depth + 1, max_depth)
    if err then
      return nil, nil, err
    end
    return {
      kind = "submsg",
      body_start = body_start,
      body_end = body_end,
      raw = str_sub(buf, body_start, body_end),
      fields = sub_fields,
      schema_meta = sub_meta,
    }, next_pos, nil

  elseif wt == M.WIRE_ARRAY then
    if depth + 1 > max_depth then
      return nil, nil, str_format("array nesting depth %d exceeds limit %d", depth + 1, max_depth)
    end
    local body_start, body_end, next_pos = read_len_range(buf, pos, end_pos, 2)
    if body_start == nil then
      return nil, nil, next_pos
    end
    local elem_wt = str_byte(buf, body_start)
    if elem_wt > M.WIRE_EXTENDED or elem_wt == M.WIRE_BOOL_TRUE then
      return nil, nil, str_format("invalid WireArray element wire type %d at offset %d", elem_wt, body_start - 1)
    end
    local count, p = M.decode_varint(buf, body_start + 1, body_end)
    if count == nil then
      return nil, nil, p
    end
    local rem = body_end - p + 1
    local aligned
    if elem_wt == M.WIRE_BOOL_FALSE then
      aligned = (count == rem)
    elseif elem_wt == M.WIRE_FIXED32 or elem_wt == M.WIRE_SFIXED32 or elem_wt == M.WIRE_FLOAT32 then
      aligned = ((rem & 3) == 0) and (count == (rem >> 2))
    elseif elem_wt == M.WIRE_FIXED64 or elem_wt == M.WIRE_SFIXED64 or elem_wt == M.WIRE_FLOAT64 then
      aligned = ((rem & 7) == 0) and (count == (rem >> 3))
    else
      if count == 0 then
        aligned = (rem == 0)
      else
        aligned = not math_ult(rem, count)
      end
    end
    if not aligned then
      return nil, nil, str_format("WireArray count %s mismatches body size %d at offset %d", M.format_uint64(count), rem, body_start - 1)
    end

    local items = {}
    for i = 1, count do
      local item_start = p
      local val, np, err = decode_value(buf, p, body_end, elem_wt, depth + 1, max_depth, true)
      if err then
        return nil, nil, err
      end
      items[i] = {
        start_pos = item_start,
        end_pos = np - 1,
        value = val,
      }
      p = np
    end
    if p ~= body_end + 1 then
      return nil, nil, str_format("trailing bytes in WireArray at offset %d", p - 1)
    end
    return {
      kind = "array",
      elem_wire_type = elem_wt,
      count = count,
      body_start = body_start,
      body_end = body_end,
      items = items,
    }, next_pos, nil

  elseif wt == M.WIRE_MAP then
    if depth + 1 > max_depth then
      return nil, nil, str_format("map nesting depth %d exceeds limit %d", depth + 1, max_depth)
    end
    local body_start, body_end, next_pos = read_len_range(buf, pos, end_pos, 3)
    if body_start == nil then
      return nil, nil, next_pos
    end
    local key_wt = str_byte(buf, body_start)
    local val_wt = str_byte(buf, body_start + 1)
    if not VALID_MAP_KEY_TYPES[key_wt] or val_wt > M.WIRE_EXTENDED or val_wt == M.WIRE_BOOL_TRUE then
      return nil, nil, str_format("invalid WireMap types (%d, %d) at offset %d", key_wt, val_wt, body_start - 1)
    end
    local count, p = M.decode_varint(buf, body_start + 2, body_end)
    if count == nil then
      return nil, nil, p
    end
    local rem = body_end - p + 1
    local ok_count
    if count == 0 then
      ok_count = (rem == 0)
    else
      ok_count = not math_ult(rem >> 1, count)
    end
    if not ok_count then
      return nil, nil, str_format("WireMap count %s mismatches body size %d at offset %d", M.format_uint64(count), rem, body_start - 1)
    end

    local entries = {}
    for i = 1, count do
      local entry_start = p
      local k_start = p
      local kval, kp, kerr = decode_value(buf, p, body_end, key_wt, depth + 1, max_depth, true)
      if kerr then
        return nil, nil, kerr
      end
      local k_end = kp - 1
      local v_start = kp
      local vval, vp, verr = decode_value(buf, kp, body_end, val_wt, depth + 1, max_depth, true)
      if verr then
        return nil, nil, verr
      end
      local v_end = vp - 1
      entries[i] = {
        start_pos = entry_start,
        end_pos = v_end,
        key_start = k_start,
        key_end = k_end,
        key = kval,
        val_start = v_start,
        val_end = v_end,
        value = vval,
      }
      p = vp
    end
    if p ~= body_end + 1 then
      return nil, nil, str_format("trailing bytes in WireMap at offset %d", p - 1)
    end
    return {
      kind = "map",
      key_wire_type = key_wt,
      val_wire_type = val_wt,
      count = count,
      body_start = body_start,
      body_end = body_end,
      entries = entries,
    }, next_pos, nil

  elseif wt == M.WIRE_EXTENDED then
    local body_start, body_end, next_pos = read_len_range(buf, pos, end_pos, 1)
    if body_start == nil then
      return nil, nil, next_pos
    end
    local subtype = str_byte(buf, body_start)
    local payload = str_sub(buf, body_start + 1, body_end)
    return {
      kind = "extended",
      subtype = subtype,
      payload = payload,
      payload_start = body_start + 1,
      payload_end = body_end,
    }, next_pos, nil

  else
    return nil, nil, str_format("unknown wire type %d at offset %d", wt, pos - 1)
  end
end

local function canonical_wt(wt)
  if wt == M.WIRE_BOOL_TRUE then
    return M.WIRE_BOOL_FALSE
  end
  return wt
end

local function array_shape_key(val)
  if type(val) ~= "table" or val.kind ~= "array" then
    return ""
  end
  local parts = { tostring(canonical_wt(val.elem_wire_type)) }
  if val.elem_wire_type == M.WIRE_ARRAY then
    local inner_shape = nil
    for _, item in ipairs(val.items) do
      local s, err = array_shape_key(item.value)
      if err then
        return nil, err
      end
      if inner_shape == nil then
        inner_shape = s
      elseif inner_shape ~= s then
        return nil, "conflicting nested WireArray element types"
      end
    end
    if inner_shape then
      parts[2] = inner_shape
    end
  end
  return table.concat(parts, ">"), nil
end

local function field_shape_key(wt, val)
  local cwt = canonical_wt(wt)
  if cwt == M.WIRE_ARRAY then
    local akey, err = array_shape_key(val)
    if err then
      return nil, err
    end
    return "A:" .. akey, nil
  elseif cwt == M.WIRE_MAP then
    return str_format("M:%d:%d", canonical_wt(val.key_wire_type), canonical_wt(val.val_wire_type)), nil
  end
  return tostring(cwt), nil
end

--- Decodes all fields in buf[start_pos..end_pos].
--- Returns (fields_list, merged_schema_meta, nil) or (nil, nil, err_msg).
decode_message_fields = function(buf, start_pos, end_pos, depth, max_depth)
  local fields = {}
  local seen_shapes = {}
  local merged_meta = nil
  local pos = start_pos
  local idx = 0

  while pos <= end_pos do
    local field_start = pos
    local fnum, wt, after_tag = M.decode_tag(buf, pos, end_pos)
    if fnum == nil then
      return nil, nil, after_tag
    end

    if fnum == 0 then
      -- Field #0 (SchemaMeta)
      if depth + 1 > max_depth then
        return nil, nil, str_format("Field #0 nesting depth %d exceeds limit %d", depth + 1, max_depth)
      end
      local body_start, body_end, next_pos = read_len_range(buf, after_tag, end_pos, 0)
      if body_start == nil then
        return nil, nil, next_pos
      end
      local meta, err = M.decode_schema_meta(buf, body_start, body_end, depth + 1, max_depth)
      if err then
        return nil, nil, err
      end
      merged_meta = M.merge_schema_meta(merged_meta, meta)
      idx = idx + 1
      fields[idx] = {
        field_num = 0,
        wire_type = wt,
        start_pos = field_start,
        end_pos = next_pos - 1,
        value = {
          kind = "schema_meta",
          body_start = body_start,
          body_end = body_end,
          meta = meta,
        },
      }
      pos = next_pos
    else
      local val, next_pos, err = decode_value(buf, after_tag, end_pos, wt, depth, max_depth, false)
      if err then
        return nil, nil, err
      end
      local shape, serr = field_shape_key(wt, val)
      if serr then
        return nil, nil, serr
      end
      if seen_shapes[fnum] ~= nil and seen_shapes[fnum] ~= shape then
        return nil, nil, str_format("field #%d shape mismatch (%s vs %s)", fnum, seen_shapes[fnum], shape)
      end
      seen_shapes[fnum] = shape
      idx = idx + 1
      fields[idx] = {
        field_num = fnum,
        wire_type = wt,
        start_pos = field_start,
        end_pos = next_pos - 1,
        value = val,
      }
      pos = next_pos
    end
  end

  if merged_meta and merged_meta.fields then
    local used_names = {}
    for fnum, fname in pairs(merged_meta.fields) do
      if fname ~= "" then
        if used_names[fname] ~= nil and used_names[fname] ~= fnum then
          return nil, nil, str_format("Field #0 duplicate field name %q for #%d and #%d", fname, used_names[fname], fnum)
        end
        used_names[fname] = fnum
      end
    end
  end

  return fields, merged_meta, nil
end

--- Decodes a full OmniBuf message from buf[start_pos..end_pos].
--- Returns (result_table, nil) or (nil, err_msg).
function M.decode_message(buf, start_pos, end_pos, opts)
  start_pos = start_pos or 1
  end_pos = end_pos or #buf
  local max_depth = (opts and opts.max_depth) or M.MAX_CONTAINER_DEPTH
  local fields, schema_meta, err = decode_message_fields(buf, start_pos, end_pos, 0, max_depth)
  if err then
    return nil, err
  end
  return {
    fields = fields,
    schema_meta = schema_meta,
  }, nil
end

--- Cursor/iterator over an OmniBuf message byte string.
--- Yields (field_num, wire_type, start_pos, end_pos, value) for each field.
--- Raises an error if malformed wire bytes are encountered during iteration.
function M.fields(buf, start_pos, end_pos, opts)
  local pos = start_pos or 1
  local limit = end_pos or #buf
  local depth = (opts and opts.depth) or 0
  local max_depth = (opts and opts.max_depth) or M.MAX_CONTAINER_DEPTH

  return function()
    if pos > limit then
      return nil
    end
    local field_start = pos
    local fnum, wt, after_tag = M.decode_tag(buf, pos, limit)
    if fnum == nil then
      error("omnibuf: " .. tostring(after_tag), 2)
    end

    if fnum == 0 then
      if depth + 1 > max_depth then
        error(str_format("omnibuf: Field #0 nesting depth %d exceeds limit %d", depth + 1, max_depth), 2)
      end
      local body_start, body_end, next_pos = read_len_range(buf, after_tag, limit, 0)
      if body_start == nil then
        error("omnibuf: " .. tostring(next_pos), 2)
      end
      local meta, err = M.decode_schema_meta(buf, body_start, body_end, depth + 1, max_depth)
      if err then
        error("omnibuf: " .. tostring(err), 2)
      end
      pos = next_pos
      return 0, wt, field_start, next_pos - 1, {
        kind = "schema_meta",
        body_start = body_start,
        body_end = body_end,
        meta = meta,
      }
    end

    local val, next_pos, err = decode_value(buf, after_tag, limit, wt, depth, max_depth, false)
    if err then
      error("omnibuf: " .. tostring(err), 2)
    end
    pos = next_pos
    return fnum, wt, field_start, next_pos - 1, val
  end
end

--- Decodes a 5-byte Connect/gRPC length-prefixed framing envelope stream.
--- Format per frame: [1-byte flags][4-byte big-endian length][payload].
--- Returns (frames, nil) or (nil, err_msg).
function M.decode_envelope_frames(buf, start_pos, end_pos)
  start_pos = start_pos or 1
  end_pos = end_pos or #buf
  local pos = start_pos
  local frames = {}
  local idx = 0

  while pos <= end_pos do
    if pos + 4 > end_pos then
      return nil, str_format("truncated 5-byte envelope header at offset %d", pos - 1)
    end
    local flags, payload_len = str_unpack(">BI4", buf, pos)
    local payload_start = pos + 5
    local payload_end = payload_start + payload_len - 1
    if payload_end > end_pos then
      return nil, str_format("truncated envelope payload (need %d bytes, have %d) at offset %d", payload_len, end_pos - payload_start + 1, pos - 1)
    end
    idx = idx + 1
    frames[idx] = {
      flags = flags,
      compressed = (flags & 0x01) ~= 0,
      end_stream = (flags & 0x02) ~= 0,
      length = payload_len,
      header_start = pos,
      header_end = pos + 4,
      payload_start = payload_start,
      payload_end = payload_end,
      payload = str_sub(buf, payload_start, payload_end),
    }
    pos = payload_end + 1
  end

  return frames, nil
end

--- Minimal, dependency-free JSON parser (RFC 8259) for schema overlay files.
local function parse_json(str)
  local pos = 1
  local len = #str

  local function skip_ws()
    while pos <= len do
      local c = str_byte(str, pos)
      if c == 32 or c == 9 or c == 10 or c == 13 then
        pos = pos + 1
      else
        break
      end
    end
  end

  local parse_value

  local function parse_string()
    pos = pos + 1 -- skip opening '"'
    local parts = {}
    local n = 0
    while pos <= len do
      local c = str_byte(str, pos)
      if c == 34 then -- '"'
        pos = pos + 1
        return table.concat(parts)
      elseif c == 92 then -- '\'
        pos = pos + 1
        local esc = str_byte(str, pos)
        if esc == 34 then n = n + 1; parts[n] = '"'
        elseif esc == 92 then n = n + 1; parts[n] = '\\'
        elseif esc == 47 then n = n + 1; parts[n] = '/'
        elseif esc == 98 then n = n + 1; parts[n] = '\b'
        elseif esc == 102 then n = n + 1; parts[n] = '\f'
        elseif esc == 110 then n = n + 1; parts[n] = '\n'
        elseif esc == 114 then n = n + 1; parts[n] = '\r'
        elseif esc == 116 then n = n + 1; parts[n] = '\t'
        elseif esc == 117 then -- \uXXXX
          local hex = str_sub(str, pos + 1, pos + 4)
          local cp = tonumber(hex, 16)
          if not cp then error("invalid \\u escape") end
          pos = pos + 4
          if cp >= 0xD800 and cp <= 0xDBFF and str_sub(str, pos + 1, pos + 2) == "\\u" then
            local hex2 = str_sub(str, pos + 3, pos + 6)
            local cp2 = tonumber(hex2, 16)
            if cp2 and cp2 >= 0xDC00 and cp2 <= 0xDFFF then
              cp = 0x10000 + ((cp - 0xD800) << 10) + (cp2 - 0xDC00)
              pos = pos + 6
            end
          end
          n = n + 1
          parts[n] = utf8.char(cp)
        else
          error("invalid escape character")
        end
        pos = pos + 1
      else
        local start_p = pos
        while pos <= len do
          local b = str_byte(str, pos)
          if b == 34 or b == 92 then break end
          pos = pos + 1
        end
        n = n + 1
        parts[n] = str_sub(str, start_p, pos - 1)
      end
    end
    error("unterminated string")
  end

  local function parse_number()
    local start_p = pos
    local s = str_sub(str, pos)
    local num_str = s:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*")
    if not num_str then
      error("invalid number at " .. start_p)
    end
    pos = pos + #num_str
    return tonumber(num_str)
  end

  local function parse_array()
    pos = pos + 1 -- skip '['
    local arr = {}
    local idx = 0
    skip_ws()
    if str_byte(str, pos) == 93 then -- ']'
      pos = pos + 1
      return arr
    end
    while true do
      skip_ws()
      idx = idx + 1
      arr[idx] = parse_value()
      skip_ws()
      local c = str_byte(str, pos)
      if c == 93 then
        pos = pos + 1
        return arr
      elseif c == 44 then
        pos = pos + 1
      else
        error("expected ',' or ']' in array at " .. pos)
      end
    end
  end

  local function parse_object()
    pos = pos + 1 -- skip '{'
    local obj = {}
    skip_ws()
    if str_byte(str, pos) == 125 then -- '}'
      pos = pos + 1
      return obj
    end
    while true do
      skip_ws()
      if str_byte(str, pos) ~= 34 then
        error("expected string key at " .. pos)
      end
      local key = parse_string()
      skip_ws()
      if str_byte(str, pos) ~= 58 then
        error("expected ':' at " .. pos)
      end
      pos = pos + 1
      skip_ws()
      obj[key] = parse_value()
      skip_ws()
      local c = str_byte(str, pos)
      if c == 125 then
        pos = pos + 1
        return obj
      elseif c == 44 then
        pos = pos + 1
      else
        error("expected ',' or '}' in object at " .. pos)
      end
    end
  end

  parse_value = function()
    skip_ws()
    local c = str_byte(str, pos)
    if c == 123 then return parse_object()
    elseif c == 91 then return parse_array()
    elseif c == 34 then return parse_string()
    elseif c == 116 and str_sub(str, pos, pos + 3) == "true" then pos = pos + 4; return true
    elseif c == 102 and str_sub(str, pos, pos + 4) == "false" then pos = pos + 5; return false
    elseif c == 110 and str_sub(str, pos, pos + 3) == "null" then pos = pos + 4; return nil
    else return parse_number()
    end
  end

  local ok, res = pcall(parse_value)
  if not ok then
    return nil, res
  end
  return res, nil
end

M.parse_json = parse_json

--- Normalizes either a lightweight OmniBuf JSON schema or a Protobuf
--- FileDescriptorSet JSON (`{ "file": [...] }`) into a fast lookup table:
--- {
---   root = "pkg.Message" or nil,
---   messages = { [full_name] = { [field_num] = { name=..., message=..., enum=... } } },
---   enums = { [full_name] = { [number] = "ENUM_LABEL" } },
--- }
function M.load_schema_from_json(json_str)
  local raw, err = parse_json(json_str)
  if raw == nil then
    return nil, "JSON parse error: " .. tostring(err)
  end

  local schema = {
    root = raw.root,
    messages = {},
    enums = {},
  }

  local function trim_leading_dot(name)
    if type(name) == "string" and str_sub(name, 1, 1) == "." then
      return str_sub(name, 2)
    end
    return name
  end

  -- Format 1: Lightweight OmniBuf JSON schema
  if type(raw.messages) == "table" then
    for msg_name, msg_def in pairs(raw.messages) do
      local ftable = {}
      local src_fields = msg_def.fields or msg_def
      if type(src_fields) == "table" then
        for k, v in pairs(src_fields) do
          local fnum = tonumber(k)
          if fnum then
            if type(v) == "string" then
              ftable[fnum] = { name = v }
            elseif type(v) == "table" then
              ftable[fnum] = {
                name = v.name,
                message = trim_leading_dot(v.message),
                enum = trim_leading_dot(v.enum),
              }
            end
          end
        end
      end
      schema.messages[trim_leading_dot(msg_name)] = ftable
    end
    if type(raw.enums) == "table" then
      for enum_name, enum_def in pairs(raw.enums) do
        local etable = {}
        for k, v in pairs(enum_def) do
          local num = tonumber(k)
          if num and type(v) == "string" then
            etable[num] = v
          end
        end
        schema.enums[trim_leading_dot(enum_name)] = etable
      end
    end
    return schema, nil
  end

  -- Format 2: Protobuf FileDescriptorSet JSON (`buf build -o schema.json`)
  if type(raw.file) == "table" then
    local function index_enum(prefix, enum_desc)
      local full = prefix ~= "" and (prefix .. "." .. enum_desc.name) or enum_desc.name
      local etable = {}
      if type(enum_desc.value) == "table" then
        for _, v in ipairs(enum_desc.value) do
          if v.number ~= nil and v.name then
            etable[tonumber(v.number)] = v.name
          end
        end
      end
      schema.enums[full] = etable
    end

    local function index_message(prefix, msg_desc)
      local full = prefix ~= "" and (prefix .. "." .. msg_desc.name) or msg_desc.name
      local ftable = {}
      if type(msg_desc.field) == "table" then
        for _, f in ipairs(msg_desc.field) do
          local fnum = tonumber(f.number)
          if fnum then
            local entry = { name = f.name }
            local tname = trim_leading_dot(f.typeName or f.type_name)
            local ftype = f.type
            if ftype == "TYPE_MESSAGE" or ftype == 11 then
              entry.message = tname
            elseif ftype == "TYPE_ENUM" or ftype == 14 then
              entry.enum = tname
            end
            ftable[fnum] = entry
          end
        end
      end
      schema.messages[full] = ftable
      if not schema.root then
        schema.root = full
      end
      if type(msg_desc.enumType) == "table" then
        for _, e in ipairs(msg_desc.enumType) do
          index_enum(full, e)
        end
      end
      if type(msg_desc.nestedType) == "table" then
        for _, nested in ipairs(msg_desc.nestedType) do
          index_message(full, nested)
        end
      end
    end

    for _, file_desc in ipairs(raw.file) do
      local pkg = file_desc.package or ""
      if type(file_desc.enumType) == "table" then
        for _, e in ipairs(file_desc.enumType) do
          index_enum(pkg, e)
        end
      end
      if type(file_desc.messageType) == "table" then
        for _, m in ipairs(file_desc.messageType) do
          index_message(pkg, m)
        end
      end
    end
    return schema, nil
  end

  return nil, "unrecognized schema JSON format (expected 'messages' or 'file')"
end

--- Loads a schema JSON file from disk.
function M.load_schema_file(path)
  if not path or path == "" then
    return nil, nil
  end
  local f, err = io.open(path, "rb")
  if not f then
    return nil, err
  end
  local content = f:read("*a")
  f:close()
  return M.load_schema_from_json(content)
end

-- ---------------------------------------------------------------------------
-- Blind JSON serializer (for conformance testing & CLI inspection)
-- ---------------------------------------------------------------------------

local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function base64_encode(data)
  local n = #data
  if n == 0 then
    return ""
  end
  local out = {}
  local idx = 0
  local i = 1
  while i <= n do
    local b1 = str_byte(data, i)
    local b2 = i + 1 <= n and str_byte(data, i + 1) or 0
    local b3 = i + 2 <= n and str_byte(data, i + 2) or 0
    local triple = (b1 << 16) | (b2 << 8) | b3

    idx = idx + 1
    local c1 = ((triple >> 18) & 0x3F) + 1
    local c2 = ((triple >> 12) & 0x3F) + 1
    local c3 = ((triple >> 6) & 0x3F) + 1
    local c4 = (triple & 0x3F) + 1

    local s1 = str_sub(B64_CHARS, c1, c1)
    local s2 = str_sub(B64_CHARS, c2, c2)
    local s3 = (i + 1 <= n) and str_sub(B64_CHARS, c3, c3) or "="
    local s4 = (i + 2 <= n) and str_sub(B64_CHARS, c4, c4) or "="
    out[idx] = s1 .. s2 .. s3 .. s4
    i = i + 3
  end
  return table.concat(out)
end

local function json_escape_string(s)
  local escaped = s:gsub('[%z\1-\31\\"]', function(ch)
    local b = str_byte(ch, 1)
    if b == 34 then return '\\"'
    elseif b == 92 then return '\\\\'
    elseif b == 8 then return '\\b'
    elseif b == 12 then return '\\f'
    elseif b == 10 then return '\\n'
    elseif b == 13 then return '\\r'
    elseif b == 9 then return '\\t'
    else return str_format("\\u%04x", b)
    end
  end)
  return '"' .. escaped .. '"'
end

local function format_float32_json(val)
  if val ~= val then
    return '"NaN"'
  elseif val == math.huge then
    return '"Infinity"'
  elseif val == -math.huge then
    return '"-Infinity"'
  elseif val == 0.0 then
    if 1 / val < 0 then
      return "-0"
    end
    return "0"
  end
  local target = string.pack("<f", val)
  for prec = 1, 9 do
    local cand = str_format("%." .. prec .. "g", val)
    local num = tonumber(cand)
    if num and string.pack("<f", num) == target then
      return cand
    end
  end
  return str_format("%.9g", val)
end

local function format_float64_json(val)
  if val ~= val then
    return '"NaN"'
  elseif val == math.huge then
    return '"Infinity"'
  elseif val == -math.huge then
    return '"-Infinity"'
  elseif val == 0.0 then
    if 1 / val < 0 then
      return "-0"
    end
    return "0"
  end
  local target = string.pack("<d", val)
  for prec = 1, 17 do
    local cand = str_format("%." .. prec .. "g", val)
    local num = tonumber(cand)
    if num and string.pack("<d", num) == target then
      return cand
    end
  end
  return str_format("%.17g", val)
end

local encode_blind_msg_json

local function format_map_key_str(wt, key)
  if wt == M.WIRE_STRING then
    return key
  elseif wt == M.WIRE_UINT or wt == M.WIRE_FIXED32 or wt == M.WIRE_FIXED64 then
    return M.format_uint64(key)
  elseif wt == M.WIRE_SINT or wt == M.WIRE_SFIXED32 or wt == M.WIRE_SFIXED64 then
    return str_format("%d", key)
  elseif wt == M.WIRE_BOOL_FALSE or wt == M.WIRE_BOOL_TRUE then
    return key and "true" or "false"
  end
  return tostring(key)
end

local function encode_blind_value_json(wt, val, child_meta)
  if wt == M.WIRE_UINT or wt == M.WIRE_FIXED32 or wt == M.WIRE_FIXED64 then
    return M.format_uint64(val)
  elseif wt == M.WIRE_SINT or wt == M.WIRE_SFIXED32 or wt == M.WIRE_SFIXED64 then
    return str_format("%d", val)
  elseif wt == M.WIRE_BOOL_FALSE or wt == M.WIRE_BOOL_TRUE then
    return val and "true" or "false"
  elseif wt == M.WIRE_FLOAT32 then
    return format_float32_json(val)
  elseif wt == M.WIRE_FLOAT64 then
    return format_float64_json(val)
  elseif wt == M.WIRE_STRING then
    return json_escape_string(val)
  elseif wt == M.WIRE_BYTES then
    return json_escape_string(base64_encode(val))
  elseif wt == M.WIRE_SUB_MSG then
    return encode_blind_msg_json(val.fields, M.merge_schema_meta(child_meta, val.schema_meta))
  elseif wt == M.WIRE_ARRAY then
    local parts = {}
    for i, item in ipairs(val.items) do
      parts[i] = encode_blind_value_json(val.elem_wire_type, item.value, child_meta)
    end
    return "[" .. table.concat(parts, ",") .. "]"
  elseif wt == M.WIRE_MAP then
    local entries_by_key = {}
    local keys = {}
    for _, entry in ipairs(val.entries) do
      local ks = format_map_key_str(val.key_wire_type, entry.key)
      if entries_by_key[ks] == nil then
        keys[#keys + 1] = ks
      end
      entries_by_key[ks] = encode_blind_value_json(val.val_wire_type, entry.value, child_meta)
    end
    table.sort(keys)
    local parts = {}
    for i, ks in ipairs(keys) do
      parts[i] = json_escape_string(ks) .. ":" .. entries_by_key[ks]
    end
    return "{" .. table.concat(parts, ",") .. "}"
  elseif wt == M.WIRE_EXTENDED then
    return str_format('{"subtype":%d,"payload":%s}', val.subtype, json_escape_string(base64_encode(val.payload)))
  end
  return "null"
end

local function merge_submsgs(a, b)
  local merged_fields = {}
  local idx = 0
  for _, f in ipairs(a.fields) do
    idx = idx + 1
    merged_fields[idx] = f
  end
  for _, f in ipairs(b.fields) do
    idx = idx + 1
    merged_fields[idx] = f
  end
  return {
    kind = "submsg",
    fields = merged_fields,
    schema_meta = M.merge_schema_meta(a.schema_meta, b.schema_meta),
  }
end

local function merge_arrays(a, b)
  local merged_items = {}
  local idx = 0
  for _, it in ipairs(a.items) do
    idx = idx + 1
    merged_items[idx] = it
  end
  for _, it in ipairs(b.items) do
    idx = idx + 1
    merged_items[idx] = it
  end
  return {
    kind = "array",
    elem_wire_type = a.elem_wire_type,
    count = idx,
    items = merged_items,
  }
end

local function merge_maps(a, b)
  local merged_entries = {}
  local idx = 0
  for _, en in ipairs(a.entries) do
    idx = idx + 1
    merged_entries[idx] = en
  end
  for _, en in ipairs(b.entries) do
    idx = idx + 1
    merged_entries[idx] = en
  end
  return {
    kind = "map",
    key_wire_type = a.key_wire_type,
    val_wire_type = a.val_wire_type,
    count = idx,
    entries = merged_entries,
  }
end

encode_blind_msg_json = function(fields, schema_meta)
  -- Merge repeated occurrences of the same field number according to OmniBuf concat rules.
  local by_num = {}
  local order = {}
  for _, f in ipairs(fields) do
    if f.field_num ~= 0 then
      local existing = by_num[f.field_num]
      if existing == nil then
        order[#order + 1] = f.field_num
        by_num[f.field_num] = { wire_type = f.wire_type, value = f.value }
      else
        if f.wire_type == M.WIRE_SUB_MSG then
          existing.value = merge_submsgs(existing.value, f.value)
        elseif f.wire_type == M.WIRE_ARRAY then
          existing.value = merge_arrays(existing.value, f.value)
        elseif f.wire_type == M.WIRE_MAP then
          existing.value = merge_maps(existing.value, f.value)
        else
          existing.wire_type = f.wire_type
          existing.value = f.value
        end
      end
    end
  end

  local entries = {}
  for _, fnum in ipairs(order) do
    local raw_name = schema_meta and schema_meta.fields and schema_meta.fields[fnum] or nil
    local fname = (raw_name and raw_name ~= "") and raw_name or ("field_" .. tostring(fnum))
    local child_meta = schema_meta and schema_meta.children and schema_meta.children[fnum] or nil
    local rec = by_num[fnum]
    entries[#entries + 1] = {
      key = fname,
      json_val = encode_blind_value_json(rec.wire_type, rec.value, child_meta),
    }
  end
  table.sort(entries, function(a, b) return a.key < b.key end)

  local parts = {}
  for i, e in ipairs(entries) do
    parts[i] = json_escape_string(e.key) .. ":" .. e.json_val
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

--- Decodes an OmniBuf packet without a schema and serializes it to canonical blind JSON.
--- Returns (json_str, nil) on success, or (nil, err_msg) on decode error.
function M.decode_blind_json(buf, start_pos, end_pos, opts)
  local decoded, err = M.decode_message(buf, start_pos, end_pos, opts)
  if err then
    return nil, err
  end
  return encode_blind_msg_json(decoded.fields, decoded.schema_meta), nil
end

--- Encodes an unsigned 64-bit integer as an OmniBuf Prefix-Varint byte string.
function M.encode_varint(v)
  if not math_ult(127, v) then
    return string.char((v << 1) | 1)
  elseif not math_ult(16383, v) then
    return string.pack("<I2", (v << 2) | 2)
  elseif not math_ult(536870911, v) then
    return string.pack("<I4", (v << 3) | 4)
  else
    return string.pack("<BI8", 0, v)
  end
end

--- Encodes a single WireString field (used by conformance.lua).
function M.encode_string_field(field_num, str)
  return M.encode_varint((field_num << 4) | M.WIRE_STRING) .. M.encode_varint(#str) .. str
end

return M
