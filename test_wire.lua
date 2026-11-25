-- test_wire.lua
-- Unit tests and conformance runner for omnibuf_wire.lua using standard Lua 5.4.
-- Run: lua test_wire.lua [path/to/conformance_corpus.json]

local wire = dofile("omnibuf_wire.lua")

local passed = 0
local failed = 0

local function assert_eq(actual, expected, label)
  if actual ~= expected then
    failed = failed + 1
    io.stderr:write(string.format("FAIL [%s]: expected %s, got %s\n", label, tostring(expected), tostring(actual)))
  else
    passed = passed + 1
  end
end

local function assert_true(cond, label)
  if not cond then
    failed = failed + 1
    io.stderr:write(string.format("FAIL [%s]: condition was false\n", label))
  else
    passed = passed + 1
  end
end

local function hex_to_bytes(hex)
  return (hex:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

-- 1. Cursor iterator & byte-range unit tests
do
  -- field #1 WireUint = 42 -> tag (1<<4)|0 = 16 -> varint (16<<1)|1 = 0x21; val 42 -> (42<<1)|1 = 0x55
  -- field #2 WireBoolTrue -> tag (2<<4)|3 = 35 -> varint (35<<1)|1 = 0x47
  -- field #3 WireString = "FRA" -> tag (3<<4)|10 = 58 -> varint (58<<1)|1 = 0x75; len 3 -> 0x07; "FRA"
  local pkt = hex_to_bytes("2155477507465241")
  local seen = {}
  for fnum, wt, s, e, val in wire.fields(pkt) do
    seen[#seen + 1] = { fnum = fnum, wt = wt, s = s, e = e, val = val }
  end
  assert_eq(#seen, 3, "cursor field count")
  assert_eq(seen[1].fnum, 1, "field 1 num")
  assert_eq(seen[1].wt, wire.WIRE_UINT, "field 1 wt")
  assert_eq(seen[1].s, 1, "field 1 start")
  assert_eq(seen[1].e, 2, "field 1 end")
  assert_eq(seen[1].val, 42, "field 1 val")

  assert_eq(seen[2].fnum, 2, "field 2 num")
  assert_eq(seen[2].wt, wire.WIRE_BOOL_TRUE, "field 2 wt")
  assert_eq(seen[2].s, 3, "field 2 start")
  assert_eq(seen[2].e, 3, "field 2 end")
  assert_eq(seen[2].val, true, "field 2 val")

  assert_eq(seen[3].fnum, 3, "field 3 num")
  assert_eq(seen[3].wt, wire.WIRE_STRING, "field 3 wt")
  assert_eq(seen[3].s, 4, "field 3 start")
  assert_eq(seen[3].e, 8, "field 3 end")
  assert_eq(seen[3].val, "FRA", "field 3 val")
end

-- 2. Unsigned 64-bit formatting (UINT64_MAX)
do
  -- field #1 WireUint = 0xFFFFFFFFFFFFFFFF -> tag 0x21, varint 0x00 + 8x0xFF
  local pkt = hex_to_bytes("2100ffffffffffffffff")
  for fnum, wt, s, e, val in wire.fields(pkt) do
    assert_eq(fnum, 1, "uint64_max fnum")
    assert_eq(wt, wire.WIRE_UINT, "uint64_max wt")
    assert_eq(s, 1, "uint64_max start")
    assert_eq(e, 10, "uint64_max end")
    assert_eq(wire.format_uint64(val), "18446744073709551615", "uint64_max format")
  end
end

-- 3. 5-byte Connect/gRPC envelope framing
do
  local msg1 = hex_to_bytes("2155")
  local msg2 = hex_to_bytes("47")
  local stream = string.pack(">BI4", 0, #msg1) .. msg1 .. string.pack(">BI4", 2, #msg2) .. msg2
  local frames, err = wire.decode_envelope_frames(stream)
  assert_eq(err, nil, "envelope no error")
  assert_eq(#frames, 2, "envelope frame count")
  assert_eq(frames[1].flags, 0, "frame 1 flags")
  assert_eq(frames[1].length, 2, "frame 1 length")
  assert_eq(frames[1].payload, msg1, "frame 1 payload")
  assert_eq(frames[2].flags, 2, "frame 2 flags")
  assert_eq(frames[2].end_stream, true, "frame 2 end_stream")
end

-- 4. Schema overlay parsing (lightweight JSON & FileDescriptorSet JSON)
do
  local light = [[{
    "root": "demo.v1.PeerUpdate",
    "messages": {
      "demo.v1.PeerUpdate": {
        "fields": {
          "1": { "name": "router", "type": "string" },
          "2": { "name": "state", "enum": "demo.v1.PeerState" }
        }
      }
    },
    "enums": {
      "demo.v1.PeerState": { "1": "ESTABLISHED" }
    }
  }]]
  local s, err = wire.load_schema_from_json(light)
  assert_eq(err, nil, "lightweight schema load")
  assert_eq(s.root, "demo.v1.PeerUpdate", "lightweight schema root")
  assert_eq(s.messages["demo.v1.PeerUpdate"][1].name, "router", "lightweight field 1")
  assert_eq(s.enums["demo.v1.PeerState"][1], "ESTABLISHED", "lightweight enum 1")

  local fds = [[{
    "file": [{
      "package": "demo.v1",
      "enumType": [{ "name": "PeerState", "value": [{ "name": "ESTABLISHED", "number": 1 }] }],
      "messageType": [{
        "name": "PeerUpdate",
        "field": [
          { "name": "router", "number": 1, "type": "TYPE_STRING" },
          { "name": "state", "number": 2, "type": "TYPE_ENUM", "typeName": ".demo.v1.PeerState" }
        ]
      }]
    }]
  }]]
  local s2, err2 = wire.load_schema_from_json(fds)
  assert_eq(err2, nil, "fds schema load")
  assert_eq(s2.root, "demo.v1.PeerUpdate", "fds schema root")
  assert_eq(s2.messages["demo.v1.PeerUpdate"][2].enum, "demo.v1.PeerState", "fds enum ref")
  assert_eq(s2.enums["demo.v1.PeerState"][1], "ESTABLISHED", "fds enum val")
end

-- Deep equality helper for comparing parsed blind JSON against expected_blind.
local function deep_equal(a, b, path)
  path = path or "$"
  local ta, tb = type(a), type(b)
  if ta ~= tb then
    return false, string.format("%s: type mismatch (%s vs %s)", path, ta, tb)
  end
  if ta == "number" then
    if a == b then
      return true
    end
    -- Allow minor float representation tolerance for JSON-parsed doubles
    if math.abs(a - b) <= 1e-12 * math.max(1.0, math.abs(a), math.abs(b)) then
      return true
    end
    return false, string.format("%s: expected %s, got %s", path, tostring(b), tostring(a))
  elseif ta == "table" then
    for k, v in pairs(b) do
      local ok, err = deep_equal(a[k], v, path .. "." .. tostring(k))
      if not ok then
        return false, err
      end
    end
    for k, _ in pairs(a) do
      if b[k] == nil then
        return false, string.format("%s.%s: unexpected key", path, tostring(k))
      end
    end
    return true
  else
    if a ~= b then
      return false, string.format("%s: expected %s, got %s", path, tostring(b), tostring(a))
    end
    return true
  end
end

-- 5. Cross-language conformance corpus verification (structure + deep expected_blind)
local corpus_path = arg[1] or "../omnibuf-go/testdata/conformance_corpus.json"
local f = io.open(corpus_path, "rb")
if f then
  local raw_json = f:read("*a")
  f:close()
  local corpus, jerr = wire.parse_json(raw_json)
  assert_eq(jerr, nil, "parse conformance_corpus.json")

  local valid_ok = 0
  local valid_total = 0
  for _, vec in ipairs(corpus.valid_vectors) do
    if not vec.skip_blind then
      valid_total = valid_total + 1
      local bytes = hex_to_bytes(vec.wire_hex)
      local blind_json, err = wire.decode_blind_json(bytes)
      if err then
        failed = failed + 1
        io.stderr:write(string.format("FAIL valid vector [%s]: %s\n", vec.name, tostring(err)))
      elseif vec.expected_blind ~= nil then
        local got_obj, perr = wire.parse_json(blind_json)
        if perr then
          failed = failed + 1
          io.stderr:write(string.format("FAIL valid vector [%s] JSON parse: %s\n", vec.name, tostring(perr)))
        else
          local eq, diff = deep_equal(got_obj, vec.expected_blind)
          if not eq then
            failed = failed + 1
            io.stderr:write(string.format("FAIL valid vector [%s] expected_blind mismatch: %s\n  got: %s\n", vec.name, diff, blind_json))
          else
            valid_ok = valid_ok + 1
            passed = passed + 1
          end
        end
      else
        valid_ok = valid_ok + 1
        passed = passed + 1
      end
    end
  end

  local invalid_ok = 0
  for _, vec in ipairs(corpus.invalid_cases) do
    local bytes = hex_to_bytes(vec.wire_hex)
    local msg, err = wire.decode_message(bytes)
    if err == nil then
      failed = failed + 1
      io.stderr:write(string.format("FAIL invalid case [%s] (%s): expected error, decoded %d fields\n", vec.name, vec.category, #msg.fields))
    else
      invalid_ok = invalid_ok + 1
      passed = passed + 1
    end
  end

  print(string.format("Conformance corpus: %d/%d valid passed (deep expected_blind), %d/%d invalid rejected",
    valid_ok, valid_total, invalid_ok, #corpus.invalid_cases))
else
  print("Skipping conformance corpus (not found at " .. corpus_path .. ")")
end

print(string.format("Total assertions: %d passed, %d failed", passed, failed))
if failed > 0 then
  os.exit(1)
end
