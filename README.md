# omnibuf-wireshark

Wireshark, `tshark`, and `termshark` Lua 5.4 dissector for the OmniBuf wire format.

## Features

- **Zero-dependency Lua 5.4 core (`omnibuf_wire.lua`)**: Decoupled from Wireshark's API so unit tests and cross-language conformance vectors run directly with `lua`.
- **Exact hex-pane highlighting**: Maps 1-based cursor offsets to 0-based Wireshark `tvb` ranges for every field, nested sub-message, array element, and map entry.
- **Transport and framing support**:
  - Automatic media-type registration for `application/omnibuf`, `application/x-omnibuf`, `application/connect+omnibuf`, `application/connect+x-omnibuf`, `application/grpc+omnibuf`, and `application/grpc+x-omnibuf`.
  - Frame-by-frame dissection of 5-byte Connect/gRPC length-prefixed streaming envelopes (`[1B flags][4B big-endian length]`).
  - `Decode As...` registration for raw TCP (with `DESEGMENT_ONE_MORE_SEGMENT` reassembly) and UDP.
- **Schema resolution**: Reads inline `Field #0` (`SchemaMeta`) automatically and supports an optional `omnibuf.schema_path` preference pointing to a lightweight JSON schema or a Protobuf `FileDescriptorSet` JSON (`buf build -o schema.json`).

## Installation

### Zero-install one-off runs (`tshark`)

```sh
tshark -X lua_script:omnibuf.lua -r capture.pcapng -Y omnibuf -V
```

With a schema overlay:

```sh
tshark -X lua_script:omnibuf.lua \
  -o omnibuf.schema_path:schema.json \
  -r capture.pcapng -Y omnibuf -V
```

### Personal plugin directory (Wireshark, `tshark`, and `termshark`)

Install both `omnibuf.lua` and `omnibuf_wire.lua` into your personal Wireshark plugins directory (`~/.local/lib/wireshark/plugins/` on macOS and Linux, `%APPDATA%\Wireshark\plugins\` on Windows):

```sh
# macOS & Linux
curl -fsSL https://raw.githubusercontent.com/omnibuf/omnibuf-wireshark/main/install.sh | sh
```

Windows PowerShell:

```powershell
$d = "$env:APPDATA\Wireshark\plugins"; New-Item -ItemType Directory -Force $d | Out-Null
irm https://raw.githubusercontent.com/omnibuf/omnibuf-wireshark/main/omnibuf.lua -OutFile "$d\omnibuf.lua"
irm https://raw.githubusercontent.com/omnibuf/omnibuf-wireshark/main/omnibuf_wire.lua -OutFile "$d\omnibuf_wire.lua"
```

Once installed in the personal plugins folder, Wireshark, `tshark`, and `termshark` load the dissector automatically without `-X lua_script`.

## Display Filters

| Filter | Description |
| --- | --- |
| `omnibuf` | Any packet containing an OmniBuf payload |
| `omnibuf.field_num == 5` | Packets containing field `#5` |
| `omnibuf.field_name == "router"` | Packets with a resolved field named `router` |
| `omnibuf.wire_type == 12` | Packets containing a `WireSubMsg` field |
| `omnibuf.string contains "FRA"` | Packets with a string value matching `FRA` |
| `omnibuf.enum == "PEER_STATE_ESTABLISHED"` | Packets matching an enum label |

## Piping `tshark` JSON into `jq`

```sh
tshark -X lua_script:omnibuf.lua -r fixtures/connect_stream.pcapng -Y omnibuf -T json --no-duplicate-keys \
  | jq '.[]._source.layers.omnibuf'
```

## Running Tests

```sh
lua test_wire.lua
python3 tests/test_tshark.py

# Cross-language TIER_BLIND conformance runner (from omnibuf-go)
../omnibuf-go/bin/conformance-runner -tier blind lua conformance.lua
```
