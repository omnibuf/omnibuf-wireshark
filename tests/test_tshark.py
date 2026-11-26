#!/usr/bin/env python3
"""Automated tshark regression tests for omnibuf.lua against .pcapng fixtures."""

from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "omnibuf.lua"
FIXTURES = ROOT / "fixtures"
sys.path.insert(0, str(ROOT / "scripts"))
import generate_fixtures as gf


def run_tshark(*args: str) -> str:
    cmd = ["tshark", "-X", f"lua_script:{PLUGIN}", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise AssertionError(
            f"tshark failed ({proc.returncode}): {' '.join(cmd)}\nSTDERR:\n{proc.stderr}"
        )
    return proc.stdout


def test_unary_http2() -> None:
    out = run_tshark(
        "-d", "tcp.port==8080,http2",
        "-r", str(FIXTURES / "unary_http2.pcapng"),
        "-Y", "omnibuf",
        "-V",
    )
    assert "OmniBuf (" in out, f"expected OmniBuf tree in HTTP/2 output:\n{out}"
    assert '#1: "fra-core-01"' in out, out
    assert '#1: "ams-edge-04"' in out, out
    assert "#3: -2" in out, out
    assert "#4: true" in out, out
    assert '#1: "FRA"' in out, out


def test_connect_stream() -> None:
    out = run_tshark(
        "-r", str(FIXTURES / "connect_stream.pcapng"),
        "-Y", "omnibuf",
        "-V",
    )
    assert "Frame #1 (flags=0x00" in out, out
    assert "Frame #2 (flags=0x00" in out, out
    assert "Frame #3 (flags=0x02, 2B, end-stream)" in out, out
    assert '#1: "fra-core-01"' in out, out
    assert '#1: "ams-edge-04"' in out, out


def test_raw_tcp_reassembly_and_schema_overlay() -> None:
    out = run_tshark(
        "-d", "tcp.port==9090,omnibuf",
        "-o", f"omnibuf.schema_path:{FIXTURES / 'schema.json'}",
        "-r", str(FIXTURES / "raw_tcp.pcapng"),
        "-Y", "omnibuf",
        "-V",
    )
    assert "2 Reassembled TCP Segments" in out, out
    assert "[Message Type: demo.v1.PeerUpdate]" in out, out
    assert '#1 router: "fra-core-01"' in out, out
    assert "#2 state: PEER_STATE_ESTABLISHED (1)" in out, out
    assert "#5 location: demo.v1.Location {1 field}" in out, out
    assert '#1 city: "FRA"' in out, out


def test_tshark_json_for_jq() -> None:
    raw_json = run_tshark(
        "-d", "tcp.port==9090,omnibuf",
        "-o", f"omnibuf.schema_path:{FIXTURES / 'schema.json'}",
        "-r", str(FIXTURES / "raw_tcp.pcapng"),
        "-Y", "omnibuf",
        "-T", "json",
        "--no-duplicate-keys",
    )
    packets = json.loads(raw_json)
    assert len(packets) == 1, f"expected 1 reassembled packet, got {len(packets)}"
    layers = packets[0]["_source"]["layers"]
    assert "omnibuf" in layers, f"missing omnibuf layer in JSON: {list(layers.keys())}"
    omnibuf_layer = json.dumps(layers["omnibuf"])
    assert "demo.v1.PeerUpdate" in omnibuf_layer
    assert "PEER_STATE_ESTABLISHED" in omnibuf_layer
    assert "fra-core-01" in omnibuf_layer
    assert "FRA" in omnibuf_layer


def _encode_bytes_field(fnum: int, raw: bytes) -> bytes:
    return gf._encode_tag(fnum, 11) + gf._encode_varint(len(raw)) + raw


def _encode_len_prefixed(raw: bytes) -> bytes:
    return gf._encode_varint(len(raw)) + raw


def _encode_array_field(fnum: int, elem_wt: int, items: list[bytes]) -> bytes:
    body = bytes([elem_wt]) + gf._encode_varint(len(items)) + b"".join(items)
    return gf._encode_tag(fnum, 13) + gf._encode_varint(len(body)) + body


def _encode_map_field(
    fnum: int, key_wt: int, val_wt: int, entries: list[tuple[bytes, bytes]]
) -> bytes:
    body = bytearray([key_wt, val_wt])
    body.extend(gf._encode_varint(len(entries)))
    for k_raw, v_raw in entries:
        body.extend(k_raw)
        body.extend(v_raw)
    return gf._encode_tag(fnum, 14) + gf._encode_varint(len(body)) + bytes(body)


def _build_editions_record_bytes() -> bytes:
    child_delim = gf._encode_sint_field(1, 42) + gf._encode_string_field(2, "delim")
    child_list_item = gf._encode_sint_field(1, 1) + gf._encode_string_field(2, "first")
    child_map_val = gf._encode_sint_field(1, 7) + gf._encode_string_field(2, "edge")
    return b"".join(
        [
            gf._encode_sint_field(1, 0),
            gf._encode_bool_field(2, False),
            gf._encode_string_field(3, ""),
            _encode_bytes_field(4, b""),
            gf._encode_uint_field(5, 0),
            gf._encode_uint_field(6, 99),
            gf._encode_submsg_field(7, child_delim),
            _encode_array_field(8, 12, [_encode_len_prefixed(child_list_item)]),
            _encode_map_field(
                9,
                10,
                12,
                [(_encode_len_prefixed(b"primary"), _encode_len_prefixed(child_map_val))],
            ),
            _encode_map_field(
                10,
                10,
                0,
                [
                    (_encode_len_prefixed(b"init"), gf._encode_varint(0)),
                    (_encode_len_prefixed(b"ready"), gf._encode_varint(1)),
                    (_encode_len_prefixed(b"future"), gf._encode_varint(99)),
                ],
            ),
        ]
    )


def _build_editions_fds_json(
    edition_val: str,
    pkg: str,
    *,
    snake_case: bool,
    delimited_type: str | int,
    msg_type: str | int = "TYPE_MESSAGE",
    enum_type: str | int = "TYPE_ENUM",
) -> str:
    k_msg = "message_type" if snake_case else "messageType"
    k_enum = "enum_type" if snake_case else "enumType"
    k_nested = "nested_type" if snake_case else "nestedType"
    k_tname = "type_name" if snake_case else "typeName"
    k_map_entry = "map_entry" if snake_case else "mapEntry"

    return json.dumps(
        {
            "file": [
                {
                    "name": "google/protobuf/descriptor.proto",
                    "package": "google.protobuf",
                    "syntax": "proto2",
                    k_msg: [{"name": "FileDescriptorSet", "field": []}],
                },
                {
                    "name": f"{pkg}.proto",
                    "package": pkg,
                    "syntax": "editions",
                    "edition": edition_val,
                    k_enum: [
                        {
                            "name": "OpenStatus",
                            "value": [
                                {"name": "OPEN_STATUS_UNSPECIFIED", "number": 0},
                                {"name": "OPEN_STATUS_READY", "number": 1},
                            ],
                        }
                    ],
                    k_msg: [
                        {
                            "name": "Record",
                            "field": [
                                {"name": "exp_i32", "number": 1, "type": "TYPE_SINT32"},
                                {"name": "exp_bool", "number": 2, "type": "TYPE_BOOL"},
                                {"name": "exp_str", "number": 3, "type": "TYPE_STRING"},
                                {"name": "exp_bytes", "number": 4, "type": "TYPE_BYTES"},
                                {
                                    "name": "exp_enum",
                                    "number": 5,
                                    "type": enum_type,
                                    k_tname: f".{pkg}.OpenStatus",
                                },
                                {
                                    "name": "unknown_enum",
                                    "number": 6,
                                    "type": enum_type,
                                    k_tname: f".{pkg}.OpenStatus",
                                },
                                {
                                    "name": "delim_child",
                                    "number": 7,
                                    "type": delimited_type,
                                    k_tname: f".{pkg}.Child",
                                },
                                {
                                    "name": "delim_list",
                                    "number": 8,
                                    "type": delimited_type,
                                    k_tname: f".{pkg}.Child",
                                },
                                {
                                    "name": "children_by_key",
                                    "number": 9,
                                    "type": msg_type,
                                    k_tname: f".{pkg}.Record.ChildrenByKeyEntry",
                                },
                                {
                                    "name": "statuses",
                                    "number": 10,
                                    "type": msg_type,
                                    k_tname: f".{pkg}.Record.StatusesEntry",
                                },
                            ],
                            k_nested: [
                                {
                                    "name": "ChildrenByKeyEntry",
                                    "field": [
                                        {"name": "key", "number": 1, "type": "TYPE_STRING"},
                                        {
                                            "name": "value",
                                            "number": 2,
                                            "type": msg_type,
                                            k_tname: f".{pkg}.Child",
                                        },
                                    ],
                                    "options": {k_map_entry: True},
                                },
                                {
                                    "name": "StatusesEntry",
                                    "field": [
                                        {"name": "key", "number": 1, "type": "TYPE_STRING"},
                                        {
                                            "name": "value",
                                            "number": 2,
                                            "type": enum_type,
                                            k_tname: f".{pkg}.OpenStatus",
                                        },
                                    ],
                                    "options": {k_map_entry: True},
                                },
                            ],
                        },
                        {
                            "name": "Child",
                            "field": [
                                {"name": "id", "number": 1, "type": "TYPE_SINT32"},
                                {"name": "label", "number": 2, "type": "TYPE_STRING"},
                            ],
                        },
                    ],
                },
            ]
        }
    )


def _assert_tshark_editions_output(out: str, pkg: str) -> None:
    assert f"[Message Type: {pkg}.Record]" in out, out
    assert "#1 exp_i32: 0" in out, out
    assert "#2 exp_bool: false" in out, out
    assert '#3 exp_str: ""' in out, out
    assert "#4 exp_bytes: 0x (0B)" in out, out
    assert "#5 exp_enum: OPEN_STATUS_UNSPECIFIED (0)" in out, out
    assert "#6 unknown_enum: 99" in out, out
    assert f"#7 delim_child: {pkg}.Child {{2 fields}}" in out, out
    assert "#1 id: 42" in out, out
    assert '#2 label: "delim"' in out, out
    assert f"[0]: {pkg}.Child {{2 fields}}" in out, out
    assert '#2 label: "first"' in out, out
    assert f'"primary": {pkg}.Child {{2 fields}}' in out, out
    assert "#1 id: 7" in out, out
    assert '#2 label: "edge"' in out, out
    assert '"init": OPEN_STATUS_UNSPECIFIED (0)' in out, out
    assert '"ready": OPEN_STATUS_READY (1)' in out, out
    assert '"future": 99' in out, out


def _semver_key(path: Path) -> tuple[int, ...]:
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", str(path))
    if not m:
        return (0, 0, 0)
    return tuple(int(p) for p in m.groups())


def _find_buf_bin() -> str | None:
    found = shutil.which("buf")
    if found:
        probe = subprocess.run([found, "--version"], capture_output=True, text=True, check=False)
        if probe.returncode == 0:
            return found
    mise_root = Path.home() / ".local" / "share" / "mise" / "installs" / "buf"
    try:
        if mise_root.is_dir():
            candidates = sorted(mise_root.glob("**/bin/buf"), key=_semver_key)
            if candidates:
                return str(candidates[-1])
    except OSError:
        return None
    return None


def test_editions_fds_overlay_in_tshark() -> None:
    # Create temporary dir inside ROOT so CI AppArmor allows tshark read access.
    with tempfile.TemporaryDirectory(dir=ROOT, prefix=".tmp_editions_") as tmp_str:
        tmp = Path(tmp_str)
        rec = _build_editions_record_bytes()
        framed = struct.pack(">BI", 0x00, len(rec)) + rec
        pcap_path = tmp / "editions.pcapng"
        gf.write_pcapng(pcap_path, gf._tcp_flow_packets(9090, [framed], []))

        cases = [
            ("EDITION_2023", "demo.ed2023", False, "TYPE_MESSAGE", "TYPE_MESSAGE", "TYPE_ENUM"),
            ("EDITION_2024", "demo.ed2024", True, "TYPE_GROUP", "TYPE_MESSAGE", "TYPE_ENUM"),
            ("EDITION_2026", "demo.ed2026", True, 10, 11, 14),
        ]
        for ed_val, pkg, snake, delim_t, msg_t, enum_t in cases:
            schema_path = tmp / f"{pkg}.schema.json"
            schema_path.write_text(
                _build_editions_fds_json(
                    ed_val,
                    pkg,
                    snake_case=snake,
                    delimited_type=delim_t,
                    msg_type=msg_t,
                    enum_type=enum_t,
                ),
                encoding="utf-8",
            )
            out = run_tshark(
                "-d", "tcp.port==9090,omnibuf",
                "-o", f"omnibuf.schema_path:{schema_path}",
                "-r", str(pcap_path),
                "-Y", "omnibuf",
                "-V",
            )
            _assert_tshark_editions_output(out, pkg)

        # If buf is installed locally, also verify real `buf build -o schema.json` for 2023/2024/2026.
        buf_bin = _find_buf_bin()
        if buf_bin is not None:
            for ed_str in ("2023", "2024", "2026"):
                pkg = f"demo.buf_ed{ed_str}"
                export_kw = "export " if ed_str in ("2024", "2026") else ""
                extra = ""
                if ed_str == "2024":
                    extra = "option features.enforce_naming_style = STYLE2024;\n"
                elif ed_str == "2026":
                    extra = (
                        "option features.enforce_naming_style = STYLE2026;\n"
                        "option features.default_symbol_visibility = STRICT;\n"
                    )
                proto_path = tmp / f"ed{ed_str}.proto"
                proto_path.write_text(
                    f"""edition = "{ed_str}";
package {pkg};
{extra}
{export_kw}enum OpenStatus {{
  OPEN_STATUS_UNSPECIFIED = 0;
  OPEN_STATUS_READY = 1;
}}
{export_kw}message Child {{
  sint32 id = 1;
  string label = 2 [features.field_presence = IMPLICIT];
}}
{export_kw}message Record {{
  sint32 exp_i32 = 1;
  bool exp_bool = 2;
  string exp_str = 3;
  bytes exp_bytes = 4;
  OpenStatus exp_enum = 5;
  OpenStatus unknown_enum = 6;
  Child delim_child = 7 [features.message_encoding = DELIMITED];
  repeated Child delim_list = 8 [features.message_encoding = DELIMITED];
  map<string, Child> children_by_key = 9;
  map<string, OpenStatus> statuses = 10;
}}
""",
                    encoding="utf-8",
                )
                schema_path = tmp / f"buf_ed{ed_str}.schema.json"
                proc = subprocess.run(
                    [buf_bin, "build", str(proto_path), "-o", str(schema_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert proc.returncode == 0, f"buf build {ed_str} failed:\n{proc.stderr}"
                out = run_tshark(
                    "-d", "tcp.port==9090,omnibuf",
                    "-o", f"omnibuf.schema_path:{schema_path}",
                    "-o", f"omnibuf.root_message:{pkg}.Record",
                    "-r", str(pcap_path),
                    "-Y", "omnibuf",
                    "-V",
                )
                _assert_tshark_editions_output(out, pkg)


def main() -> int:
    if not shutil.which("tshark"):
        print("tshark not found on PATH", file=sys.stderr)
        return 1
    for fn in (
        test_unary_http2,
        test_connect_stream,
        test_raw_tcp_reassembly_and_schema_overlay,
        test_tshark_json_for_jq,
        test_editions_fds_overlay_in_tshark,
    ):
        fn()
        print(f"PASS {fn.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
