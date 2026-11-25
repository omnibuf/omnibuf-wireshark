#!/usr/bin/env python3
"""Automated tshark regression tests for omnibuf.lua against .pcapng fixtures."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "omnibuf.lua"
FIXTURES = ROOT / "fixtures"


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


def main() -> int:
    if not shutil.which("tshark"):
        print("tshark not found on PATH", file=sys.stderr)
        return 1
    for fn in (
        test_unary_http2,
        test_connect_stream,
        test_raw_tcp_reassembly_and_schema_overlay,
        test_tshark_json_for_jq,
    ):
        fn()
        print(f"PASS {fn.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
