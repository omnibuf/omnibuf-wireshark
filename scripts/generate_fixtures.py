#!/usr/bin/env python3
"""Generates deterministic .pcapng fixtures and a matching schema.json for tshark/Wireshark tests.

Fixtures generated in fixtures/:
  1. unary_http2.pcapng   - Cleartext HTTP/2 (h2c) POST with content-type: application/omnibuf
  2. connect_stream.pcapng - HTTP/1.1 POST with content-type: application/connect+omnibuf (2 msg frames + end-stream)
  3. raw_tcp.pcapng       - Raw TCP (port 9090) carrying a 5-byte framed OmniBuf message split across 2 TCP segments
  4. schema.json          - Lightweight OmniBuf JSON schema matching demo.v1.PeerUpdate
"""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _ipv4_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return int((~total) & 0xFFFF)


def _tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_seg: bytes) -> int:
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp_seg))
    data = pseudo + tcp_seg
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return int((~total) & 0xFFFF)


def _build_eth_ipv4_tcp(
    src_ip_s: str,
    dst_ip_s: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    ip_id: int = 1,
) -> bytes:
    src_ip = socket.inet_aton(src_ip_s)
    dst_ip = socket.inet_aton(dst_ip_s)

    # Ethernet header (14B): dst MAC, src MAC, EtherType 0x0800 (IPv4)
    eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"

    # TCP header (20B)
    tcp_hdr_no_csum = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 4),  # data offset = 5 (20 bytes)
        flags,
        65535,
        0,
        0,
    )
    csum = _tcp_checksum(src_ip, dst_ip, tcp_hdr_no_csum + payload)
    tcp = (
        struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            ack,
            (5 << 4),
            flags,
            65535,
            csum,
            0,
        )
        + payload
    )

    # IPv4 header (20B)
    total_len = 20 + len(tcp)
    ip_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ip_id,
        0x4000,  # DF
        64,
        6,  # TCP
        0,
        src_ip,
        dst_ip,
    )
    ip_csum = _ipv4_checksum(ip_no_csum)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ip_id,
        0x4000,
        64,
        6,
        ip_csum,
        src_ip,
        dst_ip,
    )
    return eth + ip + tcp


def _pad4(b: bytes) -> bytes:
    rem = len(b) % 4
    return b if rem == 0 else b + b"\x00" * (4 - rem)


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    total_len = 12 + len(body)
    return struct.pack("<II", block_type, total_len) + body + struct.pack("<I", total_len)


def write_pcapng(path: Path, frames: list[bytes]) -> None:
    # Section Header Block (SHB)
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = _pcapng_block(0x0A0D0D0A, shb_body)

    # Interface Description Block (IDB): LinkType 1 (Ethernet), SnapLen 65535
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb = _pcapng_block(0x00000001, idb_body)

    out = bytearray(shb + idb)
    base_ts = 1_764_000_000_000_000  # microseconds
    for i, frame in enumerate(frames):
        ts = base_ts + i * 1000
        ts_high = (ts >> 32) & 0xFFFFFFFF
        ts_low = ts & 0xFFFFFFFF
        epb_body = (
            struct.pack("<IIIII", 0, ts_high, ts_low, len(frame), len(frame))
            + _pad4(frame)
        )
        out.extend(_pcapng_block(0x00000006, epb_body))

    path.write_bytes(bytes(out))


def _tcp_flow_packets(
    dst_port: int, client_chunks: list[bytes], server_chunks: list[bytes]
) -> list[bytes]:
    c_ip, s_ip = "10.0.0.1", "10.0.0.2"
    c_port = 51234
    c_seq, s_seq = 1000, 2000
    pkts: list[bytes] = []
    ip_id = 1

    def add(src_ip: str, dst_ip: str, sp: int, dp: int, seq: int, ack: int, flags: int, data: bytes = b"") -> None:
        nonlocal ip_id
        pkts.append(_build_eth_ipv4_tcp(src_ip, dst_ip, sp, dp, seq, ack, flags, data, ip_id))
        ip_id += 1

    SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
    # 3-way handshake
    add(c_ip, s_ip, c_port, dst_port, c_seq, 0, SYN)
    c_seq += 1
    add(s_ip, c_ip, dst_port, c_port, s_seq, c_seq, SYN | ACK)
    s_seq += 1
    add(c_ip, s_ip, c_port, dst_port, c_seq, s_seq, ACK)

    for chunk in client_chunks:
        add(c_ip, s_ip, c_port, dst_port, c_seq, s_seq, PSH | ACK, chunk)
        c_seq += len(chunk)
        add(s_ip, c_ip, dst_port, c_port, s_seq, c_seq, ACK)

    for chunk in server_chunks:
        add(s_ip, c_ip, dst_port, c_port, s_seq, c_seq, PSH | ACK, chunk)
        s_seq += len(chunk)
        add(c_ip, s_ip, c_port, dst_port, c_seq, s_seq, ACK)

    # Teardown
    add(c_ip, s_ip, c_port, dst_port, c_seq, s_seq, FIN | ACK)
    c_seq += 1
    add(s_ip, c_ip, dst_port, c_port, s_seq, c_seq, FIN | ACK)
    s_seq += 1
    add(c_ip, s_ip, c_port, dst_port, c_seq, s_seq, ACK)
    return pkts


def _encode_varint(v: int) -> bytes:
    if v <= 127:
        return bytes([(v << 1) | 1])
    if v <= 16383:
        return struct.pack("<H", (v << 2) | 2)
    if v <= 536870911:
        return struct.pack("<I", (v << 3) | 4)
    return struct.pack("<BQ", 0, v)


def _encode_tag(fnum: int, wt: int) -> bytes:
    return _encode_varint((fnum << 4) | wt)


def _encode_string_field(fnum: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return _encode_tag(fnum, 10) + _encode_varint(len(raw)) + raw


def _encode_uint_field(fnum: int, val: int) -> bytes:
    return _encode_tag(fnum, 0) + _encode_varint(val)


def _encode_sint_field(fnum: int, val: int) -> bytes:
    zz = ((val << 1) ^ (val >> 63)) & 0xFFFFFFFFFFFFFFFF
    return _encode_tag(fnum, 1) + _encode_varint(zz)


def _encode_bool_field(fnum: int, val: bool) -> bytes:
    return _encode_tag(fnum, 3 if val else 2)


def _encode_submsg_field(fnum: int, body: bytes) -> bytes:
    return _encode_tag(fnum, 12) + _encode_varint(len(body)) + body


def build_peer_update(router: str, state: int, delta: int, active: bool, city: str) -> bytes:
    location = _encode_string_field(1, city)
    return (
        _encode_string_field(1, router)
        + _encode_uint_field(2, state)
        + _encode_sint_field(3, delta)
        + _encode_bool_field(4, active)
        + _encode_submsg_field(5, location)
    )


def _h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    length = len(payload)
    hdr = bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF, frame_type, flags])
    return hdr + struct.pack("!I", stream_id & 0x7FFFFFFF) + payload


def _hpack_literal_never_indexed(name: bytes, value: bytes) -> bytes:
    return bytes([0x10, len(name)]) + name + bytes([len(value)]) + value


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    msg1 = build_peer_update("fra-core-01", 1, -2, True, "FRA")
    msg2 = build_peer_update("ams-edge-04", 2, 15, False, "AMS")

    # 1. unary_http2.pcapng (cleartext HTTP/2 h2c on port 8080)
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = _h2_frame(0x04, 0x00, 0, b"")
    settings_ack = _h2_frame(0x04, 0x01, 0, b"")
    req_hpack = (
        bytes([0x83])  # :method: POST (static index 3)
        + bytes([0x86])  # :scheme: http (static index 6)
        + _hpack_literal_never_indexed(b":path", b"/demo.v1.PeerService/Update")
        + _hpack_literal_never_indexed(b":authority", b"localhost:8080")
        + _hpack_literal_never_indexed(b"content-type", b"application/omnibuf")
    )
    req_headers = _h2_frame(0x01, 0x04, 1, req_hpack)  # END_HEADERS
    req_data = _h2_frame(0x00, 0x01, 1, msg1)  # END_STREAM

    resp_hpack = (
        bytes([0x88])  # :status: 200 (static index 8)
        + _hpack_literal_never_indexed(b"content-type", b"application/omnibuf")
    )
    resp_headers = _h2_frame(0x01, 0x04, 1, resp_hpack)
    resp_data = _h2_frame(0x00, 0x01, 1, msg2)

    h2_pkts = _tcp_flow_packets(
        8080,
        [preface + settings, req_headers + req_data],
        [settings + settings_ack, resp_headers + resp_data],
    )
    write_pcapng(FIXTURES_DIR / "unary_http2.pcapng", h2_pkts)

    # 2. connect_stream.pcapng (HTTP/1.1 POST with application/connect+omnibuf)
    env_body = (
        struct.pack(">BI", 0x00, len(msg1))
        + msg1
        + struct.pack(">BI", 0x00, len(msg2))
        + msg2
        + struct.pack(">BI", 0x02, 2)
        + b"{}"
    )
    http_req = (
        b"POST /demo.v1.PeerService/Watch HTTP/1.1\r\n"
        b"Host: localhost:8080\r\n"
        b"Content-Type: application/connect+omnibuf\r\n"
        b"Connect-Protocol-Version: 1\r\n"
        + f"Content-Length: {len(env_body)}\r\n\r\n".encode("ascii")
        + env_body
    )
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/connect+omnibuf\r\n"
        + f"Content-Length: {len(env_body)}\r\n\r\n".encode("ascii")
        + env_body
    )
    connect_pkts = _tcp_flow_packets(8080, [http_req], [http_resp])
    write_pcapng(FIXTURES_DIR / "connect_stream.pcapng", connect_pkts)

    # 3. raw_tcp.pcapng (raw TCP port 9090, 5-byte framed OmniBuf split across 2 TCP segments)
    framed = struct.pack(">BI", 0x00, len(msg1)) + msg1
    split_at = 10
    raw_pkts = _tcp_flow_packets(9090, [framed[:split_at], framed[split_at:]], [])
    write_pcapng(FIXTURES_DIR / "raw_tcp.pcapng", raw_pkts)

    # 4. Matching schema.json
    schema = {
        "root": "demo.v1.PeerUpdate",
        "messages": {
            "demo.v1.PeerUpdate": {
                "fields": {
                    "1": {"name": "router", "type": "string"},
                    "2": {"name": "state", "enum": "demo.v1.PeerState"},
                    "3": {"name": "delta", "type": "sint64"},
                    "4": {"name": "active", "type": "bool"},
                    "5": {"name": "location", "message": "demo.v1.Location"},
                }
            },
            "demo.v1.Location": {
                "fields": {
                    "1": {"name": "city", "type": "string"},
                }
            },
        },
        "enums": {
            "demo.v1.PeerState": {
                "0": "PEER_STATE_UNSPECIFIED",
                "1": "PEER_STATE_ESTABLISHED",
                "2": "PEER_STATE_ACTIVE",
            }
        },
    }
    (FIXTURES_DIR / "schema.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    print(f"Generated fixtures in {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
