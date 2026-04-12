#!/usr/bin/env python3
# Copyright (C) 2026 花吹雪又一年
#
# This file is part of Rock Kingdom Battle Protocol Parser (RKBPP).
# Licensed under the GNU Affero General Public License v3.0 only (AGPL-3.0-only).
# You must retain the author attribution, this notice, the LICENSE file,
# and the NOTICE file in redistributions and derivative works.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the LICENSE
# file for more details.

"""网络层：AES-128-CBC 解密、key 管理、BE21 帧解析、TCP 流状态。"""
from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError as exc:
    raise SystemExit("缺少 pycryptodome。先执行: python -m pip install --user pycryptodome") from exc

from scapy.all import IP, IPv6, TCP, conf  # type: ignore

from rkbpp_io import now_text

logger = logging.getLogger(__name__)

MAGIC = b"\x33\x66"
FIXED_HDR_LEN = 21

# BE21 合法 cmd 范围，用于帧头校验以减少假 magic 命中。
_KNOWN_CMD_RANGE = range(0x0001, 0x8000)

# 防止 seen_acks 无限增长。
_MAX_SEEN_ACKS = 256

# 防止连续流缓存与乱序段缓存无限增长。
_MAX_BUFFER_SIZE = 16 * 1024 * 1024
_MAX_PENDING_BYTES = 8 * 1024 * 1024


def printable_ascii(blob: bytes) -> str | None:
    return blob.decode("ascii", errors="replace") if blob and all(32 <= b < 127 for b in blob) else None


def parse_key_text(text: str) -> bytes:
    raw = text.strip()
    hex_cand = "".join(c for c in raw if c in "0123456789abcdefABCDEF")
    if len(raw) == 16:
        key = raw.encode("ascii")
    elif len(hex_cand) == 32:
        key = bytes.fromhex(hex_cand)
    else:
        raise ValueError("key 必须是 16 字节 ASCII 或 32 位 hex")
    if len(key) != 16:
        raise ValueError("AES-128 key 必须正好 16 字节")
    return key


def load_key_from_file(path: str | Path) -> bytes | None:
    path = Path(path)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return None
    first = text.splitlines()[0].strip()
    if "=" not in first:
        try:
            return parse_key_text(first)
        except ValueError:
            pass
    for line in text.splitlines():
        if line.startswith("key_hex="):
            value = line.split("=", 1)[1].strip()
            if value:
                return parse_key_text(value)
        if line.startswith("key_ascii="):
            value = line.split("=", 1)[1].strip()
            if value and value != "<non-ascii>":
                return parse_key_text(value)
    return None


def write_key_file(path: str | Path, key: bytes, flow_id: str) -> None:
    Path(path).write_text(
        f"key_hex={key.hex()}\nkey_ascii={printable_ascii(key) or '<non-ascii>'}\n"
        f"flow={flow_id}\ncaptured_at={now_text()}\n",
        encoding="utf-8",
    )


def decrypt_4013_body(key: bytes, body: bytes) -> tuple[bytes, bytes]:
    if len(body) < 32:
        raise ValueError("0x4013 body 长度不足，无法拆出 IV + 密文")
    iv = body[:16]
    ct = body[16:]
    if len(ct) % 16 != 0:
        raise ValueError("0x4013 body[16:] 不是 16 字节对齐")
    return iv, AES.new(key, AES.MODE_CBC, iv).decrypt(ct)


def packet_has_target_port(packet, port: int) -> bool:
    return packet.haslayer(TCP) and (int(packet[TCP].sport) == port or int(packet[TCP].dport) == port)


def packet_ip_tuple(packet) -> tuple[str, str] | None:
    for layer in (IP, IPv6):
        if packet.haslayer(layer):
            ip = packet[layer]
            return ip.src, ip.dst
    return None


def flow_key_from_packet(packet, port: int) -> tuple[str, str, int, str, int, str] | None:
    ip_pair = packet_ip_tuple(packet)
    if ip_pair is None or not packet.haslayer(TCP):
        return None
    src_ip, dst_ip = ip_pair
    tcp = packet[TCP]
    sp = int(tcp.sport)
    dp = int(tcp.dport)
    if dp == port:
        return src_ip, "c2s", sp, dst_ip, dp, f"{src_ip}:{sp}->{dst_ip}:{dp}"
    if sp == port:
        return dst_ip, "s2c", dp, src_ip, sp, f"{dst_ip}:{dp}->{src_ip}:{sp}"
    return None


def list_ifaces() -> None:
    for iface in conf.ifaces.values():
        print(f"{iface.name}\t{getattr(iface, 'description', '')}")


@dataclass
class Be21Packet:
    direction: str
    stream_offset: int
    cmd: int
    seq: int
    hdr_len: int
    body_len: int
    header_extra: bytes
    body: bytes


def _validate_be21_header(data: bytearray, off: int) -> bool:
    if off + FIXED_HDR_LEN > len(data):
        return False
    cmd = int.from_bytes(data[off + 6:off + 8], "big")
    hdr_len = int.from_bytes(data[off + 13:off + 17], "big")
    body_len = int.from_bytes(data[off + 17:off + 21], "big")
    if cmd not in _KNOWN_CMD_RANGE:
        return False
    if hdr_len < FIXED_HDR_LEN:
        return False
    if (hdr_len + body_len) > 4 * 1024 * 1024:
        return False
    return True


def parse_be21_from_buffer(data: bytearray, direction: str, start: int) -> tuple[list[Be21Packet], int]:
    packets: list[Be21Packet] = []
    off = start
    size = len(data)
    while off + FIXED_HDR_LEN <= size:
        if data[off:off + 2] != MAGIC:
            nxt = data.find(MAGIC, off + 1)
            if nxt < 0:
                break
            off = nxt
            continue
        if not _validate_be21_header(data, off):
            off += 2
            continue
        cmd = int.from_bytes(data[off + 6:off + 8], "big")
        seq = int.from_bytes(data[off + 9:off + 13], "big")
        hdr_len = int.from_bytes(data[off + 13:off + 17], "big")
        body_len = int.from_bytes(data[off + 17:off + 21], "big")
        pkt_len = hdr_len + body_len
        if off + pkt_len > size:
            break
        packets.append(
            Be21Packet(
                direction=direction,
                stream_offset=off,
                cmd=cmd,
                seq=seq,
                hdr_len=hdr_len,
                body_len=body_len,
                header_extra=bytes(data[off + FIXED_HDR_LEN:off + hdr_len]),
                body=bytes(data[off + hdr_len:off + pkt_len]),
            )
        )
        off += pkt_len
    return packets, off


@dataclass
class DirectionState:
    direction: str
    buffer: bytearray = field(default_factory=bytearray)
    parse_offset: int = 0
    stream_base: int = 0
    _base_seq: int | None = None
    _next_contig_seq: int | None = None
    _pending: dict[int, bytes] = field(default_factory=dict)
    _pending_bytes: int = 0

    def feed(self, seq: int, payload: bytes) -> list[Be21Packet]:
        """把 TCP 段按 seq 重组为连续字节流，再交给 BE21 解析器。"""
        if not payload:
            return []

        if self._base_seq is None:
            self._base_seq = seq
            self.buffer.extend(payload)
            self._next_contig_seq = seq + len(payload)
        else:
            self._ingest_segment(seq, payload)

        if len(self.buffer) > _MAX_BUFFER_SIZE:
            self._trim_buffer()

        base = self.stream_base
        packets, new_off = parse_be21_from_buffer(self.buffer, self.direction, self.parse_offset)
        self.parse_offset = new_off
        for packet in packets:
            packet.stream_offset += base

        if self.parse_offset >= 0x10000 and self.parse_offset > len(self.buffer) // 2:
            trim = self.parse_offset
            del self.buffer[:trim]
            self.stream_base += trim
            if self._base_seq is not None:
                self._base_seq += trim
            self.parse_offset = 0

        return packets

    def _ingest_segment(self, seq: int, payload: bytes) -> None:
        assert self._base_seq is not None
        assert self._next_contig_seq is not None

        end = seq + len(payload)
        if seq < self._base_seq:
            if end < self._base_seq:
                logger.debug(
                    "DirectionState[%s] dropping non-contiguous old segment seq=%d end=%d base=%d",
                    self.direction,
                    seq,
                    end,
                    self._base_seq,
                )
                return
            prepend_len = self._base_seq - seq
            if prepend_len > 0:
                self.buffer = bytearray(payload[:prepend_len]) + self.buffer
                self._base_seq = seq
                self.parse_offset += prepend_len
                self.stream_base = max(0, self.stream_base - prepend_len)
            if end <= self._next_contig_seq:
                return
            payload = payload[self._next_contig_seq - seq:]
            seq = self._next_contig_seq
            if not payload:
                return

        if seq <= self._next_contig_seq:
            start = seq - self._base_seq
            overlap = self._next_contig_seq - seq
            if overlap > 0 and start >= 0:
                overlap = min(overlap, len(payload))
                existing = bytes(self.buffer[start:start + overlap])
                incoming = payload[:overlap]
                if existing != incoming:
                    if start < self.parse_offset:
                        logger.debug(
                            "DirectionState[%s] ignoring conflicting retransmit over parsed bytes seq=%d",
                            self.direction,
                            seq,
                        )
                        return
                    log_func = logger.debug if existing and all(b == 0 for b in existing) else logger.warning
                    log_func(
                        "DirectionState[%s] replacing conflicting overlap at seq=%d "
                        "(existing=%s incoming=%s)",
                        self.direction,
                        seq,
                        existing[:8].hex(),
                        incoming[:8].hex(),
                    )
                    del self.buffer[start:]
                    self.buffer.extend(payload)
                    self._next_contig_seq = seq + len(payload)
                    self.parse_offset = min(self.parse_offset, start)
                    self._drain_pending()
                    return
            if overlap >= len(payload):
                return
            self.buffer.extend(payload[overlap:])
            self._next_contig_seq += len(payload) - overlap
            self._drain_pending()
            return

        self._store_pending(seq, payload)

    def _store_pending(self, seq: int, payload: bytes) -> None:
        end = seq + len(payload)

        for old_seq, old_payload in list(self._pending.items()):
            old_end = old_seq + len(old_payload)
            if old_seq <= seq and old_end >= end:
                return
            if seq <= old_seq and end >= old_end:
                self._pending_bytes -= len(old_payload)
                del self._pending[old_seq]

        existing = self._pending.get(seq)
        if existing is not None:
            if len(existing) >= len(payload):
                return
            self._pending_bytes -= len(existing)

        self._pending[seq] = payload
        self._pending_bytes += len(payload)

        while self._pending_bytes > _MAX_PENDING_BYTES and self._pending:
            farthest_seq = max(self._pending)
            dropped = self._pending.pop(farthest_seq)
            self._pending_bytes -= len(dropped)
            logger.warning(
                "DirectionState[%s] pending cache exceeded %d bytes, dropping segment at seq=%d",
                self.direction,
                _MAX_PENDING_BYTES,
                farthest_seq,
            )

    def _drain_pending(self) -> None:
        assert self._next_contig_seq is not None

        while True:
            ready = [pending_seq for pending_seq in self._pending if pending_seq <= self._next_contig_seq]
            if not ready:
                return

            seq = min(ready)
            payload = self._pending.pop(seq)
            self._pending_bytes -= len(payload)

            overlap = self._next_contig_seq - seq
            if overlap >= len(payload):
                continue
            self.buffer.extend(payload[overlap:])
            self._next_contig_seq += len(payload) - overlap

    def _trim_buffer(self) -> None:
        if not self.buffer:
            return

        logger.warning(
            "DirectionState[%s] buffer exceeded %d bytes, trimming buffered stream",
            self.direction,
            _MAX_BUFFER_SIZE,
        )
        desired = _MAX_BUFFER_SIZE // 2
        if self.parse_offset > 0:
            trim = min(self.parse_offset, max(0, len(self.buffer) - desired))
        else:
            trim = max(0, len(self.buffer) - desired)
        if trim <= 0:
            return

        del self.buffer[:trim]
        self.stream_base += trim
        self.parse_offset = max(0, self.parse_offset - trim)
        if self._base_seq is not None:
            self._base_seq += trim


class _BoundedAckSet:
    """有界去重集合，淘汰最早的条目防止内存泄漏。"""

    def __init__(self, maxsize: int = _MAX_SEEN_ACKS) -> None:
        self._data: OrderedDict[tuple[int, str], None] = OrderedDict()
        self._maxsize = maxsize

    def __contains__(self, item: tuple[int, str]) -> bool:
        return item in self._data

    def add(self, item: tuple[int, str]) -> None:
        if item in self._data:
            return
        if len(self._data) >= self._maxsize:
            self._data.popitem(last=False)
        self._data[item] = None


@dataclass
class FlowState:
    flow_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    c2s: DirectionState = field(default_factory=lambda: DirectionState("c2s"))
    s2c: DirectionState = field(default_factory=lambda: DirectionState("s2c"))
    seen_acks: _BoundedAckSet = field(default_factory=_BoundedAckSet)
    key: bytes | None = None

    def direction_state(self, direction: str) -> DirectionState:
        return self.c2s if direction == "c2s" else self.s2c
