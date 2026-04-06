#!/usr/bin/env python3
# Copyright (C) 2026 Yuzeis
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

"""RKBPP 抓包工具入口（保持原文件名）。

子命令：
  capture-key    抓取首个 0x1002 key，输出 key.txt
  live-decode    持续抓包解密，导出 CSV
  battle-analyze 持续抓包 + 战斗实时解析 + CSV

无子命令时进入交互式菜单。
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from scapy.all import AsyncSniffer, PcapWriter  # type: ignore

from rkbpp_analyzer import RkbppAnalyzer
from rkbpp_io import CsvSink, SessionLogger, ensure_output_dir, iter_offline_packets, prompt_menu, prompt_text
from rkbpp_network import list_ifaces, load_key_from_file, packet_has_target_port, parse_key_text, printable_ascii
from rkbpp_reporter import BattleConsoleReporter

DEFAULT_PORT = 8195
SCRIPT_DIR   = Path(__file__).resolve().parent

# 子命令配置：command -> (prefix, needs_csv, needs_reporter, stop_after_key)
_COMMAND_CONFIG = {
    "capture-key":    ("rkbpp_key_capture",     False, False, True),
    "live-decode":    ("rkbpp_live_decode",      True,  False, False),
    "battle-analyze": ("rkbpp_battle_analyze",   True,  True,  False),
}


# ---------------------------------------------------------------------------
# 统一抓包主循环
# ---------------------------------------------------------------------------

def _run_session(analyzer: RkbppAnalyzer, args: argparse.Namespace) -> None:
    if args.read_pcap:
        for frame_no, pkt in iter_offline_packets(args.read_pcap):
            analyzer.process_packet(pkt, frame_no)
            if analyzer.should_stop:
                break
        return
    bpf     = None if args.no_bpf else f"tcp port {args.port}"
    sniffer = AsyncSniffer(
        iface=args.iface, store=False, prn=analyzer.process_packet,
        lfilter=lambda pkt: packet_has_target_port(pkt, args.port), filter=bpf,
    )
    sniffer.start()
    try:
        while not analyzer.should_stop:
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 统一运行函数（合并原 run_capture_key / run_live_decode / run_battle_analyze）
# ---------------------------------------------------------------------------

def run_command(args: argparse.Namespace) -> int:
    command = args.command
    config = _COMMAND_CONFIG.get(command)
    if config is None:
        print(f"未知命令: {command}")
        return 1

    prefix, needs_csv, needs_reporter, stop_after_key = config
    out_dir = ensure_output_dir(args.out_dir, prefix)

    # 初始化各组件
    session_logger = SessionLogger(out_dir / "capture.log")
    csv_sink: CsvSink | None = None
    writer: PcapWriter | None = None
    reporter: BattleConsoleReporter | None = None

    try:
        if needs_csv:
            csv_path = getattr(args, "csv_out", None) or out_dir / "decoded_packets.csv"
            csv_sink = CsvSink(csv_path)

        if not args.read_pcap:
            pcap_path = args.pcap_out or out_dir / ("capture.pcap" if not needs_csv else "live_capture.pcap")
            writer = PcapWriter(str(pcap_path), append=False, sync=True)

        preset_key = None
        if hasattr(args, "key") and args.key:
            preset_key = parse_key_text(args.key)

        if needs_reporter:
            reporter = BattleConsoleReporter(logger=session_logger)

        analyzer = RkbppAnalyzer(
            port=args.port, logger=session_logger, writer=writer,
            key_file=out_dir / "key.txt", csv_sink=csv_sink,
            preset_key=preset_key, stop_after_key=stop_after_key,
            analysis_listener=reporter,
        )

        mode = "offline" if args.read_pcap else "live"
        session_logger.log(
            f"[startup] command={command} mode={mode} iface={args.iface or '<default>'} "
            f"port={args.port} out_dir={out_dir}"
            + (f" csv={csv_sink.csv_path}" if csv_sink else "")
        )

        try:
            _run_session(analyzer, args)
        except KeyboardInterrupt:
            session_logger.log("[status] keyboard_interrupt stopping")

        session_logger.log(
            f"[summary] packets={analyzer.packet_count} key_hits={analyzer.key_hits} "
            f"rows={analyzer.decoded_rows} errors={analyzer._total_errors}"
        )

        # capture-key 模式：返回 0 表示找到 key，1 表示未找到
        if stop_after_key:
            return 0 if analyzer.key_hits > 0 else 1
        return 0

    finally:
        if writer:
            writer.close()
        if csv_sink:
            csv_sink.close()
        session_logger.close()


# ---------------------------------------------------------------------------
# 交互式模式
# ---------------------------------------------------------------------------

def build_interactive_args() -> argparse.Namespace:
    choice = prompt_menu()
    iface  = prompt_text("接口名", "以太网")
    out_dir_str = prompt_text("输出目录（留空则自动创建）", "")
    out_dir = Path(out_dir_str) if out_dir_str else None
    base = argparse.Namespace(
        iface=iface, port=DEFAULT_PORT, out_dir=out_dir,
        pcap_out=None, read_pcap=None, no_bpf=False, list_ifaces=False,
    )
    if choice == "1":
        return argparse.Namespace(**vars(base), command="capture-key")

    key: str | None = None
    for kp in ([out_dir / "key.txt"] if out_dir else []) + [SCRIPT_DIR / "key.txt"]:
        kb = load_key_from_file(kp)
        if kb:
            key = kb.hex()
            print(f"已读取 {kp.name}: {key}")
            break
    if key is None:
        print("未找到 key.txt，需要手动输入秘钥。")
        while True:
            raw = input("请输入秘钥（16位ASCII或32位hex）: ").strip()
            try:
                key = parse_key_text(raw).hex()
                break
            except ValueError as e:
                print(f"秘钥格式错误: {e}")
    return argparse.Namespace(
        **vars(base),
        command="battle-analyze" if choice == "3" else "live-decode",
        csv_out=None, key=key,
    )


# ---------------------------------------------------------------------------
# argparse + main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RKBPP 抓 key / 持续抓包解密导出工具")
    parser.add_argument("--list-ifaces", action="store_true")
    sub = parser.add_subparsers(dest="command")

    def _common(p):
        p.add_argument("--iface")
        p.add_argument("--port", type=int, default=DEFAULT_PORT)
        p.add_argument("--out-dir", type=Path)
        p.add_argument("--pcap-out", type=Path)
        p.add_argument("--read-pcap", type=Path)
        p.add_argument("--no-bpf", action="store_true")

    def _key_arg(p):
        p.add_argument("--key", help="已知 key，16字节ASCII或32位hex")

    def _csv_arg(p):
        p.add_argument("--csv-out", type=Path)

    cap = sub.add_parser("capture-key", help="抓取首个 0x1002 key，输出 key.txt")
    _common(cap)

    live = sub.add_parser("live-decode", help="持续抓包，输出解密 CSV")
    _common(live)
    _key_arg(live)
    _csv_arg(live)

    battle = sub.add_parser("battle-analyze", help="持续抓包并实时输出战斗解析，同时导出 CSV")
    _common(battle)
    _key_arg(battle)
    _csv_arg(battle)

    return parser


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    args = build_parser().parse_args()
    if args.list_ifaces:
        list_ifaces()
        return 0
    if not args.command:
        args = build_interactive_args()
    return run_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
