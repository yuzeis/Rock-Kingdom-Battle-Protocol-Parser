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

"""战斗实时控制台输出：BattleConsoleReporter。"""
from __future__ import annotations

from enum import Enum, auto
from typing import Any

import rkbpp_proto as proto
from rkbpp_io import SessionLogger


class BattlePhase(Enum):
    """显式战斗阶段状态机。"""
    WAITING_PAIR   = auto()  # 等待对位信息 (inner390)
    WAITING_ROSTER = auto()  # 已收到 pair，等待 1316 + 131A
    ACTIVE         = auto()  # 战斗进行中


class BattleConsoleReporter:
    def __init__(self, *, logger: SessionLogger) -> None:
        self.logger = logger
        self._phase = BattlePhase.WAITING_PAIR
        self.opening_pair:    dict[str, Any] | None       = None
        self.opening_1316:    list[dict[str, Any]] | None = None
        self.opening_131a:    list[dict[str, Any]] | None = None
        self.active_friendly_slot: int | None = None
        self.active_enemy_slot:    int | None = None

    # ------------------------------------------------------------------
    # 主入口（统一签名：所有 handler 接收 ri, record, summary_obj）
    # ------------------------------------------------------------------

    def handle(self, row_index: int, row: dict[str, Any], parsed_info: dict[str, Any]) -> None:
        record      = parsed_info["record"]
        kind        = parsed_info["summary_kind"]
        summary_obj = parsed_info["summary_obj"]

        _HANDLERS = {
            "inner390_pair":       self._on_inner390,
            "state_update":        self._on_state_update,
            "client_skill_select": self._on_skill_select,
            "server_skill_declare":self._on_skill_declare,
            "action_resolve":      self._on_action_resolve,
            "special_refresh":     self._on_special_refresh,
            "server_action_ack":   self._on_action_ack,
            "turn_control":        self._on_turn_control,
            "inner200_commit":     self._on_inner200,
            "inner51_event":       self._on_inner51,
        }
        handler = _HANDLERS.get(kind)
        if handler:
            handler(row_index, record, summary_obj)

    # ------------------------------------------------------------------
    # 事件处理（统一签名: ri, record, summary_obj）
    # ------------------------------------------------------------------

    def _on_inner390(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        detail = obj.get("detail") or {}
        if not detail:
            return
        fp = (detail.get("friendly") or {}).get("pet_id")
        ep = (detail.get("enemy")   or {}).get("pet_id")
        if fp in {0, None} and ep in {0, None}:
            self._emit(ri, "当前对位已清空")
        else:
            self.opening_pair = detail
            if self._phase == BattlePhase.WAITING_PAIR:
                self._phase = BattlePhase.WAITING_ROSTER
            fn = (detail.get("friendly") or {}).get("name") or fp
            en = (detail.get("enemy")   or {}).get("name") or ep
            self._emit(ri, f"首发对位建立: {fn} vs {en}")

    def _on_state_update(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        # wrappers 已经在 extract_state_wrappers_from_record 中去重过了，这里不再重复去重
        wrappers = obj.get("wrappers") or []
        opcode   = int(record.get("opcode", 0))
        if opcode == 0x1316 and self.opening_1316 is None:
            self.opening_1316 = wrappers
        elif opcode == 0x131A:
            if self.opening_131a is None and len(wrappers) >= 2:
                self.opening_131a = wrappers
            if self._phase == BattlePhase.ACTIVE:
                self._emit_snapshot(ri, wrappers)
        self._maybe_emit_battle_start(ri)

    def _on_skill_select(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        d = obj.get("detail") or {}
        if d.get("skill_id") is not None or d.get("action_name"):
            suffix = f" | 槽位={d.get('command_slot')}" if d.get("command_slot") is not None else ""
            self._emit(ri, f"玩家选择动作: {self._fmt_action_or_skill(d)}{suffix}")

    def _on_skill_declare(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        d = obj.get("detail") or {}
        if d.get("skill_id") is not None or d.get("action_name"):
            self._emit(ri, f"服务器广播动作: {self._fmt_action_or_skill(d)}")

    def _on_action_resolve(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        detail = obj.get("detail") or {}
        self._emit_action_resolve(ri, detail)

    def _on_special_refresh(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        d = obj.get("detail") or {}
        parts = ["面板刷新"]
        if d.get("action_name"):
            parts.append(f"动作={d.get('action_name')}")
        if d.get("energy_delta") is not None or d.get("energy_after") is not None:
            parts.append(f"能量变化={d.get('energy_delta')} -> {d.get('energy_after')}")
        opts = self._fmt_skill_options(d.get("skill_options") or [])
        if opts:
            parts.append(f"技能列表={opts}")
        self._emit(ri, " | ".join(parts))

    def _on_action_ack(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        d = obj.get("detail") or {}
        if not (d.get("skill_id") is not None or d.get("action_name") or d.get("state_wrappers")):
            return
        parts = [f"动作确认: {self._fmt_action_or_skill(d)}"]
        if d.get("current_hp") is not None:
            parts.append(f"当前HP={d.get('current_hp')}")
        if d.get("energy_after") is not None:
            parts.append(f"当前能量={d.get('energy_after')}")
        ws = d.get("state_wrappers") or []
        if ws:
            parts += [f"实体={ws[0].get('name')}", f"技能={self._fmt_dynamic_skills(ws[0])}"]
        self._emit(ri, " | ".join(parts))

    def _on_turn_control(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        d = obj.get("detail") or {}
        self._emit(ri, f"回合控制包: phase_code={d.get('phase_code')}")

    def _on_inner200(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        c = (obj.get("detail") or {}).get("commit") or {}
        self._emit(ri, f"commit: flag={c.get('flag')} code={c.get('code')} event_time_ms={c.get('event_time_ms')}")

    def _on_inner51(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        d = obj.get("detail") or {}
        self._emit(ri, f"inner51: kind={d.get('kind')} value2={d.get('value2')} value3={d.get('value3')}")

    # ------------------------------------------------------------------
    # 开场逻辑（使用显式状态机）
    # ------------------------------------------------------------------

    def _maybe_emit_battle_start(self, ri: int) -> None:
        if self._phase == BattlePhase.ACTIVE:
            return
        if self.opening_1316 is None or self.opening_131a is None:
            return
        ff, ef = self._match_opening_active(self.opening_131a)
        if ff is None or ef is None:
            return
        self.active_friendly_slot = int(ff.get("slot") or 0)
        self.active_enemy_slot    = int(ef.get("slot") or 0)
        self._phase = BattlePhase.ACTIVE

        self._emit(ri, f"战斗开始: 我方 {ff.get('name')}(slot={ff.get('slot')}) vs 敌方 {ef.get('name')}(slot={ef.get('slot')})")
        vis_enemy   = [it for it in self.opening_1316 if self._slot_key(it) == self.active_enemy_slot]
        fri_roster  = [it for it in self.opening_1316 if self._slot_key(it) != self.active_enemy_slot]
        self._emit(ri, f"我方阵容共 {len(fri_roster)} 只，敌方当前可见 {len(vis_enemy)} 只")
        for tag, items in (("我方阵容", fri_roster), ("敌方可见", vis_enemy)):
            for it in items:
                self._emit(ri, f"{tag}: {it.get('name')} Lv{it.get('level')} slot={it.get('slot')} "
                              f"pet_id={it.get('pet_id')} 属性={self._fmt_types(it)} "
                              f"HP={it.get('current_hp')}/{it.get('battle_max_hp')} "
                              f"六维={self._fmt_stats(it)} 技能={self._fmt_dynamic_skills(it)}")
        self._emit_snapshot(ri, self.opening_131a, opening=True)

    def _emit_snapshot(self, ri: int, wrappers: list[dict[str, Any]], *, opening: bool = False) -> None:
        # wrappers 已经在上游去重，这里不再重复调用 dedupe_state_wrappers
        if self.active_friendly_slot is None:
            ff, ef = self._match_opening_active(wrappers)
        else:
            ff = next((it for it in wrappers if self._slot_key(it) == self.active_friendly_slot), None)
            ef = next((it for it in wrappers if self._slot_key(it) == self.active_enemy_slot),    None)
        if ff is None or ef is None:
            return
        prefix = "开场上场状态" if opening else "上场快照"
        for side, w in (("我方", ff), ("敌方", ef)):
            spd = (w.get("battle_stats") or [None] * 6)[:6][-1] if len(w.get("battle_stats") or []) >= 6 else None
            self._emit(ri, f"{prefix}: {side} {w.get('name')} HP={w.get('current_hp')}/{w.get('battle_max_hp')} "
                          f"速度={spd} 技能={self._fmt_dynamic_skills(w)}")

    def _emit_action_resolve(self, ri: int, detail: dict[str, Any]) -> None:
        primary = detail.get("primary_skill") or {}
        damage  = detail.get("damage_event")  or {}
        energy  = detail.get("energy_event")  or {}
        if not primary and not damage and not energy:
            return
        actor  = energy.get("actor_side_name") or damage.get("actor_side_name") or primary.get("actor_side_name") or "未知方"
        target = damage.get("target_side_name") or primary.get("target_side_name") or "未知方"
        parts  = [f"{actor}行动"]
        if primary.get("skill_id") is not None:
            parts.append(f"技能={self._fmt_skill(primary)}")
        if energy.get("energy_delta") is not None or energy.get("energy_after") is not None:
            parts.append(f"能量变化={energy.get('energy_delta')} -> {energy.get('energy_after')}")
        if damage.get("damage") is not None:
            parts += [f"伤害={damage.get('damage')}", f"目标={target}"]
        if damage.get("target_hp_after") is not None:
            parts.append(f"目标剩余HP={damage.get('target_hp_after')}")
        if damage.get("overflow") not in {None, 0}:
            parts.append(f"溢出={abs(int(damage['overflow']))}")
        if detail.get("effect_ids"):
            parts.append("状态ID=" + "/".join(str(x) for x in detail["effect_ids"]))
        if detail.get("has_defeat"):
            parts.append("包含击杀/退场事件")
        self._emit(ri, " | ".join(parts))

    # ------------------------------------------------------------------
    # 格式化助手
    # ------------------------------------------------------------------

    def _emit(self, ri: int, text: str) -> None:
        self.logger.log(f"[battle][row {ri}] {text}")

    def _fmt_skill(self, d: dict[str, Any]) -> str:
        sid = d.get("skill_id")
        name = d.get("skill_name") or "未知技能"
        return f"{name}({sid})" if sid is not None else name

    def _fmt_action_or_skill(self, d: dict[str, Any]) -> str:
        return self._fmt_skill(d) if d.get("skill_id") is not None else str(d.get("action_name") or "未知动作")

    def _fmt_skill_options(self, options: list[dict[str, Any]]) -> str:
        return "; ".join(
            f"{it.get('slot')}:{it.get('skill_name') or it.get('skill_id')}({it.get('skill_id')})"
            if it.get("slot") is not None else
            f"{it.get('skill_name') or it.get('skill_id')}({it.get('skill_id')})"
            for it in options
        )

    def _fmt_types(self, w: dict[str, Any]) -> str:
        names = proto.summarize_types(w.get("types") or [])
        return "/".join(names) if names else "-"

    def _fmt_stats(self, w: dict[str, Any]) -> str:
        s = w.get("battle_stats") or []
        return "[" + ",".join(str(v) for v in s) + "]" if s else "[]"

    def _fmt_dynamic_skills(self, w: dict[str, Any]) -> str:
        parts = []
        for it in w.get("dynamic_skills") or []:
            slot = it.get("slot")
            if slot is None or not (1 <= int(slot) <= 4):
                continue
            sid = it.get("skill_id")
            name = proto.skill_name(sid) or str(sid)
            extras = [f"aux26={it['aux26']}" if it.get("aux26") is not None else "",
                      f"aux27={it['aux27']}" if it.get("aux27") is not None else ""]
            suffix = "[" + ",".join(e for e in extras if e) + "]" if any(extras) else ""
            parts.append(f"{slot}:{name}({sid}){suffix}")
        return "; ".join(parts) if parts else "无"

    def _slot_key(self, w: dict[str, Any]) -> int:
        slot = w.get("slot")
        return int(slot) if slot is not None else -1

    def _match_opening_active(self, wrappers: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        pair = self.opening_pair or {}
        fp   = (pair.get("friendly") or {}).get("pet_id")
        ep   = (pair.get("enemy")    or {}).get("pet_id")
        ff   = next((it for it in wrappers if it.get("pet_id") == fp), None) if fp else None
        ef   = next((it for it in wrappers if it.get("pet_id") == ep and it is not ff), None) if ep else None
        if ff is None and wrappers:
            ff = next((it for it in wrappers if int(it.get("slot") or 0) != 0), wrappers[0])
        if ef is None and wrappers:
            ef = next((it for it in wrappers if it is not ff), None)
        return ff, ef
