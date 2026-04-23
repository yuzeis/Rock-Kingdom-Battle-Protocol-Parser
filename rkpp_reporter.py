#!/usr/bin/env python3
# Copyright (C) 2026 花吹雪又一年
#
# This file is part of Roco-Kingdom-Protocol-Parser (RKPP).
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

import rkpp_proto as proto
from rkpp_io import SessionLogger


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
        self._handlers = {
            "inner390_pair":       self._on_inner390,
            "battle_enter":        self._on_battle_enter,
            "round_start":         self._on_round_start,
            "client_skill_select": self._on_skill_select,
            "server_skill_declare":self._on_skill_declare,
            "action_resolve":      self._on_action_resolve,
            "pvp_perform":         self._on_action_resolve,
            "preplay":             self._on_action_resolve,
            "special_refresh":     self._on_special_refresh,
            "server_action_ack":   self._on_action_ack,
            "inner200_commit":     self._on_inner200,
            "inner51_event":       self._on_inner51,
            "battle_finish":       self._on_battle_finish,
            "round_flow":          self._on_round_flow,
        }
        self._schema_opcode_handlers = {
            0x1326: self._on_auto_cmd,
            0x132A: self._on_role_leave,
            0x132D: self._on_force_finish,
            0x1334: self._on_emoji,
            0x133C: self._on_catch_rsp,
            0x13F6: self._on_ai_skill,
        }

    # ------------------------------------------------------------------
    # 主入口（统一签名：所有 handler 接收 ri, record, summary_obj）
    # ------------------------------------------------------------------

    def handle(self, row_index: int, row: dict[str, Any], parsed_info: dict[str, Any]) -> None:
        record      = parsed_info["record"]
        kind        = parsed_info["summary_kind"]
        summary_obj = parsed_info["summary_obj"]

        handler = self._handlers.get(kind)
        if handler:
            handler(row_index, record, summary_obj)
            return

        if kind != "schema_decoded":
            return

        opcode = int(record.get("opcode", 0) or 0)
        schema_handler = self._schema_opcode_handlers.get(opcode)
        if not schema_handler:
            return
        detail = self._schema_detail_for_opcode(opcode, record.get("_decoded"))
        if detail is None:
            return
        schema_handler(row_index, record, {"detail": detail})

    def _schema_detail_for_opcode(self, opcode: int, decoded: Any) -> dict[str, Any] | None:
        if not isinstance(decoded, dict):
            return None
        detail = dict(decoded)
        if opcode == 0x1326:
            return {"auto_flag": detail.get("auto_flag", detail.get("field_1"))}
        if opcode == 0x133C:
            ret_info = detail.get("ret_info")
            if isinstance(ret_info, dict) and "ret_code" not in detail:
                detail["ret_code"] = ret_info.get("ret_code")
            return detail
        if opcode == 0x13F6:
            skill_info = detail.get("skill_info")
            if isinstance(skill_info, dict):
                merged = dict(skill_info)
                merged["pet_id"] = detail.get("pet_id")
                return merged
        return detail

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

    def _on_battle_enter(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x1316 BattleEnterNotify - 战斗进入通知。"""
        d = obj.get("detail") or {}
        wrappers = d.get("wrappers") or []
        if self.opening_1316 is None:
            self.opening_1316 = wrappers
        parts = ["战斗进入"]
        if d.get("battle_mode") is not None:
            parts.append(f"mode={d.get('battle_mode')}")
        if d.get("battle_id"):
            parts.append(f"battle_id={d.get('battle_id')}")
        if d.get("max_round"):
            parts.append(f"max_round={d.get('max_round')}")
        if d.get("weather_id"):
            parts.append(f"weather={d.get('weather_id')}")
        if d.get("is_reconnect"):
            parts.append("reconnect")
        self._emit(ri, " | ".join(parts))
        self._maybe_emit_battle_start(ri)

    def _on_round_start(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x131A BattleRoundStartNotify - 回合开始通知。"""
        d = obj.get("detail") or {}
        wrappers = d.get("wrappers") or []
        if self.opening_131a is None and len(wrappers) >= 2:
            self.opening_131a = wrappers
        if self._phase == BattlePhase.ACTIVE:
            parts = [f"回合开始: round={d.get('round')}"]
            if d.get("state_type") is not None:
                parts.append(f"state_type={d.get('state_type')}")
            if d.get("series_index"):
                parts.append(f"series={d.get('series_index')}")
            self._emit(ri, " | ".join(parts))
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

    def _on_inner200(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        c = (obj.get("detail") or {}).get("commit") or {}
        self._emit(ri, f"commit: flag={c.get('flag')} code={c.get('code')} event_time_ms={c.get('event_time_ms')}")

    def _on_inner51(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        d = obj.get("detail") or {}
        self._emit(ri, f"inner51: kind={d.get('kind')} value2={d.get('value2')} value3={d.get('value3')}")

    # --- Phase 3 新增 handler ---

    def _on_battle_finish(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x132C BattleFinishNotify - 战斗结算。"""
        d = obj.get("detail") or {}
        result = d.get("result_name") or f"code={d.get('result_code')}"
        parts = [f"★ 战斗结束: {result}"]
        if d.get("rounds"):
            parts.append(f"回合数={d.get('rounds')}")
        if d.get("seconds"):
            parts.append(f"用时={d.get('seconds')}秒")
        if d.get("is_surrender"):
            parts.append("投降")
        self._emit(ri, " | ".join(parts))
        # 输出战后宠物状态
        for p in (d.get("finish_pet_infos") or []):
            self._emit(ri, f"  战后宠物: gid={p.get('pet_gid')} "
                          f"HP={p.get('remain_hp')}/{p.get('battle_max_hp')} "
                          f"能量={p.get('remain_energy')}")
        self._reset_battle_state()

    def _on_force_finish(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x132D BattleForceFinishNotify - 强制结束。"""
        d = obj.get("detail") or {}
        self._emit(ri, f"★ 战斗强制结束: reason={d.get('reason')}")
        self._reset_battle_state()

    def _on_ai_skill(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x13F6 AiSelectSkillNotify - AI 选技能提示。"""
        d = obj.get("detail") or {}
        sname = d.get("skill_name") or d.get("skill_id")
        self._emit(ri, f"AI技能提示: pet={d.get('pet_id')} skill={sname} "
                      f"hint_level={d.get('hint_level')} cost={d.get('cost_energy')}")

    def _on_role_leave(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x132A RoleLeaveNotify - 角色离场。"""
        d = obj.get("detail") or {}
        self._emit(ri, f"角色离场: uin={d.get('player_uin')} reason={d.get('reason')}")

    def _on_emoji(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x1334 EmojiNotify - 战斗表情。"""
        d = obj.get("detail") or {}
        self._emit(ri, f"战斗表情: emoji={d.get('emoji')} "
                      f"from={d.get('src_uin')} -> {d.get('aim_uin')}")

    def _on_catch_rsp(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x133C CatchConfirmRsp - 捕捉结果。"""
        d = obj.get("detail") or {}
        parts = [f"捕捉结果: ret={d.get('ret_code')}"]
        if d.get("base_ball_num") is not None:
            parts.append(f"剩余球={d.get('base_ball_num')}")
        if d.get("boss_shiny"):
            parts.append(f"闪光={d.get('boss_shiny')}")
        self._emit(ri, " | ".join(parts))

    def _on_auto_cmd(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x1326 ChangeAutoCmdNotify - 自动战斗切换。"""
        d = obj.get("detail") or {}
        self._emit(ri, f"自动战斗切换: auto={d.get('auto_flag')}")

    def _on_round_flow(self, ri: int, record: dict[str, Any], obj: dict[str, Any]) -> None:
        """0x1312 RoundFlowNotify - 回合流通知。"""
        d = obj.get("detail") or {}
        ws = d.get("wrappers") or []
        if ws:
            self._emit(ri, f"回合流通知: wrappers={len(ws)}")
            if self._phase == BattlePhase.ACTIVE:
                self._emit_snapshot(ri, ws)

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
                              f"pet_id={it.get('pet_id')} base_id={it.get('base_id')} 属性={self._fmt_types(it)} "
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
        if detail.get("effect_names"):
            parts.append("状态=" + "/".join(str(x) for x in detail["effect_names"]))
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
        suffix = ""
        if d.get("skill_energy_cost") is not None:
            suffix = f",cost={d.get('skill_energy_cost')}"
        return f"{name}({sid}{suffix})" if sid is not None else name

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
            name = it.get("skill_name") or proto.skill_name(sid) or str(sid)
            extras = [f"aux26={it['aux26']}" if it.get("aux26") is not None else "",
                      f"aux27={it['aux27']}" if it.get("aux27") is not None else ""]
            suffix = "[" + ",".join(e for e in extras if e) + "]" if any(extras) else ""
            parts.append(f"{slot}:{name}({sid}){suffix}")
        return "; ".join(parts) if parts else "无"

    def _slot_key(self, w: dict[str, Any]) -> int:
        slot = w.get("slot")
        return int(slot) if slot is not None else -1

    def _reset_battle_state(self) -> None:
        self._phase = BattlePhase.WAITING_PAIR
        self.opening_pair = None
        self.opening_1316 = None
        self.opening_131a = None
        self.active_friendly_slot = None
        self.active_enemy_slot = None

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
