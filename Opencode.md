# RKBPP Opencode

## 1. 文档范围

本文档仅记录当前版本中已经完成提取和验证的协议层结论，内容聚焦于：

- 外层 BE21 帧结构
- `0x4013` 解密后报文结构
- 已识别的业务 `opcode`
- `0x0414` 容器内的 `inner message`
- 当前使用的字段命名约定与识别规则

本文档不涉及工具实现细节、代码结构说明或运行方式说明。

对于尚未完全确认的语义，统一使用 `[推测]` 标记，并保留中性字段名，避免过早固化命名。

---

## 2. 外层封装

### 2.1 BE21 帧

TCP 流重组后，当前解析器按 BE21 帧进行切分。

已确认特征如下：

- 帧头魔数：`33 66`
- 固定头长度：`21` 字节
- 当前主要关注的 `cmd`：
  - `0x1002`
  - `0x4013`

### 2.2 `cmd = 0x1002`

`0x1002` 目前主要用于提取会话 key。

当前实现采用如下规则：

- 从 `header_extra[2:18]` 读取 16 字节数据
- 将其作为 `AES-128-CBC` 的 key 使用

### 2.3 `cmd = 0x4013`

`0x4013` 为实际业务负载承载包。

当前解密规则如下：

- `body[0:16]` 为 `IV`
- `body[16:]` 为密文
- 解密算法为 `AES-128-CBC`

当前实现要求：

- 密文部分必须满足 16 字节对齐
- 若不满足，则直接判为异常包

---

## 3. `0x4013` 解密后报文结构

### 3.1 服务端到客户端方向 `s2c`

当前按如下格式解析：

- `body[0:4]` -> `opcode`
- `body[4:6]` -> 固定标识 `0x55AA`
- `body[6:10]` -> `subtype`
- `body[10:]` -> 业务 payload

在进入后续 proto 解析前，会先移除尾部 `tsf4g` padding。

### 3.2 客户端到服务端方向 `c2s`

当前标准格式按如下结构解析：

- `body[0:4]` -> `magic`
- `body[4:8]` -> `opcode`
- `body[8:10]` -> 固定标识 `0x3963`
- `body[10:14]` -> `req_seq`
- `body[14:]` -> 业务 payload

### 3.3 `c2s` 兜底解析

对于未命中 `0x3963` 的 `c2s` 包，当前保留一条兜底解析路径：

- 若包长满足基本条件，则仍使用 `body[4:8]` 作为 `opcode`
- 其余部分直接作为 payload 进入后续解析

该分支用于兼容非标准样本或格式变体，不代表该结构已经被完全确认。

---

## 4. 通用字段约定

### 4.1 side 映射

当前已确认映射如下：

- `1` -> 我方
- `401` -> 敌方

### 4.2 技能 ID 归一化

当前样本中，部分技能 ID 以放大 100 倍的形式出现。

现行归一化规则：

- 若值大于等于 `100000`
- 且可被 `100` 整除
- 则按 `skill_id_x100 / 100` 还原为实际 `skill_id`

因此文档中通常同时保留：

- `skill_id_x100`
- `skill_id`

### 4.3 未定名字段

对于语义尚未完全确认的字段，统一采用中性占位命名，例如：

- `arg1`
- `arg2`
- `arg3`

该命名方式表示“字段已被观察到并稳定提取”，不表示字段无意义。

---

## 5. 已识别业务 `opcode`

### 5.1 `0x0102`

当前解释：战斗开场阵容初始化包。

已稳定提取字段：

- 玩家信息
  - `user_id`
  - `uin_or_openid`
  - `nickname`
- 配置区
  - `pet_ids`
  - `active_pet_id`
- 阵容实体
  - `slot`
  - `pet_id`
  - `name`
  - `level`
  - `types`
  - `stats`
  - `skills`
  - `equipped_skills`

### 5.2 `0x1316`

当前解释：状态包装包，提取结果为 `state wrapper` 列表。

单个 wrapper 当前稳定字段：

- `name`
- `level`
- `slot`
- `pet_id`
- `types`
- `battle_stats`
- `battle_max_hp`
- `current_hp`
- `dynamic_skills`

语义判断：

- `[推测]` 更偏向开场阶段的阵容或可见状态同步

### 5.3 `0x131A`

当前解释：状态包装包，提取结果同样为 `state wrapper` 列表。

单个 wrapper 当前稳定字段与 `0x1316` 一致。

语义判断：

- `[推测]` 更偏向当前上场实体快照或战斗中的面板刷新

### 5.4 `0x130B`

当前解释：客户端动作选择包。

优先提取普通技能引用，字段包括：

- `actor_side`
- `target_side`
- `skill_id_x100`
- `skill_id`
- `skill_name`

额外字段：

- `command_slot`
- `command_flag`
- `arg6`

若未识别为普通技能，则继续按特殊动作进行匹配。

当前已接入的特殊动作：

- 愿力强化
- 能量瓶
- 换人

### 5.5 `0x1322`

当前解释：服务端动作广播包。

解析策略与 `0x130B` 基本一致：

- 优先提取普通技能
- 否则尝试识别特殊动作

当前额外提取字段：

- `battle_token`

### 5.6 `0x1324`

当前解释：行动结算包。

该包不是单一事件，而是由一组 `entry` 构成。

当前已识别的 `entry.type` 如下：

- `1` -> `skill_cast`
- `4` -> `damage`
- `2` -> `effect_apply`
- `3` -> `effect_stage`
- `7` -> `defeat`
- `10` -> `effect_link`

包级字段：

- `packet_state`
- `packet_phase`
- `packet_index`
- `entries`
- `primary_skill`
- `energy_event`
- `damage_event`
- `effect_ids`
- `has_defeat`

各类 entry 当前提取重点如下。

`skill_cast`

- 技能引用
- `energy_delta`
- `energy_after`

`damage`

- 技能引用
- `damage`
- `overflow`
- `damage_target_side`
- `target_hp_after`

`effect_apply`

- `actor_side`
- `target_side`
- `effect_id`
- `effect_stage`
- `related_skills`

`effect_stage`

- `actor_side`
- `target_side`
- `effect_id`
- `effect_base`

`defeat`

- `actor_side`
- `target_side`
- `defeat_arg`

`effect_link`

- `actor_side`
- `target_side`
- `effect_id`

### 5.7 `0x13F4`

当前解释：面板刷新包。

当前稳定提取内容主要包括：

- 技能列表刷新
- 能量变化

当前字段：

- `packet_state`
- `packet_phase`
- `packet_index`
- `skill_options`
- `energy_delta`
- `energy_after`
- `battle_token`

当前额外启发式规则：

- 若 `energy_after == 10`
- 且 `energy_delta > 0`

则附加：

- `action_name = 能量瓶`

该规则属于经验归纳，不属于已确认格式定义。

### 5.8 `0x130C`

当前解释：动作确认/动作结果包。

当前尽量提取如下信息：

- 技能引用或特殊动作名
- `battle_token`
- `current_hp`
- `energy_after`
- `result_code`
- `state_wrappers`

若未直接识别出特殊动作，则还会结合 `state_wrappers` 中的动态技能做补充推断。

当前存在一条启发式规则：

- 若 wrapper 中出现技能 `7700014`
- 则将动作推断为 `愿力强化`

### 5.9 `0x1314`

当前解释：回合控制包。

当前仅稳定提取：

- `phase_code`

各 `phase_code` 与业务阶段的映射尚未整理为正式对照表。

### 5.10 `0x01A9`

当前解释：客户端操作候选包。

当前稳定提取字段：

- `candidate_ids`
- `primary_id`
- `raw_kind`
- `actor_token`

现阶段仅能确认其承载客户端操作候选信息，`raw_kind` 的完整语义尚未完全归档。

### 5.11 `0x0220`

当前仅稳定提取：

- `handle`

该字段与实体索引、快照句柄或其他内部引用体系的对应关系尚未完全确认。

### 5.12 `0x0414`

当前解释：`inner message` 容器包。

该包自身不是最终业务语义层，实际意义取决于内部 `message_id`。

---

## 6. `0x0414` 内部 `inner message`

### 6.1 `message_id = 390`

当前解释：对位建立信息。

当前稳定提取字段：

- `pair_ctx`
- `friendly.pet_id`
- `friendly.name`
- `friendly.side_flag`
- `enemy.pet_id`
- `enemy.name`
- `enemy.side_flag`

同时保留若干未定名字段：

- `arg1`
- `arg3`
- `arg4`
- `arg5`
- `arg6`

该消息的核心价值在于建立我方与敌方的首发对应关系。

### 6.2 `message_id = 200`

当前解释：提交确认类事件。

当前稳定提取字段：

- `pair_ctx`
- `commit.flag`
- `commit.arg2_ms_like`
- `commit.event_time_ms`
- `commit.code`

### 6.3 `message_id = 51`

当前解释：事件通知类消息。

当前稳定提取字段：

- `token`
- `kind`
- `value2`
- `value3`

目前仅完成稳定字段提取，具体业务含义尚未最终命名。

### 6.4 `message_id = 1`

当前解释：效果或状态变更消息。

当前提取结果分为两部分。

`header`

- `kind`
- `actor_token`
- `actor_aux`
- `actor_ref`
- `target_ctx`
- `arg10`
- `arg11`

`effect`

- `effect_id`
- `code`
- `amount`
- `arg10`
- `arg12`
- `arg13`
- `arg15`
- `arg16`
- `arg27`
- `arg31_signed`
- `arg32`

当前阶段仅确认其与状态、生效或数值变化强相关，尚未完成逐字段业务定名。

---

## 7. 特殊动作识别规则

当前代码使用两套并行规则识别特殊动作。

### 7.1 基于 `command_flag + command_slot`

- `(8, 7)` -> 愿力强化
- `(3, 8)` -> 能量瓶
- `(2, 9)` -> 换人

### 7.2 基于 payload 中的 `kind + branch`

- `(8, 8)` -> 愿力强化
- `(3, 4)` -> 能量瓶
- `(2, 3)` -> 换人

说明：

- 当前特殊动作识别不是依赖单一字段
- 而是依赖多组结构特征的组合判断

---

## 8. `state wrapper` 结构

`state wrapper` 目前出现于如下包中：

- `0x1316`
- `0x131A`
- `0x130C`

当前可稳定提取字段：

- `name`
- `level`
- `slot`
- `pet_id`
- `types`
- `battle_stats`
- `battle_max_hp`
- `current_hp`
- `dynamic_skills`

其中 `dynamic_skills` 当前重点字段为：

- `skill_id_x100`
- `skill_id`
- `slot`
- `aux26`
- `aux27`

当前阶段可将 wrapper 理解为战斗单位状态快照。

---

## 9. 当前未完全定论的部分

以下结论目前不应视为最终定稿：

- `0x1316` 与 `0x131A` 的严格职责边界
- `0x01A9.raw_kind` 的完整枚举和业务含义
- `0x1314.phase_code` 的正式映射关系
- `inner 51` 中各值的具体语义
- `inner 1` 中各 `argX` 字段的正式业务命名
- `0x0220.handle` 与实体或快照系统的精确对应关系

这些项目目前已经具备观察基础，但尚不建议在文档中作最终命名。

---

## 10. 后续优先分析目标

若后续继续从协议层推进，建议优先分析如下对象：

- `0x1324`
  原因：结算信息密度最高，最接近完整行动语义
- `0x13F4`
  原因：与面板刷新、技能列表和能量变化直接相关
- `0x130B / 0x1322 / 0x130C`
  原因：三者可串联为动作选择、广播与确认链路
- `0x0414`
  原因：内部 `inner message` 仍有继续扩展空间
