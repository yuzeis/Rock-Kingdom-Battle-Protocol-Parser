# RKPP Opencode

## 1. 文档范围

本文档描述 Ver1.3 当前已经落实到代码中的 opencode 解析策略，重点覆盖：

- BE21 外层结构
- `0x4013` 解密后 outer record 结构
- schema-driven opcode 命名与摘要路径
- 保留硬编码语义提取的 opcode
- `0x0414` inner message 容器
- `opencode_summary.csv` 与 relay event 的字段约定

本文档不展开 battle reporter 的控制台展示逻辑；那部分见 [README.md](./README.md) 和 [Server.md](./Server.md)。

---

## 2. 外层封装

### 2.1 BE21 帧

TCP 重组后，当前按 BE21 帧切分。

已确认规则：

- 魔数：`BE 21`
- 固定头长度字段存在
- 当前核心关注命令：
  - `0x1002`
  - `0x4013`

### 2.2 `cmd = 0x1002`

当前主要用途是提取会话 key。

现行规则：

- 从 `header_extra[2:18]` 读取 16 字节
- 作为 `AES-128-CBC` 的 key

### 2.3 `cmd = 0x4013`

当前作为真正业务承载包。

现行规则：

- `body[0:16]` -> `IV`
- `body[16:]` -> ciphertext
- 算法 -> `AES-128-CBC`

若密文长度不是 16 字节对齐，则直接视为异常包。

---

## 3. 解密后 outer record

### 3.1 s2c

当前按以下结构解析：

- `body[0:4]` -> `opcode`
- `body[4:6]` -> 固定标识 `0x55AA`
- `body[6:10]` -> `subtype`
- `body[10:]` -> payload

进入 payload 的 proto 树解析前，会先尝试移除 TSF4G 尾巴。

### 3.2 c2s

当前标准路径按以下结构解析：

- `body[0:4]` -> `magic`
- `body[4:8]` -> `raw opcode`
- `body[8:10]` -> 固定标识 `0x3963`
- `body[10:14]` -> `req_seq`
- `body[14:]` -> payload

当前已确认部分 c2s 包使用 `0x0001xxxx` 形式的 32 位 opcode。  
因此 Ver1.3 会同时保留：

- `raw_opcode`
- `raw_opcode_hex`
- `opcode_normalized`

并在命中 `0x0001xxxx` 时，把低 16 位作为实际语义 opcode 使用。

### 3.3 c2s 特殊分支

当前保留一个非常窄的特殊分支给短心跳响应：

- 通过固定控制字节识别
- `opcode` 位于 `body[6:8]`
- 当前仅确认 `0x013E`

除该分支外，未命中 `0x3963` 的 c2s 包当前不会再走旧的宽松兜底，以避免把未知格式误判成已支持协议。

---

## 4. TSF4G 尾巴处理

当前实现兼容带 marker 的变长 TSF4G 尾巴。

当前已观察到的实际尾长包括：

- `...tsf4g\x06`
- `...tsf4g\x08`
- `...tsf4g\x09`
- `...tsf4g\x0A`
- `...tsf4g\x0E`
- `...tsf4g\x12`
- `...tsf4g\x01`

Ver1.3 的处理方式是：

- 若尾部命中 `tsf4g<N>`，则按最后 1 字节 `N` 表示的总尾长剥离
- 同时记录 `payload_trailer_len`
- 保留对 `...tsf4g\x01` 和小范围 PKCS7 形式的兼容

这块逻辑的目的不是实现通用 PKCS7，而是兼容腾讯这类带 marker 的历史尾巴格式，并修正 live-decode 中正文被尾巴污染的问题。

---

## 5. proto 解析与 schema 主路

### 5.1 底层 proto 树

`rkpp_proto.py` 当前仍负责：

- `read_varint()`
- `parse_proto_message()`
- `field_groups()`
- outer record 解析

其中：

- `field_groups()` 已带缓存
- `parse_proto_message()` 已增加 `max_fields=5000`

### 5.2 schema 数据来源

`rkpp_analysis.py` 使用：

- `Data/opcode.json`
- `Data/proto_schema.json`

当前数据规模：

- opcode：1497
- schema messages：3232
- schema enums：915

### 5.3 schema summary 行为

对未命中硬编码 override 的 opcode，当前统一返回：

- `summary_kind = schema_decoded`

摘要对象包含：

- `opcode_hex`
- `opcode_name`
- `opcode_desc`
- `message`
- `schema_found`
- `schema_fields`
- `decoded`
- `decoded_preview`

`summary_text` 会优先内联：

- 简单标量字段
- 一层嵌套标量字段
- `acts[0]=xxx` 这种列表中的单键动作名

---

## 6. 保留硬编码语义提取的 opcode

当前只有以下 opcode 继续保留专门语义提取：

- `0x0102`：开场阵容 / metadata
- `0x01A9`：客户端操作候选
- `0x0220`：handle
- `0x130B`：客户端动作选择
- `0x130C`：服务端动作确认 / 结果
- `0x1312`：round flow
- `0x1316`：battle enter
- `0x131A`：round start
- `0x1322`：服务端动作广播
- `0x1324`：行动结算
- `0x132C`：战斗结束
- `0x13F3`：preplay
- `0x13F4`：面板刷新
- `0x13FC`：pvp perform

保留它们的原因是这些包不只是字段翻译，还包含：

- 技能 / 动作归因
- 状态 wrapper 提取
- 能量变化整理
- 伤害事件归并
- 特殊动作识别
- 胜负结果语义

---

## 7. `0x0414` inner message

### 7.1 当前专门注册的 inner

以下 `inner_message_id` 仍保留硬编码提取：

- `390` -> `inner390_pair`
- `200` -> `inner200_commit`
- `51` -> `inner51_event`
- `1` -> `inner1_effect`

### 7.2 当前 dispatch 规则

对于 `opcode = 0x0414`：

1. 先提取 `inner_message_id`
2. 如果命中 `_INNER_REGISTRY`，走专用语义提取
3. 如果未命中，不再返回 `inner_unknown`
4. 直接回落到 schema summary
5. 并保留 `inner_message_id`

### 7.3 已确认被 schema 良好覆盖的典型 inner

在当前样本中，以下 inner 已能通过 schema 路径直接辨认：

- `11` -> `client_move`
- `35` -> `sync_player_status`
- `173` -> `throw_catch_notify`
- `31` -> `update_actor_logic_status`
- `2` -> `actor_leave`

### 7.4 典型摘要样式

`summary_text` 现在会直接显示：

- `0x0414 | ZoneScenePlayActsNotify | acts[0]=client_move | ...`
- `0x0414 | ZoneScenePlayActsNotify | acts[0]=sync_player_status | ...`

---

## 8. 特殊非 protobuf 控制帧

当前已确认以下 opcode 不应直接按 protobuf 线格式解析：

- `0x013D`：`ZoneSceneHeartbeatNty`
- `0x013F`：`ZoneSceneHeartbeatResultNty`

Ver1.3 已为其增加专门的二进制定长解析：

- `0x013D` -> `heartbeat_seq`、`server_logic_tick_ivl`
- `0x013F` -> `ret_info.ret_code`、`heartbeat_seq`、`server_time`、`trans_delay_time`、`avg_trans_delay_time`、`server_logic_frame`

因此这两类包在当前离线实跑中不再产生伪 `root_clean=False`。

---

## 9. `opencode_summary.csv`

当前会额外输出一份面向下游消费的精简 CSV：

- 文件名：`opencode_summary.csv`
- 列：
  - `opencode`
  - `meaning`
  - `content`

字段含义：

- `opencode`：`opcode_hex` 优先，否则用整数 opcode
- `meaning`：`opcode_name | opcode_desc`
- `content`：优先使用 `decoded_json`，其次 `summary_json`、`summary_text`、`root_json`

这份输出由 `build_opcode_summary()` 统一构造，CSV 和 relay server 共用同一套摘要规则。

---

## 10. relay event 结构

relay server 推送的事件对象当前包含：

- `row_index`
- `captured_at`
- `flow_id`
- `direction`
- `seq`
- `opencode`
- `opcode`
- `opcode_name`
- `meaning`
- `summary_kind`
- `summary_text`
- `content`

其中 `content` 在 relay 路径里会优先做 JSON 反序列化，便于前端直接消费。

---

## 11. 当前仍未完全定论的部分

以下内容当前不建议视为最终协议定论：

- `inner 51` 的完整业务语义
- `inner 1` 内部各 `argX` 的正式命名
- `0x0220.handle` 的最终定位
- 部分 `0x0414` acts 中扩展字段的完整业务归属
- 少量 `field_xxxx` 形式的 schema raw 字段

当前策略是：

- 能确认的字段尽量保留正式命名
- 不能确认的字段保持中性命名或 schema 原名
- 尽量避免再引入没有证据支撑的硬编码字段语义
