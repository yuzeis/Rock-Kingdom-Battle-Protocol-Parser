# RKPP Server 使用说明

## 1. 功能概览

`opencode-server` 模式延续自旧版本；Ver2.0 主要对应当前仓库中的项目命名统一、本地离线数据接入，以及 live-decode outer record 修复后的配套说明。

该模式适合：

- 本地前端页面
- 本地调试工具
- 旁路分析脚本
- 二次开发用的消费端

它不是独立抓包程序，而是建立在现有解析链路之上：

1. 抓包或离线回放
2. 解密
3. opcode / schema 解析
4. 输出 CSV
5. 同时通过 HTTP 推送摘要事件

Ver2.0 相对旧版本的直接影响是：

- `decoded_packets.csv` 中会多出 `raw_opcode`、`raw_opcode_hex`、`opcode_normalized`、`payload_trailer_len`
- c2s `0x0001xxxx` 将在 relay / summary 层按低 16 位 opcode 命名
- `0x013D / 0x013F` 心跳类控制帧现在能得到稳定摘要，不再在离线回放中大量出现伪异常

---

## 2. 启动方式

### 2.1 实时抓包

```powershell
python .\rkpp_live_tools.py opencode-server --iface "以太网" --port 8195 --key 59484438426252355a494e7467545057 --relay-host 127.0.0.1 --relay-port 8765
```

### 2.2 离线 pcap 回放

```powershell
python .\rkpp_live_tools.py opencode-server --read-pcap .\live_capture.pcap --key 59484438426252355a494e7467545057 --out-dir .\relay_replay --relay-port 8765
```

### 2.3 交互式模式

直接运行：

```powershell
python .\rkpp_live_tools.py
```

在菜单里选择：

- `4 = opencode中转Server`

---

## 3. 启动后生成的文件

输出目录下会生成：

- `capture.log`
- `decoded_packets.csv`
- `opencode_summary.csv`
- `key.txt`
- 实时模式下还会有 `live_capture.pcap`

如果 server 正常启动，日志里会出现类似：

```text
[relay] listening url=http://127.0.0.1:8765 endpoints=/health,/latest,/events
```

如果默认端口 `8765` 已被本机其他程序占用，Ver2.0 当前会自动顺延尝试后续可用端口，并在日志中输出类似：

```text
[relay] requested port 8765 unavailable, fallback port=8766
```

---

## 4. HTTP 接口

当前 server 提供 3 个接口。

### 4.1 `GET /health`

返回服务状态：

```json
{
  "status": "ok",
  "time": "2026-04-11 15:00:00",
  "events": 128,
  "history": 128,
  "clients": 1
}
```

字段含义：

- `events`：累计推送事件数
- `history`：当前历史缓存条数
- `clients`：当前连接中的实时订阅者数量

### 4.2 `GET /latest`

返回最近一批事件，默认 50 条。

示例：

```text
http://127.0.0.1:8765/latest
http://127.0.0.1:8765/latest?limit=10
```

### 4.3 `GET /events`

返回 NDJSON 实时流：

- 先推送最近 50 条历史
- 再持续推送后续新事件

每行一个 JSON 对象。

---

## 5. 事件对象格式

当前单条事件格式为：

```json
{
  "row_index": 441,
  "captured_at": "2026-04-11 14:53:48",
  "flow_id": "192.168.31.179:18946->36.155.236.215:8195",
  "direction": "s2c",
  "seq": 123456,
  "opencode": "0x1324",
  "opcode": 4900,
  "opcode_name": "ZoneBattleActionResolveNotify",
  "meaning": "ZoneBattleActionResolveNotify | 战斗行动结算通知",
  "summary_kind": "action_resolve",
  "summary_text": "我方行动 | 技能=火焰箭(7040370) | 能量变化=-2 -> 1 | 伤害=211",
  "content": {
    "primary_skill": {
      "skill_id": 7040370
    }
  }
}
```

字段说明：

- `opencode`：优先用十六进制 opcode 文本
- `meaning`：`opcode_name + opcode_desc`
- `summary_kind`：当前摘要来源
- `summary_text`：适合日志和列表展示的短摘要
- `content`：优先是 schema 解码后的 JSON 对象，否则回落到 summary / root 内容

---

## 6. 典型用法

### 6.1 浏览器查看最近结果

打开：

```text
http://127.0.0.1:8765/latest?limit=20
```

如果日志显示已回退到其他端口，请把上面的 `8765` 替换成实际监听端口。

### 6.2 PowerShell 实时订阅

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8765/events" -UseBasicParsing
```

### 6.3 curl 实时订阅

```powershell
curl.exe http://127.0.0.1:8765/events
```

### 6.4 Python 客户端

```python
import json
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8765/events") as resp:
    for raw in resp:
        if not raw.strip():
            continue
        event = json.loads(raw.decode("utf-8"))
        print(event["opencode"], event["summary_text"])
```

---

## 7. 当前 server 行为约束

当前实现是轻量本地 relay，不是完整网关服务。需要注意：

- 默认只建议监听 `127.0.0.1`
- 无鉴权
- 无 CORS 头
- `/events` 客户端队列满时会丢事件
- `/events` 先发 latest 再进入实时流，历史与实时之间存在很小的竞态窗口

因此更适合作为：

- 本地调试桥
- 前端原型数据源
- 二次开发阶段的消费接口

不建议直接暴露到公网。

---

## 8. 和 CSV 的关系

server 事件和 `opencode_summary.csv` 共用同一个摘要构造逻辑：

- `rkpp_io.build_opcode_summary()`

因此通常可以这样理解：

- 想做离线导入：读 `opencode_summary.csv`
- 想做在线界面：连 `/events`
- 想拿完整调试上下文：读 `decoded_packets.csv`

如果你要审查 outer record 层的封装问题，优先看 `decoded_packets.csv`，因为新增字段只在这份明细表中保留：

- `raw_opcode`
- `raw_opcode_hex`
- `opcode_normalized`
- `payload_trailer_len`

---

## 9. 推荐使用方式

如果你只是自己看 battle 行为，优先用：

- `battle-analyze`

如果你要把结果接给其他程序，优先用：

- `opencode-server`

如果你要离线核对某份抓包，推荐：

1. 先 `live-decode --read-pcap`
2. 再 `opencode-server --read-pcap`
3. 用 `/latest` 或 `opencode_summary.csv` 看摘要
4. 必要时回看 `decoded_packets.csv`
