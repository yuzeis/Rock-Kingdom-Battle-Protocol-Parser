# Roco-Kingdom-Protocol-Parser

**项目名称：** Roco-Kingdom-Protocol-Parser  
**项目简称：** RKPP  
**版本：** Rock Kingdom Battle Protocol Parser-Ver2.0(Notzeit)

RKPP 是一个面向学习、协议研究和离线复现的洛克王国战斗协议解析器。

## 当前能力

- `capture-key`：抓取首个 `0x1002` ACK 中的会话 key
- `live-decode`：抓包或离线读取 pcap，输出 `decoded_packets.csv`
- `battle-analyze`：输出战斗过程摘要
- `opencode-server`：通过本地 HTTP / NDJSON relay 提供事件流

## 仓库结构

- `rkpp_live_tools.py`：CLI 入口和会话编排
- `rkpp_analyzer.py`：主分析器
- `rkpp_network.py`：TCP 重组、BE21 分帧、AES-CBC 解密、key 处理
- `rkpp_proto.py`：兼容门面
- `rkpp_proto_core.py`：传输层与 proto-tree 解析
- `rkpp_proto_battle.py`：战斗语义提取
- `rkpp_analysis.py`：schema-driven 解码与字段补全
- `rkpp_reporter.py`：控制台战斗摘要输出
- `rkpp_relay.py`：本地 HTTP relay
- `rkpp_io.py`：日志、CSV、离线 pcap、交互输入
- `Data.py` / `Data/`：运行时数据访问与离线索引数据包
- `tests/`：回归测试

## 运行依赖

- Python 3.11+
- `scapy`
- `pycryptodome`

```bash
python -m pip install scapy pycryptodome
```

## 快速开始

```bash
python rkpp_live_tools.py --list-ifaces
python rkpp_live_tools.py capture-key --iface "以太网" --out-dir out/key_capture
python rkpp_live_tools.py live-decode --read-pcap sample.pcap --key <16位ASCII或32位hex> --out-dir out/live_decode
python rkpp_live_tools.py battle-analyze --iface "以太网" --key <16位ASCII或32位hex> --out-dir out/battle
python rkpp_live_tools.py opencode-server --read-pcap sample.pcap --key <16位ASCII或32位hex> --out-dir out/relay
```

## 使用边界

本项目仅面向学习、研究、教学示例、互操作性研究与安全研究。  
作者不支持将本项目用于外挂、破坏游戏环境或其他违规用途。

## License

本项目采用 **AGPL-3.0-only**。请同时遵守 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

## 致谢

- [P0pola/Roco-Kingdom-World-Data](https://github.com/P0pola/Roco-Kingdom-World-Data)

## 作者

**花吹雪又一年**
