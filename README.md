# Roco-Kingdom-Protocol-Parser

**项目名称：** Roco-Kingdom-Protocol-Parser  
**项目简称：** RKPP  
**版本：** Rock Kingdom Battle Protocol Parser-Ver1.3(Erneuerung)

---

## 项目简介

RKPP（洛克王国战斗协议解析器）是一个用于学习、研究和分析洛克王国战斗相关协议数据结构、字段语义、报文格式及解码流程的开源项目。

本项目旨在为协议研究、数据结构理解、网络数据分析、教学示例与互操作性研究提供一个可审阅、可修改、可复现的参考实现。

Ver1.3(Erneuerung)版本是在 Ver1.2(Zusammenhalt) 基础上的继续整理与修复，重点覆盖项目命名统一、本地离线数据落地、协议语义补强与 live-decode 全流程修正；不对该版本的稳定性做任何担保。

特别感谢https://github.com/P0pola/Roco-Kingdom-World-Data提供的数据，进一步完善了本项目。

假如你认可并且支持作者，请点个Star，感谢~


---

## 文件说明

当前版本主要包含以下内容：

- `rkpp_analyzer.py`：协议分析逻辑
- `rkpp_io.py`：输入输出相关逻辑
- `rkpp_live_tools.py`：入口：实时工具相关逻辑
- `rkpp_network.py`：网络处理相关逻辑
- `rkpp_proto.py`：协议与解码相关逻辑
- `rkpp_reporter.py`：报告输出相关逻辑
- `rkpp_relay.py`：报告输出json服务器
- `Data.py`：项目依赖的数据定义


---

## 本次更新摘要

以下内容为 Ver1.3(Erneuerung) 相对 Ver1.2(Zusammenhalt) 的简要变化，便于后续 Git 提交与版本整理：

- 项目整体由 `RKBPP / rkbpp_*` 统一切换为 `RKPP / rkpp_*`，并将对外名称整理为 `Roco-Kingdom-Protocol-Parser`。
- 运行时数据改为本地 `Data/` 离线数据包，`Data.py` 已统一改为 JSON bundle 主路并保留兼容 fallback。
- 新增并接入多类本地索引数据，包括属性、技能、Buff、宠物、怪物、技能池以及 opcode/protobuf 映射，用于 schema 解码后的名称与语义补全。
- `rkpp_analysis.py`、`rkpp_proto.py`、`rkpp_reporter.py` 已补强 pet / skill / attr / buff / base skill pool / monster active skills 等字段的 enrich 和展示。
- `live-decode` 的外层记录解析已修正：补上可变长度 `TSF4G` 尾巴剥离、c2s `0x0001xxxx` opcode 归一化，以及 `0x013D / 0x013F` 心跳控制帧的专门二进制解析。
- `decoded_packets.csv` 现可额外输出 `raw_opcode`、`raw_opcode_hex`、`opcode_normalized`、`payload_trailer_len`，便于后续继续审查协议外层封装。
- 已完成一轮目录下 `live-decode --read-pcap` 实跑审查，当前样本结果为 `packets=2048`、`rows=1209`、`errors=0`、`listener_errors=0`，并将未知 opcode 与 `root_clean=False` 问题修正到可稳定复现的状态。

---

## 许可协议

本项目采用 **GNU Affero General Public License v3.0 only（AGPL-3.0-only）** 发布。

这意味着：

1. 任何人都可以在遵守 AGPL-3.0-only 的前提下使用、复制、修改和再发布本项目；
2. 如对本项目进行修改并再次分发，必须继续以 AGPL-3.0-only 开源，并提供对应源码；
3. 如将修改后的版本部署为网络服务、在线接口、远程解析平台或其他可供他人通过网络交互使用的形式，亦必须按 AGPL-3.0-only 向相关用户提供对应源码；
4. 再发布或衍生版本必须保留原作者署名、版权声明、`LICENSE` 文件与 `NOTICE` 文件。


---

## 重要用途声明

**作者不支持将本项目用于外挂的行为。**

本项目发布的主要目的仅为：

- 学习研究
- 协议结构分析
- 教学示例
- 互操作性研究
- 安全研究与数据格式理解

请在使用前自行确认你的行为是否符合：

- 适用法律法规
- 服务条款 / 用户协议 / EULA
- 第三方知识产权与相关权利

**如你基于本项目实施任何违反法律法规、违反服务条款、破坏游戏环境或侵害第三方权益的行为，相关风险与责任均由你自行承担。**

---

## 免责声明

本项目按“**原样**”（**AS IS**）提供，不附带任何明示或默示担保，包括但不限于：

- 可用性担保
- 适销性担保
- 特定用途适用性担保
- 不侵权担保
- 安全性担保
- 正确性担保
- 稳定性担保

作者不保证：

- 本项目适用于任何生产环境；
- 本项目一定符合任何游戏、平台或服务商的规则；
- 本项目不存在缺陷、错误、兼容性问题或法律风险；
- 本项目可安全用于任何线上、商业或公开环境。

因使用、修改、分发、部署本项目所导致的任何直接或间接后果，包括但不限于：

- 账号处罚
- 服务封禁
- 数据丢失
- 系统损坏
- 第三方索赔
- 合同争议
- 行政责任
- 民事责任
- 刑事风险

均由使用者自行承担，**原作者不承担任何责任**。

---

## 侵权与联系说明

如果你认为本项目中的内容存在侵权、权利冲突或其他不适宜公开的问题，请联系作者处理。作者在核实后会尽快处理相关问题；如情况属实，将尽快删除、修改或下线相关内容。

---


## 作者

**花吹雪又一年**
