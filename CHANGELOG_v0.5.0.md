# v0.5.0-rc.1 变更

> 基线：v0.4.2（v0.4.1 的逐条修复对照见 `CHANGELOG_v0.4.1.md`）
> 本版是**预发布（release candidate）**：tag 形状（`-rc.1`）与 GitHub Release 均标记为 pre-release。

## 破坏性变更（升级前必读）

**权限默认收紧**，升级后以下场景会从「可用」变成「不可用」：

| 场景 | v0.4.2 | v0.5.0-rc.1 默认 |
|---|---|---|
| 私聊 + 管理员 | 可用 | **可用**（不变） |
| 私聊 + 非管理员 | 可用 | **不可用** |
| 群聊 + 任何人 | 可用 | **不可用** |

如需恢复某个群聊，把该会话的 UMO 填进「额外允许的会话 UMO」（仍要求管理员身份）。

配置层面向后兼容：只新增一个 `permission_settings` 分组，原有 17 项一字未改。

## 新增 · 权限与可见范围

三层正交设计，**成员维度是硬门，会话维度的白名单救不了它**：

| 配置项 | 默认 | 作用 |
|---|---|---|
| 允许私聊 | 开 | 私聊会话中提供健康数据工具 |
| 允许群聊 | 关 | 群聊会话中提供健康数据工具 |
| 仅 AstrBot 管理员可用 | 开 | 成员硬门，对所有会话生效（含 UMO 白名单） |
| 额外允许的会话 UMO | 空 | 只覆盖上面两个开关，**不覆盖管理员限制** |

两层实现：

1. `on_llm_request` 里把 8 个健康工具从本次请求的工具集移除 —— 省 token，且模型不会徒劳尝试
2. 每个工具函数第一行兜底 —— 防止 cron / 后台任务 / 插件自调用 / MCP 等绕过路径

UMO 格式在加载时校验（`platform:MessageType:session_id`），非法条目报错并忽略，不影响其它合法条目。

## 工程加固

- **错误信息脱敏**：新增 `hw_privacy.redact_error()`，11 条规则清洗 token / cookie / 私钥 / URL / 本机路径 / 邮箱 / AstrBot 会话标识 / 控制字符；6 个模块 26 处调用点接入
- **隐私闸门**：新增 `scripts/privacy_gate.py`，fail-closed，源码树与发布包双查（禁止后缀 / 私钥 / 已知 token 格式 / 敏感字段赋值 / cookie 对 / 本机路径 / 归档体积）；敏感键名复用单一来源（含 `castgc` / `sid` / `hwid_cas_sid`），另加 CASTGC 值特征规则
- **确定性打包**：新增 `scripts/build_release.py`，显式文件清单 + 版本号从 `metadata.yaml` 单一来源提取
- **CI**：新增 `.github/workflows/checks.yml`，Python 3.11/3.12 矩阵（隐私闸门 → pytest → compileall → 打包 → 归档闸门），外加 `astrbot-runner-contract` 双通道契约测试
- **测试入库**：178 条验收用例 + 39 条脱敏单测 + 41 条权限测试，合计 **259 passed**
- `metadata.yaml` 补 `short_desc` 与 `astrbot_version`（`>=4.26.0,<5`：`astrbot.api.web` 自 4.26.0 起提供，更早版本会在 import 阶段失败）

## 升级说明

覆盖升级即可，无需重新登录。升级后请在 WebUI 的「权限与可见范围」确认默认值符合预期。
