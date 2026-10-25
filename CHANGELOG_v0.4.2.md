# v0.4.2 变更

> 基线：v0.4.1（详细修复对照见 `CHANGELOG_v0.4.1.md`）
> 本版本**无功能变更**，仅元数据与工程文件调整。

## 变更

| 项 | 说明 |
|---|---|
| 作者署名 | `Knn` → `HuangGuaKnn`：`metadata.yaml` / `main.py` 的 register / `LICENSE` 三处统一，与 `astrbot_plugin_Scintilla_MC_Server_Control` 保持一致 |
| Issue 模板 | 新增 `.github/ISSUE_TEMPLATE/`：Bug 报告、数据缺失（华为改版反馈）、功能建议；并关闭空白 issue、引导先读 README |
| 版本号 | v0.4.1 → v0.4.2 |

## 为什么发这个补丁版本

应用市场展示的作者信息来自**提交审核时的解析快照**，仓库改动不会自动同步；
而市场按 `version` 判断更新，同版本号通常不会刷新。
因此升一个补丁版本重新提交，让作者名变成全名。

## 升级说明

代码逻辑与 v0.4.1 **完全一致**，可直接覆盖升级，无需重新登录。
