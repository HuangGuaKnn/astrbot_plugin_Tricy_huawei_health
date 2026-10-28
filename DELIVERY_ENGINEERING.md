# 工程加固交付说明（v0.5.0 候选）

> 本文件是交付证据与决策记录，**发版前删除**，未写入 README 索引。
> 对应派活单：`派活单_华为健康插件_工程加固_T1-T6.md`（含 T0 前置任务）。
> 所有命令均在 Windows 11 + PowerShell、`$env:PYTHONIOENCODING="utf-8"` 下执行。
> 文中路径一律使用占位符：`<仓库根>`、`<python>`（AstrBot 自带解释器）、`<AstrBot 安装>`。

---

## 0. 总览

| 任务 | 状态 | 产物 |
|---|---|---|
| T0 | 完成 | `tests/test_v041.py` 两条版本断言改为「三处一致性」比对 + 5 步变异验证 |
| T1 | 完成 | `hw_privacy.py`（222 行）+ `tests/test_hw_privacy.py`（39 条单测）+ 6 模块 26 处调用点 |
| T2 | 完成 | `metadata.yaml` 新增 `short_desc` / `astrbot_version` |
| T3 | 完成 | `scripts/build_release.py`（255 行，确定性打包） |
| T4 | 完成 | `scripts/privacy_gate.py`（645 行，fail-closed 闸门） |
| T5 | 完成 | `.github/workflows/checks.yml` + 178 用例搬进 `tests/` |
| T6 | 完成 | `astrbot-runner-contract` job + 两个契约脚本 + `scripts/resolve_astrbot_ref.py` |
| **P1** | **已修** | 闸门改为复用 `hw_privacy._SENSITIVE_KEYS`（单一真值来源）+ 新增 CASTGC 值特征规则 |
| **P2** | **已修** | CDP 目标地址异常保留 `scheme://host:port`，只丢弃路径与查询串 |

**未 commit、未 push、未动 tag、未改版本号**（`v0.4.2` 四处保持一致）。改动全部留在工作区，等验收人复核。

---

## 0.1 验收反馈整改（P1 / P2）

来源：`整改单_华为健康插件_验收反馈_P1P2.md`。总体结论为「有条件通过」，P1 必修、P2 建议修。

### P1 · 隐私闸门认不出本项目的核心 cookie

**根因**：同一个仓库里两套敏感键名库不一致 —— `hw_privacy.py`（T1）认识 `castgc` / `sid` / `hwid_cas_sid`，`scripts/privacy_gate.py`（T4）不认识。而「cookie 泄露」正是本项目最大的风险面。

**修法**（按整改单第 3 节）：

1. **键名只留一份权威来源**。`privacy_gate.py` 顶部改为从 `hw_privacy` 导入 `_SENSITIVE_KEYS`：

   ```python
   _REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
   if str(_REPOSITORY_ROOT) not in sys.path:
       sys.path.insert(0, str(_REPOSITORY_ROOT))
   try:
       from hw_privacy import _SENSITIVE_KEYS as _SHARED_SENSITIVE_KEYS
   except ImportError:
       print("warning: privacy_gate: 无法从 hw_privacy 导入 _SENSITIVE_KEYS，"
             "回退到内置键名副本；两份清单可能已漂移，请检查 hw_privacy.py。",
             file=sys.stderr)
       _SHARED_SENSITIVE_KEYS = (...内置副本...)
   ```

   导入失败**不是静默**：会在 stderr 打印警告，让「规则漂移」可见。

2. **织进两个现有模式**。`_SHARED_KEY_ALTERNATION` 用 `"|".join(re.escape(k) for k in sorted(keys, key=len, reverse=True))`（长键优先，`hwid_cas_sid` 先于 `sid`），分别拼进 `_SENSITIVE_NAME_PATTERN` 与 `_SENSITIVE_ASSIGNMENT_PATTERN`（后者用 bytes 版）。
   自检：`len(_SHARED_SENSITIVE_KEYS) == 40`；`_SENSITIVE_NAME_PATTERN.fullmatch('CASTGC')` → True；`.fullmatch('sid')` → True。

3. **新增按值特征的规则**（键名被改写/翻译/去掉时仍兜住）：

   ```python
   # Huawei ``CASTGC`` values look like ``TGT-<digits>-<alnum>``.
   _CASTGC_VALUE_PATTERN = re.compile(rb"(?i)(?<![\w-])TGT-\d+-[A-Za-z0-9]{6,}")
   ```

   命中记 `huawei-castgc-literal`，且先过 `_is_placeholder()`（含 `example`/`dummy`/`***` 等标记的放行）。

4. **没有**放宽 `tests/` 的豁免逻辑（那里已跳过内容规则，补键名不会引起误报）。

**A–F 六个样本实测输出**（样本目录在仓库外临时目录，非仓库内容）：

| 样本 | 内容（描述，不贴原文） | 结果 |
|---|---|---|
| **A** 必须拦 | `conn.py`：字典里 JSON 风格写 CASTGC 与 sid 两个 cookie 键值 | `worktree:conn.py:1 [sensitive-value-literal]`<br>`worktree:conn.py:1 [huawei-castgc-literal]`<br>**exit=1** ✅ |
| **B** 必须拦 | `notes.md`：`hwid_cas_sid=` 形式 | `worktree:notes.md:1 [session-cookie-literal]`<br>`worktree:notes.md:1 [sensitive-value-literal]`<br>**exit=1** ✅ |
| **C** 必须拦 | `x.txt`：只有裸值，键名被完全去掉 | `worktree:x.txt:1 [huawei-castgc-literal]`<br>**exit=1** ✅ |
| **D** 必须放行 | `README.md`：`token: example-value` + `password: ***` | `Repository privacy gate: clean (allow_D)`<br>**exit=0** ✅ |
| **E** 必须放行 | 只有 `logo.png`（SHA256 白名单命中） | `Repository privacy gate: clean (allow_E)`<br>**exit=0** ✅ |
| **F** 必须放行 | 正常 Python `def add(a, b): return a + b` | `Repository privacy gate: clean (allow_F)`<br>**exit=0** ✅ |

**不许回归的三项**：真实仓库 `--repository .` → `clean` / exit=0 ✅；`build_release.py` 产物 `--archive` → `clean` / exit=0 ✅；`pytest tests/` → **217 passed** ✅。

### P2 · CDP 目标地址异常丢失诊断价值

**现象**：`hw_auth.py` 里 `redact_error(url)` 会把整条 `ws://host:port/devtools/...` 抹成 `[remote URL]`（`redact_error` 规则 5：任意 URL），连 host:port 一起丢掉。

**修法**：新增模块级 `_cdp_endpoint_for_error(url)`，只保留 `scheme://host:port`，路径与查询串（可能带一次性 token）直接丢弃；host 段再经 `redact_error` 兜一层（万一 host 里混进异常字符）。

```python
parts = urlsplit(url)
endpoint = "%s://%s" % (parts.scheme or "ws", redact_error(parts.hostname or ""))
if port is not None:
    endpoint += ":%d" % port
```

解析失败（无 host、端口非法）时回退到 `redact_error(url)`，保持 fail-closed。

> **与整改单字面写法的一处差异（请复核）**：整改单给的片段是「先拼出 `scheme://host:port`，**再用 `redact_error(endpoint)` 兜一层**」。若照字面对整串 endpoint 再洗一次，`redact_error` 的规则 5（任意 URL → `[remote URL]`）会把 `ws://127.0.0.1:9222` 整个抹掉，**反而违反本条验收标准**（「错误消息里应能看到 `ws://127.0.0.1:9222`」）。实测：
>
> ```
> redact_error('ws://127.0.0.1:9222')  ->  '[remote URL]'
> '127.0.0.1:9222' in 上述结果          ->  False
> ```
>
> 因此改为**只对 host 段**调用 `redact_error`（`redact_error(parts.hostname)`），保留 `scheme://` 与 `:port` 字面量。兜底目的（host 里混进异常字符）仍然达到，且验收标准同时满足。这与 T2 那次属于同一类判断：整改单的建议值与它自己的验收标准冲突时，以验收标准为准并留下证据。

**验收实测**：

| 输入 | 输出 |
|---|---|
| `ws://127.0.0.1:9222/devtools/browser/<一次性 token>` | `CDP 目标地址异常：ws://127.0.0.1:9222` |
| `ws://127.0.0.1:9222/devtools/page/ABC?token=<值>` | `CDP 目标地址异常：ws://127.0.0.1:9222` |
| `wss://example.com:443/devtools/browser/zzz` | `CDP 目标地址异常：wss://example.com:443` |
| `ws://localhost:9222` | `CDP 目标地址异常：ws://localhost:9222` |
| 端口非法 `ws://127.0.0.1:notaport/x` | `CDP 目标地址异常：[remote URL]`（回退） |

`host:port 可见 = True`，`token 不可见 = True` ✅

### 本轮改动范围（只有两个文件）

| 文件 | 本轮变化 | 说明 |
|---|---|---|
| `scripts/privacy_gate.py` | P1 修法 | 共享键名导入 + 两个模式织入 + CASTGC 值规则 |
| `hw_auth.py` | P2 修法 | 新增 `_cdp_endpoint_for_error()` + 替换 1 处调用 |

`git status` 里其余条目（`main.py` / `hw_client.py` / `hw_login.py` / `hw_credentials.py` / `hw_webapi.py` / `metadata.yaml` / `.gitignore` / `hw_privacy.py` / `tests/` / `.github/`）**都是上一轮已通过验收的交付**，本轮未触碰（按修改时间排序可验证：本轮只有 `hw_auth.py`、`scripts/privacy_gate.py` 与本文件在变动）。

> 注意：P2 改了 `hw_auth.py` 的内容，所以发布包 SHA256 从上一轮的 `2E2A58…` 变为 `B930FCA2E20060E6C47ACD875A172C8701973E82282DFA52CEE56D05FFDD6A39`（见 §5.2）。这是预期的内容变更，不是构建不确定性——同输入仍同输出。

---

## 1. 改动文件清单

### 1.1 新增

| 路径 | 行数/字节 | 说明 |
|---|---|---|
| `hw_privacy.py` | 222 行 / 9,001 B | T1 脱敏工具，11 条规则 |
| `tests/test_hw_privacy.py` | 357 行 / 13,621 B | T1 单测 39 条 |
| `tests/test_v041.py` | 2,081 行 / 75,958 B | 178 条验收测试（从仓库外搬入） |
| `tests/boot.py` | 5,413 B | 测试引导，路径解析已重写 |
| `tests/stubs/astrbot/{__init__.py,api/{__init__,event,star,web}.py}` | 5 个文件 | `astrbot` 桩包 |
| `scripts/privacy_gate.py` | 645 行 / 23,695 B | T4 隐私闸门 |
| `scripts/build_release.py` | 255 行 / 8,500 B | T3 确定性打包 |
| `scripts/check_astrbot_runner_contract.py` | 492 行 | T6 静态 AST 契约检查（14 条） |
| `scripts/check_astrbot_runtime_smoke.py` | 424 行 | T6 真实导入冒烟（8 条） |
| `scripts/resolve_astrbot_ref.py` | 180 行 | T6 通道版本解析（Lead 新增） |
| `.github/workflows/checks.yml` | 2 个 job | T5 + T6 CI |

### 1.2 修改

| 路径 | 变化 | 说明 |
|---|---|---|
| `main.py` | +19 / −12 | T1：`_err()` 汇聚点 + 6 处日志 |
| `hw_auth.py` | +15 / −10 | T1：10 处日志/CDP 异常 |
| `hw_client.py` | +11 / −2 | T1：2 处 HTTP 错误文本 |
| `hw_login.py` | +6 / −3 | T1：3 处 |
| `hw_credentials.py` | +7 / −2 | T1：2 处 |
| `hw_webapi.py` | +8 / −3 | T1：3 处 WebUI 错误信封 |
| `metadata.yaml` | +6 行 | T2：`short_desc` / `astrbot_version` |
| `tests/test_v041.py` | 3 处 hunk | T5 路径解析 + T0 版本断言 |
| `.gitignore` | +2 行 | Lead：补 `dist/` |
| `scripts/privacy_gate.py` | +11 行 | Lead：`dist` 剪枝（见 §3.4） |

---

## 2. T0 · 修正钉死版本号的测试

### 2.1 做了什么

按派活单 §5 T0 的指定改法，仅动两个方法的版本比对部分 + 新增一个模块级辅助函数：

```python
def _metadata_version(root):
    """从 metadata.yaml 读取版本号，作为唯一真值来源。"""
    import re
    with open(os.path.join(root, "metadata.yaml"), encoding="utf-8") as f:
        m = re.search(r"^version:\s*(\S+)\s*$", f.read(), re.M)
    if not m:
        raise AssertionError("metadata.yaml 缺少 version 字段")
    return m.group(1)
```

- `test_version_strings`：读出 `version = _metadata_version(root)`，再断言 `main.py`、`hw_webapi.py` 各自包含 `f'"{version}"'`。语义从「三处等于一个冻死的字面值」变成「三处互相比对一致」。
- `test_status_has_login_mode`：`self.assertEqual(data["version"], _metadata_version(str(PLUGIN_DIR_UNDER_TEST)))`。
- 两个方法各补一句 docstring：「校验三处版本号互相一致，不校验具体版本值」。

**没有**放宽任何断言：没有 `assertTrue(True)`、没有删断言、没有加 skip、没有 try/except 吞异常。

### 2.2 验证方法与结果（变异验证表）

在**最终工作区的一份副本**上做变异（副本排除 `.git` / `dist` / `__pycache__`），`HW_AUDIT_PLUGIN_DIR` 指向副本，原工作区零改动：

| 步骤 | 操作 | 期望 | 实测 |
|---|---|---|---|
| ① | 最终工作区原样（v0.4.2） | 178 全绿 | `Ran 178 tests` / **OK** ✅ |
| ② | `hw_webapi.py` 版本改 `"v0.4.9"` | 变红 | `FAIL test_version_strings` + `FAIL test_status_has_login_mode` / **FAILED (failures=2)** ✅ |
| ③ | 改回；`main.py` register 版本改 `"v0.4.9"` | 变红 | `FAIL test_version_strings` / **FAILED (failures=1)** ✅ |
| ④ | 全部改回 | 178 全绿 | `Ran 178 tests` / **OK** ✅ |
| ⑤ | 指向仓库外 v0.4.1 副本 | 178 全绿（向后兼容） | `Ran 178 tests` / **OK** ✅ |

另附：harness 原始测试文件原地跑（未设环境变量）→ `Ran 178 tests` / **OK**，且该文件仍是原始 76,010 字节，证明测试源未被污染。

还原逐字节校验：`hw_webapi.py` / `main.py` 与备份 `-ceq` 比对均为 `True`。

**结论：断言不是空壳。** ②③ 都真的变红，说明守卫有效。

---

## 3. T1 · 错误信息脱敏

### 3.1 做了什么

新增 `hw_privacy.py`，提供 `redact_error(error) -> str`，11 条规则逐条实现（请求头整行、Bearer/Basic、敏感键值对、已知 token 格式、URL、Windows 绝对路径、POSIX 绝对路径、邮箱、AstrBot 会话标识、控制字符折叠、180 字符截断 + 空输入返回类型名）。

参考实现：`astrbot_plugin_mi_fitness_health/utils/privacy.py`（2,525 B）。

**相对参考实现的一处修正**（T1 主动指出）：规则 3 加了 `(?!\*\*\*)` 负向前瞻。否则规则 1 输出的 `Authorization: ***` 会被规则 3 二次改写成 `Authorization=***`，丢掉「请求头整行」的形态。

**落地改造（本任务真正的价值）**：6 个模块共 26 处调用点。

- `main.py` 的 `_err(exc)` 是 **15 处用户可见错误文本的唯一汇聚点**（8 个 LLM 工具 + WebUI refresh），改这一处即覆盖全部 ①；另包 6 处 `logger.warning`。
- `hw_webapi.py` 3 处 `str(exc)` 错误信封（前端直接显示）。
- `hw_auth.py` 10 处（含 CDP 异常与 URL）、`hw_login.py` 3 处、`hw_client.py` 2 处（HTTP 响应体）、`hw_credentials.py` 2 处。

`hw_client.py` 空响应时显示 `（空响应）` 而非空串——因为 `redact_error("")` 按规则 11 返回 `"str"`，直接拼进去会变成 `HTTP 500: str` 这种噪声。

### 3.2 验证方法与结果

**单测 39 条**（11 条规则每条 ≥1 条 + 复合命中 + 空串 + 非字符串 + `__str__` 坏掉 + 幂等 + `hw_client` 落地抽查）：

```
$ <python> -B -X utf8 -m unittest tests.test_hw_privacy -v
Ran 39 tests in 0.226s
OK
```

**独立攻击测试**（Lead 亲自用派活单 §5 T1 点名的 4 类真实格式假凭据 + 4 类扩展，共 13 个哨兵值）：

| 输入（均为假凭据，此处只作描述） | 输出 | 泄漏 |
|---|---|---|
| `ghp_` 前缀 + 40 位字符的 GitHub 令牌 | `failed to push with token ***` | 无 |
| 本机 cookie 文件的 Windows 绝对路径 | `cannot open [local path]` | 无 |
| `Authorization` 请求头携带 Bearer JWT | `Authorization: ***` | 无 |
| 华为 CASTGC / sid 的 cookie 键值对 | `CASTGC=***; sid=***` | 无 |
| `sk-ant-` 前缀的 Anthropic 风格密钥 | `key ***` | 无 |
| 邮箱 + URL + POSIX 路径复合 | `user [email] hit [remote URL] at [local path]` | 无 |
| AstrBot 会话标识（FriendMessage 形态） | `session [session]` | 无 |
| 多规则复合（请求头 + 键值 + 路径 + token） | 全 `***` | 无 |

边界：`redact_error("")` → `'str'`；`redact_error(None)` → `'None'`；`redact_error(42)` → `'42'`；`redact_error(ValueError("bad token=abc"))` → `'bad token=***'`；500 字符输入 → 长度 180；控制字符 → 折叠为单空格。**总泄漏 0。**

**回归**：178 条验收测试在改动后仍为 178 / 通过 / 2 已知失败（与改动前逐项一致，未出现第 3 个失败）。

### 3.3 遗留（需验收人定）

`health_status` 与 WebUI `/status` 返回的 `data_dir` / `cookie_file` 仍是本机绝对路径。这是**功能输出不是错误文本**，按「不许改 UI / 不许改业务逻辑」未动（改动会牵动 `pages/` 展示）。若要脱敏需单开一条。

---

## 4. T2 · 元数据补全

### 4.1 做了什么

```yaml
short_desc: 把华为运动健康数据接进对话，随时问睡眠、心率、运动能力
astrbot_version: ">=4.26.0,<5"
```

`version: v0.4.2` 一字未动。

### 4.2 `short_desc` 长度

实测 27 个字符（其中 CJK 汉字 24、标点 3），≤ 40 ✅。

### 4.3 `astrbot_version` 依据（**验收重点**）

硬瓶颈是 `hw_webapi.py:13` 的 `from astrbot.api.web import json_response, request`。三条独立证据：

1. **tag 存在性实测**（`raw.githubusercontent.com/AstrBotDevs/AstrBot/<tag>/astrbot/api/web.py`）：

   | tag | 结果 |
   |---|---|
   | v4.24.2 / v4.25.0 / v4.25.5 | **HTTP 404（不存在）** |
   | v4.26.0 / v4.26.1 / v4.29.3 | HTTP 200（存在，13,137 B 起） |

2. **目录列表**：v4.25.5 的 `astrbot/api/` 下没有 `web` 模块（既无 `web.py` 也无 `web/`）。所以 ≤4.25.5 上该 import 直接 `ImportError`，插件在 import 阶段就死。
3. **官方 changelog**（`<AstrBot 安装>/backend/app/changelogs/v4.26.0.md`）：「后端架构从 Quart 迁移至 FastAPI……（#8688）」。`astrbot.api.web` 正是这次迁移的产物。

**排除更早瓶颈**：逐文件核对 v4.25.5 与 v4.26.0 两棵树，`astrbot.api` 的 `AstrBotConfig`/`logger`、`filter.llm_tool`、`astrbot.api.star` 的 `Context`/`Star`/`register`、`register_star(name, author, desc, version)`、`Context.register_web_api(route, view_handler, methods, desc)`、`Star.__init__(context)` 全部一致。所以唯一瓶颈就是 `astrbot.api.web`。

**上界 `<5`**：只验证过 4.x；5.x 未验证，不承诺。

> **与派活单建议值的差异（请注意）**：派活单写「参考隔壁小米插件写的是 `>=4.24.2,<5`」。**本项目不能照抄**：隔壁只要 Plugin Pages（`pages/` + `register_web_api`，4.24.2 就有），本插件多用了 `astrbot.api.web` 的 `json_response`/`request` 代理，下限必须顶到 4.26.0。填 4.24.2 会造成「声明支持但实际 import 就崩」。

用 AstrBot 自己的校验函数复核：`SpecifierSet(">=4.26.0,<5")` 对 `4.26.0`/`4.29.3` 为 True、对 `4.25.5` 为 False；`PluginManager._validate_astrbot_version_specifier` 返回 `(True, None)`。

**本机 AstrBot 实际版本：4.29.3**（`<AstrBot 安装>/backend/app/astrbot/__init__.py:3`，旁证 `changelogs/v4.29.3.md`）。

### 4.4 验证

YAML 合法可解析；`short_desc` 27 字符；`astrbot_version` 在 4.26.0 与 4.29.3 上实跑通过（非纸面推断，见 §7.2）。

---

## 5. T3 · 确定性发布打包

### 5.1 做了什么

`scripts/build_release.py`，显式清单（无 `*` 遍历根目录）：

- `ROOT_FILES`（9 个）+ `RUNTIME_MODULES`（7 个，含 T1 的 `hw_privacy.py`）+ `RUNTIME_DIRS = ("pages",)`
- 版本号从 `metadata.yaml` 正则提取，**单一来源**
- 产出 `astrbot_plugin_Tricy_huawei_health-<version>.zip`，内部顶层目录同名
- 过滤禁止后缀；固定时间戳 `1980-01-01`、条目排序、压缩级别固定；临时文件 + 原子重命名
- 构建完调用 T4 的 `assert_archive_clean()`
- 文本文件 CRLF→LF 归一化（保证跨平台/跨 checkout 确定性）
- 缺失必需文件**报错退出**（实测：`build_release: 发布文件缺失：hw_privacy.py`，exit=1）

参考实现：`astrbot_plugin_mi_fitness_health/scripts/build_release.py`（6,311 B）。

### 5.2 验证

**同输入同输出**（连续两次构建）：

```
build#1 = B930FCA2E20060E6C47ACD875A172C8701973E82282DFA52CEE56D05FFDD6A39
build#2 = B930FCA2E20060E6C47ACD875A172C8701973E82282DFA52CEE56D05FFDD6A39
一致: True
```

**zip 内容（17 个条目，顶层 `astrbot_plugin_Tricy_huawei_health/`）**：

```
CHANGELOG_v0.4.1.md 18219 / CHANGELOG_v0.4.2.md 961 / LICENSE 1068 / README.md 12491
_conf_schema.json 4114 / hw_auth.py 43384 / hw_client.py 21106 / hw_credentials.py 12986
hw_login.py 52588 / hw_privacy.py 9001 / hw_store.py 4821 / hw_webapi.py 19090
logo.png 96728 / main.py 47275 / metadata.yaml 1076
pages/health_console/index.html 35345 / requirements.txt 50
```

无 `tests/`、无 `scripts/`、无 `dist/`、无 `__pycache__`。`hw_client.py` 磁盘 21,625 B → 包内 21,106 B，差值是 CRLF→LF 归一化（其余文件无变化）。

**版本号联动**：改 `metadata.yaml` 为 `v0.5.0` 后文件名自动变 `-v0.5.0.zip`（已实测，随后已改回）。

---

## 6. T4 · 隐私闸门

### 6.1 做了什么

`scripts/privacy_gate.py`，两种模式 `--repository` / `--archive`，对外接口 `assert_archive_clean(archive_path: Path) -> None`。

9 类拦截全部实现：禁止后缀、私钥、已知 token 格式、敏感字段赋值、请求头、URL userinfo、Windows 绝对路径、体积上限（单条 10MB / 总计 50MB）、占位符白名单放行。命中输出 `scope:path:line [rule]`（**不回显内容**，报告可安全粘贴）。

`logo.png` 走 SHA256 白名单：`e6b868228b296b1b849c2d27149e342bb0196fcbd7d6928c928339fa2e3bda37`（比对 basename，zip 内路径同样识别；内容不符也拦）。

参考实现：`astrbot_plugin_mi_fitness_health/scripts/privacy_gate.py`（14,587 B）。

### 6.2 验证（验收人会攻击测试）

**必须被拦 5/5 全部 exit=1 且指出命中位置**：

| 样本 | 输出 |
|---|---|
| 假 `ghp_` token | `worktree:notes.md:3 [known-token-literal]` |
| 具体账户名的 Windows 绝对路径 | `worktree:notes.md:3 [local-windows-path]` |
| `.db` 文件 | `worktree:health.db [private-artifact-file]` |
| 假私钥（PEM 头） | `worktree:server.pem:1 [private-key-literal]` |
| 真格式 CASTGC / sid cookie 键值对 | `worktree:cookies.txt:1 [session-cookie-literal]` |

**必须放行 3/3 全部 exit=0**：`token: example-value` 占位符 / `logo.png` / 正常 Python 代码。

**当前仓库 pass**：`Repository privacy gate: clean (astrbot_plugin_Tricy_huawei_health)`，exit=0，约 380 ms。

**额外防守反击**（12 项，全部符合预期）：Bearer 请求头、URL userinfo、敏感赋值、`Set-Cookie`、POSIX 路径、单条 11 MiB、总计 56 MiB、非白名单图片、`logo.png` 内容不符、zip 内 `../escape.py`、zip 内 `.db`+token、缺失必需文件。

### 6.3 Windows 路径规则：占位符放行 vs 具体用户名拦截

这是「对当前仓库必须 pass」与「必须拦真实路径」的交界，实测边界：

| 写法 | 结果 |
|---|---|
| 具体账户名的 Windows 用户目录路径 | **拦** `[local-windows-path]` |
| 真实主机名的 UNC 路径 | **拦** |
| `C:\Users\<账户>\...` / `C:\Users\*\...` / `C:\Users\{user}\...` | 放行 |
| OS 安装目录（系统盘下的 `Program Files` / `Windows` / `ProgramData`） | 放行（`hw_auth.py` 浏览器发现路径是真实功能常量） |

实现：路径正则匹配后，若匹配结束处紧跟 `<` / `*` / `{`（或紧跟分隔符后是这三者），判为占位符放行——不是「值里含 `<` 就全放行」这种粗规则。

### 6.4 三个需复核的设计决定（**请重点看**）

1. **`tests/` 在源码树模式只做路径/体积/二进制检查，不做内容规则。**
   原因：T1 的 `tests/test_hw_privacy.py` 必须写真实格式的假凭据（`ghp_`、`BEGIN RSA PRIVATE KEY`、`CASTGC=`、`Bearer`、`Users` 路径），不豁免则「对当前仓库跑一遍必须 pass」这条验收必挂。
   代价与边界：**归档模式无豁免，全规则照跑**；且 `tests/` 从不进发布包（T3 是显式清单，17 个条目里没有 `tests/`）。反证：把同一份文件复制到非 `tests/` 路径，闸门立刻命中 4 条，说明规则本身有效。
   **验收人已裁决为「接受」**（见 §12 裁决②）。
   **残余风险（登记在案）**：源码树模式下 `tests/` 跳过内容规则；若有人把真实凭据写进 `tests/`，本闸门不会拦截（仅归档模式可覆盖）。
2. **`dist/` 目录在源码树模式被剪枝（Lead 在收尾时加的，+11 行）。**
   原因：CI 第 7 步 `--output-dir dist` 会把 zip 写进仓库，第 3 步源码树闸门用的是文件系统 walk（不读 `.gitignore`），于是**同一次 CI 顺序跑没问题，但第二次运行必然报 `private-artifact-file`**，验收人手工复跑会撞上。实测确认：剪枝前带 `dist/` 跑 → exit=1；剪枝后 → exit=0。
   不削弱防护：`dist/` 是纯构建产物、永不进发布包，且发布包本身由第 8 步 `--archive` 全规则把关。同时给 `.gitignore` 补了 `dist/`。
3. **`--repository` 用文件系统 walk，不用 `git ls-files`。**
   原因：`git ls-files` 会漏掉未跟踪的新文件（交付时 `hw_privacy.py` / `tests/` / `scripts/` 都还是 `??`），且 CI 里 checkout 后是新仓库、本地是脏工作区，两者语义不一致。walk 更 fail-closed。代价：需要显式剪枝生成目录（`__pycache__` / `dist` 等）。

---

## 7. T5 · GitHub Actions CI

### 7.1 做了什么

`.github/workflows/checks.yml`：

- 触发 `push` + `pull_request`（**全部分支**，不只 main）
- `permissions: contents: read`、`timeout-minutes: 10`
- 矩阵 `python-version: ["3.11", "3.12"]`，`fail-fast: false`
- 步骤严格按派活单顺序：checkout → setup-python(cache: pip) → **隐私闸门（源码树）** → 装依赖 → **跑测试** → compileall → **构建发布包** → **隐私闸门（发布包）** → 3.12 上传 artifact

测试文件已搬进 `tests/`（`test_v041.py` + `boot.py` + `stubs/astrbot/`），路径解析改造：

- `boot.py`：`AUDIT_ROOT`（上溯两层）→ `TESTS_DIR`/`REPO_ROOT`（上溯一层）；删除对 `EXTRACT` 目录的依赖，`PLUGIN_DIR = REPO_ROOT`；`WORK_DIR` 保留为兼容别名（**为了不动测试体里的 12 处调用**）；`TMP` 从仓库内 `tmp/` 移到 `tempfile.gettempdir()`；`FORBIDDEN_PREFIXES` 里两条硬编码 `C:\Users\<账户>\...` 改为 `Path.home()` 动态拼；`default_config` 到文件尾经机器比对**逐字节未变**。
- `test_v041.py`：仅 3 处 hunk（模块 docstring 跑法说明、`AUDIT_ROOT→TESTS_DIR`、`boot.WORK_DIR→boot.PLUGIN_DIR` + 一行注释）。**0 个 assert 改动、0 个测试体改动。**

### 7.2 本地模拟 CI 完整输出（按 workflow 顺序）

```
===== STEP 3  隐私闸门（源码树）=====
Repository privacy gate: clean (astrbot_plugin_Tricy_huawei_health)
  -> exit=0

===== STEP 4  安装依赖 =====
python -m pip install -r requirements.txt pytest
  -> exit=0

===== STEP 5  pytest tests -q =====
........................................................................ [ 33%]
........................................................................ [ 66%]
........................................................................ [ 99%]
.                                                                        [100%]
217 passed in 18.09s
  -> exit=0

===== STEP 6  compileall -q . =====
  -> exit=0

===== STEP 7  build_release --output-dir dist =====
<仓库根>\dist\astrbot_plugin_Tricy_huawei_health-v0.4.2.zip
  -> exit=0

===== STEP 8  隐私闸门（发布包）=====
dist 内容: astrbot_plugin_Tricy_huawei_health-v0.4.2.zip
Release privacy gate: clean (astrbot_plugin_Tricy_huawei_health-v0.4.2.zip)
  -> exit=0
```

> **217 而不是 178**：`pytest tests` 会同时收集 `test_v041.py`（178 条验收）+ `test_hw_privacy.py`（39 条 T1 单测）= 217。派活单写「跑 178 个测试」，实际跑得更多、覆盖更严，属正向偏差。

**幂等性验证**（验收人复跑不会踩坑）：`dist/` 存在时再跑第 3 步 → `clean`，exit=0；连续两轮构建 SHA256 一致。

**YAML 合法性**：`yaml.safe_load` 解析通过；`jobs = ['test', 'astrbot-runner-contract']`；`permissions = {'contents': 'read'}`；`test.timeout-minutes = 10`；矩阵与步骤数符合预期。

### 7.3 遗留

`python tests/test_v041.py` 直接跑只有前半段用例——原文件第 ~1392 行有一个中置的 `if __name__ == "__main__": unittest.main()`，其后的类尚未定义。这是**原文件既有结构**，未改动。**CI 必须用 `pytest tests` 或 `unittest discover`，不能直接跑文件。**

---

## 8. T6 · AstrBot 契约测试

### 8.1 做了什么

`checks.yml` 第二个 job `astrbot-runner-contract`，矩阵两条通道 `["minimum-supported", "latest-stable-4x"]`，流程：检出插件 → 解析 ref → 检出 AstrBot 源码 → `pip install -e ./astrbot-runtime` → 装插件依赖 → 契约检查 → 导入冒烟。

**通道版本解析**由 `scripts/resolve_astrbot_ref.py` 完成（Lead 新增）：

- `--field minimum`：读 `metadata.yaml` 的 `astrbot_version`，取 `>=X.Y.Z` 下限 → `vX.Y.Z`。**让 T2 的声明与 T6 的 CI 参照版本共享单一真值来源，永不漂移。** 实测输出 `v4.26.0`。
- `--field latest-stable-4x`：查 GitHub releases API 取最新稳定 v4.x。实测输出 `v4.29.3`。
- 仅用标准库（CI 里这一步跑在 `pip install` 之前）。

两个检查脚本分工：

- `check_astrbot_runner_contract.py`：**纯静态 AST，不 import astrbot**，可对任意 AstrBot 源码树跑 → 两条通道共用。14 条断言。
- `check_astrbot_runtime_smoke.py`：**动态**，import 插件 → 实例化 → 反查注册结果。8 条断言。

**三条隔离（重要）**：① import astrbot 前把 `ASTRBOT_ROOT` 指向临时目录并 chdir，AstrBot 的配置/模板/日志全落临时目录；② `main._data_dir` 换成临时目录，**全程不碰真实 `plugin_data/`**；③ **不调用 `initialize()`**（它会启动后台 token 预热，真会打华为接口，违反红线 5），WebUI 注册改为直接构造 `HuaweiHealthWebApi(plugin).register()` 验证。

### 8.2 本地验证结果

| 通道 | 契约检查 | 导入冒烟 |
|---|---|---|
| **4.29.3**（本机安装） | **14/14 PASS**，exit=0 | **8/8 PASS**，exit=0 |
| **4.26.0**（官方 sdist 源码树） | **14/14 PASS**，exit=0 | **8/8 PASS**，exit=0 |
| 4.25.5（负向对照） | **3/14 FAIL**，exit=1 | — |

4.25.5 的失败正好复现了「为什么下限是 4.26.0」：
```
[FAIL] metadata.yaml 的 astrbot_version 与这份源码版本相容
[FAIL] astrbot.api.web 仍提供 json_response / request 代理
       缺少 AstrBot 源码文件：...\astrbot\api\web.py
[FAIL] 插件 Web API 调度仍是 view_handler(**path_values) + 请求上下文绑定
       缺少 AstrBot 源码文件：...\astrbot\dashboard\api\plugins.py
```

**冒烟脚本的 5 个变异负向对照全部 exit=1**（在仓库外副本上做，原仓库未动）：metadata 缺 `short_desc`、webapi handler 多一个参数、删掉一个 `@filter.llm_tool`、`metadata.version` 与 `@register` 不一致、`astrbot_version` 高于当前 AstrBot。

### 8.3 哪些断言在保护什么

**契约检查（14 条，静态）**

| 断言 | 保护什么 |
|---|---|
| 源码树 `__version__` 满足 metadata 的 `astrbot_version` | 防止「声明支持但实际跑不了」；也防止写成非法/过窄区间 |
| `astrbot.api` 导出 `AstrBotConfig` / `logger` | `main.py:26` 的 import |
| `astrbot.api.event` 导出 `AstrMessageEvent` + `filter` 子模块 | `main.py:27` |
| `filter.llm_tool` 仍别名到 `register_llm_tool` | 8 个 `@filter.llm_tool` 装饰器 |
| `astrbot.api.star` 导出 `Context`/`Star`/`register` | `main.py:28` + 类继承 |
| `astrbot.api.web` 的 `json_response`（`data` 位置参数、`status_code`/`headers` 仅关键字）、模块级 `request`、`PluginRequest.json()` 是 async、`bind_request_context` 仍是 contextmanager | **版本下限的锚点**；`hw_webapi.py` 全部 12 个 handler 的返回值与 `await request.json()` |
| `register_star(name, author, desc, version)` 前 4 个必填位置参数顺序不变 | `main.py` 用 4 个**位置**参数注册，改顺序会静默错位 |
| `register_llm_tool` 首参是 `name` 且有默认值、仍收 `**kwargs` | `@filter.llm_tool(name="health_status")` |
| `Context.register_web_api(route, view_handler, methods, desc)` 签名 | `hw_webapi.py` 12 次注册 |
| `Star.__init__` 前两参数是 `self, context` 且 `config` 有默认值 | `super().__init__(context)` |
| 加载器仍 `hasattr(..., "initialize")` + await；卸载仍按名字查 `terminate` | 插件的 ACL 收紧 / cookie 清理 / 卸载日志都在这两个钩子里 |
| Web API 调度仍是 `view_handler(**path_values)` + `bind_request_context` | **零参数 handler 约定**：插件 handler 都是 `async def get_status(self)`，AstrBot 若改传位置参数，12 条路由会同时 TypeError |
| `AstrBotConfig` 是 dict 子类，`config_path`/`schema` 有默认值 | `config.get("login_daily_limit")`；冒烟构造配置的前提 |
| `StarHandlerRegistry.get_handlers_by_module_name` 仍在 | 冒烟靠它反查「8 个工具真的注册上了」 |

**导入冒烟（8 条，动态）**：metadata 字段齐全且版本相容 / 插件能 import（含 `astrbot.api.web`）/ 能用真实 `AstrBotConfig` 实例化 / 实例是 `Star` 子类且 `data_dir` 已隔离 / **8 个 LLM 工具全部注册且都是 async** / **WebUI 12 条路由可注册、方法合法、handler 零参数且 async** / `request` 代理在 handler 外抛 RuntimeError、在 `bind_request_context` 下可用 / `metadata.name`、`metadata.version` 与 `@register` 一致。

### 8.4 T6 降级方案（**不静默删除**）

本地两条通道都真跑通了，不存在需要降级的通道。以下是 CI 预案：

1. **`minimum-supported`（v4.26.0）装不上**（最可能：`pip install -e ./astrbot-runtime` 在 3.11/3.12 上撞依赖解析或超时）
   - 降级 A（推荐）：该通道**只跑契约检查**——它不需要安装 AstrBot，只需 `pip install packaging pyyaml`。14 条里 13 条与版本无关，第 1 条正是「版本区间相容」，所以「这个版本认不认我们的用法」仍被验证。
   - 降级 B：用 PyPI 官方源码包代替 git checkout（不需 token、不受 GitHub 限流）：`pip download astrbot==4.26.0 --no-deps --no-binary :all:` 解压后 `--astrbot-root`。本地就是这么验的。
   - 降级 C：冒烟步骤对该通道 `continue-on-error: true` + `::warning::` 注明原因并写进本文件；契约步骤仍然硬失败。
2. **`latest-stable-4x` 解析不到 tag**：退化为 PyPI 最新 4.x，或钉已知稳定版（4.29.3，本机已验证）。
3. **`pip install -e` 装得上但 import 失败**：契约检查会先失败并指出缺哪个接口，照提示处理，不要跳过契约步骤。
4. **CI 时间**：契约检查纯 AST 毫秒级；冒烟需真 import AstrBot（约 1–2 秒），耗时大头是 `pip install -e`。故该 job `timeout-minutes: 15`（比主 job 的 10 分钟宽松），并建议给 pip 用 `cache: pip`。

---

## 9. 红线自检

| 红线 | 检查 | 结果 |
|---|---|---|
| 1 不碰真实凭据 | 未进入 `plugin_data/`；所有测试用打桩/临时目录 | ✅ |
| 2 不写本机绝对路径 | 全仓 grep 本机账户名 → **0 命中**；Windows 用户目录字样全仓只出现在 `tests/test_hw_privacy.py` 的一处尖括号占位符里 | ✅ |
| 3 不动 tag | `v0.4.0-installed` / `v0.4.1` / `v0.4.2` 均指向原提交，HEAD 仍 `5a4dcc4` | ✅ |
| 4 不动版本号 | `metadata.yaml: v0.4.2`、`main.py:102: "v0.4.2"`、`hw_webapi.py:94: "version": "v0.4.2"`、`README.md:3: 版本：v0.4.2` 四处一致 | ✅ |
| 5 不跑真实登录/抓取 | 冒烟不调用 `initialize()`；178 用例全程打桩；未启动浏览器、未请求华为接口 | ✅ |
| 6 无私有称呼 | 全仓 grep 派活单列出的三个私有称呼关键词 → **0 命中**（本文件也不含其字面） | ✅ |
| 7 不改业务逻辑 | `git diff -U0` 逐行审计：6 个模块的全部改动只有两类——`from hw_privacy import redact_error`，以及把错误文本参数包成 `redact_error(...)`。无逻辑/条件/控制流改动 | ✅ |
| 8 凭据不进日志/测试输出 | 演示样例一律 `example` / `dummy` / `***` / `<账户>`；闸门命中只输出规则名不回显内容 | ✅ |
| 9 不 force push | 未 push、未 commit | ✅ |
| 10 不删测试断言 | 178 条中仅 T0 授权的两个方法的版本比对部分被改（且改为更强的一致性守卫），其余 176 条 + 两方法中的其他断言一字未动 | ✅ |

---

## 10. 遗留问题与不确定项（汇总）

1. **`tests/` 隐私豁免**（§6.4-1）：源码树模式对 `tests/` 不跑内容规则。这是为了满足「对当前仓库必须 pass」，因为 T1 测试必须写真实格式假凭据。归档模式无豁免、`tests/` 不进包。**若验收人要求严格版，需同步改 T1 测试数据——请指示。**
2. **`dist/` 剪枝是 Lead 加的（计划外改动）**（§6.4-2）：不在派活单范围内，属交付方主动补充。原因是不剪枝则 CI 第二次运行必红。**验收人已裁决为「接受」**（见 §12 裁决③）。请复核这 11 行。
3. **【待办，未修复】`health_status` / WebUI `/status` 仍返回本机绝对路径**（§3.3）：验收人判断 `health_status` 是 LLM 工具，返回值会进对话上下文，本机路径确实会出现在聊天记录里，**应当脱敏**；但该改动牵动 `pages/` 与功能输出契约，**单开一条，不在本轮范围**。本轮未做任何改动。
4. **`tests/` 源码树内容规则豁免的残余风险**：源码树模式下 `tests/` 跳过内容规则；若有人把真实凭据写进 `tests/`，本闸门不会拦截（仅归档模式可覆盖）。
4. **`register`（`register_star`）在 4.29.3 已标 `[DEPRECATED]`**，当前仍可用。契约检查第 7 条会在它被移除时立刻报警。**5.x 升级时这是第一个要改的点**（改成只继承 `Star` + `metadata.yaml`）。
5. **4.26.0 通道不是「纯净 4.26.0 环境」**：用的是官方 4.26.0 源码 + 本机 4.29.3 时代的第三方依赖。AstrBot 自身代码路径是真 4.26.0，第三方依赖不是当时钉的版本。CI 里 `pip install -e` 才是纯净验证；两者结论一致。
6. **`redact_error(None)` 返回 `'None'` 而非 `'NoneType'`**：规则 11 说「空输入返回异常类型名」，对空串返回 `'str'`、对 `None` 返回 `'None'`。语义上略有出入，但不泄漏、不影响防护，未改（改了会影响 T1 已冻结的 39 条单测）。
7. **POSIX 路径的占位形态只部分脱敏**：`<`/`>` 不是合法路径字符，正则会在 `<` 前停下。Windows 侧做了「中间段允许 `<>`」所以能整段吃掉。真实用户路径不含 `<>`，不影响实际防护。
8. **`hw_client.py` 是 CRLF、其余文件 LF**：仓库原有状态，未做行尾归一（`git diff` 行数很小可证明无行尾 churn）。打包时统一归一为 LF。
9. **`privacy_gate.py` 没有自己的单测文件**：写作用域限制，测试归 `tests/`。若需要 `tests/test_privacy_gate.py` 需放开范围。
10. **`pytest` 原本未安装**：本机为跑 CI 第 5 步临时装了 `pytest 9.2.0`（AstrBot 自带解释器）。CI 里由 workflow 显式安装。

---

## 11. 验收人复现步骤（建议顺序）

```powershell
$env:PYTHONIOENCODING="utf-8"
$py = "<python>"
cd <仓库根>

# 1) T0 变异验证：先确认全绿
& $py -m unittest discover -s tests -p "test_v041.py"        # 期望 Ran 178 / OK

# 2) T1 单测
& $py -m unittest tests.test_hw_privacy -v                    # 期望 Ran 39 / OK

# 3) 全量（CI 第 5 步）
& $py -m pytest tests -q                                      # 期望 217 passed

# 4) T4 源码树闸门（幂等，dist/ 存在也能过）
& $py scripts/privacy_gate.py --repository .

# 5) T3 确定性（连跑两次比 SHA256）
& $py scripts/build_release.py --output-dir dist
(Get-FileHash dist\*.zip -Algorithm SHA256).Hash
# 期望 B930FCA2E20060E6C47ACD875A172C8701973E82282DFA52CEE56D05FFDD6A39

# 6) T4 归档闸门
& $py scripts/privacy_gate.py --archive dist\*.zip

# 7) T6 两条通道
& $py scripts/resolve_astrbot_ref.py --field minimum          # 期望 v4.26.0
& $py scripts/check_astrbot_runner_contract.py --astrbot-root "<AstrBot 安装>\backend\app"
& $py scripts/check_astrbot_runtime_smoke.py --plugin-root . --astrbot-path "<AstrBot 安装>\backend\app"
```

**T0 变异复现**（派活单 §8-4）：把 `hw_webapi.py` 的 `"version": "v0.4.2"` 改成 `"v0.4.9"` → `test_version_strings` 与 `test_status_has_login_mode` 必须变红；改回后必须全绿。`main.py` 的 `"v0.4.2"` 同理（只红 `test_version_strings`）。

---

## 12. 验收人裁决记录（四项待决事项）

来源：`整改单_华为健康插件_验收反馈_P1P2.md` 第 2 节。

### 裁决① `astrbot_version: ">=4.26.0,<5"` —— 接受，不改

验收人确认：未照抄派活单建议的 `>=4.24.2`，而是实测出 `astrbot.api.web` 在 4.24.2 / 4.25.0 / 4.25.5 全部不存在、4.26.0 起才有（另有 PR #8688 佐证）。

**要求的动作：把「为什么不是 4.24.2」的证据链保留在本文档里 → 已保留，见 §4.3**（三条独立证据：tag raw 404 实测、v4.25.5 目录列表、官方 changelog；并额外核对了 v4.25.5 → v4.26.0 其余 API 未变，确认唯一瓶颈就是 `astrbot.api.web`）。

### 裁决② `tests/` 目录的内容规则豁免 —— 接受

**要求的动作：明确写一句残余风险 → 已写入 §6.4-1 与 §10-4**，原文：

> 源码树模式下 `tests/` 跳过内容规则；若有人把真实凭据写进 `tests/`，本闸门不会拦截（仅归档模式可覆盖）。

### 裁决③ `dist/` 剪枝 11 行 + `.gitignore` 补 `dist/` —— 接受

**要求的动作：标注这是计划外改动及原因 → 已在 §6.4-2 与 §10-2 标注为「计划外改动」**，并说明原因（不剪枝则 CI 第二轮必红）与不削弱防护的理由（`dist/` 是纯构建产物、永不进发布包；发布包本身由 `--archive` 全规则把关）。

### 裁决④ `health_status` / WebUI `/status` 仍返回本机绝对路径 —— 本轮不动

验收人判断：`health_status` 是 LLM 工具，返回值会进对话上下文，本机路径确实会出现在聊天记录里，**应当脱敏**；但牵动 `pages/` 与功能输出契约，**单开一条**。

**要求的动作：在「遗留问题」里登记，措辞用「待办」而非「已修复」→ 已登记为 §10-3，标注「【待办，未修复】」，本轮未做任何改动。**

---

## 13. 本轮（P1/P2 整改）验证汇总

| 项目 | 命令 | 结果 |
|---|---|---|
| P1 样本 A/B/C（必须拦） | `privacy_gate.py --repository <样本目录>` | exit=1，指出规则名 ✅ |
| P1 样本 D/E/F（必须放行） | 同上 | exit=0，`clean` ✅ |
| 真实仓库 | `privacy_gate.py --repository .` | `clean`，exit=0 ✅ |
| 发布包 | `build_release.py` → `privacy_gate.py --archive` | `clean`，exit=0 ✅ |
| 确定性 | 连续两次构建 | SHA256 一致 `B930FC…D6A39` ✅ |
| P2 CDP 地址 | `_cdp_endpoint_for_error()` 6 个用例 | host:port 可见、token 不可见 ✅ |
| 全量测试 | `pytest tests -q` | **217 passed** ✅ |
| 178 验收 | `unittest discover -s tests` | `Ran 178 / OK` ✅ |
| T1 单测 | `unittest tests.test_hw_privacy` | `Ran 39 / OK` ✅ |
| T6 契约 | `check_astrbot_runner_contract.py` | 14/14，exit=0 ✅ |
| T6 冒烟 | `check_astrbot_runtime_smoke.py` | 8/8，exit=0 ✅ |
| 本轮改动文件 | 按修改时间 | 仅 `hw_auth.py`、`scripts/privacy_gate.py`、本文档 ✅ |
| 红线 | 全仓 grep | 本机账户名 / 私有称呼 → 0 命中 ✅ |
