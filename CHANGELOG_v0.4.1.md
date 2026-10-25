# v0.4.1 变更与修复对照

> 基线：v0.4.0（sha256 前缀 `34165ccd`）
> 依据：`reports/final.md`（41 条问题：P0×2 / P1×12 / P2×17 / P3×10）
> 验证：`work/tests/test_v041.py` —— **171 个用例全部通过**；另用原始检测探针复跑关键场景（见文末）

图例：✅ 已修复 · 🟡 部分修复（写明剩下什么） · ⬜ 未修（写明理由）

---

## P0（2 条，全部修复）

| # | 问题 | 状态 | 改法 |
|---|---|---|---|
| P0-1 | 账号密码模式每天只能用约 50 分钟（额度 1 次/天，成功不归还） | ✅ | `LOGIN_DEFAULTS["daily_limit"]` 1→3，语义改为「每天允许的**失败**次数」；`record_auto_success()` 归还名额；`_token()` 在 password 路线失败时**回退 cookie 路线**；新增配置项 `login_daily_limit` |
| P0-2 | 验证码链路：`filled` 被当成已提交、8 秒宽限期比校验还短 | ✅ | `_process_action` 拆开 `submitted`/`filled`；`SMS_RETRY_GRACE` 8→30 秒；`_sms_submit_script` 支持 6 框/单框、放宽按钮文案、支持回车提交；`sms` 探测放宽到「≥1 个 tel/numeric 输入且 maxlength 4~8」；`submit_sms` 接受 4~8 位 |

## P1（12 条）

| # | 问题 | 状态 | 改法 |
|---|---|---|---|
| P1-1 | 每次启动用配置快照覆盖 `hw_cookies.json`，滚续结果清零 | ✅ | 新增**配置指纹**（`hw_cookies.json.config_applied`）：配置没变就跳过导入；变了才应用，且**与现有 cookie 合并**而不是整份替换 |
| P1-2 | `_set_state` 每秒续期 deadline → `NEED_SMS` 永不超时 | ✅ | `_set_state(state, message, refresh=None)` 只在状态真的变化或显式 `refresh` 时重置 deadline；另加会话硬上限 `max(300, session_timeout*3)` |
| P1-3 | 密码错误无分支 → 90 秒超时报「登录等待超时」 | ✅ | `_page_state_script` 采集 `pwd_error`；`_update_page_state` 抛 `bad_credentials`（仅在真的提交过凭据后判定）；文案「账号或密码不正确，请在 WebUI 重新保存」 |
| P1-4 | 页面脚本读不到时把 `NEED_SMS/NEED_TRUST` 翻成 `SUBMITTING` | ✅ | `info` 为空时**不改状态**，只记一条 warning |
| P1-5 | 信任页误判一次即本会话永久失效 | ✅ | `trust` 判定要求「对话框特征」（信任文案 **且** 有不信任/稍后再说或正文「是否信任此浏览器」）；点过之后 `TRUST_RETRY_GRACE=12s` 重试一次，再失败转 `NEED_TRUST` 让用户手选 |
| P1-6 | `Thread.start()` 抛异常 → 永久 `LAUNCHING`，`_cleanup` 不执行 | ✅ | `start()` 包 try，失败即 `_fail("launch")` + 按需记冷却；`manager.start()` 增加 `current_session()`/`is_busy()` 便于判定 |
| P1-7 | 「取消 → 立刻重开」时旧会话的孤儿清扫杀掉新会话浏览器 | ✅ | `_stop_process(proc, sweep_profile=True)`；`_cleanup()` 只在「自己仍是当前会话」时才做 profile 级清扫；`cancel()` 的 `join(2)` → `join(15)`；`_launch()` 启动前先清孤儿（此刻占用 profile 的一定是孤儿） |
| P1-8 | `_password_token` 等 420 秒（上限 1920）且持锁、超时不 cancel | ✅ | 等待上限降到 `min(100, max(60, session_timeout))`；**需要人工介入时立刻返回**可行动提示（不再空等）；真正超时才 `cancel()`；`fetch_token` 加进程内互斥锁，避免工具超时后重复起浏览器 |
| P1-9 | 分项 cookie 按序映射静默错位/丢弃 | ✅ | `parse_cookie_fields`：纯值按序必须恰好 6 行、命名行与纯值行禁止混写，否则**直接报错**；导入后校验 `CASTGC`/`sid` 必存在 |
| P1-10 | 凭据损坏/被占用被伪装成「未保存」，password 不回退 cookie | ✅ | 新增 `CredentialsLockedError`；`status()` 返回 `state`（absent/ok/corrupt/locked/unavailable）；错误码拆成 `credentials_corrupt`/`credentials_locked`；`_token()` 失败回退 cookie；DPAPI 不可用时自动切回 cookie 模式 |
| P1-11 | CDP 断开时 `_call` 忙等（426 万次 recv/秒、单核 100% 90 秒） | ✅ | 区分超时（继续等）与连接断开（立刻抛 `CDP 连接已断开`）；`_wait_for_completion` 把它映射成 `cdp_lost`，不再等满 90 秒 |
| P1-12 | 会话凭据明文落盘 | 🟡 | `hw_cookies.json` 改为 **DPAPI 加密**（`HWCOOK1\0` + 密文，旧明文文件仍可读）；POSIX 统一 0600；数据目录 ACL 收紧（`icacls /inheritance:r`）。**`auto_trust` 仍默认开启**——这是「无感登录」的核心，改成默认关会改变用户的使用习惯，留作 WebUI 可选项（README 已写明它的含义） |

## P2（17 条）

| # | 问题 | 状态 | 改法 |
|---|---|---|---|
| P2-1 | 体重「最新」永远是均值 | ✅ | `_fmt_weight` 改用按天明细的最后一天，并标注「最近一天（YYYY-MM-DD）」 |
| P2-2 | 运动记录距离/时长原样透出（米/毫秒） | ✅ | 新增 `format_distance_m` / `format_duration_ms`；`_fmt_acts` 统一走它，LLM 工具与 WebUI 共用 |
| P2-3 | 字段漂移 8 组「看起来像没数据」 | ✅ | 新增 `SchemaDrift` + `pick()`；判据「响应非空但关键字段不在 = 改版」；`_err()` 给出「华为接口结构变了，请升级插件」 |
| P2-4 | `_parse_stats` 类型洞（AttributeError / KeyError / `day="None"`） | ✅ | 全链路类型守卫；`_fmt_day(None)` 返回空串；缺 `startDay` 不再生成 `None` 桶（全缺则报漂移） |
| P2-5 | `expireTime` 三态处理不完整 | ✅ | 抽出 `hw_auth.compute_expire_at()`，`main._token` 与 `hw_login._finish` 共用一份 |
| P2-6 | 配置/参数非数字 → 裸异常穿透 | ✅ | `_int_cfg()` / `_clamp_int` 语义统一，`days`/`limit`/`token_ttl`/`data_ttl`/`page_timeout` 全部走它 |
| P2-7 | `_clear_health_cache` N+1 连接阻塞事件循环 | ✅ | 新增 `store.clear_except()`（一条 SQL）；`PRAGMA journal_mode=WAL` 只在建库时设一次；异步调用方走 `asyncio.to_thread` |
| P2-8 | 降级链排除列表漏项 / 覆盖真实错误码 / manual 仍写冷却 | ✅ | `_FALLBACK_SKIP` 补 `browser`/`cookie`/`bad_credentials`/`wronghost`/`credentials_*`；`_fail(exc.code)` 保留真实码；`_try_visible_fallback` 的失败分支加 `and not self.manual` |
| P2-9 | 180 秒冷却对配置类错误也生效 | ✅ | 「找不到浏览器」「没有 cookie」「浏览器启动失败」不再 `_mark_failure()`；导入/清除 cookie 会 `clear_failure()` |
| P2-10 | `login_config.json` 无上界 / 静默清零 / 可手改 | ✅ | 冷却钳到 `now + FAILURE_COOLDOWN` 以内；`attempts` 丢掉未来时间戳；坏文件**备份成 `.bad.<ts>`** 并 warning；文件 0600 |
| P2-11 | 明文密码走 CDP / 端口 TOCTOU / 无域名白名单 | 🟡 | 端口改为 `--remote-debugging-port=0` + 读 `DevToolsActivePort`（消除 TOCTOU）；`_wait_cdp` 校验返回含 `webSocketDebuggerUrl`；`_attach` 校验目标地址是 127.0.0.1；填充脚本加 `huawei.com` 域名白名单（`wronghost` 硬失败）。**「本机进程能 attach 到 CDP」是 Chromium 固有形态**，插件层无法根治 |
| P2-12 | `mask_account` 7 位数字 100% 泄露 | ✅ | 数字 ≤8 位全掩，更长保留 2+2；邮箱本地部分只留 1 位、域名主体全掩；用例覆盖 1~15 位数字、邮箱、全角 |
| P2-13 | `health_status` 在 password 模式恒报「没有 cookie」且不实测 | ✅ | 按 `login_mode` 分支输出（凭据状态/会话状态/冷却/额度）；实测改用 `/user/basicInfos` 轻量验证 token，不再为「测一下」起浏览器 |
| P2-14 | `health_overview` 承诺「近期运动」但 gather 里没有 | ✅ | gather 补 `acts`，与 WebUI 概览共用 `_fmt_acts` |
| P2-15 | JSON 通道不补 CASTGC 的 `/UnifiedIDMPortal` | ✅ | 新增 `_canonical_complete()`：任何通道导入后都按 `MIN_COOKIE_SPECS` 补齐缺失的 (name, domain, path) |
| P2-16 | 跨平台：非 nt 孤儿清理空函数 / root 缺 `--no-sandbox` | ✅ | 新增 `_cleanup_orphan_browsers_posix()`（`pgrep -f <profile>` + SIGKILL）；`browser_launch_args()` 在 `geteuid()==0` 时追加 `--no-sandbox --disable-dev-shm-usage` |
| P2-17 | README/docstring 与实现不符 4 处 | ✅ | README 全面重写：补 `warmup`/`login_daily_limit`/`timezone`，压力改为「接口已接但可能为空」，`health_sleep` docstring 补「入睡/醒来时间」且实现真的输出了 `HH:MM→HH:MM`，`health_refresh` docstring 改成「数据下次查询时拉取」 |

## P3（10 条）

| # | 问题 | 状态 | 改法 |
|---|---|---|---|
| P3-1 | `_cached` 无内存缓存 / `force` 死参数 / None 不缓存 | ✅ | 命中判断加 `store.has()`（缓存 None 也生效）；docstring 改成「SQLite → 浏览器」；`force` 保留（`/refresh` 语义需要），已注明 |
| P3-2 | `data_ttl=0` → 缓存永不过期 | ✅ | `ttl <= 0` 时**不写缓存**（真正的「关掉缓存」） |
| P3-3 | `body_weight(1095)` 被钳到 730 | ✅ | `_day_window` 上限 730→1095 |
| P3-4 | `*.tmp` 崩溃残留 / POSIX 权限顺序反了 | ✅ | 新增 `purge_stale_tmp()`（启动时 + `clear_cookies()` 都会清）；所有凭据类文件写完 `chmod 0600`（`harden_file_permissions`） |
| P3-5 | XSS：`renderDiag` 的 `summary` 是唯一注入形状 | ✅ | 改 `replaceChildren()` + `textContent` |
| P3-6 | 7 天 `asset_token` 拼进每个 API URL / 路径回显 / 错误原文回显 | 🟡 | 删掉 `withToken()` 对 API 调用的拼接（`probeBridgeScript` 取脚本那段保留）；`json` 解析错误包装成「cookie JSON 格式错误」，不再回显解析器原文。**`/status` 仍返回 `data_dir`**——排障需要，且只对已登录的 WebUI 可见 |
| P3-7 | 缺 `websocket-client` 整包加载失败 / 依赖无上限 | ✅ | `hw_auth` 改为 try-import，缺失时在 `fetch_token`/`_attach` 抛明确错误；`requirements.txt` 加 `<3.0` / `<2.0` |
| P3-8 | 代码规模 / 重复 JS / 死代码 / 常量不一致 | 🟡 | `KEY_COOKIES` 与 `MIN_COOKIE_SPECS` 统一；`basic_infos()` 从死代码变成 `health_status` 的连通性探针；重复的 `fmt_acts` 合并到 `main._fmt_acts`。**文件拆分未做**（`hw_login.py` 仍 800+ 行）——大改结构风险高于收益，建议下个版本先只搬纯函数 `hw_format.py` |
| P3-9 | `login/account` 死接口 / 返回体形状不一致 | ✅ | 删掉 `login/account`（12 个接口）；`login/start` 改回 `manager.status()`，与 `/login/status` 完全一致 |
| P3-10 | 2 秒轮询全页 innerText / `login_start` 同步 fsync | 🟡 | `login_start` 改 `asyncio.to_thread`。**页面状态轮询仍 1 秒**——验证码环节的响应速度比这点 CPU 更重要，保留 |

---

## 第二轮 / 第三轮：对抗性复核之后的返工

修完之后我让两名独立复核员（`reports/verify_auth.md`、`reports/verify_data.md`）**以推翻为目标**做了对抗性复核。
他们确认了 33 条修复真实生效，但也抓出 **3 处「声称修好但只修了一半」+ 1 条自己带出来的回归**。这些已经修完：

| 编号 | 复核发现的问题 | 现在的改法 |
|---|---|---|
| **P1-A** | 「取消 → 立刻重开」仍会互杀：`_cleanup()` 修了，但 `_launch()` 的失败收尾仍用默认 `sweep_profile=True` | 新增 `_sweep_allowed()`，`_close_browser()` 的默认值改为「只有自己仍是当前会话才清扫」，三个调用点全部覆盖 |
| **P1-B** | 需要输验证码的可行动提示被 cookie 回退吞掉，用户拿到「cookie 已过期，请重新导出」 | 新增 `LoginNeedsHuman(HuaweiAuthError)`，`_token()` 单独 `except` 直接上抛；其余失败回退时**合并**两条错误原因 |
| **P1-C** | 合法空响应判据只修了一半：`_parse_stats`（心率/HRV/压力/体重四项）与 `heart_rate_zones` 仍把 `{"total":0}` / `{"code":0,…}` 判成「改版」 | 抽出 `looks_like_legit_empty()` 给四个解析器共用；补 `data` 包一层的情况。复核探针的 37 种空响应现在 **0 误报** |
| **P2-A** | `bad_credentials` 立刻写 6h 冷却，改对密码后仍锁 6 小时（提示自相矛盾） | 新增 `_COOLDOWN_SKIP`：配置类/可自愈类错误不写冷却；WebUI 保存凭据成功后 `clear_cooldown()` |
| **P2-B** | WebUI 手点「无头自动登录」成功后 `pop()` 掉别人的失败名额 | `record_auto_success(return_quota=...)` 只归还自己记过的那一格 |
| **P2-C** | `ws.send()` 在 try 之外，浏览器已死仍报「登录等待超时」/「cookie 已过期」 | `send` 也分类，断开即抛 `CDP 连接已断开` → `closed`/`cdp_lost` 分支终于可达（实测 0 秒报出） |
| **P2-D** | 解析报错文案回显最多 3 条**真实 cookie 值**（与加密投入互相抵消） | 只报行号，不回显内容 |
| **P2-E** | `_auth_mutex` 等待预算 = `page_timeout`，最坏 600 秒 | 改固定 5 秒 |
| **P2-F** | `health_status` 的实测探针用了 v0.4.0 里**从未被调用过**的 `/user/basicInfos`，403/404 渲染成「实测失败」 | 改用已实测的 `resting_heart_rate(1)`；非 401 一律报「无法验证（探针接口异常），不代表取数不可用」 |
| **P2-G** | 总览没有整体超时兜底（最坏 ≈285 秒 > 120 秒工具超时） | 加 `OVERVIEW_TIMEOUT=90`，单项超时只影响那一项 |
| **P3** | `data_ttl=0` 对总览/perf/pb 不生效；`has()` 让损坏行永久命中 None；`_invalidate_auth_cache` 两次 to_thread 之间新开调度窗口且 fail-open；`login_config` 形状不对仍静默清零；`format_duration_s` 负值；`_fmt_day` 浮点；`_fmt_weight` 边缘；`/status` 两个同名 CASTGC；`icacls` 失败静默；信任重试计数不复位；`read_devtools_port` 不看进程存活 | 逐条修掉（详见 diff） |

复核员还做了**变异测试**（把每条修复改回错误实现，看测试抓不抓得住），第一版 **21 个变异里 12 个存活**——说明测试有假绿。已按他们的点名补强：

| 补强的用例 | 原来为什么是假绿 |
|---|---|
| `TestDayWindowSpan` | 原用例比较「两个都被钳过的值」，任何上限都能通过 |
| `TestStoreHasExpiry` | 原用例靠 `get()` 先把行删掉才让 `has()` 为 False |
| `TestOverviewIncludesActs` | 原来只 `inspect.getsource()` 搜字符串，从不执行 `health_overview`；现在用假 client 真跑并断言输出含「5.00 公里」 |
| `TestHealthStatusProbe` | 实测探针三分支零覆盖；现在喂 200/401/404 断言三种不同文案 |
| `TestEmptyMatrixExtended` | 原用例漏的正是 `{"total":0}` / `{"code":0,…}` / `{"total":"0"}` |
| `TestClearCacheCallSite` | 清缓存的**调用点**无覆盖，删掉 `clear_except` 也不会红 |
| `TestLoginStartOffLoop` | 不验证 `to_thread` |
| `TestFrontendContracts` | 前端零覆盖（XSS 形状 / `asset_token` 拼接 / 凭据状态分支） |

---

## 修复统计

| 状态 | 数量 |
|---|---|
| ✅ 已修复（含复核后返工） | **41 条里的 36 条** |
| 🟡 部分修复（P1-12 `auto_trust` 默认值 / P2-11 CDP 固有形态 / P3-6 `/status` 路径回显 / P3-8 文件拆分 / P3-10 轮询频率） | **5** |
| ⬜ 未修 | **0** |

验收测试：**171 个用例全部通过**（`work/tests/test_v041.py`）。
复核报告：[`reports/verify_auth.md`](../reports/verify_auth.md) · [`reports/verify_data.md`](../reports/verify_data.md)。

---

## 本次仍未解决、需要真机确认的假设

这些**不影响「该修的都修了」**，但决定了修复在真实华为页面上是否生效：

1. 验证码页的「确定」是 `div` 还是 `button` —— 现在两种情况都能匹配，但仍建议真机看一眼。
2. 华为验证码真实校验耗时是否 >30 秒 —— 若超过，宽限期还要再放宽。
3. 华为页面是否真的显示「帐号或密码错误」这类文案 —— `pwd_error` 正则基于常见写法。
4. 登录页上是否真有「信任此浏览器」字样 —— 现在要求「对话框特征」，误判概率已大幅下降。
5. CASTGC 的 `/CAS` 与 `/UnifiedIDMPortal` 两条路径是否都必需 —— 现在两条都会补。
6. `distance`/`duration` 的单位确实是米/毫秒 —— 沿用 `_fmt_pb` 的既有假设。

---

## 怎么验证

```powershell
$py = "<AstrBot 自带的 python.exe 路径>"
$root = "<审计工作目录>"
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:HW_AUDIT_PLUGIN_DIR = "$root\work\astrbot_plugin_Tricy_huawei_health"
Push-Location $root

# 1) v0.4.1 验收测试（171 个用例）
& $py -B -X utf8 -m unittest discover -s work/tests -p "test_*.py"

# 2) 用原始检测探针复跑关键场景（同一批脚本，只换插件目录）
& $py -B -X utf8 -u probe\p1\t01_deadline_forever.py     # 修复前 1200 秒不超时 → 现在 300 秒超时
& $py -B -X utf8 -u probe\p1\t02_sms_filled_and_grace.py # filled 不再被当成已提交；宽限 30 秒
& $py -B -X utf8 -u probe\p1\t03_stuck_launching.py      # 线程启动失败 → FAILED，不再永久 LAUNCHING
& $py -B -X utf8 -u probe\lead\e_cookie_clobber.py       # 重启不再冲掉滚续 cookie，文件已加密
Pop-Location
```

实测输出（节选）：

```
# t01 修复前：B/D 跑满 1200 逻辑秒仍是 still-running
[A] outcome=LoginFlowError(timeout) elapsed=90s state=SUBMITTING
[B] outcome=LoginFlowError(timeout) elapsed=300 逻辑秒 state=NEED_SMS
[D] outcome=LoginFlowError(timeout) elapsed=300 逻辑秒 state=NEED_SMS

# t02 修复前：state=SUBMITTING _sms_action_sent=True
提交后 state=NEED_SMS  _sms_action_sent=False（脚本实际返回 'filled'，从未点击提交按钮）
 t=30.0s  NEED_SMS    验证码可能已失效，请重新输入

# t03 修复前：1 小时后 state=LAUNCHING deadline_left=0
[A] mgr.start() 抛出 LoginFlowError: launch
[A] 异常之后 status(): state=FAILED message='浏览器启动失败，请稍后重试'

# e_cookie_clobber 修复前：被冲掉的 cookie: ['JSESSIONID', '__uni__uid']
   文件头: b'HWCOOK1\x00' (加密)
   被冲掉的 cookie: 无
   重启前 CASTGC: ['RENEWED-BY-ROLLFORWARD']
   重启后 CASTGC: ['RENEWED-BY-ROLLFORWARD']      ← 配置没变，保住滚续
   改了配置后 CASTGC: ['USER-EDITED-CASTGC']      ← 配置变了，正常应用
```
