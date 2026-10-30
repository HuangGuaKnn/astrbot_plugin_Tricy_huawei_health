# 并发与账号状态切换审计 · astrbot_plugin_Tricy_huawei_health v0.5.0-rc.2

> 审计对象：PR #4 引入的并发控制与账号状态切换逻辑（`main.py` 6 个高危区段 + 配套模块）
> 审计基线：`main.py` blob `4736937e4b385a09984ac6091f179bc8ae1d76b2`（**修复前**）。**审计收尾时（22:01:51）维护者在同一工作区应用了发现 2 的 1 行修复**（`main.py` 变为 blob `f5b2354d…`，未提交）；本报告行号以修复前 blob 为准，**601 行之后的引用需 +4 行**（插入的 4 行在 `_commit_login_result` 内，例如 `_run_items 966-997` → `970-1001`）。
> 测试基线：审计起点 `python -m pytest tests -q` → **546 passed, 2 skipped**（176 subtests；2 skipped 为 macOS Keychain 专属）；交付时（含维护者审计期间两次提交 + 发现 2 修复）→ **562 passed, 2 skipped, 181 subtests**。
> 交付形态：只读审计 + 对抗性回归测试 + 变异验证；**本单未改动任何生产语义，未 commit**（工作区里的 `main.py` 改动是维护者的修复，不是本单产物）
> 日期：2026-10-30

---

## 0. 结论摘要（先看这里）

| 项 | 结果 |
|---|---|
| 发现总数 | **10** 条（其中 4 条是「攻击未击穿」的防线/清点结论；发现 2 由独立复核从「不可利用」升级为「已复现」，发现 9/10 由独立复核补充） |
| 高危 | **0** 条 |
| 中危 | **3** 条，其中 **发现 2 已在审计收尾时由维护者应用 1 行修复（工作区未提交，见 §2 发现 2 的「修复状态」）并由本单回归用例锁定**；仍开放 2 条：发现 1 跨进程缓存串号、发现 3 半完成事务重启后丢失 fail-closed |
| 低危 | **7 条**（发现 4 资源上界、发现 5 撕裂快照、发现 6 不可达的永久等待、发现 7 连接池泄漏结论、发现 8 提交路径清点结论、发现 9 死防线、发现 10 单飞继承首个 deadline） |
| 应用内切号是否还会串账号 | **不会**：唯一被击穿的路径是 password 自动登录会话提交（发现 2），已被维护者 1 行修复关闭，并由 `test_login_commit_must_invalidate_inflight_old_account_publication` 回归锁定（删掉那 1 行该用例会红）。WebUI 的 login_start / import / clear / refresh / credentials / post_config 路径本来就安全（实验证伪攻击） |
| 是否会死锁 | 未发现。锁序 `state_lock → manager/session/cookie` 单向一致；实测持 `_state_lock` 最长 31–63 ms；并发 smoke（10 次切号 + 4 个抢锁线程 + invalidate 循环）0.11 s 无挂起（独立复核探针） |
| 超时是否收敛 | **收敛**。工具返回由 `_run_items` + `_cached` 的 deadline 双重硬边界保证；残余是已放弃 worker 线程的资源上界（正常网络 ≈ deadline+≤25 s；病态慢速滴流下无硬上界，见发现 4），且不会污染数据 |
| 是否建议阻止 v0.5.0 转正 | **不建议阻止**。唯一确认的应用内串账号窗口（发现 2）已由维护者在审计收尾时用 1 行修复关闭，并被本单新增回归用例锁定；建议把这行改动随转正一起提交。仍开放的 2 条中危分别需要「插件停用期间手工换 cookie 文件」和「磁盘/加密服务故障 + 密码登录失败」才触发，都有 4–10 行最小改法，可在 v0.5.1 收掉 |
| 新增对抗性测试 | **10 条，全部绿灯**。其中 9 条常规回归从一开始就是绿灯并逐条变异验证；第 10 条（发现 2 的回归）在缺陷存在时先用 `@unittest.expectedFailure` 记录，维护者应用修复后已转正为普通绿灯测试（删掉那 1 行仍会红） |
| 变异验证 | **11/11 KILLED，存活 0**（10 条测试逐一被至少一个单点变异杀死；B2 额外验证 version 维度；D2 专门删除发现 2 的修复行。全部由 Lead 在修复后的真实树上独立重跑复核） |

**给维护者的一句话**：PR #4 的并发模型在「WebUI 应用内切号」这条主路径上是成立的——`auth_epoch` / `data_epoch` / token 删除 / store 清理 / ClientPool 代际 五件事在同一个 `_state_lock` 事务里完成，在飞任务在 publish / commit 两处被复核。唯一被击穿的是 password 模式自动登录会话的提交（`_commit_login_result` 不推进代数），你已经在 22:01 用 `self._data_epoch += 1` 补上，本单的回归用例会替你把这一行钉住。剩下值得排期的只有跨进程换号（发现 1）与半完成事务重启丢 fail-closed（发现 3），以及可以顺手清掉的死防线 `_cache_generation`（发现 9）。

---

## 1. 审计方法与覆盖

### 1.1 逐行读了什么

| 文件 | 区段 | 说明 |
|---|---|---|
| `main.py` | 107–112 `_PooledClient`；233–325 `_password_token`/`_password_token_impl`；327–338 `_assert_current`/`_load_token`；350–409 `_token`/`_client`；413–480 `_cached`；482–524 `_clear_*`/`_change_auth_state_blocking`；526–572 `_change_auth_state*`；574–607 `_import_config_cookies`/`_commit_login_result`；938–1010 `_query_key`/`_query`/`_run_items`/`_overview_items`；1206–1239 `health_status` 探针；1367–1384 `terminate` | 审计时全文件 1384 行（维护者修复后 1388 行；601 行之后的引用 +4 才是修复后行号） |
| `hw_login.py` | 144–186 会话状态机；187–245 start/cancel/join；325–430 `_run`/`_launch`/`_ensure_active`；878–930 `_finish`/`_sweep_allowed`；932–992 `_close_browser`/`_cleanup`；995–1311 Manager（start/cancel/invalidate/current_session/status） | 全文结构 + 关键路径逐行 |
| `hw_auth.py` | 421–478 实例/取消/`_check_current`；545–602 `save_cookies`（CAS mtime）；662–730 import/clear；816–948 `fetch_token`/`_fetch_token_locked` | 提交边界逐行 |
| `hw_client.py` | 40–85 预算/节流；344–460 `_request` 的 Timeout/重试；617–694 `ClientPool` | 全文结构 + 关键路径逐行 |
| `hw_webapi.py` | 349–401 import/clear/refresh；444–520 credentials；524–576 login_start；1081–1195 `post_config` 事务 | 所有会写认证状态的入口 |
| `hw_store.py` | 28–120 连接/加密 token/初始化 | 持久化语义 |
| `tests/` | `test_state_revision.py`、`test_auth_transactions.py`、`test_auth_lifecycle.py`、`test_client_lifecycle.py`、`test_webapi_revision.py`、`tests/boot.py` | 先读已有测试，避免重复造轮子；未触碰 `tests/test_v041.py` |

### 1.2 对抗性验证手段

- 只读静态分析 + 最小复现脚本（在 `%TEMP%` 副本里，不碰仓库生产代码）。
- 网络与浏览器**全假**：测试通过 `tests/boot.py` 把 `data_dir` 重定向到临时沙箱，华为接口用 Mock/SimpleNamespace，绝不真实访问华为域名、绝不启动浏览器。
- 时序全部用 `threading.Event` / `asyncio.Event` 控制；不使用 `time.sleep(0.25)` 这类脆弱等待（需要让出事件循环的位置用 `asyncio.wait`/`Event` 的有界等待，不依赖实际耗时；新增测试里只有既有 `test_auth_transactions.py` 的 `asyncio.wait(timeout=0.05)` 一处属于这种「短有界让渡」）。
- 变异验证：把生产代码复制到 `%TEMP%` 独立目录做**单点**改坏，在副本里跑对应测试，确认变红后丢弃副本（仓库生产代码始终未被修改）。
- 独立复核：另设一名独立审计员对同样 6 个区段做对抗审计，逐条裁决 8 条攻击假设（H1–H8），用 8 个一次性沙箱探针（`%TEMP%\hw_audit_probe\`，不随仓库交付）验证；其中 H1 的反例把发现 2 从「不可利用」升级为「已复现」。Lead 对关键结论（发现 2 的复现与 1 行修复）用真实代码路径独立重跑后才写入报告。

### 1.3 审计期间的环境事实（与派活单不一致，必须记录）

| 项 | 派活单写的 | 实际 |
|---|---|---|
| HEAD | `66d0c3b` | 开始审计时 `1366fd8`；审计期间维护者又提交了 `99705d6 feat(webui): report browser path fallback in status`（21:36:51）和 `7544b2f fix(privacy): redact cookie_* config keys in error messages`（≈21:59） |
| 版本 | v0.5.0-rc.2 | v0.5.0-rc.2（一致，`metadata.yaml` + `main.py` 注册名一致） |
| 工作区 | clean | 开始时 `M hw_webapi.py`、`M pages/health_console/index.html`（维护者 21:36:51 已提交），审计期间工作区被维护者恢复 clean |
| 测试基线 | 538 passed / 148 subtests | **审计起点 546 passed；交付时基线 552 passed / 178 subtests**（维护者审计期间提交了 `test_config_field_validation.py` +4、`test_hw_privacy.py` +2）。`2 skipped` 为 macOS Keychain 专属，本机无 `keyring`，正常 |

关键事实：`git diff 66d0c3b..7544b2f` 只动了 `hw_webapi.py` / `pages/health_console/index.html` / `tests/test_config_field_validation.py` / `hw_privacy.py` / `tests/test_hw_privacy.py`，**`main.py` 的 blob 全程未变**（`4736937e…`），所以本报告所有 `main.py:行号` 对派活单基线和当前 HEAD 同时有效。审计期间维护者在同一工作区持续提交，本报告的行号以 `main.py` blob 为准、不随提交漂移。

另外，审计过程中维护者还在工作区改了 `hw_privacy.py`（`cookie_CASTGC` 等键名的脱敏规则），并已于 ≈21:59 提交为 `7544b2f`（连同 `tests/test_hw_privacy.py` 的 2 条新用例）。该文件与本单审计范围无关、也不是本单改动，特此记录，以免审阅 diff 时误判。

---

## 2. T1 静态审计发现

### 发现 1：缓存/单飞 key 不含账号指纹——跨进程换号（直接替换 cookie 文件）后 TTL 内会读到上一账号的数据

- 位置：`main.py:938-944 _query_key`（key 只含指标名、时区、日期、client_id、api_version）；`main.py:415-438 _cached`（flight_key = `(auth_epoch, data_epoch, key)`，不含账号）；`main.py:176-188 initialize` 的配置 cookie 导入；持久化层 `hw_store.py`（`health.db` 跨重启保留未过期快照）。
- 触发条件：插件**停用期间**账号被换掉且只替换了 `hw_cookies.json`（换机拷贝、备份恢复、手工搬 `plugin_data`），而配置里的 `cookie_*` 字段没变（或配置里本来就只有 cookie 文件）。重启后 `_auth_epoch`/`_data_epoch` 归零，`initialize()` 的 `_import_config_cookies` 返回 0（配置指纹没变）→ **不清 health 缓存**；此时 `data_ttl`（默认 600 秒）内的 `hr:7 / sleep:7 / weight:1095 …` 仍命中上一个账号落盘的数据。`_query_key` 含当天日期，所以最坏在同一自然日内一直命中。
- 后果：串账号（读方向：把 A 的健康数据当成 B 的返回给用户）。不会写坏文件、不会污染 cookie。
- 置信度：**高**（纯代码事实，可确定性复现；限制是「跨进程 + 手工换 cookie 文件」这个入口不在正常 WebUI 流程里）。
- 复现思路：① 用 `tests/boot.py` 造实例 A（沙箱 data_dir），`store.set("hr:7", {"account":"A"})` 后退出；② 直接替换该沙箱的 `hw_cookies.json`（合成字节即可）；③ 用**同一个 data_dir** 新建实例 B（配置不变）；④ `await B._cached("hr:7", <绝不该被调用的 producer>)` → 返回 A 的数据且 producer 未被调用。`_auth_epoch/_data_epoch` 都是 0，`_assert_current` 通过。
- 建议（最小改法）：把「账号指纹」纳入隔离，任选一种——
  1. `_cached` 的 flight_key 与 store key 都加上 cookie 文件内容指纹（`hw_auth._config_digest(load_cookies())` 的 sha256 前缀，或 cookie 文件 mtime_ns + size），成本 `~3 行`；
  2. 或启动时比对「上次启动记录的 cookie mtime」与当前 mtime，不一致就 `_clear_auth_cache_blocking()`（清 token + 健康缓存），成本 `~5 行`。
  不要改 `_query_key` 的 HTTP 语义部分（时区/日期那几项是对的）。

### 发现 2（已复现，中危）：`_commit_login_result` 不推进代数——password 模式的**自动登录会话**提交后，同 epoch 在飞的旧账号查询会把数据 publish 进新账号缓存

> 本发现最初被判为「依赖外部闸门、当前不可利用」；独立复核（另一名审计员 + Lead 用真实 `_token`/`_password_token`/`_cached` 路径重跑）推翻了该结论：WebUI 路径安全，但 `_password_token_impl` 发起的自动登录会话**不经过** `_change_auth_state`，提交时两项 epoch 都不动。
>
> **修复状态（审计收尾）**：维护者于 22:01:51 在工作区应用了建议的 1 行修复（`_commit_login_result` 内 `self._data_epoch += 1`，未提交；`main.py` blob `4736937e…` → `f5b2354d…`）。本单的 `test_login_commit_must_invalidate_inflight_old_account_publication` 在修复前是 expectedFailure、修复后已转正为普通绿灯回归；变异 D2（删掉该行）会让它变红（见 §4）。

- 位置：
  - `main.py:590-607 _commit_login_result`：校验会话身份/epoch（593-598）后 `store.delete("token")`（600）、`store.clear_except("token")`（601）、`_client_pool.invalidate()`（602）、写 cookie（603）、写 token（605-606）——**不** `_auth_epoch += 1`、**不** `_data_epoch += 1`。
  - 触发会话来自 `main.py:263-274 _password_token_impl.start_session`（`manager.start("auto", manual=False)`，**没有** `_change_auth_state` 包裹）→ `hw_login.py:878-898 _finish` → `_commit_login_result`；会话 `_auth_epoch` 在 `hw_login.py:180` 创建时捕获，等于当前 epoch，所以 593-598 的校验会**通过**。
  - 旧账号 token 的来源：`main.py:370-384` 的 password 失败回退分支——它会用 cookie 文件（可能是另一账号）走 cookie 路线并把 token 写进 store（388-398），`_token` 的缓存命中路径（352-360）随后把它交给在飞查询。
  - 接受旧结果的写回点：`main.py:460-469 publish`（`_assert_current(epoch, data_epoch)` + deadline 双校验；两项 epoch 都未变 → 通过）；`main.py:991 _run_items` 的最终断言同样通过，所以**组合工具（overview）也会把提交前取到的旧账号数据直接返回**。
- 触发条件（精确时序，已在沙箱用真实代码路径复现）：
  1. `login_mode == "password"`；store 里的 token 属于**另一账号 B**（典型由来：A 的账号密码登录暂时失败 → 回退 cookie 路线，而 cookie 文件是 B 的；或发现 3 的重启状态）。
  2. 查询 Qb：`_token()` 命中该 token（`main.py:352-356`）→ 进入 producer，用 B 的 token 发慢请求（最长 `QUERY_TIMEOUT=90s`）；此时该 token 的 `expire_at` 只剩几秒。
  3. token 本地过期后，并发查询 Qa：`_token()` 发现缓存过期（360）→ `main.py:370-374` → `_password_token()` → `manager.start("auto")` 用 A 的凭据登录成功（`367-369` 的会话闸门对 `mode == "password"` **显式不生效**）→ `_finish` → `_commit_login_result`：删旧 token、清 store、invalidate 池、写 A 的 cookie/token——**两项 epoch 不变**。
  4. Qb 的慢请求在 commit 之后返回 → `publish` 的两项 epoch 校验通过 → **B 的数据写入 `(auth_epoch, data_epoch, query_key)` 缓存**；之后 A 的查询在 `data_ttl`（默认 600 s）内直接命中 B 的数据。
- 后果：**串账号**（读方向：A 的登录态返回 B 的健康数据；组合工具会返回混合结果），最长 `data_ttl`。不会写坏 cookie/token 文件。
- 置信度：**高**（真实路径复现 + 修复验证）。Lead 复现探针（`%TEMP%\hw_audit_probe\probe_lead_h1.py`，走真实 `_cached`→`_token`→`_password_token`→`_commit_login_result`，只把浏览器登录换成本地线程模拟 `_finish`）输出：
  - 当前代码：`Qa.token: token-A | epochs: 0 0 | stored: token-A`；`Qb: returned {'account':'B'} | cache_after: {'account':'B'}` → **VERDICT: OLD-ACCOUNT DATA WRITTEN BACK**。
  - 同探针 + 1 行修复（`_data_epoch += 1`）：`Qb: raised StateChanged | cache_after: None` → **VERDICT: rejected**。
  - 对照：WebUI `login_start` 路径（`hw_webapi.py:547` 的 `_change_auth_state(lambda: manager.start(...))`）先推 `data_epoch`，同一时序下在飞查询拿到 `StateChanged`、缓存为空（独立复核 Scenario B）。
- 复现思路：
  - 已有可执行的回归用例：`tests/test_state_revision.py::TestStateRevision::test_login_commit_must_invalidate_inflight_old_account_publication`（缺陷存在时是 expectedFailure，修复后已转正；删掉修复行会变红，见 §4 变异 D2）。
  - 手工复现：`python %TEMP%\hw_audit_probe\probe_lead_h1.py`（脚本在临时目录，不随仓库交付）。
- 建议（最小改法 1 行）：在 `main.py:598`（`_commit_login_result` 已通过身份/epoch 校验之后、写 token 之前）加 `self._data_epoch += 1`。副作用：同账号 cookie 模式提交也会让提交前那批在飞取数作废——但 cookie 模式下这批查询本来就被 `367-369` 拒绝、password 模式下它们在等同一个会话，不会产生可用数据，所以没有功能损失。**不要**改成推进 `_auth_epoch`（那会把正在等密码登录的 `_password_token` 等待方直接判成旧状态，语义更重）。

### 发现 3：切号事务失败是「半完成 + 仅内存 fail-closed」——重启后半完成状态会丢，旧 cookie 可能把用户带回旧账号

- 位置：`main.py:506-524 _change_auth_state_blocking`（`_clear_auth_cache_blocking` 已推进 `auth_epoch`、删 token、清 health 缓存 → `mutator()` 可能已经写入新凭据 → `clear_cookies` 抛错 → `_state_error` 留在内存 `True` 并向上抛）；`main.py:529-569 _change_auth_state_async`（finalize 抛错同样留 `_state_error=True`）；`main.py:370-384 _token` 的密码模式回退分支（凭据登录失败且 cookie 文件存在时回退 cookie 路线）；`main.py:1367-1384 terminate`（不处理 `_state_error`）。
- 触发条件：`clear_cookies()` 抛 `OSError`（Windows 上 cookie 文件被备份/杀软短暂占用、ACL 被改、磁盘满），且此前的 `mutator()` 已经把新账号凭据写入并 `set_login_mode("password")`。此时进程内 fail-closed 是正确的（所有查询报「登录状态更新未完成」）；但 `_state_error` 没有落盘，**重启后插件认为状态正常**，于是「新账号凭据 + 旧账号 cookie 文件」共存：密码自动登录成功 → B；密码登录失败（密码错/冷却/额度）→ 回退 cookie 路线拿到 A 的 token → 返回 A 的数据。用户在 WebUI 看到的是 B 的掩码账号。
- 后果：串账号（低概率、需要「磁盘/加密服务故障 + 密码登录失败」两个条件同时成立）；正常路径不会出现。更常见的后果是用户被 blocked 提示困住、只能重开插件，且失败原因没有被持久化。
- 置信度：**中**（代码路径确定；触发需要外部 I/O 故障）。
- 复现思路：① mock `auth.clear_cookies` 抛 `OSError`，`await p._change_auth_state(save_credentials, clear_cookies=True)` → 断言 `_state_error=True`、`_token()` 抛 `StateChanged`；② 用同一 data_dir 新建插件实例（模拟重启），断言 `_state_error` 为 False（即 fail-closed 丢失），且旧 cookie 文件仍在；③ mock 密码会话 FAILED + cookie 路线返回旧 token，观察 `_token()` 走回退分支拿到旧 token。
- 建议（最小改法）：`_change_auth_state_blocking` 失败时写一个 `auth_state_error.marker`（含 `auth_epoch` 与时间），`initialize()` 见到就 `_clear_auth_cache_blocking()` 一次再删 marker（恢复 fail-closed 的持久性）；或者更简单：`credentials_write` 的 `clear_cookies` 改成「先删 cookie 再写凭据」（把不可回滚的删除放在前面，失败时新凭据还没落盘，就不会出现新凭据+旧 cookie 共存）——`~4 行`。

### 发现 4：超时收敛有硬上界，但「已放弃的 worker 线程」会额外占用连接池槽位（最长约一个 socket 读超时）

- 位置：`main.py:966-997 _run_items`（`asyncio.wait(..., timeout=deadline)` + finally 取消）；`main.py:413-480 _cached`（`asyncio.timeout` + `asyncio.shield`）；`hw_client.py:401-447 _request`（`Timeout(total=remaining, connect/read=min(25, remaining))`，`MAX_RETRIES=2` 的重试仍在总预算内）；`hw_client.py:617-694 ClientPool`（`max_size=3`）；`main.py:460-467 publish`（deadline + 代数双校验，拒绝超时结果落库）。
- 触发条件：华为接口慢/网络黑洞，`_run_items` 的一批 producer 已经进入 `asyncio.to_thread`（线程无法被取消）；工具在 deadline 正常返回后，这些线程继续跑到 socket 超时/预算耗尽才退出。它们退出前一直持有 `ClientPool` 槽位（busy），最多 3 条并发；期间新查询的 `_checkout` 只能排队，直到自己的 deadline 也到点。
- 后果：`只是浪费 / 延迟`——不会串数据、不会把超时结果写进缓存（`publish` 有 `time.monotonic() >= deadline` 与 `_assert_current` 双校验），也不会死锁（`_checkout` 等待带 deadline；线程退出后 finally 一定归还槽位）。上界：**在正常网络失败路径下**，单次 socket `read` 超时 = `min(25, 剩余预算)`，重试被 `_budget_sleep`/`_remaining` 限制在总预算内，因此被放弃线程最多比 deadline 多活约一个读超时（≈25 秒）后必然退出。**例外（独立复核补充）**：`requests 2.34.2 / urllib3 2.8.0` 的 `Timeout.total` 不约束「慢速滴流」响应（每个 read 间隔小于 read timeout 时不会触发），DNS 解析也不受 socket timeout 约束；病态/对抗网络下僵尸线程没有硬上界，会持续占池，但工具调用本身仍按自己的 deadline 返回（可用性风险，不是数据正确性问题）。
- 置信度：**高**（上界可从 `hw_client.py:411-445` 直接算出；行为可由 §3 的 B1 测试确定复现）。
- 复现思路：`_cached(deadline=+0.15s)` 的 producer 阻塞在 `threading.Event` 上模拟「线程未收敛」→ 调用方 0.15 秒拿到 `TimeoutError` → 释放 Event → 等线程退出 → 断言池槽位已归还（`ClientPool` 的 busy 标记清零、后续借用能在 2 秒内成功）→ 证明「超时后不泄漏、后续查询不被永久饿死」。
- 建议：可以不改（当前是「延迟换取消不了同步 I/O」的合理取舍）。若要更硬：把 `max_size` 从 3 提到 5 并在 UI 上提示「上一次查询仍在后台收尾」，或给 `_cached` 的 producer 加一个「deadline 已过就不再进入 HTTP」的入口判断（`hw_client._request` 已有 `_remaining` 检查，属于重复防御）。

### 发现 5：`_cached` 对 `(auth_epoch, data_epoch)` 的两字段读取是撕裂快照——危险方向已被封死，但依赖相邻两行的顺序

- 位置：`main.py:415`（`epoch, data_epoch = self._auth_epoch, self._data_epoch`，无锁）；`main.py:494-504 _clear_auth_cache_blocking`（496 先 `_auth_epoch += 1`，497 立刻 `_state_error = True`，503 才 `+data_epoch`）；`main.py:327-333 _assert_current`；`main.py:423-428 lookup`（在 `_state_lock` 内二次 `_assert_current`）。
- 触发条件：读者恰好在线程切换点取到「新 auth_epoch + 旧 data_epoch」。但随后 `_assert_current` 会看到 `_state_error=True`（497 与 496 相邻，几乎无窗口）；即使侥幸过了第一关，`lookup` 在 `_state_lock` 内会等清理事务整体完成（data_epoch 已推进）再二次校验 → 抛 `StateChanged`。反向撕裂（旧 auth + 新 data）必然在 auth 校验失败。
- 后果：**无**（攻击不可达）；属于「正确性依赖两行相邻顺序」的隐式不变量，未来若有人把 `_state_error = True` 挪到清理事务末尾，就会重新打开窗口。
- 置信度：**高**（逐路径推演可证明封死）。
- 复现思路：要在测试里稳定撞出该窗口必须 mock 线程调度，会变成「测试实现细节」；本报告选择记录不变量而不写脆弱用例——§3 的 A 组测试锁定的是同一事务的对外可见语义（切换后旧查询必红、缓存必空）。
- 建议（最小改法）：把两代数合成一个对象/元组，在 `_state_lock` 内取快照（`with self._state_lock: epoch, data_epoch = self._auth_epoch, self._data_epoch`，3 行）；或把 `_state_error` 的置位与 `_data_epoch` 推进合成一个 `_epoch_bundle` 元组整体替换。

### 发现 6：`ClientPool.run(deadline=None)` 会永久等待（生产不可达，属于未来调用点的坑）

- 位置：`hw_client.py:631-656 _checkout`（`remaining = _remaining(deadline)` 为 `None` 时 `self._condition.wait(timeout=None)` 无上限）；`hw_client.py:658-680 run`；生产调用点：`main.py:450`（`_cached` 永远传入非 None deadline，因为 `main.py:421` 有默认 `QUERY_TIMEOUT`）、`main.py:111-112 _PooledClient`、`main.py:1206-1226 health_status` 探针（不走池）。
- 触发条件：未来新增一个不传 deadline 的 `ClientPool.run` 调用点，且池槽位全忙。
- 后果：死锁（仅未来版本可能）。
- 置信度：**高**（代码事实；当前不可达）。
- 复现思路：`pool.run(tok, producer)` 在 max_size=1 且另一线程持槽时永久阻塞——已有的 `test_queue_wait_respects_deadline` 从反面（给 deadline）锁定了这个语义。
- 建议：`run` 入口加 `deadline = deadline if deadline is not None else time.monotonic() + 30`，或 `assert deadline is not None`。1 行。

### 发现 7：`_PooledClient` / `ClientPool` 异常路径未发现连接泄漏（审计结论项）

- 位置：`hw_client.py:658-680 run` 的 `try/finally`；`hw_client.py:682-694 invalidate/close`；`hw_client.py:631-656 _checkout`。
- 触发条件（覆盖矩阵）：producer 抛任意异常 → finally 归还（既有 `test_exception_releases_slot_and_close_rejects_new_work`）；`invalidate()` 后 busy 客户端只在归还时关闭（既有 `test_invalidation_closes_busy_client_only_after_release`）；`close()` 幂等并拒绝新借用（同上）；`_checkout` 在创建/借出 entry 之前抛错不产生 entry，不会泄漏；`_closed` 分支先 remove 再 close，不会 double-close（`HuaweiHealthClient.close` 本身幂等）。
- 后果：无泄漏。唯一真实成本是发现 4 的「已放弃线程占槽」。
- 置信度：**高**（路径穷举 + 既有测试 + 新增 B1 覆盖「超时放弃后的归还」）。
- 复现思路/建议：不需要修复；建议保持 `run` 的 finally 结构，不要在中间加 `return`（会跳过归还）。

### 发现 8：`_assert_current` 提交路径清点——所有会改变账号态的生产写路径都过校验，唯一例外是发现 2

- 位置：逐路径见下表。
- 后果：回答派活单问题「所有提交路径都过了这一关吗？」——**是**（下表 12 条路径逐条核对），唯一不推进代数的写路径是 `_commit_login_result`（发现 2）。
- 置信度：**高**（逐条代码证据）。
- 复现思路：无（这是清点结论）。建议：把下表固化成代码注释或单测清单，防止未来新增写路径绕过。

| # | 写路径 | 位置 | 代数/身份校验 |
|---|---|---|---|
| 1 | `_token` 浏览器/cookie 认证提交 | `main.py:388-398` | `commit()` 内 `_state_lock` + `_assert_current(epoch)`；认证对象自身 `_check_current()`（`hw_auth.py:476-479`，`is_current` 绑定的 epoch 来自 `main.py:229-230`） |
| 2 | `_token` 密码登录 | `main.py:370-384` | `_password_token` 轮询每圈 `_assert_current(epoch)`（`main.py:292`）；`_commit_login_result` 身份+epoch 双重校验 |
| 3 | 健康缓存 publish | `main.py:460-467` | `_state_lock` 内 `_assert_current(epoch, data_epoch)` + deadline 校验 |
| 4 | 缓存命中 lookup | `main.py:423-428` | `_state_lock` 内 `_assert_current(epoch, data_epoch)` |
| 5 | WebUI 导入 cookie | `hw_webapi.py:372` → `main.py:506-524` | `_change_auth_state`（auth+data 代数推进） |
| 6 | WebUI 清除 cookie | `hw_webapi.py:386` | 同上 + `auth.clear_cookies()` |
| 7 | WebUI 刷新 | `hw_webapi.py:397` | 同上，然后 `_token(force=True)` |
| 8 | WebUI 保存/清除凭据 | `hw_webapi.py:470,502` | `_change_auth_state`（保存时 `clear_cookies=True`），finalize 期间 blocked |
| 9 | WebUI 开始登录 | `hw_webapi.py:547` | `_change_auth_state(lambda: login_manager.start(...))`；`_commit_login_result` 再校验会话身份 |
| 10 | WebUI 配置保存（cookie/查询参数变更） | `hw_webapi.py:1162-1168` | `_change_auth_state_async` + `check_current`（配置 revision） |
| 11 | 启动时配置文件导入 | `main.py:176-188` → `574-588` | `_state_lock` 内 `_import_config_cookies`，`n>0` 时 `_clear_auth_cache_blocking` |
| 12 | `health_refresh` 工具 | `main.py:1361` | `_invalidate_auth_cache` → `_change_auth_state` |
| — | `_clear_health_cache` 单独调用 | `main.py:482-492`、`hw_login.py:908` | 只推进 `data_epoch`；生产仅被 `_clear_auth_cache_blocking` 包在事务里调用；`hw_login.py:908` 那条是「插件没有 `_commit_login_result`」的兼容桩路径（生产不会走到） |

### 发现 9：`_cache_generation` 是「死防线」——注释声称防旧结果回写，但没有任何读者（低危）

- 位置：`main.py:141-142`（`self._cache_generation = {}` + 注释「generation 用于阻止刷新后旧请求把结果写回缓存」）；`main.py:485-486`（`_clear_health_cache` 里对已有键自增）；`tests/test_v041.py:2072-2074`（只断言自增）。全仓库检索 `_cache_generation` 只有这三处，**没有任何读取点参与放行/拒绝**。
- 触发条件：不触发缺陷，是「防御声明与实现不一致」。
- 后果：当前正确性完全由 `(auth_epoch, data_epoch)` + `_state_lock` 内 `_assert_current` 保证（发现 2 的复现说明：epoch 不动时旧结果确实会回写）。但若后续有人以为 generation 已兜底而放宽 epoch 断言，就会变成真实回写。
- 置信度：**高**（grep 结果可复核）。
- 复现思路：`grep -n "_cache_generation" -r .`；观察 `_cached` 的 flight_key/publish 只用 `(auth_epoch, data_epoch, key)`。
- 建议：删除 `_cache_generation`（含注释与 485-486 两行），或真正接进 `_cached` 的 flight_key/publish 校验。保留现状会让后来者误判防线位置。**注意红线**：`tests/test_v041.py` 里那条自增断言是 v0.4.1 验收基线，本次未动；若决定删除该字段，需维护者单独评估那条基线用例。

### 发现 10：`_cached` 的共享单飞任务继承「首个调用者」的 deadline/ttl（低危，仅提前超时/缓存时长偏差）

- 位置：`main.py:421`（deadline 由首个调用者确定）；`main.py:438-474`（flight_key 只含 `(epoch, data_epoch, key)`，已有任务直接复用）；`main.py:441-469 produce` 闭包捕获首个调用者的 `deadline`/`ttl`；`main.py:477-478` 第二个调用者用**自己的** timeout 等同一个 task。
- 触发条件：两个调用者对同一 cache key 并发且首个 deadline 更早（例如 WebUI `/overview` 的 90 s 预算与 LLM 工具的调用先后脚），或两者传入的 ttl 不同（`_overview_items` 写死 600，`health_sleep` 用配置 `data_ttl`）。
- 后果：第二个调用者会在**首个调用者的** deadline 处拿到 `TimeoutError`（比自己应得的更早），缓存时长也按首个调用者的 ttl 记。不产生账号串数据（publish 仍按首个的 epoch/deadline 校验）。
- 置信度：**中高**（代码路径可指认；未单独写时序用例——后果仅是延迟）。
- 复现思路：`_cached("k", p1, deadline=t+0.2)` 与 `_cached("k", p2, deadline=t+5)` 并发，第二个也会在 0.2 s 附近超时。
- 建议：可只记录。若要改，不要简单地把 deadline 放进 flight_key（会让单飞失效）；更合理的是 produce 用 `max(调用者 deadline)` 或让调用方统一 deadline（`_run_items` 已经统一）。

### 2.9 派活单三个重点问题的直接回答

**Q1 旧结果回写：任务 A 在飞（epoch=1）时切账号（epoch→2），A 的 finally 里有没有路径能写 `_cache` / `_token` / cookie 文件？**
- `_cache`：能走到 `publish`，但 `publish` 在 `_state_lock` 内 `_assert_current(epoch, data_epoch)`，epoch 不匹配 → 抛 `StateChanged`，不写。✅ 封死。
- `_token`：`_token.commit` 同样 `_assert_current(epoch)`；`hw_auth` 的 cookie 回写有 `_check_current()` + mtime CAS（`save_cookies(expected_mtime_ns)`）双保险。✅ 封死。
- cookie 文件：正常清理/导入会 `os.replace` 原子替换；认证线程的回写在 `_state_lock` 内做 mtime CAS，检测到变化就放弃（`hw_auth.py:560-575`）。✅ 封死。
- **唯一不在这个闭环里的写路径**是 `_commit_login_result`（发现 2）：它不推进代数，而 password 自动登录会话又不经过 `_change_auth_state`。WebUI 的 login_start 路径因为先推 epoch 而安全，自动登录路径**已复现**旧账号数据回写（见发现 2 的时序与探针输出）——**该窗口已在审计收尾时由维护者 1 行修复关闭**。

**Q2 缓存串账号：`_cached()` 的 key 里含账号标识吗？**
- 不含账号名/凭据指纹。替代机制是 `(auth_epoch, data_epoch)` + 切号事务里 `store.clear_except("token")`。**WebUI 的所有切号入口**（发现 8 的表 5–12）都推进代数并清 store，所以「切账号后同一 key 取到上一账号数据」在 WebUI 路径上**不成立**；但 **password 自动登录会话提交（发现 2）** 是一个反例：它清 store 却不推进代数，在飞旧账号查询随后把数据写回同一 `(epoch, data_epoch)` 的 key，**会**串账号（已复现）。跨进程重启是另一个缺口（发现 1）。**结论：key 里不含账号指纹是根因；在「自动登录提交」与「跨进程换号」两个入口上，这个根因已经能兑现成真实串号。**

**Q3 超时不收敛：`_run_items(deadline=...)` 下某个 producer 永久阻塞时，整体能否在 deadline 附近返回？**
- 能。工具侧返回时间由 `asyncio.wait(tasks, timeout=deadline-now)`（`main.py:983`）+ 每个 `_cached` 自己的 `asyncio.timeout`（`main.py:454,477`）双重保证；`asyncio.shield` 只保护共享任务不被单个调用方取消，不阻塞返回。`finally` 对未完成任务 `cancel()` + `gather(..., return_exceptions=True)`，不会被 `asyncio.to_thread` 里的线程拖住（线程不可取消，但协程可以）。
- 残余：被放弃的线程最多多活约一个 socket 读超时并占用池槽位（发现 4），属于资源上界而非收敛失败；它们**不会**把超时结果写进缓存（`publish` 双校验）。

---

## 3. T2 新增对抗性测试（共 10 条，交付时全部绿灯）

> 原则：只补「现有 5 个文件没有覆盖」的场景；全部加进已有文件，没有新建平行测试文件；每条 docstring 写明「如果这条测试红了，说明生产出了什么问题」。

### 3.1 `tests/test_state_revision.py`（+4 常规 + 1 条发现 2 回归，纯追加 236 行）

| 测试 | 锁定的防线 / 红了说明什么 |
|---|---|
| `test_active_login_session_blocks_old_cookie_authentication` | `_token` 的「网页登录正在进行」闸门（`main.py:367-369`）。红了 = cookie 模式在 NEED_SMS 会话进行中绕开闸门、用旧 cookie 发起认证：用户可能拿到上一账号/过期凭据的数据，且拉起的登录会话永远等不到用户输入 |
| `test_epoch_change_during_password_wait_raises_state_changed` | 密码轮询循环里的 `_assert_current(epoch)`（`main.py:292`）。红了 = 等密码登录期间切号后，等待方继续空等 60~100 秒超时（极端情况下把旧会话 token 当新账号 token 返回） |
| `test_auth_expired_retry_forces_new_token_and_rejects_old_result` | `_token` 的 `stale_token` 语义（`main.py:361`）+ `_cached` 的 AuthExpired 重试（`main.py:456-459`）+ commit 的代数校验。红了 = 401 后继续复用死 token、或把旧 token 上的失败结果写进缓存、或缓存已是新 token 时重复触发登录 |
| `test_identical_concurrent_queries_run_producer_once` | `_cache_inflight[flight_key] = task` 的单飞注册（`main.py:474`）。红了 = 同 key 并发查询各起一个 producer，同一华为接口被重复打（限流/风控），两个调用方还可能拿到不同快照 |

### 3.2 `tests/test_client_lifecycle.py`（+2，纯追加 125 行；两个新测试类）

| 测试 | 锁定的防线 / 红了说明什么 |
|---|---|
| `TestAbandonedWorkerReleasesSlot::test_abandoned_worker_releases_pool_slot_for_later_queries` | `ClientPool.run` 的 `finally` 归还（`hw_client.py:669-680`）+ `_cached` 的 deadline 放弃（`main.py:477-478`）。红了 = 一次超时后，被放弃的 worker 线程占住的槽位没还回来，后续查询被永久饿死到自己的 deadline（发现 4 的最坏形态） |
| `TestClientPoolKeyIsolation::test_pool_key_separates_timezone_version_and_client_id` | `ClientPool.run` 的 key 五元组（`hw_client.py:660-662`）。红了 = 配置切换 timezone / api_version / client_id 后复用按旧语义构造的 `requests.Session`：`startDay/endDay` 差一天、`x-version`/`x-client-id` 串台 |

### 3.3 `tests/test_auth_transactions.py`（+3，纯追加）

| 测试 | 锁定的防线 / 红了说明什么 |
|---|---|
| `test_account_switch_during_token_fetch_rejects_old_token` | `_token` 的 `commit()` 内 `_assert_current(epoch)`（`main.py:390`）。红了 = 旧账号认证在飞时切号，旧 token 被回写进 store（旧结果回写问题①）、或切号被旧认证拖死 |
| `test_concurrent_token_requests_share_one_authentication` | `_token` 的 `async with self._lock`（`main.py:357`）。红了 = 并发请求各起一套浏览器/OAuth 抢同一个 profile（额度/风控），认证没有单飞 |
| `test_cookie_clear_failure_keeps_queries_blocked_and_cookie_file` | `_change_auth_state_blocking` 的失败重抛与 `_state_error` fail-closed（`main.py:512-521`）。红了 = 清 cookie 失败被吞掉、查询被放行、旧 cookie 文件被半完成事务删掉（发现 3） |

补充说明：
- 10 条常规测试都只用 `threading.Event` / `asyncio.Event` 控制时序，没有 `time.sleep(0.25)` 这类脆弱等待；网络与浏览器全假（`boot.py` 沙箱 + Mock auth）；没有新增依赖、没有新建平行测试文件。
- 每条测试的 docstring 都写明了「红了说明生产出了什么问题」，与上表一一对应。

### 3.4 发现 2 的回归用例（+1，交付时为普通绿灯测试）

`tests/test_state_revision.py::TestStateRevision::test_login_commit_must_invalidate_inflight_old_account_publication`

- 直接复现发现 2：Qb 用即将过期的 B 账号 token 进入生产者 → Qa 走真实的 `_token → _password_token → manager.start("auto") → _commit_login_result` 提交 A 账号 → Qb 返回后断言「缓存必须为空、Qb 必须收到 `StateChanged`」。
- 历史：缺陷存在时它以 `@unittest.expectedFailure` 落地（xfailed 也算 pytest 绿）；维护者应用 1 行修复后它变为 "Unexpected success"，已删除装饰器转正为普通回归——**现在删掉 `_commit_login_result` 里那行修复，它会立刻变红**（§4 变异 D2）。
- 这条用例同时是把发现 2 的修复钉在 CI 里的手段：修复不是靠人工记得，而是靠变异可杀的断言。

---

## 4. T3 变异验证记录（11/11 KILLED，存活 0）

> 方法：仓库整体复制到 `%TEMP%` 独立目录 → 对副本做**单点**改坏 → 在副本里跑对应测试文件 → 确认指定测试变红 → 丢弃副本。仓库生产代码全程未被修改。11 个单点变异覆盖 §3 的 10 条新测试（B2 多验了 version 维度）。本轮在**修复后的真实树**（`main.py` blob `f5b2354d…`）上重跑，全部 KILLED。

| 变异 | 改了什么 | 结果 |
|---|---|---|
| 1（A1） | `main.py:367-369` 整段删除 `_token` 的「网页登录正在进行」闸门 | **KILLED**：`test_active_login_session_blocks_old_cookie_authentication` 红（`_fetch_auth` 真被调用，`AssertionError: 旧 cookie 不得被用于认证`） |
| 2（A2） | `main.py:292` 删除密码轮询循环里的 `self._assert_current(epoch)` | **KILLED**：`test_epoch_change_during_password_wait_raises_state_changed` 红（`asyncio.wait_for(...,2)` 抛 `TimeoutError` 而不是 `StateChanged`） |
| 3（A3） | `main.py:361` `if not force or (stale_token and cached["token"] != stale_token):` → `if not force:` | **KILLED**：`test_auth_expired_retry_forces_new_token_and_rejects_old_result` 红（`AssertionError: 缓存已有新 token 时不得重复登录`）。注：在「cached == stale_token」主路径上该改法与原文等价，真正报警的是同一测试第二段断言（强制刷新已生效后 `force + stale_token` 必须复用新缓存、不得二次登录）——即该测试钉住的是这条守卫的完整语义，不是单一分支 |
| 4（A4） | `main.py:474` 删除 `self._cache_inflight[flight_key] = task`（单飞注册） | **KILLED**：`test_identical_concurrent_queries_run_producer_once` 红（producer 被调用 `['test','test']` 两次） |
| 5（C1） | `main.py:390` 删除 `commit()` 内 `self._assert_current(epoch)` | **KILLED**：`test_account_switch_during_token_fetch_rejects_old_token` 红（旧账号 token 被写进 store） |
| 6（C2） | `main.py:357` `async with self._lock:` → `async with asyncio.Lock():`（等价于取消认证互斥） | **KILLED**：`test_concurrent_token_requests_share_one_authentication` 红（`2 != 1`：并发 `_token()` 触发了两次认证） |
| 7（C3） | `main.py:521` `_change_auth_state_blocking` 的 `except Exception:` 内 `raise` → `pass` | **KILLED**：`test_cookie_clear_failure_keeps_queries_blocked_and_cookie_file` 红（`OSError not raised`；既有 `test_mutator_failure_never_runs_finalizer_or_reuses_old_cache` 同变异也红，多点检出，不影响结论） |
| 8（B1） | `hw_client.py:675` 删除 `ClientPool.run` 的 `finally` 里 `entry["busy"] = False` | **KILLED**：`test_abandoned_worker_releases_pool_slot_for_later_queries` 红（后续借用在 `_checkout` 等满 deadline 抛 `RequestDeadlineExceeded`，槽位被永久占住） |
| 9（B2a） | `hw_client.py:660-662` key 元组里 `tz` → `"+0800"`（忽略时区变化） | **KILLED**：`test_pool_key_separates_timezone_version_and_client_id` 红（时区变了仍返回 base 客户端） |
| 10（B2b，附加） | 同 key 元组里 `version or DEFAULT_VERSION` → `DEFAULT_VERSION`（忽略版本变化） | **KILLED**：同一测试红（版本变了仍复用旧会话） |
| 11（D2） | 删除 `main.py` `_commit_login_result` 里的 `self._data_epoch += 1`（维护者刚补上的那一行，修复前不存在此行） | **KILLED**：`test_login_commit_must_invalidate_inflight_old_account_publication` 红（`StateChanged` 未抛出，旧账号结果被 publish 进缓存）。同时 `probe_lead_h1.py` 在删行副本上复现 `cache_after: {'account':'B'}` → 证明该行是这条用例的**唯一**保护 |

**复核方式**：以上 11 个变异由 Lead 用同一套脚本独立重跑（不是只信执行者的汇报）：仓库复制到 `%TEMP%\hw_verify\repo` → 逐个把原文件还原后做单点替换（`str.replace` 断言只命中一次）→ 在副本里跑**定向 node id** → 记录 returncode → 还原。仓库生产代码全程未被修改；脚本跑完自行删除副本。复核结果：**11/11 KILLED，存活 0**。

**发现 2 的修复与验证闭环**：Lead 先用 `probe_lead_h1.py`（真实 `_token`/`_password_token`/`_cached`/`_commit_login_result` 路径，只把浏览器登录换成本地线程模拟 `_finish`）在修复前复现（`cache_after: {'account':'B'}`）、在临时副本加 1 行后验证被拒（`StateChanged`、`cache_after: None`）；随后维护者在真实工作区应用了同一修复（22:01:51，未提交），本单把当时的 expectedFailure 用例转正为普通回归，并用变异 D2 在真实树副本上确认「删掉该行 → 用例必红」。

**交叉印证发现 6**：B1 的变异（删 `busy=False`）若跑整个 `test_client_lifecycle.py` 会**挂起超过 50 秒**——因为既有 `TestClientPool` 有用例以 `deadline=None` 等槽位，槽位泄漏后 `Condition.wait(None)` 永久等待。这正好在运行时印证了发现 6：「`ClientPool.run(deadline=None)` 会永久等待」是真实存在的语义，当前只是靠「生产调用点都传 deadline」不可达。所以 B1 的 KILLED 证据用定向用例 + `--deselect TestClientPool` 取得，原仓库完整命令全绿。

---

## 5. T4 结论

- **发现总数：10；高危：0；中危：3（发现 1/2/3，其中发现 2 已修复关闭）；低危：7（发现 4/5/6/7/8/9/10）。**
- **是否建议阻止 v0.5.0 转正：不建议阻止。** 理由：
  1. 唯一被击穿的应用内路径是发现 2（password 自动登录会话提交，已复现），维护者已在审计收尾时用 1 行修复关闭，并由本单回归用例锁定（变异 D2 可杀）。建议把这行改动随转正一起提交。
  2. WebUI 的全部应用内切号路径（导入/清除/刷新/保存凭据/开始登录/health_refresh/配置变更）都走同一个 `_state_lock` 事务，`auth_epoch`、`data_epoch`、token 删除、store 清理、ClientPool 代际、登录会话失效六件事原子完成；在飞任务在 `publish` 与 `commit` 两处复核代数。这些路径没有找到可复现的串号/回写/死锁（独立复核也逐条证伪了攻击）。
  3. 仍开放的两条中危（发现 1 跨进程、发现 3 半完成事务）分别需要「插件停用期间手工替换 cookie 文件」和「磁盘/加密服务故障 + 密码登录失败」，正常使用路径不会出现，且都有 4–10 行最小改法，建议 v0.5.1 收掉。
  4. 超时收敛与连接池异常路径未发现缺陷；残余的 worker 线程占用是同步 HTTP 无法取消的物理下界，且不会污染数据。
- **如果只能做一件事**：确认工作区里发现 2 的 1 行修复随转正提交、并保留 `test_login_commit_must_invalidate_inflight_old_account_publication` 这条回归（它现在能杀死删掉该行的变异）。下一优先级是把发现 1 的「cookie 指纹进缓存 key / 启动时比对」做掉。
- **独立复核说明**：本单另设一名独立审计员，对同一 6 个区段做对抗审计并裁决 8 条假设（4 条被实验证伪：H4/H6/H7/H8；2 条确认：H2/H3；2 条部分成立：H1 升级为发现 2、H5 降级为资源上界），产出 `%TEMP%\hw_audit\findings_auditor.md` 与 8 个一次性探针脚本（不随仓库交付）。本报告的发现 2 由该复核从「不可利用」升级为「已复现」，并补充了发现 9/10；Lead 用真实代码路径重跑了关键复现与修复验证后才定稿。
- **未能覆盖 / 不能确定的部分（明确列出）**：
  1. **真机并发**：本审计全部是离线单测 + 静态推演；没有在 AstrBot 真实事件循环里做多用户并发压测，也没有跨进程/跨平台（Linux/macOS 的 DPAPI/Keychain 分支）验证。`read_devtools_port` 那类「只在真机出现」的问题不在本审计能力范围内。
  2. **AstrBot 框架语义**：`filter.on_llm_request` / `llm_tool` 的取消、工具超时（120 秒）与事件循环任务调度细节按代码注释理解，未在框架源码里逐一核对（这会改变「取消发生在哪一刻」的假设，但不改变 `_assert_current` 的结论）。
  3. **WebUI 前端并发**：`pages/health_console` 的多标签页/重复点击只按后端幂等语义推断，未审前端；`hw_webapi` 的 config revision 事务只做了代码阅读级审计。
  4. **`hw_login.py` 浏览器会话内部**：CDP/验证码/信任设备的状态机只审了与插件状态锁交汇的部分（`_finish` / `_ensure_active` / `cancel` / `_close_browser`），没有逐行审计 CDP 脚本与页面状态机；已有的 `test_login_cookie_ready.py` 覆盖面之外的风险未排除。
  5. **持久化对抗**：SQLite WAL / DPAPI / AES-GCM 的崩溃一致性只按 `save_cookies` 的「临时文件 + fsync + os.replace」与 `HealthStore` 每次新建连接的注释理解，未做断电/崩溃注入测试。
  6. **长时间运行**：`_cache_inflight`、`ClientPool._entries`、登录额度列表等结构的长期增长只做了静态判断（都有上界或清理路径），未做 24 小时 soak 测试。

---

## 6. 红线与验收自查

| 验收项 | 结果 |
|---|---|
| `pytest tests -q` 仍全绿且 ≥538 passed | **562 passed, 2 skipped, 181 subtests**（交付时实测，退出码 0；含维护者的发现 2 修复）。数字对账：审计起点基线 546 → 维护者 `99705d6` +4、`7544b2f` +2 → 552 → 本单新增 10 条测试 → 562 passed。`2 skipped` 为 macOS Keychain 专属，本机无 `keyring`，正常 |
| 新增测试 ≥8 条，全部围绕并发/取消/账号切换 | **10 条**（4+2+3+1，全部绿灯），见 §3 |
| 每条新测试有变异验证记录，存活 0 | **11 个单点变异 11/11 KILLED，存活 0**（§4；含专门删除发现 2 修复行的 D2） |
| 每个发现都有触发条件 + 复现思路 | 10/10（§2） |
| `python scripts/privacy_gate.py --repository .` 输出 clean | **clean** |
| `git diff --name-only` 只显示 `tests/` 与新增 `AUDIT_concurrency.md` | 本单自身改动只有下 4 项。工作区还显示 `M main.py`，那是**维护者**在审计收尾时应用的发现 2 修复（22:01:51，本单未触碰）；维护者审计期间的其它改动（`hw_webapi.py`/`pages`/`test_config_field_validation.py`/`hw_privacy.py`/`test_hw_privacy.py`）已被维护者提交（`99705d6`、`7544b2f`） |
| 未动 `tests/test_v041.py` | 未动（红线 1） |
| 未改业务语义 / 未引入依赖 / 未读真实凭据 / 未提权 / 测试全假 / 未改 CHANGELOG·metadata·版本号 / 未 commit | 全部遵守（红线 2–8） |

**本单实际改动清单**（交付时以 `git diff --name-only` 为准）：
```
AUDIT_concurrency.md            ← 新增（本报告）
tests/test_state_revision.py    ← 追加 4 条常规测试 + 1 条发现 2 回归（原 expectedFailure，修复后转正）
tests/test_client_lifecycle.py  ← 追加 2 条
tests/test_auth_transactions.py ← 追加 3 条
```
不包含 `main.py`：它的未提交改动是维护者的修复，不是本单产物。
