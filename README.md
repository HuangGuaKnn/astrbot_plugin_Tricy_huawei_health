# 华为运动健康 · AstrBot 插件

版本：v0.4.2

把华为运动健康**网页端**的睡眠 / 静息心率 / HRV / 运动记录 / 跑力数据接进 AstrBot，
按需查询睡眠、心率、HRV 等健康数据。

数据源：`health.cloud.huawei.com`（华为运动健康云 / 训练营网页端）
认证：默认注入 cookie → 自动走 OAuth；WebUI 也可打开可见浏览器手动完成登录 → accessToken
取数：纯 HTTP，**不需要浏览器常开**，也不需要手机 / 手表 / ADB

---

## v0.4.1 变更（一轮完整检测后的修复）

> 检测共发现 41 条问题（P0×2 / P1×12 / P2×17 / P3×10），本版修复了其中绝大多数，
> 逐条对应关系见 `CHANGELOG_v0.4.1.md`。最要紧的几条：

1. **账号密码模式原本每天只能用 50 分钟**：额度语义改成「每天允许的**失败**次数」，
   成功登录会归还名额（默认 3 次/天）；失败时还能退回 cookie 路线。
2. **验证码链路**：`filled`（只填框没找到提交按钮）不再被当成「已提交」；
   重发宽限期 8 秒 → 30 秒；支持 4~8 位与单输入框。
3. **每次插件启动不再用配置快照覆盖 `hw_cookies.json`**——这是最隐蔽的一条：
   原来每次重启都会把认证回写的滚续结果冲掉，失败还误报「cookie 已过期」。
   现在用配置指纹判重：配置没变就不动文件，改了才应用，且与现有 cookie 合并而不是整份替换。
4. **登录状态机不再有「进得去出不来」**：`_set_state` 只为真正的状态变化重置超时；
   另加会话硬上限。原来 `NEED_SMS` 可以无限期挂着。
5. **`hw_cookies.json` 现在是 DPAPI 加密的**（`HWCOOK1\0` + 密文，旧明文文件仍可读），
   POSIX 下统一 0600，数据目录 ACL 收紧。
6. **数据层能区分「接口改版」和「真的没数据」**：字段缺失/改名会报
   「华为接口结构变了，请升级插件」，而不是静默显示「最近 7 天没有睡眠记录」。
7. **体重「最新」不再是均值**、运动记录的距离/时长补上了单位。
8. 依赖加了版本上限；`websocket-client` 缺失不再让整个插件加载失败。

---

## 工具（8 个 LLM 工具）

| 工具 | 作用 |
|---|---|
| `health_status` | 通道状态：登录方式、凭据/cookie、token 剩余、实测连通性 |
| `health_today` | 今日概况：今天静息心率 + 最近一晚睡眠 + 近期运动 |
| `health_sleep` | 最近 N 天睡眠明细（入睡/醒来时间、深浅睡 / REM / 得分 / 入睡用时 / 夜醒） |
| `health_heart` | 最近 N 天静息心率 + 睡眠 HRV |
| `health_activities` | 运动记录列表（距离/时长已带单位） |
| `health_performance` | 运动能力评估（跑力 / 预测成绩）+ 跑步个人纪录 |
| `health_overview` | 一次性查看全部已接入的健康数据（含近期运动） |
| `health_refresh` | 清缓存并强制重新认证（数据在下次查询时重新拉取） |

---

## 配置

插件配置页里能填的：

| 配置项 | 说明 |
|---|---|
| `cookie_CASTGC` / `cookie_sid` / `cookie_hwid_cas_sid` | 从 `.id1.cloud.huawei.com` 复制对应 cookie 的值；CASTGC 会自动生成 `/CAS` 与 `/UnifiedIDMPortal` 两条 |
| `cookie_HuaweiID_CAS_ISCASLOGIN` / `cookie_CASLOGINSITE` / `cookie_LOGINACCSITE` | 从 `.huawei.com` 复制对应 cookie 的值 |
| `cookie_json` | 旧版兼容入口：Cookie-Editor 导出的整段 JSON（仍可使用；导入时同样会补齐 CASTGC 的两条路径） |
| `page_timeout` | 认证浏览器/CDP 超时秒数（默认 90） |
| `browser_path` | 浏览器路径，留空自动探测 Edge / Chrome |
| `headless` | 无头模式（默认开） |
| `token_ttl` | accessToken 缓存秒数（默认 3000） |
| `data_ttl` | 数据缓存秒数（默认 600）；**设为 0 = 彻底不缓存**（连总览/运动能力都现取） |
| `warmup` | 启动时后台预热 token（默认开；**开启后插件启动 8 秒会自己起一次浏览器**） |
| `login_daily_limit` | 账号密码模式每日自动登录**失败**次数上限（默认 3，成功不计入） |
| `timezone` | 取数用的时区偏移（默认 `+0800`） |
| `client_id` / `api_version` | 华为网页端的 `x-client-id` / `x-version`，接口不变就别改 |

cookie 也可以直接用文件：`data/plugin_data/astrbot_plugin_Tricy_huawei_health/hw_cookies.json`
（配置里的分项 cookie 或旧版 `cookie_json` 有内容时**会写入**这个文件；文件已存在且配置没变时不会覆盖）

> **配置导入的判重规则**：插件启动时会把「配置里那六条」算一个指纹存在
> `hw_cookies.json.config_applied`。指纹没变就跳过导入（保住认证回写的滚续 cookie）；
> 指纹变了才应用，并且是**合并**到现有 cookie 里，不会删掉 OAuth 期间下发的其它 cookie。
> 想强制以配置为准：删掉 `.config_applied` 文件，或改一下任意一条 cookie 值。

---

## 怎么拿 cookie

1. 电脑浏览器登录 <https://health.cloud.huawei.com/TrainingCamp>，确认能看到自己的数据；
2. 在 Cookie-Editor 中分别复制下面 6 条的值：
   - `CASTGC`：`.id1.cloud.huawei.com`，插件自动生成 `/CAS` 与 `/UnifiedIDMPortal` 两个路径；
   - `sid`、`hwid_cas_sid`：`.id1.cloud.huawei.com`；
   - `HuaweiID_CAS_ISCASLOGIN`、`CASLOGINSITE`、`LOGINACCSITE`：`.huawei.com`；
3. 把值填入插件设置页对应的 6 个分项字段，或在 WebUI 控制面板逐项填写；
4. 旧版也可继续导出整段 JSON，粘贴到 `cookie_json` 或 WebUI 的 JSON 框。

`CASTGC` 是 session cookie，关闭原浏览器后会失效；重新登录后需重新复制有效值。

> **按序填写必须是恰好 6 行**（或每行写成 `名称=值`）。少一行会让后面的值整体错位，
> 多一行会被丢弃——v0.4.1 起这两种情况会直接报错，不再静默导入。
> 缺 `CASTGC` / `sid` 会直接报错；缺其余四项只会在日志里告警。

---

## WebUI 控制面板

页面在 `pages/health_console/`，从 AstrBot 插件管理页打开（与 MC 智控台同一套页面机制）。

| 区块 | 内容 |
|---|---|
| 通道状态 | cookie 条数 / 更新时间、token 剩余秒数、浏览器探测结果、缓存条数、数据目录 |
| 关键 cookie 表 | 六条关键 cookie 的域与到期日，一眼看出「信任设备」还剩多久 |
| 账号登录 | 打开独立可见浏览器，在窗口内手动输入账号密码；验证码可从 WebUI 提交，信任设备支持自动或手动选择；成功后自动保存新 Cookie |
| 账号密码凭据 | WebUI 主动保存后写入 Windows DPAPI 加密的 `credentials.bin`；页面只显示账号掩码和保存时间，不回填密码 |
| 操作 | 清缓存并重新认证 · 刷新状态 |
| 数据概览 | 9 项数据的取数结果 + 取数时间 |
| 重新导入 Cookie | 六条分项值或 Cookie-Editor JSON 导入（自动作废 token 缓存）；也可一键清除 cookie |

技术：走 AstrBot 的 bridge SDK（`window.AstrBotPluginPage`），iframe 内用 bridge、
独立窗口降级直连 `/api/v1/plugins/extensions/<plugin>/page/...`；主题跟随系统并支持手动切换。

登录相关的非敏感选项保存在插件数据目录的 `login_config.json`（包含模式和 `auto_trust`）。
账号密码不会写入插件配置、WebUI 状态或日志；凭据由 Windows DPAPI 绑定当前用户加密，文件被误传、备份泄露或被其他程序顺手读取时不能直接还原。
DPAPI 不防同一 Windows 用户下已经能执行代码的恶意程序；它必须能在本机自动解密，才能支持无感登录。账号密码模式支持无头自动填充、验证码 WebUI 介入和可选的可见窗口兜底，并带跨重启的失败次数限制与失败冷却。

> **账号密码模式需要人工介入时，取数工具会立刻返回提示**，不会占着工具调用等 7 分钟
> （AstrBot 的默认工具超时是 120 秒）。看到「自动登录需要你输入手机验证码」就去
> WebUI 的「账号登录」区完成，会话会保留 5 分钟，完成后再问一次即可。
>
> `hw_cookies.json` 现在是 DPAPI 加密的；换 Windows 用户或换机器后它解不开，需要重新导入 cookie。
> 非 Windows 平台没有 DPAPI，该文件会退回明文但权限是 0600。

### 开发踩坑（2026-10-22 实测）

1. **bridge 返回的是「裸数据」，不是整个响应体。**
   AstrBot 插件 API 的约定是 `{status, message, data}`，但 `bridge.apiGet()` / `apiPost()`
   会把 `data` **解包一层**直接给你。所以前端**不要写 `if (r.status === "ok")`** —— 永远为 false，
   会表现为「接口明明成功、页面却报失败」。页面里的 `unwrap()` 做了两种形态兼容。
2. **改完 `pages/**/*.html` 要在浏览器里 `Ctrl + F5` 强刷。**
   页面是服务端每次现读文件（无缓存），但**浏览器会缓存**，不加时间戳重载会一直跑旧版。
3. **插件页面入口的 URL 形态**：`/api/v1/plugins/<plugin>/views/<view>/_t/<JWT>/?asset_token=<JWT>`，
   token 同时在路径与 query 里；iframe 是 sandbox 隔离的，`fetch` 直连带不上 cookie，
   所以**iframe 内必须走 bridge**。
4. **直连降级只对「独立窗口」有意义**（同源、有 cookie），iframe 内直连必定 401。
5. **`asset_token` 不要拼进 API URL**：AstrBot 的 `/api/v1` 鉴权只看 `Authorization` 头和 cookie，
   不读 query 里的 token（v0.4.0 会把一枚 7 天有效的 JWT 撒进诊断面板和反向日志）。

---

## 工作原理

```
取数请求
  ↓
token 缓存有效？──是──→ requests 直连 hihealthbase 取数
  │否
  ↓
起 headless 浏览器 → 注入 cookie 文件
  → 打开 TrainingCamp → 无 token 就自动点「登录」
  → OAuth 自动授权（信任设备，无二次验证）
  → 读 sessionStorage.accessToken → 回写新 cookie → 关浏览器  （约 30~40 秒）
  ↓
requests 直连 API 取数 → 落 SQLite → 返回
```

关键细节（踩过的坑，别改）：

- 华为登录态的核心 cookie（`CASTGC` / `JSESSIONID` / `CASLOGINSITE`）是 **session cookie**，
  **关浏览器即失效**，所以不能只靠持久化 profile，必须每次注入 cookie 文件；
- 但成功登录后服务端会下发新 cookie，**回写文件即可滚动续期**——
  只要在有效期内被用上一次，就不会断。**前提是启动时别用旧配置把它盖掉**（见上文「配置导入的判重规则」）；
- 时间口径：活动列表用**毫秒**，睡眠明细用**纳秒**，聚合统计用 `startDay/endDay`
  （`sampleSet` 端点传数字、`healthRecords` 端点传字符串）；
- 睡眠记录的字段是**蛇形命名**（`all_sleep_time` / `sleep_score` / `deep_sleep_time`…），
  不是驼峰；
- `avgHrv` 在 `healthRecords` 统计端点**只返回 count，不返回值本身**，插件会如实说明。

---

## 数据边界

**能拿到**：静息心率（含按天明细）、睡眠记录（分段/得分/效率/夜醒）、睡眠 HRV（仅条数）、
运动记录、运动能力评估（跑力 / 预测成绩）、个人纪录、体重。

**接口已接但可能为空**：压力（`stressScore`）。部分账号/设备不返回压力明细，
此时概览里会显示「没有压力数据」——那是真的没有，不是插件漏了。

**拿不到**：连续心率曲线、血氧、体温、ECG —— 网页端没有这些，云侧接口也就没有。

时效性：云侧数据 = 手表 → 手机 → 云的同步结果，不是实时。手表没连手机时，今天的数据上不来。

> 华为改版后，字段改名会让插件报「华为接口结构变了（缺少 xxx），请升级插件」。
> 这是**故意**报错的：v0.4.0 会静默显示成「最近 N 天没有数据（可能没戴表）」，那种错更难查。

---

## 排障

| 现象 | 原因 | 处理 |
|---|---|---|
| `自动登录失败：页面未拿到 accessToken` | cookie 过期，或华为改版 | 先重新导出 cookie；仍然失败就看日志里有没有「接口结构变了」 |
| `找不到 Edge/Chrome` | 浏览器路径未探测到 | 配置里填 `browser_path` |
| 浏览器调试端口未就绪 | 上次进程残留 / 被安全软件拦 / root 下缺 `--no-sandbox` | v0.4.1 会自动加 `--no-sandbox` 并清理孤儿进程；仍失败就手动结束 msedge |
| `自动登录需要你输入手机验证码` | 华为要求二次验证 | 去 WebUI「账号登录」区填验证码，会话保留 5 分钟 |
| `今日自动登录失败次数已达上限` | 当天失败次数到顶（默认 3） | 等冷却，或在 WebUI 手动点一次登录（手动不计入额度） |
| `账号或密码不正确` | 密码改过 | 在 WebUI 凭据区重新保存 |
| `凭据文件损坏或无法解密` | 换了 Windows 用户 / 换了机器 | 重新保存账号密码 |
| 数据为空但通道正常 | 手表没戴 / 没同步到云 | 等同步，或手动同步一次 |

---

## 免责

本项目只读取**用户本人账号、本人授权**的数据，不实现任何绕过华为权限、破解认证、
窃取 Cookie 的功能。凭证由用户自己从已登录的浏览器导出，只存在本机。
请低频使用（按需查询），高频访问有触发华为风控的风险。

---

## 许可证与免责声明

本项目采用 [MIT License](LICENSE) 开源。

- 本项目仅供**个人学习与研究**使用，与华为技术有限公司无任何关联，不代表官方立场。
- 插件使用**你自己的**华为账号登录，所有数据仅在本机流转，不会上传到任何第三方服务器。
- 自动化登录与数据抓取可能**违反华为服务条款**，使用风险自负；因使用本插件导致的账号异常、数据丢失等后果，作者不承担任何责任。
- 请勿将本项目用于商业用途。
