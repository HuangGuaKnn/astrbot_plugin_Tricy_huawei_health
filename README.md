# 华为运动健康 · AstrBot 插件

版本：v0.3.1

把华为运动健康**网页端**的睡眠 / 静息心率 / HRV / 运动记录 / 跑力数据接进 AstrBot，
让皮莉卡能按需查询主人的身体状况。

数据源：`health.cloud.huawei.com`（华为运动健康云 / 训练营网页端）
认证：注入 cookie → 自动走 OAuth（华为认「信任设备」，无二次验证）→ accessToken
取数：纯 HTTP，**不需要浏览器常开**，也不需要手机 / 手表 / ADB

---

## 工具（8 个 LLM 工具）

| 工具 | 作用 |
|---|---|
| `health_status` | 通道状态：cookie 有没有、token 还能用多久、实测连通性 |
| `health_today` | 今日概况：今天静息心率 + 最近一晚睡眠 + 近期运动 |
| `health_sleep` | 最近 N 天睡眠明细（深浅睡 / REM / 得分 / 入睡用时 / 夜醒） |
| `health_heart` | 最近 N 天静息心率 + 睡眠 HRV |
| `health_activities` | 运动记录列表 |
| `health_performance` | 运动能力评估（跑力 / 预测成绩）+ 跑步个人纪录 |
| `health_overview` | 一次性查看全部已接入的健康数据 |
| `health_refresh` | 清缓存并强制重新认证、重新拉最新数据 |

---

## 配置

插件配置页里能填的：

| 配置项 | 说明 |
|---|---|
| `cookie_CASTGC` / `cookie_sid` / `cookie_hwid_cas_sid` | 从 `.id1.cloud.huawei.com` 复制对应 cookie 的值；CASTGC 会自动生成 `/CAS` 与 `/UnifiedIDMPortal` 两条 |
| `cookie_HuaweiID_CAS_ISCASLOGIN` / `cookie_CASLOGINSITE` / `cookie_LOGINACCSITE` | 从 `.huawei.com` 复制对应 cookie 的值 |
| `cookie_json` | 旧版兼容入口：Cookie-Editor 导出的整段 JSON（仍可使用） |
| `page_timeout` | 认证浏览器/CDP 超时秒数（默认 90） |
| `browser_path` | 浏览器路径，留空自动探测 Edge / Chrome |
| `headless` | 无头模式（默认开） |
| `token_ttl` | accessToken 缓存秒数（默认 3000） |
| `data_ttl` | 数据缓存秒数（默认 600） |
| `client_id` / `api_version` | 华为网页端的 `x-client-id` / `x-version`，接口不变就别改 |

cookie 也可以直接用文件：`data/plugin_data/astrbot_plugin_huawei_health/hw_cookies.json`
（配置里的分项 cookie 或旧版 `cookie_json` 有内容时会写入这个文件）

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

> 也可以只导出 `.huawei.com` / `.id1.cloud.huawei.com` / `.dcloud.net.cn` 三个域的 cookie，
> 或者直接把 JSON 存成 `hw_cookies.json` 放进插件数据目录。
> 最省事的方式：打开插件的 **WebUI 控制面板**，填写六条分项值；也可把导出的 JSON 粘进去点「导入」。

---

## WebUI 控制面板

页面在 `pages/health_console/`，从 AstrBot 插件管理页打开（与 MC 智控台同一套页面机制）。

| 区块 | 内容 |
|---|---|
| 通道状态 | cookie 条数 / 更新时间、token 剩余秒数、浏览器探测结果、缓存条数、数据目录 |
| 关键 cookie 表 | `sid` / `hwid_cas_sid` / `CASTGC` 的域与到期日，一眼看出「信任设备」还剩多久 |
| 操作 | 拉取概览 · 清缓存并重新认证 · 刷新状态 |
| 数据概览 | 静息心率 / 睡眠 / HRV 的取数结果 + 取数时间 |
| 重新导入 Cookie | 六条分项值或 Cookie-Editor JSON 导入（自动作废 token 缓存）；也可一键清除 cookie |

技术：走 AstrBot 的 bridge SDK（`window.AstrBotPluginPage`），iframe 内用 bridge、
独立窗口降级直连 `/api/v1/plugins/extensions/<plugin>/page/...`；主题跟随系统并支持手动切换。

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
  只要在有效期内被用上一次，就不会断；
- 时间口径：活动列表用**毫秒**，睡眠明细用**纳秒**，聚合统计用 `startDay/endDay`
  （`sampleSet` 端点传数字、`healthRecords` 端点传字符串）；
- 睡眠记录的字段是**蛇形命名**（`all_sleep_time` / `sleep_score` / `deep_sleep_time`…），
  不是驼峰；
- `avgHrv` 在 `healthRecords` 统计端点**只返回 count，不返回值本身**，插件会如实说明。

---

## 数据边界

**能拿到**：静息心率（含按天明细）、睡眠记录（分段/得分/效率/夜醒）、睡眠 HRV（仅条数）、
运动记录、运动能力评估（跑力 / 预测成绩）、个人纪录、体重/BMI 卡片。

**拿不到**：连续心率曲线、血氧、压力、体温、ECG —— 网页端没有这些，云侧接口也就没有。

时效性：云侧数据 = 手表 → 手机 → 云的同步结果，不是实时。手表没连手机时，今天的数据上不来。

---

## 排障

| 现象 | 原因 | 处理 |
|---|---|---|
| `自动登录失败：页面未拿到 accessToken` | cookie 过期 | 重新导出 cookie 导入 |
| `找不到 Edge/Chrome` | 浏览器路径未探测到 | 配置里填 `browser_path` |
| 浏览器调试端口未就绪 | 上次进程残留 / 被安全软件拦 | 杀掉残留 msedge 进程后重试 |
| 数据为空但通道正常 | 手表没戴 / 没同步到云 | 等同步，或让主人手动同步一次 |

---

## 免责

本项目只读取**用户本人账号、本人授权**的数据，不实现任何绕过华为权限、破解认证、
窃取 Cookie 的功能。凭证由用户自己从已登录的浏览器导出，只存在本机。
请低频使用（按需查询），高频访问有触发华为风控的风险。

<!-- TODO(v0.3.2)：分发前对 pages_html/ 与 docs/ 中的真实健康数值和个人标识做脱敏。 -->
