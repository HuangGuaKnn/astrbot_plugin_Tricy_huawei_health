# 华为运动健康 · AstrBot 插件

版本：v0.5.1

> 各版本变更见 [Releases](https://github.com/HuangGuaKnn/astrbot_plugin_Tricy_huawei_health/releases) 与 [CHANGELOG_v0.4.1.md](CHANGELOG_v0.4.1.md)、[CHANGELOG_v0.4.2.md](CHANGELOG_v0.4.2.md)、[CHANGELOG_v0.5.0.md](CHANGELOG_v0.5.0.md)。

把华为运动健康**网页端**的睡眠 / 静息心率 / HRV / 运动记录 / 跑力数据接进 AstrBot，
按需查询睡眠、心率、HRV 等健康数据。

数据源：`health.cloud.huawei.com`（华为运动健康云 / 训练营网页端）
认证：默认注入 cookie → 自动走 OAuth；WebUI 也可打开可见浏览器手动完成登录 → accessToken
取数：纯 HTTP，**不需要浏览器常开**，也不需要手机 / 手表 / ADB

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

## 权限与可见范围

健康数据属于个人隐私，**默认只在私聊、且只对 AstrBot 管理员开放**。配置页里的「权限与可见范围」分组控制这些：

工具返回的睡眠、心率、体重和运动记录会进入 AstrBot 对话。使用云端模型时，工具结果可能发送给所配置的模型服务；回复也会经所配置的聊天平台传递。插件没有另设健康数据上传服务器，但这不等于健康数据只在本机处理。需要本地处理时，请同时检查模型、消息平台与日志保存设置。

| 配置项 | 默认 | 说明 |
|---|---|---|
| `allow_private` | 开 | 私聊会话里提供健康数据工具 |
| `allow_group` | 关 | 群聊会话里提供健康数据工具 |
| `extra_umo_whitelist` | 空 | 额外允许的会话 UMO，每行一个，格式 `platform:MessageType:session_id`（例：`aiocqhttp:GroupMessage:123456789`） |
| `admin_only` | 开 | 只允许 AstrBot 管理员（框架 `admins_id` 里的账号）调用 |

判定顺序是**两层正交**的：

1. **成员准入**（`admin_only`）先判，是硬门；
2. **会话准入**（`allow_private` / `allow_group`）后判，可以被 `extra_umo_whitelist` 覆盖。

也就是说：**把某个群加进白名单，只代表「允许这个群」，不代表「允许群里每个人」。**
非管理员在白名单群里依然会被拒绝——否则「把群加进白名单」就等于把本人的健康数据对全群开放。

两处生效点：

- LLM 请求前把 8 个工具从本次请求的工具集里摘掉（省 token，模型也不会徒劳去试）；
- 每个工具函数第一行还有一道兜底，覆盖 cron / 后台任务 / MCP 等绕过前者的路径。

填错的 UMO（比如 `abc`、`a:b`、`x:FriendMessage:`）不会生效：插件启动时日志会报错，
WebUI 的 `/status` 也会在 `permission.invalid_umos` 里回显，便于当场发现。

> **从旧版本升级**：按默认值，群聊与非管理员会立刻无法使用这 8 个工具。
> 如果原来靠群聊使用，需要显式打开「允许群聊」，或把该会话的 UMO 加进白名单。

---

## 配置

插件配置页里能填的：

非 Windows 平台请先完成下方「跨平台加密存储」配置，再导入 Cookie 或保存账号密码。主密钥不属于插件配置项，也不要放进聊天消息或 WebUI 表单。插件 WebUI 的「设置」与「Cookie 导入」均使用加密保存；在「设置」成功提交完整 Cookie 后，七个旧配置字段会清空，页面只显示是否已有值。直接编辑 AstrBot 原始插件配置仍可能留下明文兼容副本；请优先使用插件控制台。

| 配置项 | 说明 |
|---|---|
| `cookie_CASTGC` / `cookie_sid` / `cookie_hwid_cas_sid` | 从 `.id1.cloud.huawei.com` 复制对应 cookie 的值；CASTGC 会自动生成 `/CAS` 与 `/UnifiedIDMPortal` 两条 |
| `cookie_HuaweiID_CAS_ISCASLOGIN` / `cookie_CASLOGINSITE` / `cookie_LOGINACCSITE` | 从 `.huawei.com` 复制对应 cookie 的值 |
| `cookie_json` | Cookie-Editor 导出的整段 JSON；控制台设置页仅作安全导入，成功后清空原始配置值 |
| `page_timeout` | 认证浏览器/CDP 超时秒数（默认 90） |
| `browser_path` | 浏览器路径，留空自动探测 Edge / Chrome |
| `headless` | 无头模式（默认开） |
| `token_ttl` | accessToken 缓存秒数（默认 3000） |
| `data_ttl` | 数据缓存秒数（默认 600）；**设为 0 = 彻底不缓存**（连总览/运动能力都现取） |
| `warmup` | 启动时后台预热 token（默认开；**开启后插件启动 8 秒会自己起一次浏览器**） |
| `login_daily_limit` | 账号密码模式每日自动登录**失败**次数上限（默认 3，成功不计入） |
| `timezone` | 日期边界与取数时间使用的时区偏移（默认 `+0800`，也支持 `+08:00`、`UTC`、`Z`） |
| `client_id` / `api_version` | 华为网页端的 `x-client-id` / `x-version`，接口不变就别改 |

按天查询以配置时区为准，不依赖服务器操作系统的时区。睡眠、心率等明细会展示本次接口返回的全部记录，不再固定截为 7 条；「今日概况」仍只摘要展示最近一次主睡眠。这不保证华为上游返回全部历史数据。

并发查询会复用最多 3 个 HTTP 会话，并限制排队、重试与整体等待时间。同一数据项的并发请求共用一次取数，刷新或切换账号后不会复用旧请求的结果。

Cookie 文件由插件维护：`data/plugin_data/astrbot_plugin_Tricy_huawei_health/hw_cookies.json`。新保存的内容为密文，文件名中的 `.json` 仅为兼容旧版本；请通过 WebUI 导入，勿手动覆盖密文文件。
（配置里的分项 cookie 或旧版 `cookie_json` 有内容时**会写入**这个文件；文件已存在且配置没变时不会覆盖）

> **配置导入的判重规则**：插件启动时会把「配置里那六条」算一个指纹存在
> `hw_cookies.json.config_applied`。指纹没变就跳过导入（保住认证回写的滚续 cookie）；
> 指纹变了才应用，并**替换**旧 Cookie 集合，避免混入其他账号的辅助会话。WebUI 显式导入也采用替换；请提供完整必要项 CASTGC 和 sid。
> 想强制以配置为准：删掉 `.config_applied` 文件，或改一下任意一条 cookie 值。

---

## 怎么拿 cookie

1. 电脑浏览器登录 <https://health.cloud.huawei.com/TrainingCamp>，确认能看到自己的数据；
2. 在 Cookie-Editor 中分别复制下面 6 条的值：
   - `CASTGC`：`.id1.cloud.huawei.com`，插件自动生成 `/CAS` 与 `/UnifiedIDMPortal` 两个路径；
   - `sid`、`hwid_cas_sid`：`.id1.cloud.huawei.com`；
   - `HuaweiID_CAS_ISCASLOGIN`、`CASLOGINSITE`、`LOGINACCSITE`：`.huawei.com`；
3. 在插件 WebUI 的设置页或 Cookie 导入页填写完整集合，至少同时提供 CASTGC 和 sid；也可粘贴包含这两项的完整 JSON。可选项需要随完整集合一起提交，留空表示不修改；
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
| 账号密码凭据 | WebUI 主动保存后加密写入 `credentials.bin`；页面只显示账号掩码和保存时间，不回填密码 |
| 存储保护 | 显示 Windows DPAPI / AES-256-GCM、主密钥来源及未配置或已锁定状态；不显示密钥或密钥路径 |
| 操作 | 清缓存并重新认证 · 刷新状态 |
| 数据概览 | 9 项数据的取数结果 + 取数时间 |
| 重新导入 Cookie | 六条分项值或 Cookie-Editor JSON 导入（自动作废 token 缓存）；也可一键清除 cookie |

技术：走 AstrBot 的 bridge SDK（`window.AstrBotPluginPage`），iframe 内用 bridge、
独立窗口降级直连 `/api/v1/plugins/extensions/<plugin>/page/...`；主题跟随系统并支持手动切换。

登录相关的非敏感选项保存在插件数据目录的 `login_config.json`（包含模式和 `auto_trust`）。
账号密码不会写入插件配置、WebUI 状态或日志。Windows 使用 DPAPI，非 Windows 使用 AES-256-GCM 与外部主密钥。账号密码模式支持无头自动填充、验证码 WebUI 介入和可选的可见窗口兜底，并带跨重启的失败次数限制与失败冷却。

> **账号密码模式需要人工介入时，取数工具会立刻返回提示**，不会占着工具调用等 7 分钟
> （AstrBot 的默认工具超时是 120 秒）。看到「自动登录需要你输入手机验证码」就去
> WebUI 的「账号登录」区完成，会话会保留 5 分钟，完成后再问一次即可。
>
> 旧 Windows DPAPI 文件仍需原 Windows 用户和机器才能解密；迁移到其他平台时，请配置新的安全存储并重新导入 Cookie、保存账号密码。
> **本次改动后，非 Windows 平台也禁止将新 Cookie、账号密码或 token 持久化为明文。**未配置主密钥时，保存会明确报错。

加密失败时保存会明确报错，并保留原有文件。已有明文 Cookie 保留读取兼容；配置好主密钥后，在 WebUI 重新导入即可原子替换成加密文件，读取操作不会擅自回写。保存账号密码会清除旧 Cookie、token 与健康缓存，下次查询重新认证；清除账号密码则切回 Cookie 模式、保留已有 Cookie 并清空缓存。导入、清除或刷新登录态时，旧登录与旧查询结果会失效，避免换账号后继续显示上一个账号的数据。

### 跨平台加密存储

Windows 无需额外主密钥，继续使用当前用户的 DPAPI。其他平台需要一次性配置独立的 **32 字节随机主密钥**；它是原始二进制数据，不是 32 个字符的密码，也不是十六进制或 Base64 文本文件。插件使用 AES-256-GCM 保存凭据，并将账号密码、Cookie 和 token 用途隔离，文件被篡改或主密钥不匹配时拒绝解密。

主密钥查找顺序为：

1. `HUAWEI_HEALTH_MASTER_KEY_FILE` 指定的绝对文件路径；
2. `$CREDENTIALS_DIRECTORY/huawei-health-master`，由 systemd 提供；
3. 仅 macOS：显式设置 `HUAWEI_HEALTH_KEYCHAIN=1` 后读取系统 Keychain。

显式配置的来源无效时不会改用其他来源。插件不会自动生成新钥匙来替代丢失的旧钥匙。配置后重启 AstrBot，在 WebUI 的账号凭据区确认存储状态已就绪，再保存账号密码或导入 Cookie。

#### Linux 服务：推荐 systemd credentials

需要提供 `systemd-creds` 和 `LoadCredentialEncrypted=` 的 systemd 版本（加密凭据功能自 v250 提供）。以下命令用于**首次初始化**，在宿主机运行；随机主密钥通过管道传入加密工具，磁盘上仅保存加密后的凭据：

```sh
sudo install -d -m 0700 /etc/credstore.encrypted
openssl rand 32 | sudo systemd-creds encrypt --with-key=host \
  --name=huawei-health-master - /etc/credstore.encrypted/huawei-health-master
```

有可用 TPM2 的主机可将 `--with-key=host` 改为 `--with-key=host+tpm2`，将解密同时绑定到主机密钥与 TPM2。纯 `host` 模式不要求 TPM，但无法防止同时获得整盘数据和主机密钥的攻击者。

在 AstrBot 的实际 systemd 服务配置中加入：

```ini
[Service]
LoadCredentialEncrypted=huawei-health-master:/etc/credstore.encrypted/huawei-health-master
```

随后重新加载服务配置并重启对应服务。systemd 在服务运行时提供可读取的凭据文件，插件通过 `CREDENTIALS_DIRECTORY` 自动发现；无需把密钥值放进环境变量。若以前设置了 `HUAWEI_HEALTH_MASTER_KEY_FILE`，它仍优先，请在切换前移除该设置。

已有加密数据时，迁移必须保留同一主密钥，不能重新执行 `openssl rand` 生成替代钥匙。主机密钥或 TPM 变化可能使 systemd 凭据无法解密，迁移前应准备单独保护的恢复副本。更多细节见 [systemd-creds 官方文档](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html)。

#### 普通进程或容器：外部主密钥文件

在插件目录运行以下命令，将 `--data-dir` 替换成真实插件数据目录。创建工具拒绝覆盖已有文件；不要把主密钥放进插件安装目录、数据目录、代码仓库、镜像或与凭据相同的备份中。

```sh
install -d -m 0700 "$HOME/.config/astrbot-secrets"
python hw_secure_storage.py create-file \
  --output "$HOME/.config/astrbot-secrets/huawei-health.key" \
  --data-dir /srv/astrbot/data/plugin_data/astrbot_plugin_Tricy_huawei_health
export HUAWEI_HEALTH_MASTER_KEY_FILE="$HOME/.config/astrbot-secrets/huawei-health.key"
```

使用同一环境启动 AstrBot。文件必须是普通文件，不能是符号链接；POSIX 下所有者必须是运行用户或 root，组用户与其他用户不能拥有权限（常用 `0600` / `0400`）。服务实际运行的用户必须能读取它。文件方式保护插件目录单独泄漏的场景，主密钥文件本身仍依赖操作系统权限、加密磁盘或外部秘密管理系统保护。

容器可把部署环境提供的主密钥以只读文件挂载到容器外部配置路径，并将该路径写入 `HUAWEI_HEALTH_MASTER_KEY_FILE`。注意容器内 UID 和文件权限必须满足上述要求。**普通 Docker Compose secrets 只负责挂载，不会加密宿主机来源文件**；Swarm secrets 的静态加密是另一套机制。不要把密钥直接写进 Compose YAML 或 Dockerfile。参见 [Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/)。

#### macOS：系统 Keychain

使用安装了插件依赖的同一 Python 解释器首次初始化：

```sh
python hw_secure_storage.py create-keychain
export HUAWEI_HEALTH_KEYCHAIN=1
```

然后使用同一用户和环境启动 AstrBot。工具将随机主密钥写入系统 Keychain，服务名为 `astrbot.huawei_health`、账户标识为 `master-key-v1`；不会写入插件配置或普通文件，也不会覆盖已有主密钥。运行时仅使用明确的 macOS Keychain 后端，不启用明文或自动选择的替代后端。

Keychain 需要允许当前运行用户和 Python 进程访问；未登录、Keychain 锁定或系统拒绝授权时，插件会报告存储未就绪。它不保证任意后台启动方式都能无人干预解锁；这类部署可改用受保护的外部文件供钥。

#### 升级、备份与恢复

- 旧 DPAPI 凭据与旧 Cookie 文件仍按原格式识别。旧明文 Cookie 在重新导入或成功保存后才迁移；迁移失败保留原文件。
- 主密钥与加密数据需要分别备份、分别授权；恢复时必须使用原主密钥。没有原主密钥无法恢复密文，需重新保存账号密码或重新导入 Cookie。
- 错钥、锁定与文件损坏不会自动创建新密钥或降级成明文。先恢复正确的钥匙，再重试；确认放弃原凭据时才显式清除并重新配置。
- 插件控制台设置页成功导入 Cookie 后，会清空七个旧配置字段；无关设置修改不会自动清除尚未迁移的旧副本。
- 本功能保护插件持久化的登录凭据，不等于全盘加密。健康数据缓存、旧版备份、AstrBot 的旧 Cookie 配置副本、浏览器自身的运行时文件需要分别管理。
- 运行时需要使用明文凭据，取得 root、同一用户代码执行能力或 AstrBot 进程控制权的攻击者仍可能读取它们；不要把不受信任的插件放在同一进程中。

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
| `加密存储未就绪` | 未配置主密钥、文件权限不符或 Keychain 未解锁 | 按上方步骤配置，并重启 AstrBot 后刷新状态 |
| `凭据已锁定` / `凭据文件损坏或无法解密` | 主密钥不匹配、密文被改动，或 DPAPI 文件离开原 Windows 用户环境 | 优先恢复原主密钥和文件；确认无法恢复后，再显式清除并重新保存 |
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
- 插件使用**你自己的**华为账号登录，不另设健康数据上传服务器。健康数据作为工具结果进入 AstrBot 后，可能发送给你配置的云端模型和聊天平台，具体流向取决于这些服务及日志设置。
- 自动化登录与数据抓取可能**违反华为服务条款**，使用风险自负；因使用本插件导致的账号异常、数据丢失等后果，作者不承担任何责任。
- 请勿将本项目用于商业用途。
