# DELIVERY_WEBUI.md · T8 华为健康插件「设置迁移到 WebUI + 控制台重设计」

> 内部交付文档，**不进发布包**。
> 交付时间：2026-10-30　｜　基线：`main@011d123`，`v0.5.0-rc.2`
> 需求来源：`派活单_华为健康插件_WebUI重构与配置同源.md`（**343 行版**，含 §6 T0）
> 结论：**T0 + T1 + T2 + T3 + T4 全部完成**。`pytest tests/ -q` = **362 passed, 45 subtests passed, 0 failed**。

---

## 0. 一句话结论

配置**只有一份**（AstrBot 注入的 `AstrBotConfig`），WebUI 直接读写它；21 个配置叶子**全部改完即生效、无需重启**（`reloaded` 恒为 `[]`）；7 个 cookie 项对外**只有掩码**；非法输入一律 400 且配置文件 sha256 不变；控制台重排为 5 个 Tab，④ 设置按 `_conf_schema.json` **动态渲染**（以后加配置项 WebUI 自动跟上）。

---

## 1. 改动文件清单

绝对路径前缀：`C:\Users\<用户名>\.astrbot\data\plugins\astrbot_plugin_Tricy_huawei_health\`

| 文件 | 行数变化 | 说明 |
|---|---|---|
| `hw_webapi.py` | **443 → 1037 行**（+594 / −0） | 新增 `GET/POST /page/config` 及校验、钳制、并发防护、热生效；**12 条既有路由一行未改** |
| `pages\health_console\index.html` | 777 → **1670 行**（+1391 / −249，净 +893） | 5 Tab 重排 + ④ 设置（schema 驱动）；单文件、原生 JS、无构建 |
| `tests\test_v041.py` | 2107 行（**仅 1 行数字**，+1/−1） | T0 授权范围：`assertEqual(len(routes), 12)` → `14` |
| `tests\test_webapi_config.py` | **新建 1533 行**（97 用例 / 20 个测试类） | 后端接口测试，契约驱动 |
| `DELIVERY_WEBUI.md` | 新建 | 本文档 |

`git status` 只应看到：`M hw_webapi.py`、`M pages/health_console/index.html`、`M tests/test_v041.py`、`?? tests/test_webapi_config.py`、`?? DELIVERY_WEBUI.md`。
**未改动**：`hw_auth.py` / `hw_client.py` / `hw_login.py` / `hw_credentials.py` / `hw_store.py` / `hw_privacy.py` / `main.py` / `_conf_schema.json` / `metadata.yaml` / `README.md` / `tests/boot.py` / `tests/stubs/**`。
**未做**：未改版本号（四处仍 `v0.5.0-rc.2`）、未动 tag（仍 5 个旧 tag）、未 commit、未 push。

---

## 2. 核心设计：「配置同源，绝不双写」

```
WebUI ④ 设置  ──GET /page/config──►  读 self.plugin.config（AstrBotConfig）
              ◄─schema 动态建表单───
              ──POST /page/config──►  校验 → 落盘 save_config_async → 热生效
                                          │
AstrBot 配置页 ──────────────────────────┘  同一份 config / 同一个 JSON 文件
```

- **没有第二份配置文件**。仓库内 `*.json` 仍只有 `_conf_schema.json` 一个。
- 落盘走 `await config.save_config_async(replace_config=<完整合并后的 dict>, indent=2)`（异步、不阻塞事件循环、框架内部有 revision 防旧快照覆盖）。
- `AstrBotConfig.__setattr__` 只做 `self[key]=value`（不落盘），所以保存路径**必须**显式调用上面那个方法——已核实并照做。

### 2.1 一个必须绕开的坑：`save_config_async` 是**浅合并**

它的实现是 `self.update(replace_config)` + `deepcopy`。所以传 `{"permission_settings": {"allow_group": true}}` 会把**整组替换**、丢掉 `extra_umo_whitelist`。因此后端在调用前**自己把嵌套组读出来逐子键合并**（`_apply_writes`），并且在原配置根本没有该分组时（老配置升级场景）用 schema 默认值补齐整组，避免写出「半组子键」。

### 2.2 revision 方案（选定方案，按派活单要求写明）

```python
revision = "%s-%s-%s" % (config._save_revision, config._save_committed_revision,
                         os.stat(config.config_path).st_mtime_ns)
```

理由：
- `_save_revision` / `_save_committed_revision` 是框架自增计数器，**任何**走 `save_config_async` 的保存（包括 AstrBot 配置页那条路径）都会让它变化 → 覆盖「另一侧改了配置」的场景；
- 追加 `mtime_ns` 兜住「绕过 AstrBotConfig 直接改文件」；
- 三者皆不可得（测试桩/极简 dict）时退化为常量 `None-None-0`，**不会误报 409**。

### 2.3 处理顺序（契约的一部分）

```
解析 JSON → values 白名单/类型/钳制/UMO 校验（纯计算，无副作用）
          → revision 比对（不匹配 409）
          → cookie 组导入（失败 400，此时配置文件还没被写过 → sha256 不变）
          → save_config_async（失败 500）
          → 其余热生效（daily_limit / 权限缓存 / warmup）+ cookie 变更后清 token 与数据缓存
```

> 校验**先于** revision：这样「填错」永远稳定返回 400，而不会被「版本过期」抢先变成 409。

### 2.4 类型校验（自己实现，不依赖 dashboard 的 `validate_config`）

| schema type | 规则 | 备注 |
|---|---|---|
| `bool` | 必须 `bool` | 拒绝 `"true"`、拒绝 `1` |
| `int` | 必须 `int`，且**排除 `bool`** | 拒绝 `"abc"`、拒绝 `true`；上下界**钳制**（不是拒绝），沿用 `_int_cfg` 语义 |
| `float` | `int`/`float`（排除 bool） | 当前无 float 配置项 |
| `string`/`text` | 必须 `str` | |
| `list` | 必须 `list[str]` | `extra_umo_whitelist` 另做逐条 UMO 校验 |
| `object` | 必须 `dict`，只接受 schema 声明的子键 | 未知子键 400 |

**白名单**：schema 里不存在的 key 一律 400（`field` = 该 key），不写脏数据。
**UMO**：复用 `main._parse_umos()` 既有规则（`platform:MessageType:session_id`，`MessageType ∈ {FriendMessage, GroupMessage, OtherMessage}`，`split(":", 2)`）；**非法整单拒绝**并指出是哪一条，不写进配置。

### 2.5 掩码与「绝不回写」

- 7 个敏感项（`cookie_json` + 6 个 `cookie_*`）在 **GET 与 POST 的响应里永远是 `"***"`**；是否有值只体现在 `meta.has_value`。
- 请求体里敏感项的值等于 `"***"` → 后端**直接跳过**（视为未修改）。
- 前端**三重防线**：① 敏感项输入框恒为空（不回显 `***`）、`type=password`；② 输入为空或 `"***"` 时从脏集合中删除；③ `buildPayload` 再过滤一次。→ 未修改的敏感项**根本不出现在请求体里**。
- 实测：`POST {"cookie_CASTGC": "***"}` 后 `plugin.auth.load_cookies()` 里的真实 CASTGC **未被覆盖**。

### 2.6 21 项热生效

18 项本来就是运行时实时 `self.config.get(...)`，落盘即生效。只有 3 组需要额外动作：

| 配置 | 额外动作 |
|---|---|
| `login_daily_limit` | `login_manager.daily_limit = max(1, min(10, 新值))`（保留原钳制） |
| cookie 组（7 项） | `await asyncio.to_thread(auth.import_cookie_sources, cookie_json, fields, True)`，成功后作废 token 与健康缓存；失败 → 400 且配置不落盘 |
| `warmup` | false→true 起 `_warmup_task`；true→false `cancel()` 并 await |
| `permission_settings.*` | 改完调 `_build_umo_whitelist()` 刷新 `_umo_whitelist` 缓存（否则 `_whitelist()` 还用旧的） |

---

## 3. 接口契约

`PAGE_PREFIX = astrbot_plugin_Tricy_huawei_health/page`

### `GET /page/config`

```json
{"status":"ok","data":{
  "values": {"...21 个叶子，结构镜像配置文件，7 个敏感项为 \"***\"..."},
  "schema": {"..._conf_schema.json 原样返回（18 顶层键，不改写）..."},
  "meta": {"revision":"...","sensitive":["...7 项..."],"has_value":{"...":true},
           "bounds":{"page_timeout":[1,600],"token_ttl":[0,86400],
                     "data_ttl":[0,86400],"login_daily_limit":[1,10]},
           "updated_at":"2026-10-30 01:23:45","source":"astrbot_config"}}}
```

### `POST /page/config`

请求：`{"values": {<只发要改的叶子>}, "revision": "<GET 拿到的 meta.revision>"}`（支持部分更新）

分组子键支持**两种写法**，两者走**完全相同**的校验路径（`_expand_dotted()` 先归一化）：

```json
{"values": {"permission_settings": {"allow_group": true}}}      // 嵌套
{"values": {"permission_settings.allow_group": true}}           // 点号
```

成功 200（顶层与 `data` 同构，顶层满足派活单字面形状，`data` 满足前端 `unwrap()`）：

```json
{"status":"ok","message":"已生效 2 项",
 "applied":["token_ttl","permission_settings.allow_group"],
 "reloaded":[],  "revision":"<新>", "changed":["token_ttl","permission_settings.allow_group"],
 "clamped":{"page_timeout":600},
 "data":{...同上，另含保存后的 values/meta...}}
```

- `applied`：真的写下去并已生效的叶子（**值没变的不计入**）；`changed`：值真的变了的叶子；`reloaded`：**恒为 `[]`**。
- `clamped`：被上下界钳制过的项 → 最终值（前端提示「已按上下限调整」）。

失败：`{"status":"error","message":"<中文>","field":"<叶子路径|空>"}`

| 情况 | HTTP | field |
|---|---|---|
| 非 JSON / 非对象 / `values` 缺失或非对象 | 400 | 空 / `values` |
| 未知 key / 未知子键 | 400 | 该 key |
| 类型错误 / 钳制之外的校验 | 400 | 该叶子 |
| 非法 UMO（含非字符串条目） | 400 | `permission_settings.extra_umo_whitelist` |
| cookie 导入失败 | 400 | 具体变更的 cookie 键 |
| revision 不匹配或缺失 | **409** | `revision` |
| 落盘失败 | 500 | 空 |

---

## 4. 证据 ①：21 项逐项热生效（22/22）

每项都用**该配置项真正的运行时消费者**验证，不是回读 config。脚本为沙箱 + 打桩，不联网、不启动浏览器、不碰真实 `plugin_data`。

| # | 配置项 | 改前 → 改后 | 验证方式（真实消费者） | 观测结果 | 判定 |
|---|---|---|---|---|---|
| 1 | `cookie_json` | `''` → 6 条 Cookie-Editor JSON | `auth.load_cookies()` 中 CASTGC | `EV-JSON-CASTGC` | PASS |
| 2 | `cookie_CASTGC` | `''` → `EV-FIELD-CASTGC` | 同上 | `EV-JSON-CASTGC, EV-FIELD-CASTGC, EV-FIELD-CASTGC`（两条路径） | PASS |
| 3 | `cookie_sid` | `''` → `EV-FIELD-SID` | 同上 | `EV-FIELD-SID` | PASS |
| 4 | `cookie_hwid_cas_sid` | `''` → `EV-FIELD-HWID` | 同上 | `EV-FIELD-HWID` | PASS |
| 5 | `cookie_HuaweiID_CAS_ISCASLOGIN` | `''` → `'true'` | 同上 | `true` | PASS |
| 6 | `cookie_CASLOGINSITE` | `''` → `EV-FIELD-CASLOGINSITE` | 同上 | `EV-FIELD-CASLOGINSITE` | PASS |
| 7 | `cookie_LOGINACCSITE` | `''` → `EV-FIELD-LOGINACC` | 同上 | `EV-FIELD-LOGINACC` | PASS |
| 8 | `browser_path` | `''` → `C:\Program Files\EvBrowser\msedge.exe` | `plugin.auth.browser_path` | 同值 | PASS |
| 9 | `headless` | `True` → `False` | `plugin.auth.headless` | `False` | PASS |
| 10 | `page_timeout` | `90` → `123` | `plugin.auth.page_timeout` | `123` | PASS |
| 11 | `token_ttl` | `3000` → `1200` | `_token()` 写 token 缓存时的 `expire_at` | 剩余 1200 秒 | PASS |
| 12 | `data_ttl` | `600` → `1234` | `_cached()` 传给缓存层的 ttl | `ttl=1234` | PASS |
| 13 | `warmup` | `False` → `True` | `_warmup_task` 被创建 | 已创建 | PASS |
| 13b | `warmup`（反向） | `True` → `False` | 任务被 cancel | `done()=True` | PASS |
| 14 | `login_daily_limit` | `3` → `7` | `login_manager.daily_limit` | `7` | PASS |
| 15 | `timezone` | `+0800` → `+0900` | `main._client()` 构造客户端 | `timezone='+0900'` | PASS |
| 16 | `client_id` | `106533743` → `999888777` | 同上 | `client_id='999888777'` | PASS |
| 17 | `api_version` | `HealthKitRunningGroupPortal_6.26.4.200` → `HealthKitPortal_EV` | 同上（构造参数名 `version`） | `version='HealthKitPortal_EV'` | PASS |
| 18 | `permission_settings.admin_only` | `True` → `False` | `_is_allowed(非管理员私聊)` | 由 False 变 True | PASS |
| 19 | `permission_settings.allow_private` | `True` → `False` | `_is_allowed(管理员私聊)` | 由 True 变 False | PASS |
| 20 | `permission_settings.allow_group` | `False` → `True` | `_is_allowed(管理员群聊)` | 由 False 变 True | PASS |
| 21 | `permission_settings.extra_umo_whitelist` | `[]` → `["aiocqhttp:GroupMessage:987654321"]` | `_is_allowed()` + `_whitelist()` | 白名单生效 | PASS |

**所有 POST 的 `reloaded` 均为 `[]`。**

---

## 5. 证据 ②：掩码（`GET /page/config`）

```
cookie_json                      = '***'   has_value=True
cookie_CASTGC                    = '***'   has_value=True
cookie_sid                       = '***'   has_value=True
cookie_hwid_cas_sid              = '***'   has_value=True
cookie_HuaweiID_CAS_ISCASLOGIN   = '***'   has_value=True
cookie_CASLOGINSITE              = '***'   has_value=True
cookie_LOGINACCSITE              = '***'   has_value=True
```

- 7 项恒为 `"***"`；真实**值**在整个响应体 JSON 里**零命中**。
- `CASTGC` 这个串只作为**键名 / schema 描述**出现（配置项本来就叫 `cookie_CASTGC`，无法避免）；`TGT-`、`sid=` 零命中。
- 反向（掩码回写）已防护并实测：`POST {"cookie_CASTGC":"***"}` 后真实 cookie 不变。

---

## 6. 证据 ③：非法输入 / 脏写（400 + sha256 不变）与并发（409）

| 攻击输入 | 说明 | HTTP | field | 配置 sha256 |
|---|---|---|---|---|
| `{"token_ttl": "abc"}` | int 传字符串 | 400 | `token_ttl` | 未变 |
| `{"headless": "true"}` | bool 传字符串 | 400 | `headless` | 未变 |
| `{"不存在的key": 1}` | 未知 key | 400 | `不存在的key` | 未变 |
| `{"permission_settings": {"nope": true}}` | 未知子键 | 400 | `permission_settings.nope` | 未变 |
| `{"permission_settings": {"extra_umo_whitelist": ["bad-umo"]}}` | 非法 UMO | 400 | `permission_settings.extra_umo_whitelist` | 未变 |
| `{"permission_settings": {"extra_umo_whitelist": ["aiocqhttp:FriendMessage:x", 42]}}` | list 混入非字符串 | 400 | 同上 | 未变 |
| `{"token_ttl": true}` | int 传 bool | 400 | `token_ttl` | 未变 |
| `{"data_ttl": 111}` + 伪造旧 `revision` | 并发覆盖 | **409** | `revision` | 未变 |

基准 sha256：`7845a69715406c1bdaa57521663990c6ab9e964f50d1a65ee1b8aeda5402d06a`（该基准为沙箱临时配置文件，每次运行会重新生成）。

**同源反向**：直接改 `plugin.config`（模拟 AstrBot 配置页）→ 再 `GET config` 立即反映新值（`tests/test_webapi_config.py` 覆盖）。

---

## 7. 证据 ④：T0 的 4 步变异验证

在**仓库副本**上做变异（真实仓库零改动），只跑 `tests/test_v041.py::TestWebApi::test_no_account_route`：

| 步骤 | 操作 | 路由数 | 结果 | 判定 |
|---|---|---|---|---|
| ① | 完成后跑该测试 | 14 | **通过** | 符合预期 |
| ② | 注释掉 `register()` 里 `overview` 的 `reg(...)` | 13 | **失败** `AssertionError: 13 != 14` | 符合预期 |
| ③ | 额外插入一条假 `reg(...)` | 15 | **失败** `AssertionError: 15 != 14` | 符合预期 |
| ④ | 全部还原 | 14 | **通过** | 符合预期 |

→ 断言**不是空壳**：少一条红、多一条也红。

`git diff tests/test_v041.py` 全文只有一行：

```diff
-        self.assertEqual(len(routes), 12)
+        self.assertEqual(len(routes), 14)
```

同测试的 `assertFalse(any(r.endswith("/login/account") for r in routes))` 主断言逐字未动；用例名、类名、同文件其它断言均未改。

---

## 8. 证据 ⑤：设计自查表

自动化自查脚本 **53 项全过**（`§5.3` 九条禁止项 + `§5.5` 既有测试硬约束 + `§5.1/§5.2` 结构）。

### §5.3 九条禁止项：逐条 ✗（零命中）

| 禁止项 | 结果 | 依据 |
|---|---|---|
| 渐变背景/按钮 | ✗ 未命中 | 全文无 `gradient` |
| 玻璃拟态 | ✗ 未命中 | 全文无 `backdrop-filter` |
| `box-shadow` 超 `0 2px 8px rgba(0,0,0,.08)` | ✗ 未命中 | **完全没用 `box-shadow`** |
| emoji 当图标 | ✗ 未命中 | Unicode 范围扫描零命中；唯一图标是内联 `<svg>` 折叠箭头 |
| 英雄区 + 三栏卡片 | ✗ 未命中 | 无 `hero` 类；结构为「Tab 栏 + 单列卡片」 |
| `border-radius` > 12px | ✗ 未命中 | 取值仅 `4px / 6px / 8px / 50%`（50% 只用于 7px 状态点做圆） |
| 动画 > 200ms | ✗ 未命中 | 仅 `transition .12s / .15s`，无 `animation`、无 `@keyframes` |
| 引入框架/构建步骤 | ✗ 未命中 | 单文件原生 JS；无 vue/react/tailwind/jquery |
| 外部 CDN | ✗ 未命中 | 唯一 `<script src>` 是相对路径 `/api/plugin/page/bridge-sdk.js` |

### §5.2 必须做到：逐条 ✓

| 要求 | 结果 | 说明 |
|---|---|---|
| Tab 切换，不一屏到底 | ✓ | 5 个 panel，切换只切 `hidden`，不重渲染、不丢状态 |
| 状态用小圆点 + 文字 | ✓ | 沿用 `.dot.ok/.warn/.err` |
| 靠间距/字号建立层级，不靠边框阴影 | ✓ | 无阴影；分组用 `1px solid var(--line)` |
| cookie 明细等宽字体、紧凑行高 | ✓ | `ui-monospace` 系 |
| 危险操作二次确认 | ✓ | 清除 cookie / 清除凭据 / **清缓存** / 有未保存改动时重新读取 / 放弃修改（共 5 处 `confirm`） |
| 保存后局部 toast，不整页刷新 | ✓ | `toast()` + 状态区；用响应里的 `values/meta` 就地重建表单 |
| 保留明暗主题 | ✓ | `localStorage['hw_health_theme']`，auto/light/dark 三态 |
| 移动端可看 | ✓ | `.tabs{overflow-x:auto}`；`@media (max-width:640px)` 卡片单列 |

**DOM 片段（结构核对用，行号以交付时文件为准）**

```html
<!-- Tab 栏（L201 附近）：5 个 tab 按钮 + 5 个 panel（L210/261/276/356/373） -->
<nav class="tabs" role="tablist"> … 概览 / 数据 / 登录 / 设置 / 诊断 … </nav>

<!-- ⑤ 诊断默认收起：diagBox 初始 display:none；diagSum 仍由 replaceChildren() 填充（L579） -->
<div id="diagBox" style="display:none"> … </div>

<!-- ④ 设置：容器为空，控件由 renderConfig() 按 schema 动态生成 -->
<div id="cfgForm"></div>
```

设置 Tab 的 schema 驱动证据：`CFG_GROUPS` 只用 **key 数组**声明分组位置，控件一律由 `buildControl(path, schema[k])` 生成（`bool`→checkbox、`int`→number+`meta.bounds`、`string`→input、`text`→textarea、`list`→标签式、`object`→子分组）；schema 里出现但未被 4 组列到的 key 自动进「其他」兜底组。HTML 里**没有任何**硬编码的 21 个配置 input（脚本断言 ≤0 个 `id="cfg_*"` 硬编码控件）。

---

## 9. 证据 ⑥：`pytest tests/ -q`

```
$ cd <仓库>; $env:PYTHONIOENCODING="utf-8"
$ python -m pytest tests/ -q
362 passed, 45 subtests passed in 22.57s
```

- 基线 **265** + 新增 `tests/test_webapi_config.py` **97** = **362**。
- 既有 265 条断言**一条未删、一条未放宽**（唯一改动是 T0 授权的那个数字 `12 → 14`）。
- 新测试覆盖：21 叶子逐项生效、类型/白名单/UMO 校验、脏写 sha256、revision 409、`reloaded==[]`、掩码不泄漏、`"***"` 不回写、三项热生效、权限缓存刷新、落盘失败 500、裸 dict 降级路径。

---

## 10. 我在实现中做的判断（请验收时一并核对）

1. **`applied` 只统计真正写下去的项**：值相同的 POST 返回 `applied=[]`、`changed=[]`、不落盘、revision 不推进。
2. **int 越界是钳制不是拒绝**（沿用 `_int_cfg` 语义），钳制结果回显在 `clamped`。
3. **`bool` 严格**（拒 `"true"`）、**`int` 严格排除 bool**（拒 `true` 当 1）。这是对派活单「填错拒绝保存」的从严执行；若验收人希望 `"600"` 这类字符串被宽容接受，需要明确改契约。
4. **cookie 组无法通过设置页「清空」**：`import_cookie_sources` 对空内容会报「cookie 内容为空」，且清空单条会触发「缺 CASTGC/sid」致命校验。清空走 ③ 登录 Tab 的「清除 cookie」（带二次确认）。前端也据此把敏感项做成「留空 = 不修改」。
5. **cookie 变更后自动作废 token 与健康缓存**（沿用既有 `cookie/import` 的行为，避免旧账号 token 取新账号数据）。
6. **`bridge` 模式下的错误不带 `field`**（bridge SDK 只透传 message），此时前端靠 `message` 正则识别 409；`directApi` 模式则完整带 `field` + `httpStatus`。
7. **未新增任何配置项**：`_conf_schema.json` 一个字节都没改（顶层仍 18 键），分组/排序全部由前端 `CFG_GROUPS` 表达。

---

## 11. 独立验收（第二轮）发现并已修复的缺陷

交付前另起了一个**只读**的独立验收 Agent（不看实现者报告、自己复用沙箱夹具 + 自己做变异测试）。它判定 PASS，但指出 2 个真缺陷 + 3 处测试洞，均已处理：

| 编号 | 级别 | 缺陷 | 修复 |
|---|---|---|---|
| **D-1** | 契约级 | 点号写法的顶层键绕过 UMO 校验：`{"permission_settings.extra_umo_whitelist": ["garbage"]}` 精确命中摊平后的叶子表 → 走 `list` 分支只查类型、不调 `_check_umos` → **200 且脏值落盘**（嵌套写法则正确 400） | 新增 `_expand_dotted()`：把 `"group.sub"` 先归一化成嵌套 dict，两种写法走**完全相同**的校验路径。附带支持「同一分组内点号键与 dict 混发」 |
| **D-2** | §5.2 | 「清缓存并重新认证」**没有**二次确认（§5.2 明确把「清缓存」列为危险操作） | `doRefresh()` 开头加 `confirm`；现共 5 处确认 |
| **D-3** | 掩码 | 掩码判定是严格 `== "***"`，`" *** "`（带空白）会被当真实值写入并**覆盖真实 cookie** | 改为 `strip()` 后比较（`_is_mask`），`" *** "` / `"***\t"` 均视为未修改 |
| **D-4** | 测试洞 | `test_true_to_false_cancels_task` 的 `done()/cancelled()` 在 `asyncio.run()` **退出后**求值 → `asyncio.run` 会 cancel 剩余任务，断言**自满足**（变异下仍绿） | 测试改为在事件循环**内**取状态再断言；已用变异自证：删掉实现的 `task.cancel()` 后**只有这条变红** |
| **D-5** | 测试洞 | D-1 缺陷 0 覆盖；`applied` 的「真变 + 同值」混合场景无覆盖 | 补 **8** 条：5 条点号键回归 + 1 条混合提交 + 1 条带空白掩码 + 1 条真实消费者（`browser_path`/`headless`/`page_timeout`）；均已用变异自证（把归一化改回直通 / `applied = accepted` → 对应用例立刻变红） |
| **D-6** | 契约级（轻） | `_expand_dotted()` 遇到「同名分组已存在但不是 dict」时用空 dict 顶替 → `{"permission_settings":"x", "permission_settings.allow_group":true}` 会 **200 并静默丢弃**非法值，**结果依赖 JSON 成员顺序**（反序则 400） | 改为直接抛 `ConfigValueError(group, "必须是对象")`。现 8 种形态（非对象在前/在后 × `"x"`/`None`/`list`，外加叠加非法 UMO、单独非对象基线）**全部 400 + field 精确 + 未落盘**；「两种写法并存且都是 dict」仍正常合并生效 |

> D-1 ~ D-3 的修复均有独立复现脚本验证（嵌套/点号两种写法都 400 且 sha256 不变、合法点号仍生效、混发生效、三种掩码写法都不覆盖真实 cookie）。
> D-1 另做了**对抗性补测（27 条攻击 + 10 条合法用例全过）**：点号+非法 UMO / 点号+非字符串条目 / 点号+非 list / 点号+未知消息类型 / 点号+空 platform / 点号+未知子键 / 点号+更深层级 / 嵌套里合法与非法混装 / 非敏感项传 `"***"` —— 全部 **400 + `field` 精确 + sha256 不变**；合法点号 UMO、合法点号 bool/int/string、越界钳制、分组兄弟键完整性 —— 全部 **200 且生效**（没有把功能修坏）。
> D-4 / D-5 的补测均配**变异自证**（在仓库副本上把实现改坏 → 对应用例必须变红 → 还原），确保新测试不是空壳。测试总数因此从 349 增至 **362**。
> D-6 由第二轮复审发现（复审报告里记作「D-1b」）。注意**编号对账**：独立验收报告 `AUDIT_REPORT.md` 与本文档的 D 编号不一一对应（复审报告的「D-3」是本文档 D-5 里的混合 `applied` 洞；复审报告的「D-1b」= 本文档 D-6）。
> **关于 D-6 的第二个 `raise` 是否冗余**：测试作者一度判定它「等价变异、可删」，**该结论不成立**。它在「给**非分组叶子**塞点号子键」时是唯一防线：去掉后 `{"timezone.x": 1, "timezone": "abc"}` 会 **200 且静默丢弃** `timezone.x`、把 `abc` 接受下来；只有 `permission_settings` 这种**分组**键才会被后续分组分支独立兜底。故第二个 `raise` **保留**（并已补测试钉住）。

### 11.1 关于 `reloaded == []` 的诚实说明

`reloaded` 在实现里是**恒为空**的（`_config_payload()` 直接返回 `[]`），所以测试里所有 `assertEqual(reloaded, [])` 都是同义反复、**零证明力**。

「改完不用重启」的**真正证据**是本文 §4 的逐项验证：每一项都作用到该配置项真实的运行时消费者（`plugin.auth.*`、`login_manager.daily_limit`、`_warmup_task`、`_is_allowed()`、`main._client()` 的构造参数、`_token()`/`_cached()` 写缓存时的 ttl），而不是回读配置对象。请验收人按 §4 的口径复核，不要拿 `reloaded` 当证据。

### 11.2 第三轮独立确认（最终状态）

独立验收对最终代码做了增量确认（9 组变异），**判定 PASS**：

- `pytest tests/ -q` **362 passed**（265 + 97）；`--ignore=tests/test_webapi_config.py` → 265；无 SKIP / XFAIL / deselected。
- D-6 顺序无关性：**5 种非对象形态 × 2 种成员顺序 = 10 态全部 400**（`field="permission_settings"`、sha256 + 内存深比较 + `save_calls` 三不变）；普通叶子 `timezone` 塞点号子键 **6 态全部 400**；「两种 dict 写法并存」**4 种组合全 200**（没修成一律拒绝）。
- **存活变异 = 1 个，且是等价变异（不是测试洞）**：`_expand_dotted()` 第二处 `out.get(key, _MISSING)` 的哨兵冗余——`_MISSING` 是 `object()`，`isinstance(_MISSING, dict)` 恒为假，两种写法整条条件都为假，任何输入都无法区分。**故保留**：不为消灭一个等价变异去改动已通过最终验收的文件。其余 8 组变异全部 KILLED（含 `N1` 只去掉第二个 `raise` → **恰好只红**那条专杀用例；`N4` 把 `_MISSING` 第一处退化成 `out.get(group)` → **只红 `bad=None` 那一格**，证明哨兵只对 `None` 承重）。
- 回归：6 个业务文件与 HEAD blob 逐字节相同；12 条老路由差异数 0 + 12 个 handler 签名 `CHANGED_COUNT=0`；`hw_webapi.py` numstat `594 0`（无删除行）；`test_v041.py` `1 1`；§5.3 九条与 emoji 扫描 ZERO HIT；私有称呼 39 个文件 ZERO HIT。

**最终快照 sha256（供对账）**

```
hw_webapi.py                       E6302E6B4D0C488B1589A2F1B665E00B7D2373F0CE3229E3C6289FED733A1A51
tests/test_webapi_config.py        612BF512348224B60CC26137C1223C678943415D555F792DE1E8399FD64FCD19
pages/health_console/index.html    91ADA59D…
tests/test_v041.py                 EE8C3B41…
_conf_schema.json                  588A3441…（未改动）
```

（`DELIVERY_WEBUI.md` 本身在本节写入后会变化，不参与代码锚定。）

---

## 12. 验收人操作指引（复现我说的每一句）

```powershell
$R = 'C:\Users\<用户名>\.astrbot\data\plugins\astrbot_plugin_Tricy_huawei_health'
$PY = 'C:\Users\<用户名>\AppData\Local\AstrBot\backend\python\python.exe'
$env:PYTHONIOENCODING = 'utf-8'

# 1) 全量回归
cd $R; & $PY -m pytest tests/ -q            # 期望 362 passed

# 2) 变更面（应只有 3 个 M + 2 个 ??）
git -C $R status --porcelain

# 3) 12 条旧路由零改动
git -C $R diff -U0 -- hw_webapi.py | Select-String '^[+-]\s+reg\('   # 期望只有 2 行 "+"

# 4) T0 只改了一个数字
git -C $R diff -- tests/test_v041.py        # 期望恰好 1 处 +/-

# 5) 设计禁止项
Select-String -Path "$R\pages\health_console\index.html" `
  -Pattern 'gradient|backdrop-filter|box-shadow|animation\s*:|@keyframes|vue|react|tailwind|src="http|href="http'
# 期望：无输出

# 6) 红线：派活单 §7.5 列出的三个私有称呼 + 本机真实账户名
#    （为避免本文档自己命中红线，这里不把那些字面量抄进来；请直接用派活单 §7.5 的原词做 pattern）
Select-String -Path "$R\*.py","$R\pages\health_console\index.html","$R\DELIVERY_WEBUI.md" -Pattern '<派活单 §7.5 的三个词>'
# 期望：无输出
```

真机联调（需要重启插件加载新后端一次，之后**改配置全程不用重启**）：
AstrBot → 插件 → 华为运动健康 → ④ 设置，重点看三处：**留空的敏感项不出现在请求体**、**400 时对应控件高亮**、**409 时自动重取并保留未保存的输入**。

---

## 13. 已知限制

1. **需要重启插件一次**才能加载新的 `hw_webapi.py` / `index.html`（这是部署动作，不是配置生效）；此后 21 项改完即生效。
2. 前端只在**离线 DOM/VM 沙箱**里跑过 96 项冒烟 + 逐字复刻既有前端断言的 13 项检查，**没有在真实 AstrBot 页面里点过**（受「不许跑真实登录/取数」红线限制）。
3. `bridge` 通道下的 `field` 透传受限（见 §10.6）。
4. 沙箱证据里的 sha256 是**临时配置文件**的指纹，每次运行重新生成，不是真实 AstrBot 配置文件的 sha256。
