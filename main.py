# -*- coding: utf-8 -*-
"""astrbot_plugin_huawei_health —— 把华为运动健康接进 AstrBot

数据源：health.cloud.huawei.com（华为运动健康网页端）
认证：注入浏览器 cookie → 自动走 OAuth（信任设备，无二次验证）→ accessToken
取数：纯 HTTP（不需要浏览器常开）

2026-10-22 实机验证通过的链路，见 hw_auth.py 顶部注释。
"""

import asyncio
import datetime
import json
import os
import time

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register

try:  # 插件作为包加载
    from .hw_auth import HuaweiAuth, HuaweiAuthError, MIN_COOKIE_SPECS
    from .hw_client import AuthExpired, HuaweiHealthClient, HuaweiHealthError
    from .hw_store import HealthStore
except ImportError:  # 插件目录在 sys.path 里
    from hw_auth import HuaweiAuth, HuaweiAuthError, MIN_COOKIE_SPECS
    from hw_client import AuthExpired, HuaweiHealthClient, HuaweiHealthError
    from hw_store import HealthStore

PLUGIN_NAME = "astrbot_plugin_huawei_health"
DEFAULT_CLIENT_ID = "106533743"
DEFAULT_VERSION = "HealthKitRunningGroupPortal_6.26.4.200"

# v0.3.1 对齐实际装饰器注册结果，health_overview 也属于可用工具。
TOOL_NAMES = [
    "health_status", "health_today", "health_sleep", "health_heart",
    "health_activities", "health_performance", "health_overview", "health_refresh",
]


def _data_dir() -> str:
    """插件数据目录（cookie / 数据库都放这儿）。"""
    try:
        from astrbot.core.utils.astrbot_path import get_astrbot_data_path

        base = get_astrbot_data_path()
    except Exception:
        base = os.path.join(os.path.expanduser("~"), ".astrbot", "data")
    path = os.path.join(base, "plugin_data", PLUGIN_NAME)
    os.makedirs(path, exist_ok=True)
    return path


# 版本号与 metadata、WebUI 状态和 README 保持一致，便于升级后核对。
@register(
    PLUGIN_NAME,
    "Knn",
    "把华为运动健康（网页端）的睡眠 / 静息心率 / HRV / 训练数据接进 AstrBot",
    "v0.3.1",
)
class HuaweiHealthPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.data_dir = _data_dir()
        self.cookie_file = os.path.join(self.data_dir, "hw_cookies.json")
        self.db_path = os.path.join(self.data_dir, "health.db")
        self.store = HealthStore(self.db_path)
        self._lock = asyncio.Lock()
        # 记录每个缓存键的进行中任务，避免并发请求重复打华为接口。
        self._cache_inflight = {}
        # generation 用于阻止刷新后旧请求把结果写回缓存。
        self._cache_generation = {}
        self._warmup_task = None
        self.logger = logger

    async def initialize(self):
        # 配置同时兼容旧整段 JSON 和新分条值，避免升级后必须重新导出全部 cookie。
        raw = (self.config.get("cookie_json") or "").strip()
        fields = {
            name: self.config.get("cookie_" + name, "")
            for name, _, _ in MIN_COOKIE_SPECS
        }
        if raw or any(str(value or "").strip() for value in fields.values()):
            try:
                n = self.auth.import_cookie_sources(raw, fields)
                self.logger.info("[华为健康] 已从配置导入 %d 条 cookie" % n)
            except Exception as exc:
                self.logger.warning("[华为健康] 配置里的 cookie 解析失败：%s" % exc)
        self.logger.info("[华为健康] 插件已就绪，数据目录：%s" % self.data_dir)
        # 注册 WebUI 页面 API（页面在 pages/health_console/）
        try:
            try:
                from .hw_webapi import HuaweiHealthWebApi
            except ImportError:
                from hw_webapi import HuaweiHealthWebApi
            HuaweiHealthWebApi(self).register()
            self.logger.info("[华为健康] WebUI 页面 API 已注册")
        except Exception as exc:
            self.logger.warning("[华为健康] WebUI API 注册失败：%s" % exc)
        # 后台预热 token：主人第一次提问就不用等 30 多秒的浏览器启动
        if self.config.get("warmup", True):
            self._warmup_task = asyncio.create_task(self._warmup())

    async def _warmup(self):
        try:
            await asyncio.sleep(8)
            await self._token()
            self.logger.info("[华为健康] token 预热完成，后续查询可秒回")
        except Exception as exc:
            self.logger.warning("[华为健康] token 预热失败（不影响后续使用）：%s" % exc)

    # ================= 内部：认证 / 客户端 =================

    @property
    def auth(self) -> HuaweiAuth:
        return HuaweiAuth(
            cookie_file=self.cookie_file,
            profile_dir=os.path.join(self.data_dir, "browser_profile"),
            browser_path=(self.config.get("browser_path") or "").strip(),
            headless=bool(self.config.get("headless", True)),
            page_timeout=self.config.get("page_timeout", 90),
            logger=self.logger,
        )

    async def _token(self, force: bool = False, stale_token: str = "") -> str:
        """取 accessToken：内存 → SQLite → 起浏览器自动登录。"""
        if not force:
            cached = self.store.get("token")
            if cached and cached.get("token") and cached.get("expire_at", 0) > time.time():
                return cached["token"]

        async with self._lock:
            cached = self.store.get("token")
            if cached and cached.get("token") and cached.get("expire_at", 0) > time.time():
                # 401 重认证只在缓存仍是同一个失效 token 时启动浏览器；
                # 并发请求若已经被前一个请求刷新，则复用新 token，避免重复启动浏览器。
                if not force or (stale_token and cached.get("token") != stale_token):
                    return cached["token"]

            ttl = int(self.config.get("token_ttl", 3000))
            # 保留认证对象引用，读取页面真实 expireTime；旧页面没有该字段时回退配置 TTL。
            auth = self.auth
            token = await asyncio.to_thread(auth.fetch_token)
            now = time.time()
            actual_expire_at = float(getattr(auth, "token_expire_at", 0.0) or 0.0)
            if actual_expire_at > now:
                # 提前半分钟失效，避免刚好在请求边界使用过期 token。
                expire_at = actual_expire_at - 30
                if ttl > 0:
                    expire_at = min(expire_at, now + ttl)
            else:
                expire_at = now + ttl
            self.store.set("token", {
                "token": token,
                "expire_at": expire_at,
                "obtained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            return token

    async def _client(self, force: bool = False, stale_token: str = "") -> HuaweiHealthClient:
        token = await self._token(force=force, stale_token=stale_token)
        return HuaweiHealthClient(
            token,
            client_id=(self.config.get("client_id") or DEFAULT_CLIENT_ID).strip(),
            version=(self.config.get("api_version") or DEFAULT_VERSION).strip(),
        )

    async def _cached(self, key: str, producer, ttl: int = None, force: bool = False):
        """带缓存地跑 producer(client)。401 时自动重认证重试一次。"""
        if not force:
            hit = self.store.get(key)
            if hit is not None:
                return hit
        ttl = int(self.config.get("data_ttl", 600)) if ttl is None else ttl
        # 同一 key 共用一个任务；刷新通过 generation 使旧任务结果失效。
        task = self._cache_inflight.get(key)
        if task is None or task.done():
            generation = self._cache_generation.get(key, 0)

            async def produce():
                used_token = ""

                async def run(force_auth: bool, stale_token: str = ""):
                    nonlocal used_token
                    client = await self._client(force=force_auth, stale_token=stale_token)
                    used_token = client.token
                    return await asyncio.to_thread(producer, client)
                try:
                    try:
                        result = await run(False)
                    except AuthExpired:
                        self.logger.warning("[华为健康] token 失效，重新认证…")
                        result = await run(True, stale_token=used_token)
                    if self._cache_generation.get(key, 0) == generation:
                        self.store.set(key, result, ttl=ttl)
                    return result
                finally:
                    if self._cache_inflight.get(key) is asyncio.current_task():
                        self._cache_inflight.pop(key, None)

            task = asyncio.create_task(produce())
            self._cache_inflight[key] = task
        return await asyncio.shield(task)

    def _clear_health_cache(self):
        """清 cookie 时同步废弃全部健康缓存，防止新账号读到旧账号数据。"""
        # 同时推进所有正在运行的 key；这些任务即使完成，也不能把旧账号结果写回。
        keys = set(self._cache_generation) | set(self._cache_inflight)
        for key in keys:
            self._cache_generation[key] = self._cache_generation.get(key, 0) + 1
        for key in list(self.store.keys()):
            if key != "token":
                self.store.delete(key)

    async def _invalidate_auth_cache(self):
        """在认证锁内清理凭证和健康缓存，避免并发认证完成后把旧 token 写回来。"""
        async with self._lock:
            self._clear_health_cache()
            self.store.delete("token")

    @staticmethod
    def _err(exc: Exception) -> str:
        if isinstance(exc, HuaweiAuthError):
            return "拿不到登录态：%s" % exc
        if isinstance(exc, AuthExpired):
            return "登录态失效了，请重新导入 cookie。"
        if isinstance(exc, HuaweiHealthError):
            return "华为接口报错：%s" % exc
        return "出错了：%s: %s" % (type(exc).__name__, exc)

    # ================= 内部：格式化 =================

    @staticmethod
    def _stat_line(stats: dict, count_label: str = "条") -> str:
        if not stats:
            return "无数据"
        parts = []
        for k, label in (("avg", "均"), ("min", "最低"), ("max", "最高")):
            if stats.get(k) is not None:
                parts.append("%s%s" % (label, stats[k]))
        if stats.get("count") is not None:
            parts.append("%s %s" % (stats["count"], count_label))
        return " / ".join(parts) if parts else "无数据"

    @staticmethod
    def _daily_has_value(daily: list) -> bool:
        """按天明细里到底有没有真数值（HRV 那种只回 count 的就没有）。"""
        for item in daily or []:
            for field, stats in item.items():
                if field == "day" or not isinstance(stats, dict):
                    continue
                if stats.get("avg") is not None or stats.get("max") is not None:
                    return True
        return False

    def _metric_text(self, parsed: dict, unit: str, days: int, name: str,
                     count_label: str = "条") -> str:
        # TODO(v0.3.2)：逐日输出补充 min/count，当前仅保留既有 avg/max 口径。
        overall = parsed.get("overall") or {}
        daily = parsed.get("daily") or []
        if not overall and not daily:
            return "最近 %d 天没有 %s 数据（可能没戴表 / 没同步）。" % (days, name)
        lines = []
        for field, stats in overall.items():
            lines.append("%s %s：%s" % (name, field, self._stat_line(stats, count_label)))
        if daily and self._daily_has_value(daily):
            lines.append("按天：")
            for item in daily[-7:]:
                day = item.get("day")
                vals = []
                for field, stats in item.items():
                    if field == "day" or not isinstance(stats, dict):
                        continue
                    if stats.get("avg") is not None:
                        vals.append("%s" % stats["avg"])
                    elif stats.get("max") is not None:
                        vals.append("%s" % stats["max"])
                lines.append("  %s  %s %s" % (day, " / ".join(vals) if vals else "-", unit))
        elif daily:
            lines.append("（云端只回了记录条数，没有逐日数值）")
        return "\n".join(lines)

    @staticmethod
    def _is_nap(rec: dict) -> bool:
        """华为云端会把「零星小睡」也塞进睡眠记录，用类型 / 时长判一下。"""
        def v(*keys):
            for item in (rec.get("value") or []):
                if item.get("fieldName") in keys:
                    for k in ("floatValue", "integerValue", "longValue", "doubleValue"):
                        if item.get(k) is not None:
                            return item[k]
            return None
        stype = v("sleep_type", "sleepType")
        if stype is not None and stype != 1:
            return True
        total = v("all_sleep_time", "allSleepTime")
        return total is not None and total < 180

    @classmethod
    def _sleep_text(cls, records: list, days: int, night_only: bool = False) -> str:
        if night_only:
            records = [r for r in records if not cls._is_nap(r)]
        if not records:
            return "最近 %d 天没有睡眠记录（可能没戴表）。" % days
        lines = []
        for rec in records[-7:]:
            def val(*keys):
                for item in (rec.get("value") or []):
                    if item.get("fieldName") in keys:
                        for k in ("floatValue", "integerValue", "longValue", "doubleValue"):
                            if item.get(k) is not None:
                                return item[k]
                return None

            start = rec.get("startTime")
            try:
                day = datetime.datetime.fromtimestamp(int(start) / 1e9).strftime("%m-%d")
            except Exception:
                day = "?"
            total = val("all_sleep_time", "allSleepTime")
            score = val("sleep_score", "sleepScore")
            deep = val("deep_sleep_time", "deepSleepTime")
            light = val("light_sleep_time", "lightSleepTime")
            dream = val("dream_time", "dreamTime")
            awake = val("awake_time", "awakeTime")
            latency = val("sleep_latency", "sleepLatency")
            wakeup = val("wakeup_count", "wakeupCount")
            bits = []
            if total:
                bits.append("总睡 %s 分" % total)
            if score:
                bits.append("得分 %s" % score)
            if deep is not None or light is not None or dream is not None:
                bits.append("深 %s / 浅 %s / REM %s" % (
                    "-" if deep is None else deep,
                    "-" if light is None else light,
                    "-" if dream is None else dream))
            if awake is not None:
                bits.append("清醒 %s 分" % awake)
            if latency is not None:
                bits.append("入睡用 %s 分" % latency)
            if wakeup is not None:
                bits.append("夜醒 %s 次" % wakeup)
            tag = "（小睡）" if cls._is_nap(rec) else ""
            lines.append("  %s%s  %s" % (day, tag, "，".join(bits) if bits else "有记录但字段未识别"))
        return "最近睡眠：\n" + "\n".join(lines)

    # ---------- 其它数据项的格式化 ----------

    @staticmethod
    def _fmt_duration(sec) -> str:
        try:
            sec = int(sec)
        except (TypeError, ValueError):
            return "-"
        h, r = divmod(sec, 3600)
        m, s = divmod(r, 60)
        return "%d:%02d:%02d" % (h, m, s) if h else "%d:%02d" % (m, s)

    @classmethod
    def _fmt_perf(cls, d: dict) -> str:
        if not d:
            return "没有运动能力评估数据"
        pt = d.get("predictedTimes") or {}
        try:
            rank = round(float(d.get("ranking") or 0), 1)
        except (TypeError, ValueError):
            rank = "-"
        return "\n".join([
            "跑力指数 %s ｜ 排名超过 %s%% 的跑者" % (d.get("runningAbility", "-"), rank),
            "状态 %s ｜ 体能 %s ｜ 疲劳 %s" % (
                d.get("condition", "-"), d.get("fitness", "-"), d.get("fatigue", "-")),
            "预测成绩：1km %s ｜ 3km %s ｜ 5km %s ｜ 10km %s" % (
                cls._fmt_duration(pt.get("km1")), cls._fmt_duration(pt.get("km3")),
                cls._fmt_duration(pt.get("km5")), cls._fmt_duration(pt.get("km10"))),
            "　　　　　半马 %s ｜ 全马 %s" % (
                cls._fmt_duration(pt.get("halfMarathon")), cls._fmt_duration(pt.get("marathon"))),
        ])

    @staticmethod
    def _fmt_pb(d: dict) -> str:
        names = {
            "bestRunDistance": "最长跑步距离",
            "bestRunPartTime5KM": "5 公里最快",
            "bestRunPartTime3KM": "3 公里最快",
            "bestRunPace": "最佳配速",
            "accumulatedRunDistance": "累计跑量",
        }

        def fmt(name: str, v):
            if v is None:
                return "-"
            if "Distance" in name:
                try:
                    return "%.2f 公里" % (float(v) / 1000.0)
                except (TypeError, ValueError):
                    return str(v)
            if "Pace" in name:
                try:
                    m, s = divmod(int(v), 60)
                    return "%d'%02d''" % (m, s)
                except (TypeError, ValueError):
                    return str(v)
            if "Time" in name:
                try:
                    m, s = divmod(int(v), 60)
                    return "%d 分 %02d 秒" % (m, s)
                except (TypeError, ValueError):
                    return str(v)
            return str(v)

        lines = []
        for rep in (d.get("sportReports") or []):
            for item in (rep.get("personalBest") or []):
                n = str(item.get("name"))
                lines.append("  %s：%s" % (names.get(n, n), fmt(n, item.get("value"))))
            for item in (rep.get("accumulate") or []):
                n = str(item.get("name"))
                lines.append("  %s：%s" % (names.get(n, n), fmt(n, item.get("value"))))
        if not lines:
            return "没有个人纪录"
        return "个人纪录：\n" + "\n".join(lines)

    @staticmethod
    def _fmt_zones(z: dict) -> str:
        if not z:
            return "没有心率区间配置"
        order = [
            ("anaerobic_advance", "无氧进阶"), ("anaerobic", "无氧耐力"), ("anaerobic_base", "无氧基础"),
            ("lactic_acid", "乳酸阈值"), ("aerobic_advance", "有氧进阶"), ("aerobic", "有氧耐力"),
            ("aerobic_base", "有氧基础"), ("fat_burn", "燃脂"), ("warm_up", "热身"),
        ]
        lines = ["静息 %s ｜ 最大 %s bpm" % (z.get("rest", "-"), z.get("max", "-"))]
        for key, name in order:
            if z.get(key) is not None:
                lines.append("  %s ≥ %s bpm" % (name, z[key]))
        return "\n".join(lines)

    @staticmethod
    def _fmt_weight(parsed: dict) -> str:
        overall = parsed.get("overall") or {}
        daily = parsed.get("daily") or []
        if not overall and not daily:
            return "没有体重记录"
        lines = []
        for field, st in overall.items():
            # 「最新」以按天明细的最后一条为准（服务端的 last 不保证按日期序）
            latest = st.get("last", st.get("avg"))
            if daily:
                v = (daily[-1] or {}).get(field)
                if isinstance(v, dict) and v.get("last") is not None:
                    latest = v.get("last")
            lines.append("%s：最新 %s kg ｜ 均 %s ｜ 共 %s 条" % (
                field, latest, st.get("avg"), st.get("count")))
        for item in daily[-5:]:
            day = item.get("day")
            for field, st in item.items():
                if field == "day" or not isinstance(st, dict):
                    continue
                lines.append("  %s  %s kg" % (day, st.get("last", st.get("avg"))))
                break
        return "\n".join(lines)

    # ================= LLM 工具 =================

    @filter.llm_tool(name="health_status")
    async def health_status(self, event: AstrMessageEvent):
        """检查华为运动健康数据通道的状态：cookie 有没有、token 还能用多久。

        主人问「健康数据通道通不通」「你的健康数据还能用吗」时用这个。
        """
        has_cookie = os.path.exists(self.cookie_file)
        cached = self.store.get("token") or {}
        left = int(cached.get("expire_at", 0) - time.time()) if cached.get("expire_at") else 0
        lines = [
            "cookie 文件：%s" % ("有（%s）" % self.cookie_file if has_cookie else "没有，需要导入"),
            "token 缓存：%s" % ("有效，剩 %d 秒" % left if left > 0 else "无 / 已过期"),
        ]
        if has_cookie:
            try:
                await self._token()
                lines.append("实测：可以正常拿到 token ✓")
            except Exception as exc:
                lines.append("实测失败：%s" % self._err(exc))
        return "\n".join(lines)

    @filter.llm_tool(name="health_today")
    async def health_today(self, event: AstrMessageEvent):
        """查看主人今天的健康概况：今天的静息心率、最近一晚睡眠、近期运动记录。

        主人问「我今天身体怎么样」「我昨晚睡得怎么样」「我的心率如何」时优先用这个。
        """
        parts = []
        try:
            hr = await self._cached("hr:2", lambda c: c.resting_heart_rate(2))
            parts.append("【静息心率】\n" + self._metric_text(hr, "bpm", 2, "静息心率", count_label="天"))
        except Exception as exc:
            parts.append("【静息心率】取数失败：%s" % self._err(exc))
        try:
            sl = await self._cached("sleep:3", lambda c: c.sleep_records(3))
            parts.append("【睡眠】\n" + self._sleep_text(sl, 3, night_only=True))
        except Exception as exc:
            parts.append("【睡眠】取数失败：%s" % self._err(exc))
        try:
            acts = await self._cached("act:7:10", lambda c: c.activities(7, 10))
            if acts:
                parts.append("【近期运动】共 %d 条" % len(acts))
            else:
                parts.append("【近期运动】最近 7 天没有运动记录")
        except Exception as exc:
            parts.append("【近期运动】取数失败：%s" % self._err(exc))
        return "\n\n".join(parts)

    @filter.llm_tool(name="health_overview")
    async def health_overview(self, event: AstrMessageEvent):
        """一次性查看全部已接入的健康数据：静息心率、睡眠、睡眠 HRV、压力、体重、心率区间、运动能力与预测成绩、个人纪录、近期运动。

        主人问「我的健康状况整体怎么样」「把能看的都给我看看」「健康总览」时用这个。
        """
        async def add(key, title, producer, ttl=600):
            try:
                text = await self._cached("ov:%s" % key, producer, ttl=ttl)
                return "【%s】\n%s" % (title, text)
            except Exception as exc:
                return "【%s】%s" % (title, self._err(exc))

        # 最多同时请求 3 项，缩短总览耗时并控制华为接口压力。
        sem = asyncio.Semaphore(3)
        async def limited(*args, **kwargs):
            async with sem:
                return await add(*args, **kwargs)
        # gather 按传入顺序返回，保证并发后总览展示顺序仍稳定。
        parts = await asyncio.gather(
            limited("heart", "静息心率（近 7 天）", lambda c: self._metric_text(c.resting_heart_rate(7), "bpm", 7, "静息心率", count_label="天")),
            limited("sleep", "睡眠（近 7 晚）", lambda c: self._sleep_text(c.sleep_records(7), 7)),
            limited("hrv", "睡眠 HRV", lambda c: self._metric_text(c.hrv_stats(7), "", 7, "HRV")),
            limited("stress", "压力（近 7 天）", lambda c: self._metric_text(c.stress_stats(7), "", 7, "压力")),
            limited("weight", "体重", lambda c: self._fmt_weight(c.body_weight(1095))),
            limited("zones", "心率区间", lambda c: self._fmt_zones(c.heart_rate_zones())),
            limited("perf", "运动能力与预测成绩", lambda c: self._fmt_perf(c.athletic_performance()), ttl=3600),
            limited("pb", "个人纪录", lambda c: self._fmt_pb(c.personal_bests("running")), ttl=3600),
        )
        return "\n\n".join(parts)

    @filter.llm_tool(name="health_sleep")
    async def health_sleep(self, event: AstrMessageEvent, days: int = 7):
        """查看最近 N 天的睡眠记录（每晚的上床/入睡/醒来、深浅睡与 REM 分段、总分）。

        Args:
            days(number): 查询天数，默认 7，范围 1~30
        """
        days = max(1, min(int(days or 7), 30))
        try:
            sl = await self._cached("sleep:%d" % days, lambda c: c.sleep_records(days))
            return self._sleep_text(sl, days)
        except Exception as exc:
            return self._err(exc)

    @filter.llm_tool(name="health_heart")
    async def health_heart(self, event: AstrMessageEvent, days: int = 7):
        """查看最近 N 天的静息心率与睡眠 HRV（恢复状态）。

        Args:
            days(number): 查询天数，默认 7，范围 1~90
        """
        days = max(1, min(int(days or 7), 90))
        out = []
        try:
            hr = await self._cached("hr:%d" % days, lambda c: c.resting_heart_rate(days))
            out.append("【静息心率 bpm】\n" + self._metric_text(hr, "bpm", days, "静息心率", count_label="天"))
        except Exception as exc:
            out.append("【静息心率】%s" % self._err(exc))
        try:
            hrv = await self._cached("hrv:%d" % days, lambda c: c.hrv_stats(days))
            out.append("【睡眠 HRV】\n" + self._metric_text(hrv, "", days, "HRV"))
        except Exception as exc:
            out.append("【睡眠 HRV】%s" % self._err(exc))
        return "\n\n".join(out)

    @filter.llm_tool(name="health_activities")
    async def health_activities(self, event: AstrMessageEvent, days: int = 30, limit: int = 10):
        """查看最近的运动记录列表。

        Args:
            days(number): 回溯天数，默认 30，范围 1~365
            limit(number): 最多返回几条，默认 10，范围 1~50
        """
        days = max(1, min(int(days or 30), 365))
        limit = max(1, min(int(limit or 10), 50))
        try:
            acts = await self._cached("act:%d:%d" % (days, limit),
                                      lambda c: c.activities(days, limit))
        except Exception as exc:
            return self._err(exc)
        if not acts:
            return "最近 %d 天没有运动记录。" % days
        lines = ["最近 %d 天运动记录（%d 条）：" % (days, len(acts))]
        for a in acts[:limit]:
            def val(*keys):
                for k in keys:
                    if a.get(k) is not None:
                        return a[k]
                return None

            ts = val("endTime", "startTime")
            when = ""
            if ts:
                try:
                    ms = int(ts)
                    ms = ms / 1e6 if ms > 1e13 else ms
                    when = datetime.datetime.fromtimestamp(ms / 1000).strftime("%m-%d %H:%M")
                except Exception:
                    when = str(ts)
            bits = [when]
            if val("activityType") is not None:
                bits.append("类型%s" % val("activityType"))
            if val("distance"):
                bits.append("距离%s" % val("distance"))
            if val("duration"):
                bits.append("时长%s" % val("duration"))
            if val("avgHeartRate", "averageHeartRate"):
                bits.append("均心率%s" % val("avgHeartRate", "averageHeartRate"))
            lines.append("  " + " | ".join(str(b) for b in bits if b))
        return "\n".join(lines)

    @filter.llm_tool(name="health_performance")
    async def health_performance(self, event: AstrMessageEvent):
        """查看运动能力评估（跑力指数、预测成绩）与跑步个人纪录。

        主人问「我跑力多少」「半马能跑多久」「我的 PB」时用这个。
        """
        out = []
        try:
            perf = await self._cached("perf", lambda c: c.athletic_performance(), ttl=3600)
            # 统一走可读格式，避免把截断 JSON 直接交给 LLM。
            out.append("【运动能力评估】\n" + self._fmt_perf(perf))
        except Exception as exc:
            out.append("【运动能力评估】%s" % self._err(exc))
        try:
            pb = await self._cached("pb", lambda c: c.personal_bests("running"), ttl=3600)
            out.append("【跑步个人纪录】\n" + self._fmt_pb(pb))
        except Exception as exc:
            out.append("【跑步个人纪录】%s" % self._err(exc))
        return "\n\n".join(out)

    @filter.llm_tool(name="health_refresh")
    async def health_refresh(self, event: AstrMessageEvent):
        """清空本地缓存并强制重新拉取最新数据（token 也一起刷新）。

        主人问「刷新一下最新的健康数据」时用这个。
        """
        # 刷新时推进 generation，避免尚未结束的旧请求覆盖刷新后的缓存。
        await self._invalidate_auth_cache()
        try:
            await self._token(force=True)
            return "缓存已清空，并已重新拿到最新 token。可以继续查询了。"
        except Exception as exc:
            return "缓存已清空，但重新认证失败：%s" % self._err(exc)

    async def terminate(self):
        if self._warmup_task and not self._warmup_task.done():
            self._warmup_task.cancel()
            try:
                await self._warmup_task
            except asyncio.CancelledError:
                pass
        self.logger.info("[华为健康] 插件已卸载/停用。")
