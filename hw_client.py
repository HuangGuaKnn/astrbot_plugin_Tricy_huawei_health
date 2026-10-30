# -*- coding: utf-8 -*-
"""华为运动健康 · 数据客户端

端点全部来自 2026-10-22 对 health.cloud.huawei.com/TrainingCamp 的实抓，
并用纯 requests（无浏览器、无 cookie）验证过可用。

时间口径（别踩）：
    - 活动记录列表：毫秒时间戳
    - GET /healthRecords（睡眠明细）：纳秒时间戳
    - 聚合统计：用 startDay/endDay
        · sampleSet 端点 → 数字，如 20261016
        · healthRecords 端点 → 字符串，如 "20261016"
"""

import datetime
import json
import re
import threading
import time

import requests
from urllib3.util import Timeout

try:  # 插件作为包加载
    from .hw_privacy import redact_error
except ImportError:  # 插件目录在 sys.path 里
    from hw_privacy import redact_error

BASE = "https://hihealthbase-drcn.things.dbankcloud.cn/healthrunninggroup/v1"
DEFAULT_CLIENT_ID = "106533743"
DEFAULT_VERSION = "HealthKitRunningGroupPortal_6.26.4.200"

RESTING_HR_TYPE = "com.huawei.instantaneous.resting_heart_rate"
SLEEP_TYPE = "com.huawei.health.record.sleep"
HRV_FIELD = "avgHrv"
STRESS_TYPE = "com.huawei.instantaneous.stress"
WEIGHT_TYPE = "com.huawei.instantaneous.body_weight"
#: 心率区间阈值配置（GET /sampleConfigs?type=9002&id=900200028）
HR_ZONE_CONFIG_TYPE = "9002"
HR_ZONE_CONFIG_ID = "900200028"

STRATEGY = ["MAX", "MIN", "AVG", "COUNT"]
# 华为接口偶发 429/5xx 时只做有限退避，避免把一次查询放大成无限重试。
MAX_RETRIES = 2
# 总览会并发多个只读请求；全局间隔避免短时间内形成请求突刺。
_REQUEST_GATE = threading.Lock()
_LAST_REQUEST_AT = 0.0
_MIN_REQUEST_INTERVAL = 0.2


def _remaining(deadline):
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RequestDeadlineExceeded("取数已超过总时间预算，请稍后重试")
    return remaining


def _budget_sleep(delay, deadline=None):
    remaining = _remaining(deadline)
    if remaining is not None and delay >= remaining:
        raise RequestDeadlineExceeded("剩余时间不足以完成重试，请稍后重试")
    if delay > 0:
        time.sleep(delay)
    _remaining(deadline)


def _throttle_request(deadline=None):
    global _LAST_REQUEST_AT
    remaining = _remaining(deadline)
    acquired = (_REQUEST_GATE.acquire() if remaining is None
                else _REQUEST_GATE.acquire(timeout=remaining))
    if not acquired:
        raise RequestDeadlineExceeded("请求排队超过总时间预算，请稍后重试")
    try:
        now = time.monotonic()
        wait = _MIN_REQUEST_INTERVAL - (now - _LAST_REQUEST_AT)
        if wait > 0:
            _budget_sleep(wait, deadline)
        _remaining(deadline)
        _LAST_REQUEST_AT = time.monotonic()
    finally:
        _REQUEST_GATE.release()


class HuaweiHealthError(Exception):
    """业务/网络错误。"""


class RequestDeadlineExceeded(HuaweiHealthError):
    """一次工具查询的时间预算已耗尽，不应继续排队或重试。"""


class AuthExpired(HuaweiHealthError):
    """401 —— 登录态失效，需要重新走认证。"""


class SchemaDrift(HuaweiHealthError):
    """华为接口的结构/字段与预期不符（多半是网页端改版）。

    v0.4.0 遇到这种情况一律 ``raw.get(...) or []`` 兜成空，用户看到的是
    「最近 7 天没有睡眠记录（可能没戴表）」——**把「接口变了」说成「你没数据」**。
    v0.4.1 起对「响应非空但关键字段不在」直接抛这个异常，让上层给出可行动的提示。
    """


def pick(obj, key, where: str):
    """取一个必需字段；缺失/类型不对时抛 SchemaDrift 而不是静默返回 None。"""
    if not isinstance(obj, dict):
        raise SchemaDrift("%s 不是对象（%s）" % (where, type(obj).__name__))
    if key not in obj:
        raise SchemaDrift("%s 缺少字段 %r，实际键=%s" % (where, key, list(obj)[:8]))
    return obj[key]


#: 这些键为 0 时表示「查询成功但没有记录」。
_EMPTY_HINT_KEYS = ("total", "count", "totalCount", "totalNum", "size", "recordCount")

#: 纯信封响应里允许出现的键（没有数据负载）。
_ENVELOPE_KEYS = {
    "code", "message", "msg", "success", "status", "hasMore", "pageNo", "pageNum",
    "pageSize", "total", "count", "totalCount", "totalNum", "size", "recordCount",
    "data", "result", "ret", "timestamp", "traceId",
}


def _is_zero(value) -> bool:
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        try:
            return float(value) == 0
        except ValueError:
            return False
    return False


def looks_like_legit_empty(raw, expected_keys=()) -> bool:
    """这个响应是不是「合法的没有数据」而不是「接口改版」。

    判据（v0.4.1 第三轮，四个解析器共用）：
      1. 期望的列表字段存在但为 ``null`` 或 ``[]``；
      2. ``total`` / ``count`` / ``totalCount`` 为 0（含字符串 ``"0"``）；
      3. 纯信封响应（只含 code/message/pageNo 之类，且没有任何非空 list/dict 负载）。

    这一条是 ``SchemaDrift`` 的**反面**：判宽了会把改版说成「没数据」，判严了会把
    「真的没数据」说成「插件坏了」——后者更难排查（用户会去等新版本而不是去戴表）。
    """
    if not isinstance(raw, dict):
        return False
    if not raw:
        return True
    for key in expected_keys:
        if key in raw:
            value = raw[key]
            if value is None:
                return True
            if isinstance(value, list) and not value:
                return True
    for key in _EMPTY_HINT_KEYS:
        if key in raw and _is_zero(raw[key]):
            return True
    if set(raw).issubset(_ENVELOPE_KEYS):
        for value in raw.values():
            if isinstance(value, list) and value:
                return False
            if isinstance(value, dict) and value:
                return False
        return True
    return False


def format_distance_m(meters) -> str:
    """米 → 「5.00 公里」；无法解析时原样带单位返回。"""
    try:
        value = float(meters)
    except (TypeError, ValueError):
        return str(meters)
    if value >= 1000:
        return "%.2f 公里" % (value / 1000.0)
    return "%.0f 米" % value


def format_duration_ms(ms) -> str:
    """毫秒 → 「30 分 00 秒」；小于 1 分钟的给秒。"""
    try:
        seconds = int(round(float(ms) / 1000.0))
    except (TypeError, ValueError):
        return str(ms)
    if seconds < 0:
        return str(ms)
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return "%d 小时 %02d 分" % (hours, minutes)
    if minutes:
        return "%d 分 %02d 秒" % (minutes, secs)
    return "%d 秒" % secs


def format_duration_s(seconds) -> str:
    """秒 → 时长文本（运动能力预测成绩用）。"""
    try:
        seconds = int(round(float(seconds)))
    except (TypeError, ValueError):
        return "-"
    if seconds < 0:
        # 负值只会来自字段漂移/异常数据，别把 "-1:59:59" 交给 LLM。
        return "-"
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return "%d:%02d:%02d" % (hours, minutes, secs)
    return "%d:%02d" % (minutes, secs)


def _fmt_day(value) -> str:
    if value is None or value == "":
        return ""
    # JSON 数字可能是 20261020.0，先归一化成整数再判 8 位。
    try:
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        elif isinstance(value, str) and value.replace(".", "", 1).isdigit() and "." in value:
            as_float = float(value)
            if as_float.is_integer():
                value = int(as_float)
    except (TypeError, ValueError, OverflowError):
        pass
    s = str(value)
    if len(s) == 8 and s.isdigit():
        return "%s-%s-%s" % (s[:4], s[4:6], s[6:8])
    return s


def _norm_stats(stats) -> dict:
    """统计键统一小写：华为若把 avg 改成 AVG，v0.4.0 会显示「无数据」。"""
    if not isinstance(stats, dict):
        return {}
    return {str(k).lower(): v for k, v in stats.items()}


def _parse_stats(raw) -> dict:
    """把 periodStatistics 的 results + groupResults 压成 {overall, daily}。

    判据：**响应非空但关键字段不在 = 改版**（抛 SchemaDrift）；响应为空 = 真的没数据。
    """
    if not isinstance(raw, dict):
        raise SchemaDrift("periodStatistics 响应不是对象（%s）" % type(raw).__name__)
    results = raw.get("results")
    group_results = raw.get("groupResults")
    if results is None and group_results is None:
        # 有些端点把负载再包一层 {"code":0,"data":{...}}；先剥掉再判。
        inner = raw.get("data")
        if isinstance(inner, dict) and inner:
            return _parse_stats(inner)
        if looks_like_legit_empty(raw, ("results", "groupResults")):
            return {"overall": {}, "daily": []}
        raise SchemaDrift(
            "periodStatistics 响应缺少 results/groupResults，实际键=%s" % list(raw)[:8])

    overall = {}
    for item in results or []:
        if not isinstance(item, dict):
            raise SchemaDrift("results 元素不是对象（%s）" % type(item).__name__)
        fn = item.get("fieldName")
        if fn and fn != "any":
            overall[fn] = _norm_stats(item.get("statistics"))

    daily = {}
    skipped = 0
    if group_results is not None and not isinstance(group_results, list):
        raise SchemaDrift("groupResults 不是数组（%s）" % type(group_results).__name__)
    for grp in group_results or []:
        if not isinstance(grp, dict):
            raise SchemaDrift("groupResults 元素不是对象（%s）" % type(grp).__name__)
        rows = grp.get("groupStatistics") or []
        if not isinstance(rows, list):
            raise SchemaDrift("groupStatistics 不是数组（%s）" % type(rows).__name__)
        for item in rows:
            if not isinstance(item, dict):
                raise SchemaDrift("groupStatistics 元素不是对象（%s）" % type(item).__name__)
            day = _fmt_day(item.get("startDay"))
            fn = item.get("fieldName")
            if not day:
                # 不要生成 day="None" 的桶（v0.4.0 会把它渲染成用户可见的 None）。
                skipped += 1
                continue
            if not fn or fn == "any":
                continue
            daily.setdefault(day, {})[fn] = _norm_stats(item.get("statistics"))
    if skipped and not daily:
        raise SchemaDrift("groupStatistics 全部缺少 startDay（共 %d 条）" % skipped)
    return {"overall": overall, "daily": [{"day": d, **v} for d, v in sorted(daily.items())]}


def parse_timezone(value="+0800"):
    """把配置中的 +0800 / +08:00 转为时区，避免依赖服务器本地时区。"""
    if isinstance(value, datetime.tzinfo):
        return value
    text = str(value or "+0800").strip()
    if text.upper() in ("UTC", "Z"):
        return datetime.timezone.utc
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text)
    if not match:
        raise ValueError("时区格式应为 +0800 或 +08:00")
    hours, minutes = int(match[2]), int(match[3])
    if hours > 23 or minutes > 59:
        raise ValueError("时区偏移超出有效范围")
    offset = datetime.timedelta(hours=hours, minutes=minutes)
    return datetime.timezone(offset if match[1] == "+" else -offset)


def _day_window(days: int, timezone="+0800"):
    days = max(1, min(int(days), 1095))
    today = datetime.datetime.now(parse_timezone(timezone)).date()
    start = today - datetime.timedelta(days=days - 1)
    return start.strftime("%Y%m%d"), today.strftime("%Y%m%d")


class HuaweiHealthClient:
    """只读客户端。"""

    def __init__(self, token: str, client_id: str = "", version: str = "",
                 timeout: int = 25, timezone: str = "+0800", deadline=None):
        self.token = token
        self.client_id = client_id or DEFAULT_CLIENT_ID
        self.version = version or DEFAULT_VERSION
        self.timeout = timeout
        self.tz = parse_timezone(timezone)
        self.timezone = datetime.datetime.now(self.tz).strftime("%z")
        self.deadline = deadline
        self._closed = False
        # 复用 TCP/TLS 连接，降低总览接口连续请求的延迟和连接开销。
        self.session = requests.Session()

    def close(self):
        if not self._closed:
            self._closed = True
            self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    # ---------- 底层 ----------

    def _headers(self, json_body: bool = False) -> dict:
        h = {
            "Authorization": "Bearer " + self.token,
            "x-client-id": self.client_id,
            "x-version": self.version,
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://health.cloud.huawei.com",
            "Referer": "https://health.cloud.huawei.com/",
        }
        if json_body:
            h["Content-Type"] = "application/json;charset=utf-8"
        return h

    @staticmethod
    def _handle(resp: requests.Response):
        if resp.status_code == 401:
            raise AuthExpired("华为返回 401，登录态已失效")
        if resp.status_code >= 400:
            # 响应体里可能回显请求头/URL，洗完再拼进异常。
            raise HuaweiHealthError(
                "HTTP %d: %s" % (resp.status_code,
                                 redact_error(resp.text[:200] or "（空响应）")))
        try:
            return resp.json()
        except Exception:
            raise HuaweiHealthError(
                "响应不是 JSON: %s" % redact_error(resp.text[:200] or "（空响应）"))

    def _request(self, method: str, path: str, *, params=None, body=None):
        """发起一次有限重试的请求；401 交给上层只做一次重认证。"""
        if self._closed:
            raise HuaweiHealthError("数据客户端已关闭")
        for attempt in range(MAX_RETRIES + 1):
            try:
                _throttle_request(self.deadline)
                remaining = _remaining(self.deadline)
                # total 扣除连接耗时后再约束读取。同步 requests 无法强制中断
                # 已开始的系统 I/O；上层仍应限制协程等待并拒绝超时结果。
                timeout = self.timeout if remaining is None else Timeout(
                    total=remaining, connect=min(self.timeout, remaining),
                    read=min(self.timeout, remaining))
                if method == "GET":
                    resp = self.session.get(
                        BASE + path,
                        headers=self._headers(),
                        params=params,
                        timeout=timeout,
                    )
                else:
                    resp = self.session.post(
                        BASE + path,
                        headers=self._headers(json_body=True),
                        json=body,
                        timeout=timeout,
                    )
            except requests.RequestException:
                if attempt >= MAX_RETRIES:
                    raise
                _budget_sleep(0.5 * (2 ** attempt), self.deadline)
                continue

            _remaining(self.deadline)
            # 401 必须立即交给 main._cached，不能在这里重放旧 token。
            if resp.status_code == 401:
                return self._handle(resp)
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < MAX_RETRIES:
                    retry_after = resp.headers.get("Retry-After", "")
                    try:
                        delay = max(0.5, min(float(retry_after), 10.0))
                    except (TypeError, ValueError):
                        delay = 0.5 * (2 ** attempt)
                    _budget_sleep(delay, self.deadline)
                    continue
            return self._handle(resp)
        raise HuaweiHealthError("华为接口重试次数耗尽")

    def _get(self, path: str, params=None):
        return self._request("GET", path, params=params)

    def _post(self, path: str, body: dict):
        return self._request("POST", path, body=body)

    # ---------- 统计类 ----------

    def _stats_body(self, data_type: str, start_day, end_day, field_names=None) -> dict:
        req = {
            "dataType": data_type,
            "startDay": start_day,
            "endDay": end_day,
            "strategy": list(STRATEGY),
            "groupOption": "day",
            "timeZone": self.timezone,
        }
        if field_names:
            req["fieldNames"] = list(field_names)
        return {"reqs": [dict(req)], "groupReqs": [dict(req)]}

    # ---------- 对外工具 ----------

    def basic_infos(self) -> dict:
        return self._get("/user/basicInfos")

    def resting_heart_rate(self, days: int = 7) -> dict:
        """静息心率（sampleSet 端点，startDay/endDay 用数字，fieldName=restBpm）。"""
        s, e = _day_window(days, self.tz)
        raw = self._post("/sampleSet/periodStatistics:calculate",
                         self._stats_body(RESTING_HR_TYPE, int(s), int(e)))
        return _parse_stats(raw)

    def hrv_stats(self, days: int = 7) -> dict:
        """睡眠 HRV（healthRecords 端点，startDay/endDay 用字符串）。"""
        s, e = _day_window(days, self.tz)
        raw = self._post("/healthRecords/periodStatistics:calculate",
                         self._stats_body(SLEEP_TYPE, s, e, [HRV_FIELD]))
        return _parse_stats(raw)

    def sleep_records(self, days: int = 7) -> list:
        """睡眠明细（GET /healthRecords，纳秒窗口）。"""
        days = max(1, min(int(days), 730))
        now = datetime.datetime.now(self.tz)
        start = now - datetime.timedelta(days=days)
        raw = self._get("/healthRecords", params={
            "dataType": SLEEP_TYPE,
            "startTime": int(start.timestamp() * 1_000_000_000),
            "endTime": int(now.timestamp() * 1_000_000_000),
        })
        if isinstance(raw, dict):
            records = raw.get("healthRecords")
            if records is None:
                if looks_like_legit_empty(raw, ("healthRecords",)):
                    return []
                raise SchemaDrift(
                    "GET /healthRecords 响应缺少 healthRecords，实际键=%s" % list(raw)[:8])
            if not isinstance(records, list):
                # v0.4.0 会把 dict 直接返回，下游 records[-7:] 抛 KeyError: slice
                raise SchemaDrift("healthRecords 不是数组（%s）" % type(records).__name__)
            return records
        if isinstance(raw, list):
            return raw
        raise SchemaDrift("GET /healthRecords 响应类型异常（%s）" % type(raw).__name__)

    def activities(self, days: int = 30, limit: int = 20) -> list:
        """运动记录列表（毫秒窗口）。"""
        days = max(1, min(int(days), 730))
        now_ms = int(datetime.datetime.now(self.tz).timestamp() * 1000)
        raw = self._post("/activityRecord:query", {
            "startTime": now_ms - days * 86400000,
            "endTime": now_ms,
            "limit": max(1, min(int(limit), 99)),
            "filterList": [],
            "order": "endTimeDesc",
        })
        if isinstance(raw, dict):
            for key in ("activityRecords", "records", "list"):
                if isinstance(raw.get(key), list):
                    return raw[key]
            if looks_like_legit_empty(raw, ("activityRecords", "records", "list")):
                return []
            raise SchemaDrift(
                "activityRecord:query 响应缺少 activityRecords，实际键=%s" % list(raw)[:8])
        if isinstance(raw, list):
            return raw
        raise SchemaDrift("activityRecord:query 响应类型异常（%s）" % type(raw).__name__)

    def athletic_performance(self) -> dict:
        """最新运动能力评估（跑力 / 预测成绩）。注意 timeZone 是必填参数。"""
        return self._get("/athleticPerformance/latest", params={"timeZone": self.timezone})

    def personal_bests(self, activity_type: str = "running") -> dict:
        """个人纪录。"""
        return self._get("/sportReports", params={"activityType": activity_type})

    def stress_stats(self, days: int = 7) -> dict:
        """压力（stressScore，sampleSet 端点）。"""
        s, e = _day_window(days, self.tz)
        raw = self._post("/sampleSet/periodStatistics:calculate",
                         self._stats_body(STRESS_TYPE, int(s), int(e)))
        return _parse_stats(raw)

    def body_weight(self, days: int = 365) -> dict:
        """体重（bodyWeight，sampleSet 端点）。"""
        s, e = _day_window(days, self.tz)
        raw = self._post("/sampleSet/periodStatistics:calculate",
                         self._stats_body(WEIGHT_TYPE, int(s), int(e)))
        return _parse_stats(raw)

    def heart_rate_zones(self) -> dict:
        """储备心率区间阈值（GET /sampleConfigs）。"""
        raw = self._get("/sampleConfigs", params={
            "type": HR_ZONE_CONFIG_TYPE, "id": HR_ZONE_CONFIG_ID})
        if not isinstance(raw, dict):
            raise SchemaDrift("GET /sampleConfigs 响应不是对象（%s）" % type(raw).__name__)
        configs = raw.get("sampleConfigs")
        if configs is None:
            if looks_like_legit_empty(raw, ("sampleConfigs",)):
                return {}
            raise SchemaDrift("sampleConfigs 缺失，实际键=%s" % list(raw)[:8])
        if not isinstance(configs, list):
            raise SchemaDrift("sampleConfigs 不是数组（%s）" % type(configs).__name__)
        # 字段语义已按实际响应核实（2026-10-29，Issue #2）：华为的
        # ``mAnaerobicThreshold``(166) 低于 ``mAnaerobicBaseThreshold``(170)，
        # 因此前者才是「无氧基础」、后者是「无氧耐力」。九档按数值排列为
        # 110 → 129 → 135 → 147 → 153 → 165 → 166 → 170 → 178，严格单调。
        for item in configs:
            if not isinstance(item, dict):
                continue
            cfg = item.get("configData")
            if not cfg:
                continue
            if isinstance(cfg, dict):
                data = cfg
            else:
                try:
                    data = json.loads(cfg)
                except Exception:
                    continue
            if not isinstance(data, dict):
                continue
            hr = data.get("mOtherHeartRateData") or {}
            if not isinstance(hr, dict) or not hr:
                continue
            zones = {
                "rest": hr.get("mRestHeartRate"),
                "max": hr.get("mMaxThreshold"),
                "warm_up": hr.get("mWarmUpThreshold"),
                "fat_burn": hr.get("mFatBurnThreshold"),
                "aerobic_base": hr.get("mAerobicBaseThreshold"),
                "aerobic": hr.get("mAerobicThreshold"),
                "aerobic_advance": hr.get("mAerobicAdvanceThreshold"),
                "lactic_acid": hr.get("mLacticAcidThreshold"),
                # 注意：这两个字段名与语义是反的，见上方说明与 Issue #2。
                "anaerobic_base": hr.get("mAnaerobicThreshold"),
                "anaerobic": hr.get("mAnaerobicBaseThreshold"),
                "anaerobic_advance": hr.get("mAnaerobicAdvanceThreshold"),
            }
            if all(v is None for v in zones.values()):
                # 11 个字段全空 = 字段名变了，别渲染成「静息 None ｜ 最大 None bpm」
                raise SchemaDrift(
                    "心率区间字段全部缺失（mOtherHeartRateData 键=%s）" % list(hr)[:8])
            return zones
        return {}


class ClientPool:
    """有限的同步客户端池；一次借用独占 Session，允许跨查询复用连接。

    run 应在工作线程里调用。invalidate 不打断正在执行的 requests，旧代
    客户端归还时关闭；调用方必须另外校验账号代数，拒绝旧请求的结果。
    """

    def __init__(self, max_size=3):
        self.max_size = max(1, int(max_size))
        self._condition = threading.Condition()
        self._entries = []
        self._generation = 0
        self._closed = False

    def _checkout(self, key, deadline):
        with self._condition:
            while True:
                if self._closed:
                    raise HuaweiHealthError("数据连接池已关闭")
                remaining = _remaining(deadline)
                idle = [entry for entry in self._entries if not entry["busy"]]
                for entry in idle:
                    if entry["key"] == key:
                        entry["busy"] = True
                        entry["client"].deadline = deadline
                        return entry
                if len(self._entries) >= self.max_size and idle:
                    evicted = idle[0]
                    self._entries.remove(evicted)
                    evicted["client"].close()
                if len(self._entries) < self.max_size:
                    token, client_id, version, timezone, timeout = key
                    client = HuaweiHealthClient(
                        token, client_id=client_id, version=version,
                        timezone=timezone, timeout=timeout, deadline=deadline)
                    entry = {"key": key, "client": client, "busy": True,
                             "generation": self._generation}
                    self._entries.append(entry)
                    return entry
                self._condition.wait(timeout=remaining)

    def run(self, token, producer, *, client_id="", version="", timezone="+0800",
            timeout=25, deadline=None):
        tz = datetime.datetime.now(parse_timezone(timezone)).strftime("%z")
        key = (token, client_id or DEFAULT_CLIENT_ID,
               version or DEFAULT_VERSION, tz, timeout)
        entry = self._checkout(key, deadline)
        try:
            _remaining(deadline)
            result = producer(entry["client"])
            _remaining(deadline)
            return result
        finally:
            with self._condition:
                if self._closed or entry["generation"] != self._generation:
                    self._entries.remove(entry)
                    entry["client"].close()
                else:
                    entry["busy"] = False
                    entry["client"].deadline = None
                    # 最后使用的排在末尾，换 token / 配置时优先淘汰最旧空闲项。
                    self._entries.remove(entry)
                    self._entries.append(entry)
                self._condition.notify_all()

    def invalidate(self):
        with self._condition:
            self._generation += 1
            for entry in list(self._entries):
                if not entry["busy"]:
                    self._entries.remove(entry)
                    entry["client"].close()
            self._condition.notify_all()

    def close(self):
        with self._condition:
            self._closed = True
            self.invalidate()
