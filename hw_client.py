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
import threading
import time

import requests

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


def _throttle_request():
    global _LAST_REQUEST_AT
    with _REQUEST_GATE:
        now = time.monotonic()
        wait = _MIN_REQUEST_INTERVAL - (now - _LAST_REQUEST_AT)
        if wait > 0:
            time.sleep(wait)
        _LAST_REQUEST_AT = time.monotonic()


class HuaweiHealthError(Exception):
    """业务/网络错误。"""


class AuthExpired(HuaweiHealthError):
    """401 —— 登录态失效，需要重新走认证。"""


def _fmt_day(value) -> str:
    s = str(value)
    if len(s) == 8 and s.isdigit():
        return "%s-%s-%s" % (s[:4], s[4:6], s[6:8])
    return s


def _parse_stats(raw: dict) -> dict:
    """把 periodStatistics 的 results + groupResults 压成 {overall, daily}。"""
    # TODO(v0.3.1)：为纯解析函数补充 fixture 单测，覆盖字段漂移和异常响应。
    overall = {}
    for item in raw.get("results") or []:
        fn = item.get("fieldName")
        if fn and fn != "any":
            overall[fn] = item.get("statistics") or {}
    daily = {}
    for grp in raw.get("groupResults") or []:
        for item in grp.get("groupStatistics") or []:
            day = _fmt_day(item.get("startDay"))
            fn = item.get("fieldName")
            if not day or not fn or fn == "any":
                continue
            daily.setdefault(day, {})[fn] = item.get("statistics") or {}
    return {"overall": overall, "daily": [{"day": d, **v} for d, v in sorted(daily.items())]}


def _day_window(days: int):
    days = max(1, min(int(days), 730))
    # TODO(v0.3.1)：显式使用 Asia/Shanghai 日历，当前契约仍固定传 +0800。
    today = datetime.date.today()
    start = today - datetime.timedelta(days=days - 1)
    return start.strftime("%Y%m%d"), today.strftime("%Y%m%d")


class HuaweiHealthClient:
    """只读客户端。"""

    def __init__(self, token: str, client_id: str = "", version: str = "", timeout: int = 25):
        self.token = token
        self.client_id = client_id or DEFAULT_CLIENT_ID
        self.version = version or DEFAULT_VERSION
        self.timeout = timeout
        # 复用 TCP/TLS 连接，降低总览接口连续请求的延迟和连接开销。
        self.session = requests.Session()

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
            raise HuaweiHealthError("HTTP %d: %s" % (resp.status_code, resp.text[:200]))
        try:
            return resp.json()
        except Exception:
            raise HuaweiHealthError("响应不是 JSON: %s" % resp.text[:200])

    def _request(self, method: str, path: str, *, params=None, body=None):
        """发起一次有限重试的请求；401 交给上层只做一次重认证。"""
        for attempt in range(MAX_RETRIES + 1):
            try:
                _throttle_request()
                if method == "GET":
                    resp = self.session.get(
                        BASE + path,
                        headers=self._headers(),
                        params=params,
                        timeout=self.timeout,
                    )
                else:
                    resp = self.session.post(
                        BASE + path,
                        headers=self._headers(json_body=True),
                        json=body,
                        timeout=self.timeout,
                    )
            except requests.RequestException:
                if attempt >= MAX_RETRIES:
                    raise
                time.sleep(0.5 * (2 ** attempt))
                continue

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
                    time.sleep(delay)
                    continue
            return self._handle(resp)
        raise HuaweiHealthError("华为接口重试次数耗尽")

    def _get(self, path: str, params=None):
        return self._request("GET", path, params=params)

    def _post(self, path: str, body: dict):
        return self._request("POST", path, body=body)

    # ---------- 统计类 ----------

    @staticmethod
    def _stats_body(data_type: str, start_day, end_day, field_names=None) -> dict:
        req = {
            "dataType": data_type,
            "startDay": start_day,
            "endDay": end_day,
            "strategy": list(STRATEGY),
            "groupOption": "day",
            "timeZone": "+0800",
        }
        if field_names:
            req["fieldNames"] = list(field_names)
        return {"reqs": [dict(req)], "groupReqs": [dict(req)]}

    # ---------- 对外工具 ----------

    def basic_infos(self) -> dict:
        return self._get("/user/basicInfos")

    def resting_heart_rate(self, days: int = 7) -> dict:
        """静息心率（sampleSet 端点，startDay/endDay 用数字，fieldName=restBpm）。"""
        s, e = _day_window(days)
        raw = self._post("/sampleSet/periodStatistics:calculate",
                         self._stats_body(RESTING_HR_TYPE, int(s), int(e)))
        return _parse_stats(raw)

    def hrv_stats(self, days: int = 7) -> dict:
        """睡眠 HRV（healthRecords 端点，startDay/endDay 用字符串）。"""
        s, e = _day_window(days)
        raw = self._post("/healthRecords/periodStatistics:calculate",
                         self._stats_body(SLEEP_TYPE, s, e, [HRV_FIELD]))
        return _parse_stats(raw)

    def sleep_records(self, days: int = 7) -> list:
        """睡眠明细（GET /healthRecords，纳秒窗口）。"""
        # TODO(v0.3.1)：按 startTime 排序并按睡眠夜晚语义取最近记录。
        days = max(1, min(int(days), 730))
        now = datetime.datetime.now()
        start = now - datetime.timedelta(days=days)
        raw = self._get("/healthRecords", params={
            "dataType": SLEEP_TYPE,
            "startTime": int(start.timestamp() * 1_000_000_000),
            "endTime": int(now.timestamp() * 1_000_000_000),
        })
        if isinstance(raw, dict):
            return raw.get("healthRecords") or []
        if isinstance(raw, list):
            return raw
        return []

    def activities(self, days: int = 30, limit: int = 20) -> list:
        """运动记录列表（毫秒窗口）。"""
        days = max(1, min(int(days), 730))
        now_ms = int(datetime.datetime.now().timestamp() * 1000)
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
        if isinstance(raw, list):
            return raw
        return []

    def athletic_performance(self) -> dict:
        """最新运动能力评估（跑力 / 预测成绩）。注意 timeZone 是必填参数。"""
        return self._get("/athleticPerformance/latest", params={"timeZone": "+0800"})

    def personal_bests(self, activity_type: str = "running") -> dict:
        """个人纪录。"""
        return self._get("/sportReports", params={"activityType": activity_type})

    def stress_stats(self, days: int = 7) -> dict:
        """压力（stressScore，sampleSet 端点）。"""
        s, e = _day_window(days)
        raw = self._post("/sampleSet/periodStatistics:calculate",
                         self._stats_body(STRESS_TYPE, int(s), int(e)))
        return _parse_stats(raw)

    def body_weight(self, days: int = 365) -> dict:
        """体重（bodyWeight，sampleSet 端点）。"""
        s, e = _day_window(days)
        raw = self._post("/sampleSet/periodStatistics:calculate",
                         self._stats_body(WEIGHT_TYPE, int(s), int(e)))
        return _parse_stats(raw)

    def heart_rate_zones(self) -> dict:
        """储备心率区间阈值（GET /sampleConfigs）。"""
        raw = self._get("/sampleConfigs", params={
            "type": HR_ZONE_CONFIG_TYPE, "id": HR_ZONE_CONFIG_ID})
        # TODO(v0.3.1)：核实华为端区间字段的真实语义和上下界，避免仅凭字段名推断顺序。
        for item in (raw.get("sampleConfigs") or []):
            cfg = item.get("configData")
            if not cfg:
                continue
            try:
                data = json.loads(cfg)
            except Exception:
                continue
            hr = data.get("mOtherHeartRateData") or {}
            if not hr:
                continue
            return {
                "rest": hr.get("mRestHeartRate"),
                "max": hr.get("mMaxThreshold"),
                "warm_up": hr.get("mWarmUpThreshold"),
                "fat_burn": hr.get("mFatBurnThreshold"),
                "aerobic_base": hr.get("mAerobicBaseThreshold"),
                "aerobic": hr.get("mAerobicThreshold"),
                "aerobic_advance": hr.get("mAerobicAdvanceThreshold"),
                "lactic_acid": hr.get("mLacticAcidThreshold"),
                "anaerobic_base": hr.get("mAnaerobicBaseThreshold"),
                "anaerobic": hr.get("mAnaerobicThreshold"),
                "anaerobic_advance": hr.get("mAnaerobicAdvanceThreshold"),
            }
        return {}
