#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Actions 定时任务：抓取银联 CNY/BYN 与 Myfin USD/BYN 汇率，
生成根目录的 rates.json 供静态页面读取（同源，无 CORS 问题）。
仅使用 Python 标准库，无需安装任何依赖。
"""
import datetime
import json
import time
import urllib.request
from pathlib import Path

MSK_TZ = datetime.timezone(datetime.timedelta(hours=3))
UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
)
DESKTOP_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
RATE_URL = "https://m.unionpayintl.com/jfimg/{date}.json"
NBRB_URLS = (
    "https://www.nbrb.by/api/exrates/rates/USD?parammode=2",
    "https://www.nbrb.by/api/exrates/rates?periodicity=0",
)
OUT = Path(__file__).resolve().parent.parent.parent / "rate" / "rates.json"


def http_get(url, ua, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def fetch_unionpay():
    """明斯克时间当天，周末/节假日回退到最近有数据的工作日（最多 10 天）。"""
    today = datetime.datetime.now(MSK_TZ).date()
    errors = []
    for back in range(10):
        day = today - datetime.timedelta(days=back)
        compact = day.strftime("%Y%m%d")
        try:
            payload = json.loads(http_get(RATE_URL.format(date=compact), UA))
            for item in payload.get("exchangeRateJson", []):
                if item.get("transCur") == "BYN" and item.get("baseCur") == "CNY":
                    rate = float(item.get("rateData"))
                    return {
                        "rate": round(rate, 3),
                        "inverse": round(1 / rate, 3),
                        "dataDate": compact,
                        "expression": f"1 BYN = {round(rate,3)} CNY",
                    }
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{compact}: {exc}")
    return {"error": "暂时无法获取银联汇率", "detail": errors[-3:]}


def fetch_myfin():
    """从 Myfin 国际站抓 1 USD = ? BYN。"""
    errors = []
    for url in NBRB_URLS:
        for attempt in range(2):
            try:
                payload = json.loads(http_get(url, DESKTOP_UA, timeout=30))
                if isinstance(payload, list):
                    payload = next(
                        (item for item in payload if item.get("Cur_Abbreviation") == "USD"),
                        None,
                    )
                if not payload or "Cur_OfficialRate" not in payload:
                    raise ValueError("响应中缺少 USD 官方汇率")
                scale = float(payload.get("Cur_Scale", 1)) or 1
                rate = float(payload["Cur_OfficialRate"]) / scale
                quote_date = str(payload.get("Date", ""))[:10]
                return {
                    "rate": round(rate, 3),
                    "inverse": round(1 / rate, 3),
                    "quoteDate": quote_date,
                    "expression": f"1 USD = {round(rate,3)} BYN",
                }
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url}: {exc}")
                time.sleep(2 * (attempt + 1))
    return {"error": f"无法获取 Myfin 数据: {errors[-1]}"}


def main():
    myfin = fetch_myfin()
    if "error" in myfin:
        try:
            previous = json.loads(OUT.read_text(encoding="utf-8")).get("myfin", {})
            if previous.get("rate"):
                myfin = previous
        except Exception:  # noqa: BLE001
            pass
    data = {
        "updatedAt": datetime.datetime.now(MSK_TZ).isoformat(timespec="seconds"),
        "unionpay": fetch_unionpay(),
        "myfin": myfin,
    }
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("rates.json 已更新:", json.dumps(data, ensure_ascii=False))


if __name__ == "__main__":
    main()
