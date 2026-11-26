#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Actions 定时任务：抓取银联 CNY/BYN 与 Myfin USD/BYN 汇率，
生成根目录的 rates.json 供静态页面读取（同源，无 CORS 问题）。
仅使用 Python 标准库，无需安装任何依赖。
"""
import datetime
import json
import re
import urllib.request
from pathlib import Path

BJ_TZ = datetime.timezone(datetime.timedelta(hours=8))
UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
)
DESKTOP_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
RATE_URL = "https://m.unionpayintl.com/jfimg/{date}.json"
MYFIN_URL = "https://myfin.uk/currency-converter/usd-byn"
OUT = Path(__file__).resolve().parent.parent.parent / "rate" / "rates.json"


def http_get(url, ua, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def fetch_unionpay():
    """北京时间当天，周末/节假日回退到最近有数据的工作日（最多 10 天）。"""
    today = datetime.datetime.now(BJ_TZ).date()
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
    try:
        html = http_get(MYFIN_URL, DESKTOP_UA)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"无法获取 Myfin 数据: {exc}"}
    m = re.search(r"today,\s*(\d{4}-\d{2}-\d{2})\s*is\s*([\d.,]+)\s*BYN", html)
    if m:
        quote_date, rate_str = m.group(1), m.group(2)
    else:
        m2 = re.search(r"1 USD\s*=\s*</span>\s*<span[^>]*>\s*([\d.,]+)\s*BYN", html)
        if not m2:
            return {"error": "未能从 Myfin 页面解析出汇率"}
        rate_str = m2.group(1)
        quote_date = datetime.datetime.now(BJ_TZ).strftime("%Y-%m-%d")
    rate = float(rate_str.replace(",", ""))
    return {
        "rate": round(rate, 3),
        "inverse": round(1 / rate, 3),
        "quoteDate": quote_date,
        "expression": f"1 USD = {round(rate,3)} BYN",
    }


def main():
    data = {
        "updatedAt": datetime.datetime.now(BJ_TZ).isoformat(timespec="seconds"),
        "unionpay": fetch_unionpay(),
        "myfin": fetch_myfin(),
    }
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("rates.json 已更新:", json.dumps(data, ensure_ascii=False))


if __name__ == "__main__":
    main()
