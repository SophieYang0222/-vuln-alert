#!/usr/bin/env python3
"""
Vulnerability alert agent -> LINE Messaging API

Sources (toggle with SOURCES env, comma-separated):
  nics       NICS 國家資通安全研究院 漏洞警訊公告  (Vulnerability Alert Announcements)
  nics_news  NICS 漏洞警示新聞                    (Vulnerability Alerts / KEV weekly)
  tvn        TWCERT/CC TVN 台灣漏洞公告           (Taiwan vendor CVEs)
  kev        CISA Known Exploited Vulnerabilities (actively exploited, global)
  twcert_news TWCERT/CC 資安新聞                  (off by default; more noise)

Usage:
  python vuln_alert.py              # normal run (push new items to LINE, or print if LINE not configured)
  python vuln_alert.py --dry-run    # fetch + print, do not push, do not save state
  python vuln_alert.py --discover   # debug the NICS page: print links / JSON endpoints the page loads
  python vuln_alert.py --test-line  # send one test message to LINE
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin

import feedparser
import requests

# ---------------------------------------------------------------- config
TPE = timezone(timedelta(hours=8))
STATE_FILE = Path(os.getenv("STATE_FILE", "state/seen.json"))
WATCHLIST_FILE = Path(os.getenv("WATCHLIST_FILE", "watchlist.txt"))
SOURCES = [s.strip() for s in (os.getenv("SOURCES") or "nics,nics_news,tvn,kev,zerowire").split(",") if s.strip()]
# "all" = notify every new item; "watchlist" = only items matching watchlist (or critical)
SOURCE_MODE = {
    "nics": os.getenv("MODE_NICS", "all"),
    "nics_news": os.getenv("MODE_NICS_NEWS", "all"),
    "tvn": os.getenv("MODE_TVN", "all"),
    "kev": os.getenv("MODE_KEV", "all"),
    "twcert_news": os.getenv("MODE_TWCERT_NEWS", "watchlist"),
    "zerowire": os.getenv("MODE_ZEROWIRE", "all"),
}
# EPSS (FIRST.org): probability a CVE is exploited in the next 30 days. Cached, refreshed once a day.
EPSS_ENABLED = os.getenv("EPSS", "on").strip().lower() not in ("0", "off", "false", "no")
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_FILE = Path(os.getenv("EPSS_FILE", "docs/epss.json"))
DATA_FILE = Path(os.getenv("DATA_FILE", "docs/data.json"))      # dashboard history (committed)
# Publish which items match the watchlist? Keep "false" for a public dashboard: the matches would reveal
# which vendors/products you run. Set "true" only if the dashboard is private (GitHub Enterprise Cloud).
PUBLISH_WATCHLIST = os.getenv("PUBLISH_WATCHLIST", "false").strip().lower() in ("1", "true", "yes")
STATUS_FILE = Path(os.getenv("STATUS_FILE", "docs/status.json"))  # dashboard run status (not committed)
# LINE: 1 = only 🔴 exploited/critical, 2 = also 🟠 watchlist hits, 3 = everything new
LINE_MIN_PRIORITY = int(os.getenv("LINE_MIN_PRIORITY", "3"))
MAX_ITEMS_PER_RUN = int(os.getenv("MAX_ITEMS_PER_RUN", "40"))
FAIL_ALERT_AFTER = int(os.getenv("FAIL_ALERT_AFTER", "3"))  # consecutive failures before warning
KEEP_DAYS = int(os.getenv("KEEP_DAYS", "120"))

LINE_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "").strip()
LINE_TO = os.getenv("LINE_TO", "").strip()  # your userId (U...), or a groupId (C...)
LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push"
LINE_TEXT_LIMIT = 5000

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")

URLS = {
    "nics": "https://www.nics.nat.gov.tw/core_business/information_security_information_sharing/Vulnerability_Alert_Announcements/",
    "nics_news": "https://www.nics.nat.gov.tw/core_business/information_security_information_sharing/Vulnerability_Alerts/",
    "tvn": "https://www.twcert.org.tw/tw/rss-132-1.xml",
    "twcert_news": "https://www.twcert.org.tw/tw/rss-104-1.xml",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "zerowire": "https://radar.cloudflare.com/security/zero-wire/rss",
}
# NICS's official RSS for 漏洞警訊公告 (from https://www.nics.nat.gov.tw/rss_service/).
# Used first; the headless-browser scrape is only a fallback if the feed fails. Set NICS_RSS_URL=off to disable.
NICS_RSS_URL = (os.getenv("NICS_RSS_URL") or "https://www.nics.nat.gov.tw/RSS2.xml").strip()

LABELS = {
    "nics": "NICS 漏洞警訊公告",
    "nics_news": "NICS 漏洞警示新聞",
    "tvn": "TWCERT/CC 台灣漏洞(TVN)",
    "kev": "CISA KEV 已遭利用漏洞",
    "twcert_news": "TWCERT/CC 資安新聞",
    "zerowire": "Cloudflare Zero Wire",
}

HOT = re.compile(r"已遭.{0,6}利用|遭駭客利用|在野|零時差|0-?day|actively exploited|in the wild|勒索", re.I)
VULN_WORDS = re.compile(r"CVE-\d{4}-\d+|漏洞|安全性公告|安全更新|修補|弱點|KEV|vulnerab", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
DATE_RE = re.compile(r"(20\d{2}|1\d{2})[/.\-年](\d{1,2})[/.\-月](\d{1,2})")

log = logging.getLogger("vuln_alert")


# ---------------------------------------------------------------- model
@dataclass
class Item:
    source: str
    id: str
    title: str
    link: str
    date: str = ""
    extra: str = ""
    priority: int = 3          # 1 critical, 2 watchlist hit, 3 normal
    matches: list[str] = field(default_factory=list)
    vendor: str = ""
    product: str = ""
    due: str = ""
    ransomware: bool = False
    status: str = ""           # Zero Wire: "Needs attention" / "Reference"
    action: str = ""           # Zero Wire: recommended action, e.g. "Prioritize patching."
    tags: list[str] = field(default_factory=list)


def norm_date(text: str) -> str:
    """Find a date in text; ROC years (e.g. 115) converted to AD."""
    m = DATE_RE.search(text or "")
    if not m:
        return ""
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if y < 1000:
        y += 1911
    try:
        return datetime(y, mo, d).strftime("%Y-%m-%d")
    except ValueError:
        return ""


def http_get(url: str, timeout: int = 30) -> requests.Response:
    r = requests.get(url, headers={"User-Agent": UA, "Accept-Language": "zh-TW,zh;q=0.9,en;q=0.8"},
                     timeout=timeout)
    r.raise_for_status()
    return r


# ---------------------------------------------------------------- fetchers
def parse_rss(content: bytes, source: str) -> list[Item]:
    feed = feedparser.parse(content)
    items = []
    for e in feed.entries:
        title = (e.get("title") or "").strip()
        link = (e.get("link") or "").strip()
        if not title:
            continue
        date = ""
        for key in ("published_parsed", "updated_parsed"):
            if e.get(key):
                date = datetime(*e[key][:6]).strftime("%Y-%m-%d")
                break
        if not date:
            date = norm_date(e.get("published", "") or e.get("updated", ""))
        summary = re.sub(r"<[^>]+>", " ", e.get("summary", "") or "")
        items.append(Item(source, (e.get("id") or link or title).strip(), title, link, date,
                          re.sub(r"\s+", " ", summary)[:300]))
    return items


def fetch_rss(url: str, source: str) -> list[Item]:
    items = parse_rss(http_get(url).content, source)
    if not items:
        raise RuntimeError(f"RSS returned 0 items: {url}")
    return items


def parse_kev(data: dict) -> list[Item]:
    items = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID", "")
        name = v.get("vulnerabilityName") or f"{v.get('vendorProject','')} {v.get('product','')}"
        ransom = " ⚠勒索軟體利用" if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else ""
        extra = f"{v.get('vendorProject','')} {v.get('product','')} | CISA修補期限 {v.get('dueDate','')}{ransom}"
        items.append(Item("kev", cve, f"{cve} {name}", f"https://nvd.nist.gov/vuln/detail/{cve}",
                          v.get("dateAdded", ""), extra, vendor=v.get("vendorProject", "").strip(),
                          product=v.get("product", "").strip(), due=v.get("dueDate", ""),
                          ransomware=bool(ransom)))
    return items


def fetch_kev() -> list[Item]:
    items = parse_kev(http_get(URLS["kev"], timeout=60).json())
    if not items:
        raise RuntimeError("KEV feed empty")
    return items


ZW_STATUSES = ("needs attention", "reference")
SENTENCE_END = re.compile(r"(?<=[.!?。！？])\s")


def parse_zerowire(content: bytes) -> list[Item]:
    """Cloudflare Radar Zero Wire RSS. Status + CVEs + tags arrive as <category>; the description opens with
    the recommended action. The guid embeds the update date (slug@YYYY-MM-DD), so track briefings by link."""
    feed = feedparser.parse(content)
    items = []
    for e in feed.entries:
        title = (e.get("title") or "").strip()
        link = (e.get("link") or "").strip()
        if not title or not link:
            continue
        cats = [(t.get("term") or "").strip() for t in e.get("tags", []) if (t.get("term") or "").strip()]
        status = next((c for c in cats if c.lower() in ZW_STATUSES), "")
        cves = sorted({c.upper() for c in cats if CVE_RE.fullmatch(c)} |
                      {c.upper() for c in CVE_RE.findall(title)})
        tags = [c for c in cats if c != status and not CVE_RE.fullmatch(c)]
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", e.get("summary", "") or "")).strip()
        action = SENTENCE_END.split(text, 1)[0][:120] if text else ""
        date = ""
        for key in ("published_parsed", "updated_parsed"):
            if e.get(key):
                date = datetime(*e[key][:6]).strftime("%Y-%m-%d")
                break
        items.append(Item("zerowire", link.rstrip("/"), title, link, date,
                          extra=" ".join([action] + cves), status=status, action=action, tags=tags[:6]))
    return items


def fetch_zerowire() -> list[Item]:
    items = parse_zerowire(http_get(URLS["zerowire"]).content)
    if not items:
        raise RuntimeError("Zero Wire RSS returned 0 items")
    return items


def extract_items_from_anchors(anchors: list[dict], source: str, page_url: str) -> list[Item]:
    """Heuristic: keep links whose text looks like a vulnerability announcement title."""
    items, seen = [], set()
    for a in anchors:
        text = re.sub(r"\s+", " ", a.get("text") or "").strip()
        href = (a.get("href") or "").strip()
        if len(text) < 12 or not VULN_WORDS.search(text):
            continue
        if not href or href.startswith(("javascript:", "mailto:")) or href.rstrip("/") == page_url.rstrip("/"):
            continue
        href = urljoin(page_url, href)
        if href in seen:
            continue
        seen.add(href)
        ctx = a.get("ctx") or ""
        # title text often contains the date at the end; strip it for a clean title
        title = DATE_RE.sub("", text).strip(" -|") or text
        items.append(Item(source, href, title, href, norm_date(text) or norm_date(ctx)))
    return items


def extract_items_from_json(payloads: list[tuple[str, object]], source: str, page_url: str) -> list[Item]:
    """Fallback: walk JSON responses captured while the page loaded, look for a list of announcement records."""
    title_keys = ("title", "subject", "name", "caption", "Title", "Subject", "Name")
    id_keys = ("id", "seq", "Id", "ID", "Seq", "sn", "uuid", "guid")
    date_keys = ("date", "publishDate", "publish_date", "postDate", "createDate", "createdAt",
                 "releaseDate", "startDate", "PublishDate", "Date")
    best: list[Item] = []

    def walk(obj):
        nonlocal best
        if isinstance(obj, list) and obj and all(isinstance(x, dict) for x in obj):
            found = []
            for rec in obj:
                t = next((str(rec[k]) for k in title_keys if rec.get(k)), "")
                if not t or not VULN_WORDS.search(t):
                    continue
                rid = next((str(rec[k]) for k in id_keys if rec.get(k)), t)
                d = next((str(rec[k]) for k in date_keys if rec.get(k)), "")
                link = next((str(rec[k]) for k in ("url", "link", "href", "Url", "Link") if rec.get(k)), "")
                found.append(Item(source, f"json:{rid}", t.strip(), urljoin(page_url, link) if link else page_url,
                                  norm_date(d) or d[:10]))
            if len(found) > len(best):
                best = found
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    for _, data in payloads:
        walk(data)
    return best


def render_page(url: str, discover: bool = False) -> tuple[list[dict], list[tuple[str, object]]]:
    from playwright.sync_api import sync_playwright

    payloads: list[tuple[str, object]] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(user_agent=UA, locale="zh-TW")

        def on_response(resp):
            if "json" in (resp.headers.get("content-type") or ""):
                try:
                    payloads.append((resp.url, resp.json()))
                except Exception:
                    pass

        page.on("response", on_response)
        # Don't wait for "networkidle": the NICS site keeps background requests open, so it never goes idle.
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=60_000)
        except Exception as e:  # slow page: still try to read whatever has rendered
            log.warning("page load slow (%s), continuing", str(e).splitlines()[0][:120])
        try:  # wait until the "Loading..." shell has been replaced by real announcement links
            page.wait_for_function(
                "() => [...document.querySelectorAll('a')].filter(a => /CVE-|漏洞|KEV|Vulnerab|安全性公告/i.test(a.innerText)).length >= 3",
                timeout=40_000)
        except Exception:
            log.warning("announcement links did not appear within 40s on %s", url)
        page.wait_for_timeout(2000)
        anchors = page.eval_on_selector_all(
            "a",
            """els => els.map(a => {
                 const box = a.closest('li,tr') || a.parentElement || a;
                 return {href: a.getAttribute('href') || '', text: a.innerText || a.title || '',
                         ctx: (box.innerText || '').slice(0, 400)};
               })""")
        browser.close()
    if discover:
        print(f"\n=== {url}\n--- JSON responses captured ({len(payloads)}):")
        for u, _ in payloads:
            print("  ", u)
        print(f"--- anchors ({len(anchors)}), showing vulnerability-looking ones:")
        for a in anchors:
            if VULN_WORDS.search(a.get("text") or ""):
                print(f"   {a['text'][:90]!r} -> {a['href']}")
    return anchors, payloads


def fetch_nics(source: str, discover: bool = False) -> list[Item]:
    url = URLS[source]
    if source == "nics" and NICS_RSS_URL.lower() != "off" and not discover:
        try:
            return fetch_rss(NICS_RSS_URL, source)
        except Exception as e:
            log.warning("[nics] RSS failed (%s), falling back to rendering the page", e)
    anchors, payloads = render_page(url, discover)
    items = extract_items_from_anchors(anchors, source, url)
    if not items:
        items = extract_items_from_json(payloads, source, url)
    if not items:
        raise RuntimeError(f"No announcements found on rendered page {url} "
                           f"(site may block this network or layout changed; try --discover)")
    return items


def fetch(source: str) -> list[Item]:
    if source in ("nics", "nics_news"):
        return fetch_nics(source)
    if source == "kev":
        return fetch_kev()
    if source == "zerowire":
        return fetch_zerowire()
    if source in ("tvn", "twcert_news"):
        return fetch_rss(URLS[source], source)
    raise ValueError(f"unknown source {source}")


# ---------------------------------------------------------------- classify
def load_watchlist() -> list[str]:
    words = []
    env = os.getenv("WATCHLIST", "")
    words += [w.strip() for w in env.split(",") if w.strip()]
    if WATCHLIST_FILE.exists():
        for line in WATCHLIST_FILE.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                words.append(line)
    return sorted(set(words), key=str.lower)


def classify(item: Item, watch: list[str]) -> Item:
    hay = f"{item.title} {item.extra} {' '.join(item.tags)}".lower()
    item.matches = [w for w in watch if w.lower() in hay]
    zw_urgent = item.source == "zerowire" and item.status.lower() == "needs attention"
    if item.source == "kev" or zw_urgent or HOT.search(f"{item.title} {item.extra}"):
        item.priority = 1
    elif item.matches:
        item.priority = 2
    else:
        item.priority = 3
    return item


def wanted(item: Item) -> bool:
    return SOURCE_MODE.get(item.source, "all") == "all" or item.priority <= 2


# ---------------------------------------------------------------- state
def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("state file corrupt, starting fresh")
    return {"seen": {}, "errors": {}}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")


def prune(state: dict, current_ids: dict[str, set[str]]) -> None:
    cutoff = (datetime.now(TPE) - timedelta(days=KEEP_DAYS)).isoformat()
    for src, seen in state["seen"].items():
        live = current_ids.get(src)
        if live is None:  # source failed this run: don't prune
            continue
        state["seen"][src] = {k: v for k, v in seen.items() if k in live or v >= cutoff}


# ---------------------------------------------------------------- dashboard data
VENDOR_ALIASES = {
    "微軟": "Microsoft", "microsoft": "Microsoft", "谷歌": "Google", "google": "Google",
    "思科": "Cisco", "cisco": "Cisco", "蘋果": "Apple", "apple": "Apple", "甲骨文": "Oracle",
    "oracle": "Oracle", "華碩": "ASUS", "asus": "ASUS", "友訊": "D-Link", "d-link": "D-Link",
    "合勤": "Zyxel", "zyxel": "Zyxel", "群暉": "Synology", "synology": "Synology",
    "威聯通": "QNAP", "qnap": "QNAP", "fortinet": "Fortinet", "ivanti": "Ivanti",
    "palo": "Palo Alto Networks", "paloalto": "Palo Alto Networks", "vmware": "VMware",
    "citrix": "Citrix", "adobe": "Adobe", "mozilla": "Mozilla", "linux": "Linux",
    "f5": "F5", "sonicwall": "SonicWall", "juniper": "Juniper", "gitlab": "GitLab",
    "atlassian": "Atlassian", "samsung": "Samsung", "android": "Google", "chrome": "Google",
    "windows": "Microsoft", "tp-link": "TP-Link", "tplink": "TP-Link",
}
LATIN_WORD = re.compile(r"[A-Za-z][A-Za-z0-9.\-]*")


def canonical_vendor(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    for k, v in VENDOR_ALIASES.items():
        if raw.lower().startswith(k):
            return v
    return raw


def guess_vendor(it: Item) -> str:
    if it.vendor:
        return canonical_vendor(it.vendor)
    if it.source == "zerowire":  # briefing titles are nicknames ("php2shell"); the first tag is the technology
        return canonical_vendor(it.tags[0]) if it.tags else ""
    t = it.title.strip()
    if it.source in ("tvn",):
        head = re.split(r"[｜|]", t, 1)[0] if re.search(r"[｜|]", t) else t.split(" - ")[0]
    else:
        head = re.split(r"存在|釋出|發布|針對|修補", t, 1)[0]
    head = head.strip(" 【】[]")
    for k, v in VENDOR_ALIASES.items():
        if k in head.lower()[:20]:
            return v
    m = LATIN_WORD.search(head)
    if m:
        return canonical_vendor(m.group(0))
    return head[:8]


def _epss_batches(cves: list[str], max_chars: int = 1900) -> list[list[str]]:
    """The FIRST API caps the cve= parameter at 2000 characters (commas included)."""
    batches, cur, size = [], [], 0
    for c in cves:
        if cur and size + len(c) + 1 > max_chars:
            batches.append(cur)
            cur, size = [], 0
        cur.append(c)
        size += len(c) + 1
    if cur:
        batches.append(cur)
    return batches


def fetch_epss(cves: list[str]) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {}
    for batch in _epss_batches(cves):
        r = requests.get(EPSS_URL, params={"cve": ",".join(batch), "limit": len(batch) + 10},
                         headers={"User-Agent": UA}, timeout=30)
        r.raise_for_status()
        for d in r.json().get("data", []):
            try:
                out[d["cve"].upper()] = [round(float(d["epss"]), 4), round(float(d["percentile"]), 3)]
            except (KeyError, TypeError, ValueError):
                continue
    return out


def refresh_epss(cves: set[str]) -> tuple[dict[str, list[float]], dict]:
    """Return {cve: [epss, percentile]} from docs/epss.json, refreshing all scores once per (Taipei) day and
    looking up CVEs that are new since the last refresh. Failures keep the previous scores."""
    today = datetime.now(TPE).strftime("%Y-%m-%d")
    cache = {"date": "", "scores": {}, "none": []}
    if EPSS_FILE.exists():
        try:
            cache.update(json.loads(EPSS_FILE.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            log.warning("epss cache unreadable, refetching")
    scores: dict[str, list[float]] = cache.get("scores", {})
    status = {"enabled": EPSS_ENABLED, "ok": True, "date": cache.get("date", ""), "error": ""}
    if not EPSS_ENABLED or not cves:
        status["count"] = len(scores)
        return scores, status

    full = cache.get("date") != today
    unscored_today = set(cache.get("none", [])) if not full else set()
    want = sorted(cves) if full else sorted(c for c in cves if c not in scores and c not in unscored_today)
    if want:
        try:
            got = fetch_epss(want)
            if full:
                scores = {c: v for c, v in scores.items() if c in cves}  # drop CVEs no longer tracked
            scores.update(got)
            none = sorted(unscored_today | {c for c in want if c not in got})  # e.g. too new to be scored
            new_date = today if full else cache.get("date", today)
            EPSS_FILE.parent.mkdir(parents=True, exist_ok=True)
            EPSS_FILE.write_text(json.dumps({"date": new_date, "scores": scores, "none": none},
                                            sort_keys=True, separators=(",", ":")), encoding="utf-8")
            status["date"] = new_date
            log.info("EPSS: looked up %d CVEs, %d scored%s", len(want), len(got), " (daily refresh)" if full else "")
        except Exception as e:
            status.update(ok=False, error=str(e)[:200])
            log.error("EPSS lookup failed, keeping previous scores: %s", e)
    status["count"] = len(scores)
    return scores, status


def update_dashboard(fetched: dict[str, list[Item]], watch: list[str], errors: dict[str, int],
                     error_msgs: dict[str, str], now_iso: str) -> None:
    """Merge this run's items into docs/data.json (history) and write docs/status.json (run health)."""
    store: dict[str, dict] = {}
    if DATA_FILE.exists():
        try:
            for rec in json.loads(DATA_FILE.read_text(encoding="utf-8")).get("items", []):
                store[f"{rec['source']}|{rec['id']}"] = rec
        except (json.JSONDecodeError, KeyError):
            log.warning("dashboard data file unreadable, rebuilding")

    for src, items in fetched.items():
        for it in items:
            key = f"{src}|{it.id}"
            rec = store.get(key, {"first_seen": now_iso[:10]})
            cves = sorted({c.upper() for c in CVE_RE.findall(f"{it.id} {it.title} {it.extra}")})
            rec.update({"source": src, "id": it.id, "title": it.title, "link": it.link,
                        "date": it.date or rec.get("date") or rec["first_seen"], "cves": cves,
                        "vendor": guess_vendor(it), "product": it.product, "due": it.due,
                        "ransomware": it.ransomware})
            if src == "zerowire":
                rec.update({"status": it.status, "action": it.action, "tags": it.tags})
            store[key] = rec

    kev_cves = {r["id"].upper() for r in store.values() if r["source"] == "kev"}
    # CVE -> newest Zero Wire briefing, to link plain-language briefings from NICS/TVN/KEV items
    zw_by_cve: dict[str, dict] = {}
    for r in sorted((r for r in store.values() if r["source"] == "zerowire"), key=lambda r: r["date"]):
        for c in r.get("cves", []):
            zw_by_cve[c] = {"t": r["title"], "u": r["link"], "s": r.get("status", "")}
    epss, epss_status = refresh_epss({c for r in store.values() for c in r.get("cves", [])})

    for rec in store.values():
        text = f"{rec['title']} {rec.get('vendor','')} {rec.get('product','')} {' '.join(rec.get('tags', []))}"
        zw = next((zw_by_cve[c] for c in rec.get("cves", []) if c in zw_by_cve), None)
        if zw and rec["source"] != "zerowire":
            rec["zw"] = zw
        else:
            rec.pop("zw", None)
        scored = [epss[c] for c in rec.get("cves", []) if c in epss]
        if scored:
            best = max(scored)
            rec["epss"], rec["epss_pct"] = best[0], best[1]
        else:
            rec.pop("epss", None)
            rec.pop("epss_pct", None)
        if PUBLISH_WATCHLIST:
            rec["watch"] = [w for w in watch if w.lower() in text.lower()]
        else:
            rec.pop("watch", None)
        in_kev = [c for c in rec.get("cves", []) if c in kev_cves]
        if rec["source"] == "kev":
            rec["exploited"], rec["why"] = True, "CISA KEV"
        elif in_kev:
            rec["exploited"], rec["why"] = True, "列於 CISA KEV: " + ", ".join(in_kev)
        elif HOT.search(f"{rec['title']} {rec.get('action', '')}"):
            rec["exploited"], rec["why"] = True, "公告指出已遭利用"
        else:
            rec["exploited"], rec["why"] = False, ""

    items = sorted(store.values(), key=lambda r: (r["date"], r["source"], r["id"]), reverse=True)
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"items": items, "watchlist": watch if PUBLISH_WATCHLIST else None}
    DATA_FILE.write_text(json.dumps(payload, ensure_ascii=False,
                                    sort_keys=True, separators=(",", ":")), encoding="utf-8")
    status = {"generated": now_iso,
              "sources": [{"key": s, "label": LABELS.get(s, s), "url": URLS.get(s, ""),
                           "ok": s in fetched, "fail_count": errors.get(s, 0),
                           "error": error_msgs.get(s, ""),
                           "count": sum(1 for r in items if r["source"] == s)} for s in SOURCES],
              "epss": epss_status}
    STATUS_FILE.write_text(json.dumps(status, ensure_ascii=False, indent=1), encoding="utf-8")
    log.info("dashboard data: %d items -> %s", len(items), DATA_FILE)


# ---------------------------------------------------------------- messages
ICON = {1: "🔴", 2: "🟠", 3: "🔵"}


def format_item(it: Item) -> str:
    line = f"{ICON[it.priority]} {it.title}"
    detail = it.extra if it.source == "kev" else ""
    if it.source == "zerowire":
        cves = ", ".join(CVE_RE.findall(it.extra)[:3])
        detail = " | ".join(x for x in (it.status, it.action, cves) if x)
    meta = " | ".join(x for x in (it.date, detail) if x)
    if it.matches:
        meta = (meta + " | " if meta else "") + "命中: " + ", ".join(it.matches)
    out = line + (f"\n   {meta}" if meta else "")
    if it.link:
        out += f"\n   {it.link}"
    return out


def build_messages(items: list[Item], notices: list[str]) -> list[str]:
    now = datetime.now(TPE).strftime("%Y-%m-%d %H:%M")
    items = sorted(items, key=lambda i: (i.priority, i.source, i.date), reverse=False)
    shown, hidden = items[:MAX_ITEMS_PER_RUN], len(items) - MAX_ITEMS_PER_RUN
    n_crit = sum(1 for i in items if i.priority == 1)
    if items:
        header = f"🛡️ 資安漏洞警訊 {now}\n新項目 {len(items)} 則" + (f"（🔴 {n_crit} 則需優先處理）" if n_crit else "")
    else:
        header = f"🛡️ 資安警訊機器人 系統通知 {now}"
    blocks = [header]
    for n in notices:
        blocks.append(n)
    current = None
    for it in sorted(shown, key=lambda i: (list(LABELS).index(i.source), i.priority)):
        if it.source != current:
            current = it.source
            blocks.append(f"\n【{LABELS[it.source]}】")
        blocks.append(format_item(it))
    if hidden > 0:
        blocks.append(f"\n…另有 {hidden} 則未列出")
    if items:
        blocks.append("\n🔴 已遭利用/重大  🟠 命中關注清單  🔵 一般")

    # chunk into LINE text messages (<= 5000 chars each, <= 5 per push)
    msgs, buf = [], ""
    for b in blocks:
        piece = (b if not buf else "\n" + b)
        if len(buf) + len(piece) > LINE_TEXT_LIMIT - 50:
            msgs.append(buf)
            buf = b
        else:
            buf += piece
    if buf:
        msgs.append(buf)
    if len(msgs) > 5:
        msgs = msgs[:5]
        msgs[-1] = msgs[-1][: LINE_TEXT_LIMIT - 40] + "\n…(訊息過長已截斷)"
    return msgs


def line_push(texts: list[str]) -> None:
    if not texts:
        return
    if not (LINE_TOKEN and LINE_TO):
        print("\n" + ("\n" + "-" * 40 + "\n").join(texts))
        log.info("LINE not configured (LINE_CHANNEL_ACCESS_TOKEN / LINE_TO): printed to console instead")
        return
    for i in range(0, len(texts), 5):  # one push request = up to 5 message bubbles
        r = requests.post(
            LINE_PUSH_URL,
            headers={"Authorization": f"Bearer {LINE_TOKEN}", "Content-Type": "application/json",
                     "X-Line-Retry-Key": str(uuid.uuid4())},
            json={"to": LINE_TO, "messages": [{"type": "text", "text": t} for t in texts[i:i + 5]]},
            timeout=30)
        if r.status_code >= 400:
            raise RuntimeError(f"LINE push failed {r.status_code}: {r.text[:300]}")
    log.info("pushed %d message(s) to LINE", len(texts))


# ---------------------------------------------------------------- main
def run(dry_run: bool = False) -> int:
    state = load_state()
    state.setdefault("seen", {})
    state.setdefault("errors", {})
    watch = load_watchlist()
    now_iso = datetime.now(TPE).isoformat(timespec="seconds")

    new_items: list[Item] = []
    notices: list[str] = []
    current_ids: dict[str, set[str]] = {}
    pending_seen: dict[str, dict[str, str]] = {}
    fetched: dict[str, list[Item]] = {}
    error_msgs: dict[str, str] = {}

    for src in SOURCES:
        try:
            items = fetch(src)
            fetched[src] = items
        except Exception as e:  # keep going with the other sources
            n = state["errors"].get(src, 0) + 1
            state["errors"][src] = n
            error_msgs[src] = str(e)[:200]
            log.error("[%s] fetch failed (%d in a row): %s", src, n, e)
            if n == FAIL_ALERT_AFTER:
                notices.append(f"⚠️ 來源「{LABELS[src]}」已連續 {n} 次抓取失敗，可能網站改版或封鎖此網路。\n   {str(e)[:150]}")
            continue
        if state["errors"].get(src, 0) >= FAIL_ALERT_AFTER:
            notices.append(f"✅ 來源「{LABELS[src]}」已恢復")
        state["errors"][src] = 0

        current_ids[src] = {i.id for i in items}
        seen = state["seen"].get(src)
        first_run = seen is None
        seen = seen or {}
        fresh = [classify(i, watch) for i in items if i.id not in seen]
        pending_seen[src] = {i.id: now_iso for i in fresh}
        log.info("[%s] %d items, %d new%s", src, len(items), len(fresh), " (baseline)" if first_run else "")
        if first_run:
            notices.append(f"✅ 開始監控「{LABELS[src]}」，已建立基準 {len(items)} 則（不推播舊資料）")
            continue
        new_items += [i for i in fresh if wanted(i) and i.priority <= LINE_MIN_PRIORITY]

    msgs = build_messages(new_items, notices) if (new_items or notices) else []
    if dry_run:
        print("\n".join(msgs) if msgs else "(nothing new)")
        return 0

    try:
        update_dashboard(fetched, watch, state["errors"], error_msgs, now_iso)
    except Exception as e:  # never let the dashboard break the alerts
        log.error("dashboard export failed: %s", e)

    try:
        line_push(msgs)
    except Exception as e:
        log.error("%s — state not saved so items will be retried next run", e)
        return 2

    for src, ids in pending_seen.items():
        state["seen"].setdefault(src, {}).update(ids)
    prune(state, current_ids)
    state.pop("last_run", None)  # keep the committed state stable between quiet runs
    save_state(state)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="fetch and print; no LINE push, no state save")
    ap.add_argument("--discover", action="store_true", help="debug NICS pages: show links and JSON endpoints")
    ap.add_argument("--test-line", action="store_true", help="send a test message to LINE")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if a.test_line:
        line_push([f"✅ 資安警訊機器人連線測試成功 {datetime.now(TPE):%Y-%m-%d %H:%M}"])
        return 0
    if a.discover:
        for src in ("nics", "nics_news"):
            try:
                items = fetch_nics(src, discover=True)
                print(f"--- parsed {len(items)} items, first 5:")
                for i in items[:5]:
                    print(f"   [{i.date}] {i.title[:80]}  ({i.link})")
            except Exception as e:
                print(f"!!! {src}: {e}")
        return 0
    return run(dry_run=a.dry_run)


if __name__ == "__main__":
    sys.exit(main())
