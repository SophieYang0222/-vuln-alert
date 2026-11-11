# 資安漏洞儀表板 + LINE 警訊 (Vulnerability Dashboard & Alerts)

Every 30 minutes a GitHub Action checks the sources below, keeps a running history, and publishes a **dashboard on GitHub Pages**. LINE alerts are optional.

| Source | Why it's worth your attention |
|---|---|
| **NICS 漏洞警訊公告** | Taiwan's official high-risk vulnerability alerts (from the NICS RSS feed) |
| **NICS 漏洞警示新聞** | NICS vendor advisories and weekly KEV digests |
| **TWCERT/CC TVN** | CVEs in Taiwanese products (ASUS, D-Link, Zyxel, local enterprise software…) |
| **CISA KEV** | Vulnerabilities confirmed as exploited in the wild, the "patch now" list |
| **Cloudflare Zero Wire** | Plain-language briefings on critical internet-facing vulnerabilities: what happened and what to do now. "Needs attention" briefings count as 🔴 |
| TWCERT/CC 資安新聞 | General security news (off by default; enable with `SOURCES=…,twcert_news`) |

## What the dashboard shows

- **Headline numbers**: exploited vulnerabilities added in the last 30 days (vs the 30 before), ransomware-linked ones in the last 90 days, NICS alerts in the last 30 days, and watchlist hits.
- **Weekly trend** over 26 weeks for NICS, KEV and TVN. Hover to see a week's numbers. The current week is drawn dashed because it isn't over yet.
- **Most-exploited vendors** in the last 180 days, from KEV.
- **Taiwan-flagged and exploited**: NICS/TVN announcements whose CVE is already in CISA KEV, or that say the vulnerability is already being exploited.
- **Cloudflare Zero Wire briefings**: the latest briefings, "Needs attention" first, each with its recommended action. Any NICS, TVN or KEV item about the same CVE gets a **Cloudflare 簡報 ↗** link to the briefing.
- **Likely to be exploited (EPSS)**: recent Taiwan notices and Zero Wire briefings that are *not yet* exploited, ranked by their EPSS score, the FIRST.org estimate of the chance of exploitation in the next 30 days. The full list has an EPSS column and can be sorted by it.
- **Full list** with filters for time range, source, exploited only and watchlist only, plus search by title, vendor or CVE.
- **Source health**: a red chip appears when a source failed on the last run.

"已遭利用" (exploited) means the item is in CISA KEV, or the official announcement says it is being exploited. Vendor names are guessed from titles and may occasionally be wrong.

---

## Setup

### 1. Put the files on GitHub
1. Create a repository at <https://github.com/new>.
   - **The dashboard is public by default.** A GitHub Pages site can be opened by anyone with the link, even when the repo is private, unless your organization uses **GitHub Enterprise Cloud** and sets the site to private (see step 5). On a free account the repo must also be public. That is fine for this project: the vulnerability data is public anyway, secrets such as the LINE token are never shown, and your watchlist is kept out of everything published (step 5).
2. Click **uploading an existing file** and drag in `vuln_alert.py`, `requirements.txt`, `watchlist.txt`, `README.md` and `.gitignore`. Commit.
3. Click **Add file → Create new file**, name it `docs/index.html`, paste in the contents of `docs\index.html`, and commit.
4. Click **Add file → Create new file**, name it `.github/workflows/vuln-alert.yml`, paste in the contents of that file, and commit.

### 2. Turn on GitHub Pages
Go to **Settings → Pages → Build and deployment → Source** and choose **GitHub Actions**.

### 3. First run
Go to the **Actions** tab, select **vuln-alert**, and click **Run workflow**. When it finishes (about 3 minutes), click the run: the dashboard link is shown under **Publish dashboard**, and it is also on the Settings → Pages screen. It looks like `https://<your-account>.github.io/<repo>/`.

On this first run the dashboard fills with everything currently in the feeds, including the full KEV catalog, so it is useful right away. History builds up from there.

### 4. LINE (optional)
- **No LINE**: don't add any LINE secrets. Nothing is sent.
- **LINE for urgent items only**: add the two secrets below, then add a **variable** `LINE_MIN_PRIORITY` = `1`. Only 🔴 exploited/critical items are pushed.
- **LINE for everything new**: add the two secrets and leave out `LINE_MIN_PRIORITY`.

Secrets go under **Settings → Secrets and variables → Actions → New repository secret**:
- `LINE_CHANNEL_ACCESS_TOKEN`: from the LINE Developers console, Messaging API tab, *Channel access token (long-lived)*.
- `LINE_TO`: your user ID from the Basic settings tab (starts with `U`). Add the bot as a friend first, or messages won't arrive.

### 5. Your watchlist (keeping it private)
Your watchlist reveals which vendors and products your company runs, so by default it is **never published**:

- **On the dashboard**: open **我的關注清單** at the top of the page and type your keywords. They are saved only in that browser on that device. Each colleague sets their own, and nothing is uploaded. The 🟠 badges, the 只看關注清單 filter and the watchlist number all use it.
- **For LINE 🟠 alerts**: add a repository **secret** named `WATCHLIST` with comma-separated keywords, for example `Fortinet, FortiOS, Ivanti, Windows, Synology`. Secrets are never shown, even in a public repo. Leave `watchlist.txt` without real product names if the repo is public, because anyone can read that file.

The published `data.json` contains no watchlist information at all. Only flagging items would still give the list away, because anyone could see which vendors get flagged.

**If your dashboard is private** (GitHub Enterprise Cloud with the Pages site set to private, so only people with repo access can open it), you can add a repository **variable** `PUBLISH_WATCHLIST` = `true`. The dashboard then uses the shared list from the secret and `watchlist.txt`, and the browser box is hidden.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **Prepare dashboard** fails with "Get Pages site failed" | Pages isn't enabled: do step 2. |
| **Publish dashboard** fails with a branch protection / environment error | Settings → Environments → `github-pages` → allow your default branch (usually `main`). |
| **Save state** fails | Settings → Actions → General → Workflow permissions → **Read and write permissions**. |
| A source chip is red on the dashboard | That source failed on the last run. One failure is usually a blip. If NICS keeps failing, the site may be blocking GitHub's US servers; run the job on a computer in Taiwan instead (below). |
| `LINE push failed 401` / `400` | Wrong token / wrong user ID, or bot not added as a friend. |

## Running locally instead (e.g. a PC or Raspberry Pi in Taiwan)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
python vuln_alert.py                 # updates docs/data.json + docs/status.json
cd docs && python -m http.server 8000   # dashboard at http://localhost:8000
```

On Windows, run `set PYTHONUTF8=1` first. Opening `docs/index.html` directly as a file won't load the data; use the small web server shown above.

## Settings (environment variables / repo variables)

| Setting | Default | Meaning |
|---|---|---|
| `SOURCES` | `nics,nics_news,tvn,kev,zerowire` | sources to check |
| `LINE_MIN_PRIORITY` | `3` | LINE: `1` only 🔴 exploited, `2` also 🟠 watchlist, `3` all new items |
| `MODE_TVN`, `MODE_KEV`, `MODE_NICS`, `MODE_NICS_NEWS`, `MODE_TWCERT_NEWS` | `all` (`watchlist` for news) | LINE: `watchlist` = only push items matching your watchlist or marked 🔴 |
| `WATCHLIST` (secret) | — | your comma-separated keywords for LINE 🟠 alerts; combined with `watchlist.txt` |
| `PUBLISH_WATCHLIST` | `false` | `true` = show the shared watchlist on the dashboard (only for a private dashboard) |
| `EPSS` | `on` | `off` = don't look up EPSS scores |
| `MODE_ZEROWIRE` | `all` | LINE: `watchlist` = only push Zero Wire briefings matching your watchlist or marked "Needs attention" |
| `NICS_RSS_URL` | `https://www.nics.nat.gov.tw/RSS2.xml` | NICS feed; `off` = read the page with the headless browser |
| `FAIL_ALERT_AFTER` | 3 | consecutive failures before a LINE warning |

`python vuln_alert.py --dry-run` fetches and prints without writing anything. `--discover` shows what the NICS pages load, which helps if their layout changes. `--test-line` sends a test LINE message.

### About EPSS

EPSS scores come from the free FIRST.org API. All tracked CVEs are looked up once a day (Taipei time) and cached in `docs/epss.json`; runs later that day only look up newly seen CVEs. Brand-new CVEs often have no score for a day or two. If the API is unavailable, the dashboard keeps the previous scores and shows a red **FIRST EPSS** marker. EPSS is a probability estimate, not evidence of exploitation.
