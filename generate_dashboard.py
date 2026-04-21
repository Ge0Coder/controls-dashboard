#!/usr/bin/env python3
"""Controls Engineering Daily Dashboard Generator.

Fetches ICS/automation RSS news and CISA Known Exploited Vulnerabilities,
then uses Claude to produce summaries and a daily fact, rendering everything
as a self-contained index.html suitable for GitHub Pages.
"""

import html as html_mod
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import anthropic
import feedparser

# ── Configuration ─────────────────────────────────────────────────────────────

RSS_FEEDS = [
    {"name": "CISA ICS Advisories",  "url": "https://www.cisa.gov/ics/advisories/advisories.xml"},
    {"name": "SecurityWeek",          "url": "https://feeds.feedburner.com/Securityweek"},
    {"name": "Control Engineering",   "url": "https://www.controleng.com/rss"},
    {"name": "Automation World",      "url": "https://www.automationworld.com/rss.xml"},
    {"name": "SANS ISC",              "url": "https://isc.sans.edu/rssfeed_full.xml"},
]

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
MAX_ITEMS_PER_FEED = 6
KEV_LOOKBACK_DAYS  = 30

# ── Helpers ───────────────────────────────────────────────────────────────────

_TAG_RE = re.compile(r"<[^>]+>")


def strip_tags(text: str) -> str:
    return _TAG_RE.sub("", text).strip()


def text_to_html(text: str) -> str:
    """Escape plain text and wrap double-newline paragraphs in <p> tags."""
    escaped = html_mod.escape(text)
    paras = [p.strip() for p in escaped.split("\n\n") if p.strip()]
    return "".join(
        f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paras
    ) if paras else ""


# ── Data Fetching ─────────────────────────────────────────────────────────────

def fetch_rss_feeds() -> list[dict[str, str]]:
    """Return a flat list of articles from all configured RSS feeds."""
    articles: list[dict[str, str]] = []
    for cfg in RSS_FEEDS:
        try:
            feed = feedparser.parse(cfg["url"])
            for entry in feed.entries[:MAX_ITEMS_PER_FEED]:
                raw = entry.get("summary") or entry.get("description") or ""
                articles.append({
                    "source":    cfg["name"],
                    "title":     strip_tags(entry.get("title", "(no title)")),
                    "link":      entry.get("link", ""),
                    "summary":   strip_tags(raw)[:400],
                    "published": entry.get("published", ""),
                })
        except Exception as exc:
            print(f"  Feed error ({cfg['name']}): {exc}", file=sys.stderr)
    return articles


def fetch_cisa_kev() -> list[dict[str, Any]]:
    """Return CISA KEV entries added within the last KEV_LOOKBACK_DAYS days."""
    try:
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"User-Agent": "controls-dashboard/1.0"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        cutoff = datetime.now(timezone.utc) - timedelta(days=KEV_LOOKBACK_DAYS)
        recent = [
            v for v in data.get("vulnerabilities", [])
            if datetime.strptime(v.get("dateAdded", "1970-01-01"), "%Y-%m-%d")
               .replace(tzinfo=timezone.utc) >= cutoff
        ]
        return sorted(recent, key=lambda v: v.get("dateAdded", ""), reverse=True)
    except Exception as exc:
        print(f"  CISA KEV error: {exc}", file=sys.stderr)
        return []


# ── Claude Integration ────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are an expert assistant for industrial controls and automation engineers, "
    "specialising in ICS/SCADA security, OT, PLCs, DCS, process automation, and "
    "industrial networking. Your audience are practising controls engineers who value "
    "accuracy, brevity, and relevance to their day-to-day work. "
    "Write in plain prose without markdown formatting or bullet points."
)

_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "news_summary": {
            "type": "string",
            "description": (
                "3–5 paragraph digest of the most relevant ICS/OT/automation news, "
                "highlighting anything that directly affects plant floor engineers."
            ),
        },
        "cisa_summary": {
            "type": "string",
            "description": (
                "2–3 paragraph summary of recent CISA KEV entries most relevant to OT "
                "environments, with practical remediation context."
            ),
        },
        "interesting_fact": {
            "type": "string",
            "description": (
                "One interesting, surprising, or underappreciated fact relevant to "
                "controls engineers — 2–4 sentences, suitable for a daily knowledge bite."
            ),
        },
    },
    "required": ["news_summary", "cisa_summary", "interesting_fact"],
    "additionalProperties": False,
}


def summarise_with_claude(
    articles: list[dict[str, str]],
    cisa_vulns: list[dict[str, Any]],
    client: anthropic.Anthropic,
) -> dict[str, str]:
    today = datetime.now(timezone.utc).strftime("%A %d %B %Y")

    news_block = "\n\n".join(
        f"[{a['source']}] {a['title']}\n{a['summary']}"
        for a in articles[:20]
    ) or "No articles available today."

    cisa_block = "\n".join(
        f"- {v.get('cveID', '')} ({v.get('dateAdded', '')}): "
        f"{v.get('vendorProject', '')} / {v.get('product', '')} — "
        f"{v.get('shortDescription', '')[:250]}"
        for v in cisa_vulns[:20]
    ) or "No recent CISA KEV entries."

    user_message = (
        f"Today is {today}.\n\n"
        "## ICS / Automation News\n"
        f"{news_block}\n\n"
        "## CISA Known Exploited Vulnerabilities (last 30 days)\n"
        f"{cisa_block}"
    )

    response = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=4096,
        thinking={"type": "adaptive"},
        system=[{
            "type": "text",
            "text": _SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{"role": "user", "content": user_message}],
        output_config={
            "format": {
                "type": "json_schema",
                "schema": _OUTPUT_SCHEMA,
            }
        },
    )

    text_block = next(
        (b for b in response.content if b.type == "text"), None
    )
    if text_block is None:
        raise RuntimeError("No text block in Claude response")

    return json.loads(text_block.text)


# ── HTML Rendering ────────────────────────────────────────────────────────────

_CSS = """\
:root{--bg:#0d1117;--surf:#161b22;--bord:#30363d;--text:#c9d1d9;--muted:#8b949e;
      --green:#39d353;--amber:#e3b341;--red:#f85149;--link:#58a6ff;--r:6px;
      --mono:"Courier New",monospace;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.6}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
header{background:var(--surf);border-bottom:1px solid var(--bord);padding:14px 24px;
       display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
header h1{font-family:var(--mono);font-size:1rem;letter-spacing:.08em;color:var(--green)}
.ts{font-size:.75rem;color:var(--muted)}
main{max-width:1320px;margin:0 auto;padding:20px 16px;
     display:grid;grid-template-columns:1fr 1fr;gap:20px}
.span2{grid-column:1/-1}
section{background:var(--surf);border:1px solid var(--bord);border-radius:var(--r);overflow:hidden}
.sh{padding:10px 16px;border-bottom:1px solid var(--bord);display:flex;align-items:center;gap:8px}
.sh h2{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dg{background:var(--green)}.da{background:var(--amber)}.dr{background:var(--red)}
.sb{padding:16px}
.ai-text p{margin:.5em 0;font-size:.88rem}
.fact-box{background:#0d2a12;border:1px solid #39d35366;border-radius:var(--r);
          padding:16px;color:var(--green);font-size:.92rem;line-height:1.7}
.fact-box p{margin:.3em 0}
.card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.card{background:var(--bg);border:1px solid var(--bord);border-radius:var(--r);padding:12px}
.badge{display:inline-block;font-size:.68rem;background:#21262d;border:1px solid var(--bord);
       color:var(--muted);padding:2px 7px;border-radius:12px;margin-bottom:5px;font-family:var(--mono)}
.card h3{font-size:.82rem;font-weight:600;line-height:1.4;margin:4px 0}
.pub-date{font-size:.7rem;color:var(--muted);margin-bottom:5px}
.excerpt{font-size:.78rem;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bord);color:var(--muted);
   font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top}
tr:last-child td{border-bottom:none}
.cve{font-family:var(--mono);color:var(--amber);font-size:.76rem;white-space:nowrap}
footer{text-align:center;padding:20px;font-size:.72rem;color:var(--muted);
       border-top:1px solid var(--bord);margin-top:4px}
@media(max-width:768px){main{grid-template-columns:1fr}.span2{grid-column:1}}
"""


def _article_cards(articles: list[dict[str, str]]) -> str:
    e = html_mod.escape
    return "\n".join(
        f'<article class="card">'
        f'<span class="badge">{e(a["source"])}</span>'
        f'<h3><a href="{e(a["link"])}" target="_blank" rel="noopener">{e(a["title"])}</a></h3>'
        f'<p class="pub-date">{e(a.get("published", ""))}</p>'
        f'<p class="excerpt">{e(a["summary"][:240])}…</p>'
        f"</article>"
        for a in articles
    )


def _kev_rows(vulns: list[dict[str, Any]]) -> str:
    e = html_mod.escape
    return "\n".join(
        f"<tr>"
        f'<td><span class="cve">{e(v.get("cveID",""))}</span></td>'
        f"<td>{e(v.get('dateAdded',''))}</td>"
        f"<td>{e(v.get('vendorProject',''))}</td>"
        f"<td>{e(v.get('product',''))}</td>"
        f"<td>{e(v.get('vulnerabilityName','')[:70])}</td>"
        f"</tr>"
        for v in vulns
    )


def render_html(
    articles: list[dict[str, str]],
    cisa_vulns: list[dict[str, Any]],
    summaries: dict[str, str],
    build_time: datetime,
) -> str:
    ts        = build_time.strftime("%Y-%m-%d %H:%M UTC")
    fact_html = text_to_html(summaries.get("interesting_fact", ""))
    news_html = text_to_html(summaries.get("news_summary", ""))
    cisa_html = text_to_html(summaries.get("cisa_summary", ""))
    cards     = _article_cards(articles)
    rows      = _kev_rows(cisa_vulns)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Controls Engineering Daily — {ts}</title>
  <style>{_CSS}</style>
</head>
<body>
<header>
  <h1>&#9881; Controls Engineering Daily</h1>
  <span class="ts">Built {ts} &nbsp;|&nbsp; Powered by Anthropic Claude</span>
</header>

<main>

  <!-- Daily Fact -->
  <div class="span2">
    <section>
      <div class="sh"><span class="dot dg"></span><h2>Today's Fact</h2></div>
      <div class="sb"><div class="fact-box">{fact_html}</div></div>
    </section>
  </div>

  <!-- News Digest -->
  <section>
    <div class="sh"><span class="dot dg"></span><h2>ICS / OT News Digest</h2></div>
    <div class="sb ai-text">{news_html}</div>
  </section>

  <!-- CISA Digest -->
  <section>
    <div class="sh"><span class="dot da"></span><h2>CISA Vulnerability Digest</h2></div>
    <div class="sb ai-text">{cisa_html}</div>
  </section>

  <!-- Raw Feed -->
  <div class="span2">
    <section>
      <div class="sh"><span class="dot dg"></span>
        <h2>Raw Feed &mdash; {len(articles)} articles</h2></div>
      <div class="sb">
        <div class="card-grid">{cards}</div>
      </div>
    </section>
  </div>

  <!-- CISA KEV Table -->
  <div class="span2">
    <section>
      <div class="sh"><span class="dot dr"></span>
        <h2>CISA KEV &mdash; {len(cisa_vulns)} entries in last {KEV_LOOKBACK_DAYS} days</h2></div>
      <div class="sb" style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>CVE</th><th>Date Added</th><th>Vendor</th>
              <th>Product</th><th>Vulnerability</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </section>
  </div>

</main>
<footer>
  Controls Engineering Dashboard &nbsp;&bull;&nbsp; {ts}
  &nbsp;&bull;&nbsp; Summaries by Anthropic Claude
</footer>
</body>
</html>"""


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    print("Fetching RSS feeds…")
    articles = fetch_rss_feeds()
    print(f"  {len(articles)} articles from {len(RSS_FEEDS)} feeds")

    print("Fetching CISA KEV…")
    cisa_vulns = fetch_cisa_kev()
    print(f"  {len(cisa_vulns)} CVEs added in last {KEV_LOOKBACK_DAYS} days")

    print("Calling Claude (claude-opus-4-7)…")
    client = anthropic.Anthropic()
    try:
        summaries = summarise_with_claude(articles, cisa_vulns, client)
    except anthropic.APIError as exc:
        print(f"Claude API error: {exc}", file=sys.stderr)
        sys.exit(1)
    print("  Done")

    build_time = datetime.now(timezone.utc)
    html_content = render_html(articles, cisa_vulns, summaries, build_time)

    out = Path("index.html")
    out.write_text(html_content, encoding="utf-8")
    print(f"Written → {out}  ({len(html_content):,} bytes)")


if __name__ == "__main__":
    main()
