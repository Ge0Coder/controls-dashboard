#!/usr/bin/env python3
"""Controls Engineering Daily Dashboard Generator."""

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

# ── Configuration ──────────────────────────────────────────────────────────────

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
VENDORS = ["Siemens", "Rockwell", "Schneider", "ABB", "Honeywell"]

# ── Helpers ────────────────────────────────────────────────────────────────────

_TAG_RE = re.compile(r"<[^>]+>")


def strip_tags(text: str) -> str:
    return _TAG_RE.sub("", text).strip()


def text_to_html(text: str) -> str:
    escaped = html_mod.escape(text)
    paras = [p.strip() for p in escaped.split("\n\n") if p.strip()]
    return "".join(
        f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paras
    ) if paras else ""


def kev_severity(vuln: dict[str, Any]) -> str:
    if vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known":
        return "critical"
    return "high"


def vendor_status(vendor: str, articles: list[dict], cisa_vulns: list[dict]) -> str:
    name_lower = vendor.lower()
    for kev in cisa_vulns:
        kev_text = (kev.get("vendorProject", "") + " " + kev.get("vulnerabilityName", "")).lower()
        if name_lower in kev_text and kev.get("knownRansomwareCampaignUse") == "Known":
            return "critical"
    for a in articles:
        if name_lower in (a["title"] + " " + a["summary"]).lower():
            return "active"
    for kev in cisa_vulns:
        if name_lower in (kev.get("vendorProject", "") + " " + kev.get("product", "")).lower():
            return "active"
    return "none"


def count_vendor_mentions(vendor: str, articles: list[dict], cisa_vulns: list[dict]) -> int:
    name_lower = vendor.lower()
    count = 0
    for a in articles:
        if name_lower in (a["title"] + " " + a["summary"]).lower():
            count += 1
    for kev in cisa_vulns:
        if name_lower in (kev.get("vendorProject", "") + " " + kev.get("product", "")).lower():
            count += 1
    return count


# ── Data Fetching ──────────────────────────────────────────────────────────────

def fetch_rss_feeds() -> list[dict[str, str]]:
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


# ── Claude Integration ─────────────────────────────────────────────────────────

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
        "threat_level": {
            "type": "string",
            "enum": ["green", "amber", "red"],
            "description": "Overall ICS/OT threat level today based on the news and KEV data.",
        },
        "threat_summary": {
            "type": "string",
            "description": "One-line summary (under 120 chars) describing today's threat landscape.",
        },
        "news_summary": {
            "type": "string",
            "description": (
                "3-5 paragraph digest of the most relevant ICS/OT/automation news, "
                "highlighting anything that directly affects plant floor engineers."
            ),
        },
        "cisa_summary": {
            "type": "string",
            "description": (
                "2-3 paragraph summary of recent CISA KEV entries most relevant to OT "
                "environments, with practical remediation context."
            ),
        },
        "interesting_fact": {
            "type": "string",
            "description": (
                "One interesting, surprising, or underappreciated fact relevant to "
                "controls engineers — 2-4 sentences, suitable for a daily knowledge bite."
            ),
        },
        "tech_spotlight": {
            "type": "string",
            "description": (
                "2-3 paragraphs explaining one emerging technology relevant to controls engineers "
                "(e.g. OPC-UA over TSN, 5G in OT, digital twins, AI in SCADA) in plain English. "
                "Include practical implications and current adoption challenges."
            ),
        },
        "standards_watch": {
            "type": "string",
            "description": (
                "2-3 paragraphs covering recent updates or notable activity around IEC 62443, "
                "ISA standards, NIST frameworks, or other relevant OT/ICS standards. "
                "If no specific news, provide useful context on an important standard."
            ),
        },
        "incident_of_week": {
            "type": "string",
            "description": (
                "2-3 paragraphs summarising one real, notable OT/ICS security incident or "
                "near-miss. Include what happened, how it happened, and 2-3 key lessons learned "
                "for controls engineers."
            ),
        },
    },
    "required": [
        "threat_level", "threat_summary",
        "news_summary", "cisa_summary", "interesting_fact",
        "tech_spotlight", "standards_watch", "incident_of_week",
    ],
    "additionalProperties": False,
}


def summarise_with_claude(
    articles: list[dict[str, str]],
    cisa_vulns: list[dict[str, Any]],
    client: anthropic.Anthropic,
) -> dict[str, Any]:
    today = datetime.now(timezone.utc).strftime("%A %d %B %Y")

    news_block = "\n\n".join(
        f"[{a['source']}] {a['title']}\n{a['summary']}"
        for a in articles[:20]
    ) or "No articles available today."

    cisa_block = "\n".join(
        f"- {v.get('cveID', '')} ({v.get('dateAdded', '')}): "
        f"{v.get('vendorProject', '')} / {v.get('product', '')} — "
        f"{v.get('shortDescription', '')[:250]}"
        f" [Ransomware: {v.get('knownRansomwareCampaignUse', 'Unknown')}]"
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
        max_tokens=6000,
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


# ── HTML Fragments ─────────────────────────────────────────────────────────────

def _vendor_nodes(articles: list[dict], cisa_vulns: list[dict]) -> str:
    e = html_mod.escape
    nodes = []
    for vendor in VENDORS:
        status = vendor_status(vendor, articles, cisa_vulns)
        count  = count_vendor_mentions(vendor, articles, cisa_vulns)
        css    = f"vendor-node {status}" if status != "none" else "vendor-node"
        label  = f"{count} mention{'s' if count != 1 else ''}" if count > 0 else "No mentions"
        nodes.append(
            f'<div class="{css}">'
            f'<div class="vendor-indicator"></div>'
            f'<div class="vendor-name">{e(vendor)}</div>'
            f'<div class="vendor-count">{label}</div>'
            f'</div>'
        )
    return "\n".join(nodes)


def _article_items(articles: list[dict[str, str]]) -> str:
    e = html_mod.escape
    items = []
    for a in articles:
        is_critical = a["source"] == "CISA ICS Advisories"
        dot = (
            '<span class="dot dr pulse" style="flex-shrink:0;margin-top:3px"></span>'
            if is_critical else
            '<span class="dot dg" style="flex-shrink:0;margin-top:3px"></span>'
        )
        crit_cls = "sum-critical" if is_critical else ""
        pub = e(a.get("published", "")[:16])
        items.append(
            f'<details>'
            f'<summary class="{crit_cls}">'
            f'{dot}'
            f'<div style="flex:1;min-width:0">'
            f'<div class="sum-meta">'
            f'<span class="sum-badge">{e(a["source"])}</span>'
            f'<span style="font-size:.65rem;color:var(--muted)">{pub}</span>'
            f'</div>'
            f'<span class="sum-title">{e(a["title"])}</span>'
            f'</div>'
            f'</summary>'
            f'<div class="detail-body">'
            f'<p>{e(a["summary"][:320])}</p>'
            f'<a class="read-more" href="{e(a["link"])}" target="_blank" rel="noopener">Read more &#8594;</a>'
            f'</div>'
            f'</details>'
        )
    return "\n".join(items)


def _kev_rows(vulns: list[dict[str, Any]]) -> str:
    e = html_mod.escape
    rows = []
    for v in vulns:
        sev = kev_severity(v)
        badge = (
            '<span class="sev sev-critical">CRITICAL</span>'
            if sev == "critical" else
            '<span class="sev sev-high">HIGH</span>'
        )
        rows.append(
            f"<tr>"
            f"<td>{badge}</td>"
            f'<td><span class="cve">{e(v.get("cveID",""))}</span></td>'
            f"<td>{e(v.get('dateAdded',''))}</td>"
            f"<td>{e(v.get('vendorProject',''))}</td>"
            f"<td>{e(v.get('product',''))}</td>"
            f"<td>{e(v.get('vulnerabilityName','')[:70])}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


# ── CSS ────────────────────────────────────────────────────────────────────────

_CSS = """\
:root{
  --bg:#0d1117;--surf:#161b22;--surf2:#1c2128;--bord:#30363d;
  --text:#c9d1d9;--muted:#8b949e;--green:#39d353;--amber:#e3b341;
  --red:#f85149;--link:#58a6ff;--r:8px;
  --mono:"Courier New",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
[data-theme="light"]{
  --bg:#f6f8fa;--surf:#ffffff;--surf2:#f0f3f6;--bord:#d0d7de;
  --text:#24292f;--muted:#656d76;--green:#1a7f37;--amber:#9a6700;
  --red:#cf222e;--link:#0969da;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.6}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}

/* Heat Strip */
.heat-strip{
  width:100%;padding:9px 24px;display:flex;align-items:center;gap:12px;
  font-size:.82rem;font-weight:500;letter-spacing:.02em;
}
.heat-strip.green{background:#0d2a12;border-bottom:2px solid var(--green);color:var(--green)}
.heat-strip.amber{background:#2a1f00;border-bottom:2px solid var(--amber);color:var(--amber)}
.heat-strip.red{background:#2a0000;border-bottom:2px solid var(--red);color:var(--red)}
[data-theme="light"] .heat-strip.green{background:#dafbe1;color:#1a7f37}
[data-theme="light"] .heat-strip.amber{background:#fff8c5;color:#9a6700}
[data-theme="light"] .heat-strip.red{background:#ffebe9;color:#cf222e}
.heat-label{
  font-family:var(--mono);font-size:.68rem;font-weight:700;
  padding:2px 8px;border-radius:4px;border:1px solid currentColor;
  text-transform:uppercase;letter-spacing:.08em;white-space:nowrap;
}

/* Header */
header{
  background:var(--surf);border-bottom:1px solid var(--bord);
  padding:12px 24px;display:flex;justify-content:space-between;
  align-items:center;flex-wrap:wrap;gap:8px;
}
header h1{font-family:var(--mono);font-size:1rem;letter-spacing:.08em;color:var(--green)}
.header-right{display:flex;align-items:center;gap:12px}
.ts{font-size:.75rem;color:var(--muted)}
.theme-btn{
  background:var(--surf2);border:1px solid var(--bord);color:var(--text);
  border-radius:6px;padding:5px 12px;cursor:pointer;font-size:.8rem;
  transition:background .15s;font-family:var(--sans);
}
.theme-btn:hover{background:var(--bord)}

/* Stats Bar */
.stats-bar{
  max-width:1320px;margin:0 auto;padding:12px 16px;
  display:flex;gap:10px;flex-wrap:wrap;
}
.stat-card{
  background:var(--surf);border:1px solid var(--bord);border-radius:var(--r);
  padding:10px 18px;display:flex;align-items:center;gap:10px;
  flex:1;min-width:150px;
}
.stat-icon{font-size:1.2rem;line-height:1}
.stat-val{font-size:1.3rem;font-weight:700;font-family:var(--mono);line-height:1.2}
.stat-lbl{font-size:.68rem;color:var(--muted);margin-top:1px}
.stat-val.red{color:var(--red)}
.stat-val.amber{color:var(--amber)}
.stat-val.green{color:var(--green)}
.stat-val.blue{color:var(--link)}

/* Main Grid */
main{
  max-width:1320px;margin:0 auto;padding:16px;
  display:grid;grid-template-columns:1fr 1fr;gap:16px;
}
.span2{grid-column:1/-1}
section{background:var(--surf);border:1px solid var(--bord);border-radius:var(--r);overflow:hidden}

/* Section Header */
.sh{
  padding:10px 16px;border-bottom:1px solid var(--bord);
  display:flex;align-items:center;gap:8px;
}
.sh h2{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}
.sh-icon{font-size:.9rem;line-height:1}
.sb{padding:16px}
.ai-text p{margin:.5em 0;font-size:.88rem}

/* Dots */
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dg{background:var(--green)}
.da{background:var(--amber)}
.dr{background:var(--red)}

@keyframes pulse{
  0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(248,81,73,.5)}
  50%{opacity:.8;box-shadow:0 0 0 6px rgba(248,81,73,0)}
}
.pulse{animation:pulse 1.8s ease-in-out infinite}

/* Vendor Radar */
.vendor-grid{display:flex;flex-wrap:wrap;gap:12px;padding:16px}
.vendor-node{
  display:flex;flex-direction:column;align-items:center;gap:6px;
  background:var(--surf2);border:1px solid var(--bord);border-radius:var(--r);
  padding:14px 18px;min-width:100px;transition:border-color .2s;
}
.vendor-node.active{border-color:var(--amber)}
.vendor-node.critical{border-color:var(--red)}
.vendor-indicator{
  width:14px;height:14px;border-radius:50%;background:var(--bord);transition:background .2s;
}
.vendor-node.active .vendor-indicator{background:var(--amber)}
.vendor-node.critical .vendor-indicator{background:var(--red);animation:pulse 1.8s ease-in-out infinite}
.vendor-name{font-size:.78rem;font-weight:600}
.vendor-count{font-size:.65rem;color:var(--muted);font-family:var(--mono)}

/* Fact Box */
.fact-box{
  background:var(--surf2);border:1px solid rgba(57,211,83,.25);border-radius:var(--r);
  padding:16px;color:var(--green);font-size:.9rem;line-height:1.7;
}
.fact-box p{margin:.3em 0}

/* Collapsed News */
.news-list{display:flex;flex-direction:column}
details{border-bottom:1px solid var(--bord)}
details:last-child{border-bottom:none}
summary{
  padding:10px 14px;cursor:pointer;list-style:none;
  display:flex;align-items:flex-start;gap:8px;font-size:.84rem;
  user-select:none;
}
summary::-webkit-details-marker{display:none}
summary::before{
  content:"›";color:var(--muted);flex-shrink:0;font-size:1.1rem;
  line-height:1.3;transition:transform .15s;
}
details[open] summary::before{transform:rotate(90deg)}
summary:hover{background:var(--surf2)}
.sum-meta{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:2px}
.sum-badge{
  font-size:.62rem;background:var(--surf2);border:1px solid var(--bord);
  color:var(--muted);padding:1px 6px;border-radius:10px;font-family:var(--mono);white-space:nowrap;
}
.sum-title{font-size:.84rem;line-height:1.4}
.sum-critical .sum-title{color:var(--red)}
.detail-body{padding:6px 14px 14px 30px;font-size:.8rem;color:var(--muted)}
.detail-body p{margin-bottom:6px}
.read-more{font-size:.78rem;color:var(--link)}

/* Severity Badges */
.sev{
  display:inline-block;font-size:.62rem;font-family:var(--mono);
  padding:2px 7px;border-radius:4px;font-weight:700;white-space:nowrap;
}
.sev-critical{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.4)}
.sev-high{background:rgba(227,179,65,.12);color:var(--amber);border:1px solid rgba(227,179,65,.35)}

/* KEV Table */
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{
  text-align:left;padding:8px 10px;border-bottom:1px solid var(--bord);
  color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;
}
td{padding:6px 10px;border-bottom:1px solid var(--surf2);vertical-align:top}
tr:last-child td{border-bottom:none}
.cve{font-family:var(--mono);color:var(--amber);font-size:.76rem;white-space:nowrap}

/* Footer */
footer{
  text-align:center;padding:20px;font-size:.72rem;color:var(--muted);
  border-top:1px solid var(--bord);margin-top:4px;
}

@media(max-width:768px){
  main{grid-template-columns:1fr}
  .span2{grid-column:1}
  .stats-bar{gap:8px}
}
"""

_JS = """\
(function(){
  var html = document.documentElement;
  var btn  = document.getElementById('themeBtn');
  function apply(t){
    html.setAttribute('data-theme', t);
    btn.textContent = t === 'dark' ? '☀ Light' : '🌙 Dark';
    try{ localStorage.setItem('ced-theme', t); }catch(e){}
  }
  btn.addEventListener('click', function(){
    apply(html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  });
  try{
    var saved = localStorage.getItem('ced-theme');
    if(saved === 'light') apply('light');
  }catch(e){}
})();
"""


# ── HTML Renderer ──────────────────────────────────────────────────────────────

def render_html(
    articles: list[dict[str, str]],
    cisa_vulns: list[dict[str, Any]],
    summaries: dict[str, Any],
    build_time: datetime,
) -> str:
    ts = build_time.strftime("%Y-%m-%d %H:%M UTC")
    e  = html_mod.escape

    threat_level   = summaries.get("threat_level", "amber")
    threat_summary = summaries.get("threat_summary", "")
    fact_html      = text_to_html(summaries.get("interesting_fact", ""))
    news_html      = text_to_html(summaries.get("news_summary", ""))
    cisa_html      = text_to_html(summaries.get("cisa_summary", ""))
    tech_html      = text_to_html(summaries.get("tech_spotlight", ""))
    std_html       = text_to_html(summaries.get("standards_watch", ""))
    inc_html       = text_to_html(summaries.get("incident_of_week", ""))

    kev_count      = len(cisa_vulns)
    critical_count = sum(1 for v in cisa_vulns if kev_severity(v) == "critical")
    ics_count      = sum(1 for a in articles if a["source"] == "CISA ICS Advisories")
    article_count  = len(articles)

    heat_icons = {"green": "&#10003;", "amber": "&#9888;", "red": "&#9888;"}
    heat_icon  = heat_icons.get(threat_level, "&#9888;")

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Controls Engineering Daily &#8212; {ts}</title>
  <style>{_CSS}</style>
</head>
<body>

<div class="heat-strip {e(threat_level)}">
  <span class="heat-label">{heat_icon} {e(threat_level.upper())}</span>
  <span>{e(threat_summary)}</span>
</div>

<header>
  <h1>&#9881; Controls Engineering Daily</h1>
  <div class="header-right">
    <span class="ts">Built {ts} &nbsp;&#124;&nbsp; Anthropic Claude</span>
    <button class="theme-btn" id="themeBtn">&#9728; Light</button>
  </div>
</header>

<div class="stats-bar">
  <div class="stat-card">
    <span class="stat-icon">&#128737;</span>
    <div>
      <div class="stat-val amber">{kev_count}</div>
      <div class="stat-lbl">KEVs this month</div>
    </div>
  </div>
  <div class="stat-card">
    <span class="stat-icon">&#128225;</span>
    <div>
      <div class="stat-val green">{ics_count}</div>
      <div class="stat-lbl">ICS advisories</div>
    </div>
  </div>
  <div class="stat-card">
    <span class="stat-icon">&#128308;</span>
    <div>
      <div class="stat-val red">{critical_count}</div>
      <div class="stat-lbl">Critical (ransomware)</div>
    </div>
  </div>
  <div class="stat-card">
    <span class="stat-icon">&#128240;</span>
    <div>
      <div class="stat-val blue">{article_count}</div>
      <div class="stat-lbl">Articles today</div>
    </div>
  </div>
</div>

<main>

  <!-- Vendor Threat Radar -->
  <div class="span2">
    <section>
      <div class="sh"><span class="sh-icon">&#128225;</span><h2>Vendor Threat Radar</h2></div>
      <div class="vendor-grid">{_vendor_nodes(articles, cisa_vulns)}</div>
    </section>
  </div>

  <!-- Knowledge Bite -->
  <section>
    <div class="sh"><span class="sh-icon">&#128161;</span><h2>Today&#39;s Knowledge Bite</h2></div>
    <div class="sb"><div class="fact-box">{fact_html}</div></div>
  </section>

  <!-- Tech Spotlight -->
  <section>
    <div class="sh"><span class="sh-icon">&#128300;</span><h2>Tech Spotlight</h2></div>
    <div class="sb ai-text">{tech_html}</div>
  </section>

  <!-- Standards Watch -->
  <section>
    <div class="sh"><span class="sh-icon">&#128203;</span><h2>Standards Watch</h2></div>
    <div class="sb ai-text">{std_html}</div>
  </section>

  <!-- Incident of the Week -->
  <section>
    <div class="sh">
      <span class="dot dr pulse"></span>
      <h2>Incident of the Week</h2>
    </div>
    <div class="sb ai-text">{inc_html}</div>
  </section>

  <!-- News Digest -->
  <div class="span2">
    <section>
      <div class="sh"><span class="dot dg"></span><h2>ICS / OT News Digest</h2></div>
      <div class="sb ai-text">{news_html}</div>
    </section>
  </div>

  <!-- Collapsed Feed -->
  <div class="span2">
    <section>
      <div class="sh">
        <span class="sh-icon">&#128240;</span>
        <h2>Today&#39;s Feed &mdash; {article_count} articles</h2>
      </div>
      <div class="news-list">{_article_items(articles)}</div>
    </section>
  </div>

  <!-- CISA Digest -->
  <div class="span2">
    <section>
      <div class="sh"><span class="dot da"></span><h2>CISA Vulnerability Digest</h2></div>
      <div class="sb ai-text">{cisa_html}</div>
    </section>
  </div>

  <!-- CISA KEV Table -->
  <div class="span2">
    <section>
      <div class="sh">
        <span class="dot dr pulse"></span>
        <h2>CISA KEV &mdash; {kev_count} entries &middot; last {KEV_LOOKBACK_DAYS} days</h2>
      </div>
      <div class="sb" style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>Severity</th><th>CVE</th><th>Date Added</th>
              <th>Vendor</th><th>Product</th><th>Vulnerability</th>
            </tr>
          </thead>
          <tbody>{_kev_rows(cisa_vulns)}</tbody>
        </table>
      </div>
    </section>
  </div>

</main>

<footer>
  Controls Engineering Dashboard &nbsp;&bull;&nbsp; {ts}
  &nbsp;&bull;&nbsp; Summaries by Anthropic Claude
</footer>

<script>{_JS}</script>
</body>
</html>"""


# ── Entry Point ────────────────────────────────────────────────────────────────

def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    print("Fetching RSS feeds...")
    articles = fetch_rss_feeds()
    print(f"  {len(articles)} articles from {len(RSS_FEEDS)} feeds")

    print("Fetching CISA KEV...")
    cisa_vulns = fetch_cisa_kev()
    print(f"  {len(cisa_vulns)} CVEs added in last {KEV_LOOKBACK_DAYS} days")

    print("Calling Claude (claude-opus-4-7)...")
    client = anthropic.Anthropic()
    try:
        summaries = summarise_with_claude(articles, cisa_vulns, client)
    except anthropic.APIError as exc:
        print(f"Claude API error: {exc}", file=sys.stderr)
        sys.exit(1)
    print("  Done")

    build_time   = datetime.now(timezone.utc)
    html_content = render_html(articles, cisa_vulns, summaries, build_time)

    out = Path("index.html")
    out.write_text(html_content, encoding="utf-8")
    print(f"Written -> {out}  ({len(html_content):,} bytes)")


if __name__ == "__main__":
    main()
