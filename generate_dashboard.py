#!/usr/bin/env python3
"""Controls Engineering Daily Dashboard Generator."""
from __future__ import annotations

import argparse
import html as html_mod
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import anthropic
    import feedparser
except ImportError:
    anthropic = None  # type: ignore[assignment]
    feedparser = None  # type: ignore[assignment]

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


_SENT_RE = re.compile(r'(?<=[.!?])\s+(?=[A-Z"])')


def _truncate_ai_html(text: str, max_sentences: int = 2) -> str:
    """Show first max_sentences then hide the rest behind a Read more toggle."""
    if not text:
        return ""
    sentences = _SENT_RE.split(text.strip())
    if len(sentences) <= max_sentences:
        return text_to_html(text)
    uid = f"rm{abs(hash(text[:40])) % 999983}"
    e = html_mod.escape
    visible = e(" ".join(sentences[:max_sentences]))
    rest    = e(" ".join(sentences[max_sentences:]))
    return (
        f'<p class="ai-p">{visible} '
        f'<span id="{uid}" style="display:none">{rest}</span>'
        f'<a class="rm-toggle" href="#" '
        f'onclick="rmToggle(\'{uid}\',this);return false">'
        f'Read more &rarr;</a></p>'
    )


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
        "morning_briefing": {
            "type": "string",
            "description": (
                "3-4 sentences summarising the single most important thing a controls engineer "
                "needs to know today — written as a direct, confident, actionable brief. "
                "Lead with the most significant development; end with a practical implication."
            ),
        },
        "engineering_curiosity": {
            "type": "string",
            "description": (
                "One surprising or thought-provoking fact about control theory, industrial "
                "history, physics, or engineering — 3-4 sentences that would make a controls "
                "engineer pause and think. Avoid cybersecurity topics; favour history, science, "
                "or the unexpected origins of everyday engineering concepts."
            ),
        },
    },
    "required": [
        "threat_level", "threat_summary",
        "news_summary", "cisa_summary", "interesting_fact",
        "tech_spotlight", "standards_watch", "incident_of_week",
        "morning_briefing", "engineering_curiosity",
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
    for a in articles[:5]:
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
            f'<span class="sum-title"><a href="{e(a["link"])}" target="_blank" rel="noopener">{e(a["title"])}</a></span>'
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
    for v in vulns[:3]:
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

/* Header / Hero */
header{
  background:var(--surf);border-bottom:2px solid var(--bord);
  padding:28px 24px 22px;display:grid;
  grid-template-columns:1fr auto 1fr;align-items:center;gap:16px;
  position:relative;
}
header::after{
  content:"";position:absolute;bottom:-2px;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent 0%,var(--green) 25%,var(--green) 75%,transparent 100%);
  opacity:.6;
}
.hero-center{text-align:center}
header h1{
  font-family:'Rajdhani',var(--sans);font-size:1.9rem;font-weight:700;letter-spacing:.08em;
  color:var(--green);line-height:1.2;
}
.hero-sub{
  font-size:.68rem;letter-spacing:.2em;text-transform:uppercase;
  color:var(--muted);margin-top:6px;
}
.hero-right{display:flex;flex-direction:column;align-items:flex-end;gap:6px}
.ts{font-size:.7rem;color:var(--muted);text-align:right;line-height:1.5}
.theme-btn{
  background:var(--surf2);border:1px solid var(--bord);color:var(--text);
  border-radius:6px;padding:5px 12px;cursor:pointer;font-size:.8rem;
  transition:background .15s;font-family:var(--sans);
}
.theme-btn:hover{background:var(--bord)}
.rm-toggle{font-size:.78rem;color:var(--link);margin-left:4px;white-space:nowrap}
.ai-p{margin:.5em 0;font-size:.88rem}

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
section{background:var(--surf);border:1px solid var(--bord);border-radius:var(--r);overflow:hidden;transition:box-shadow .2s,border-color .2s}
section:hover{box-shadow:0 6px 28px rgba(0,0,0,.4)}
[data-theme="light"] section:hover{box-shadow:0 4px 20px rgba(0,0,0,.1)}
section.s-green{border-top:3px solid var(--green)}
section.s-amber{border-top:3px solid var(--amber)}
section.s-red  {border-top:3px solid var(--red)}
section.s-blue {border-top:3px solid var(--link)}

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
/* Dot grid body background */
body{background-image:radial-gradient(circle,rgba(48,54,61,.55) 1px,transparent 1px);background-size:28px 28px}
[data-theme="light"] body{background-image:radial-gradient(circle,rgba(208,215,222,.9) 1px,transparent 1px)}
/* Section source footer */
.sec-foot{padding:8px 16px;border-top:1px solid var(--bord);font-size:.7rem;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.sec-foot::before{content:"Sources:";font-size:.62rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);opacity:.55;flex-shrink:0}
.sec-foot a{color:var(--muted);transition:color .15s}
.sec-foot a:hover{color:var(--link);text-decoration:none}
/* Article title links */
.sum-title a{color:inherit;text-decoration:none}
.sum-title a:hover{color:var(--link)}
.sum-critical .sum-title a{color:var(--red)}
/* Morning Briefing */
.briefing-wrap{max-width:1320px;margin:0 auto;padding:0 16px 4px}
.briefing-card{
  background:var(--surf);border:1px solid var(--bord);border-left:4px solid var(--green);
  border-radius:var(--r);padding:20px 24px;
  background-image:linear-gradient(135deg,rgba(57,211,83,.04) 0%,transparent 55%);
}
[data-theme="light"] .briefing-card{background-image:linear-gradient(135deg,rgba(26,127,55,.05) 0%,transparent 55%)}
.briefing-head{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.briefing-label{font-family:var(--mono);font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.15em;color:var(--green)}
.briefing-date{font-size:.68rem;color:var(--muted);margin-left:auto}
.briefing-body{font-size:.96rem;line-height:1.75}
.briefing-body p{margin:.35em 0}
/* Acronym Bar */
.acro-bar-wrap{max-width:1320px;margin:0 auto;padding:6px 16px 10px}
.acro-bar{
  background:var(--surf);border:1px solid var(--bord);border-radius:var(--r);
  padding:9px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;
}
.acro-bar-label{font-size:.67rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;white-space:nowrap;font-family:var(--mono);flex-shrink:0}
.acro-input{
  flex:1;min-width:160px;max-width:280px;background:var(--surf2);
  border:1px solid var(--bord);border-radius:5px;padding:5px 10px;
  color:var(--text);font-size:.84rem;font-family:var(--mono);
  outline:none;transition:border-color .15s;
}
.acro-input:focus{border-color:var(--link)}
.acro-result{font-size:.8rem;color:var(--muted);flex:1;line-height:1.5;min-width:160px}
.acro-result strong{color:var(--link);font-family:var(--mono)}
/* Engineering Curiosity */
.curiosity-box{display:flex;gap:16px;align-items:flex-start}
.curiosity-icon{font-size:2.2rem;line-height:1;flex-shrink:0;opacity:.6;margin-top:2px}
.curiosity-body p{margin:.4em 0;font-size:.88rem;line-height:1.65}
/* Acronym tooltips */
abbr[title]{text-decoration:underline dotted var(--muted);cursor:help;text-underline-offset:3px}
"""

_JS = """\
(function(){
  var html=document.documentElement,btn=document.getElementById('themeBtn');
  function apply(t){
    html.setAttribute('data-theme',t);
    btn.textContent=t==='dark'?'☀ Light':'🌙 Dark';
    try{localStorage.setItem('ced-theme',t);}catch(e){}
  }
  btn.addEventListener('click',function(){ apply(html.getAttribute('data-theme')==='dark'?'light':'dark'); });
  try{ var s=localStorage.getItem('ced-theme'); if(s==='light') apply('light'); }catch(e){}
})();

function rmToggle(id,a){
  var s=document.getElementById(id);
  if(s.style.display==='none'){s.style.display='inline';a.textContent='Read less ←';}
  else{s.style.display='none';a.innerHTML='Read more →';}
}

var ACRONYM_DEFS={
  "SCADA":      "Supervisory Control and Data Acquisition — software platform used to monitor and control industrial processes from a central location",
  "HMI":        "Human-Machine Interface — the screen, panel, or software operators use to interact with a control system",
  "DCS":        "Distributed Control System — a control architecture where processing is distributed across multiple controllers located throughout the plant",
  "PLC":        "Programmable Logic Controller — a ruggedised industrial computer used to automate electromechanical processes",
  "OPC-UA":     "OPC Unified Architecture — a platform-independent, service-oriented standard for industrial data exchange, successor to classic OPC",
  "OPC":        "OLE for Process Control — a set of standards enabling data exchange between Windows-based software and industrial hardware",
  "RTU":        "Remote Terminal Unit — a microprocessor-controlled device that connects physical field equipment to a SCADA system",
  "IED":        "Intelligent Electronic Device — a microprocessor-based controller used in power systems, such as protection relays and bay controllers",
  "HART":       "Highway Addressable Remote Transducer — a protocol overlaid on 4-20mA loops allowing digital data exchange with smart field instruments",
  "Modbus":     "A serial communication protocol developed in 1979 for PLCs; still widely used for simple device communication over RS-232, RS-485, and TCP/IP",
  "Profibus":   "Process Field Bus — a fieldbus standard for serial communication between field devices and control systems",
  "Profinet":   "Process Field Network — an industrial Ethernet standard for automation, providing real-time communication and replacing Profibus in many new installations",
  "EtherNet/IP":"Ethernet Industrial Protocol — an industrial network standard using standard Ethernet hardware with the Common Industrial Protocol (CIP)",
  "IEC 62443":  "An international series of standards defining requirements for securing industrial automation and control systems across their lifecycle",
  "ISA-95":     "An international standard (also IEC 62264) for integrating enterprise resource planning (ERP) systems with manufacturing and control systems",
  "CVSS":       "Common Vulnerability Scoring System — a 0-10 numerical score representing the severity and exploitability of a software vulnerability",
  "KEV":        "Known Exploited Vulnerabilities — CISA's catalog of vulnerabilities confirmed to be actively exploited in the wild",
  "CVE":        "Common Vulnerabilities and Exposures — a standardised identifier (e.g. CVE-2024-1234) for publicly disclosed cybersecurity vulnerabilities",
  "OT":         "Operational Technology — hardware and software that monitors and controls physical devices, processes, and infrastructure",
  "IT":         "Information Technology — computer systems, networks, and software used to process and store business data",
  "ICS":        "Industrial Control System — an umbrella term covering SCADA, DCS, PLCs, and other systems used to control industrial processes",
  "CISA":       "Cybersecurity and Infrastructure Security Agency — the US federal agency responsible for critical infrastructure security and resilience",
  "TSN":        "Time-Sensitive Networking — IEEE 802.1 extensions to Ethernet providing deterministic, bounded-latency communication for real-time control",
  "MES":        "Manufacturing Execution System — software that tracks, monitors, and manages production activities on the plant floor in real time",
  "historian":  "A software application (e.g. OSIsoft PI, Aveva Historian) that collects, stores, and retrieves time-series process data from control systems"
};

(function(){
  var inp=document.getElementById('acroInput'),res=document.getElementById('acroResult');
  if(!inp) return;
  inp.addEventListener('input',function(){
    var q=this.value.trim();
    if(!q){res.innerHTML='';return;}
    var key=Object.keys(ACRONYM_DEFS).find(function(k){return k.toLowerCase()===q.toLowerCase();});
    res.innerHTML=key
      ?'<strong>'+key+'</strong> — '+ACRONYM_DEFS[key]
      :'<span style="opacity:.5">No definition found</span>';
  });
})();

function wrapAcronyms(){
  var skip=['IT','historian'];
  var terms=Object.keys(ACRONYM_DEFS).filter(function(k){return skip.indexOf(k)<0;})
    .sort(function(a,b){return b.length-a.length;});
  var pats=terms.map(function(t){return t.replace(/[-\\/\\\\^$*+?.()|[\\]{}]/g,'\\\\$&');});
  var re=new RegExp('(?<![A-Za-z0-9])('+pats.join('|')+')(?![A-Za-z0-9])','g');
  var roots=document.querySelectorAll('.sb,.briefing-body,.detail-body,.fact-box,.curiosity-body');
  roots.forEach(function(root){
    var walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT,{
      acceptNode:function(n){
        var tag=n.parentElement&&n.parentElement.tagName;
        if(!tag) return NodeFilter.FILTER_REJECT;
        return ['SCRIPT','STYLE','ABBR','A','INPUT','BUTTON','H1','H2','LABEL'].indexOf(tag)>=0
          ?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT;
      }
    });
    var nodes=[],node;
    while((node=walker.nextNode())) nodes.push(node);
    nodes.forEach(function(tn){
      var text=tn.textContent;
      re.lastIndex=0;
      if(!re.test(text)) return;
      re.lastIndex=0;
      var frag=document.createDocumentFragment(),last=0,m;
      while((m=re.exec(text))!==null){
        if(m.index>last) frag.appendChild(document.createTextNode(text.slice(last,m.index)));
        var abbr=document.createElement('abbr');
        var key=terms.find(function(k){return k.toLowerCase()===m[0].toLowerCase();});
        abbr.title=key?ACRONYM_DEFS[key]:'';
        abbr.textContent=m[0];
        frag.appendChild(abbr);
        last=m.index+m[0].length;
      }
      if(last<text.length) frag.appendChild(document.createTextNode(text.slice(last)));
      if(frag.childNodes.length) tn.parentNode.replaceChild(frag,tn);
    });
  });
}
wrapAcronyms();
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
    news_html      = _truncate_ai_html(summaries.get("news_summary", ""))
    cisa_html      = _truncate_ai_html(summaries.get("cisa_summary", ""))
    tech_html      = _truncate_ai_html(summaries.get("tech_spotlight", ""))
    std_html       = _truncate_ai_html(summaries.get("standards_watch", ""))
    inc_html       = _truncate_ai_html(summaries.get("incident_of_week", ""))
    briefing_html  = text_to_html(summaries.get("morning_briefing", ""))
    curiosity_html = text_to_html(summaries.get("engineering_curiosity", ""))

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
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@700&display=swap" rel="stylesheet">
  <style>{_CSS}</style>
</head>
<body>

<div class="heat-strip {e(threat_level)}">
  <span class="heat-label">{heat_icon} {e(threat_level.upper())}</span>
  <span>{e(threat_summary)}</span>
</div>

<header>
  <div></div>
  <div class="hero-center">
    <h1>&#128187; Controls Engineering Daily</h1>
    <p class="hero-sub">ICS &middot; OT &middot; SCADA Intelligence Briefing</p>
  </div>
  <div class="hero-right">
    <button class="theme-btn" id="themeBtn">&#9728; Light</button>
    <span class="ts">Built {ts}<br>Anthropic Claude</span>
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

<div class="briefing-wrap">
  <div class="briefing-card">
    <div class="briefing-head">
      <span>&#9728;</span>
      <span class="briefing-label">Morning Briefing</span>
      <span class="briefing-date">{ts}</span>
    </div>
    <div class="briefing-body">{briefing_html}</div>
  </div>
</div>

<div class="acro-bar-wrap">
  <div class="acro-bar">
    <span class="acro-bar-label">&#128270; Acronym Lookup</span>
    <input type="text" id="acroInput" class="acro-input" placeholder="Type SCADA, HMI, PLC, DCS&hellip;" autocomplete="off" spellcheck="false">
    <div id="acroResult" class="acro-result"></div>
  </div>
</div>

<main>

  <!-- Vendor Threat Radar -->
  <div class="span2">
    <section class="s-amber">
      <div class="sh"><span class="sh-icon">&#128225;</span><h2>Vendor Threat Radar</h2></div>
      <div class="vendor-grid">{_vendor_nodes(articles, cisa_vulns)}</div>
    </section>
  </div>

  <!-- Knowledge Bite -->
  <section class="s-green">
    <div class="sh"><span class="sh-icon">&#128161;</span><h2>Today&#39;s Knowledge Bite</h2></div>
    <div class="sb"><div class="fact-box">{fact_html}</div></div>
  </section>

  <!-- Engineering Curiosity -->
  <section class="s-blue">
    <div class="sh"><span class="sh-icon">&#9883;</span><h2>Engineering Curiosity</h2></div>
    <div class="sb">
      <div class="curiosity-box">
        <div class="curiosity-icon">&#9883;</div>
        <div class="curiosity-body ai-text">{curiosity_html}</div>
      </div>
    </div>
  </section>

  <!-- Tech Spotlight -->
  <section class="s-blue">
    <div class="sh"><span class="sh-icon">&#128300;</span><h2>Tech Spotlight</h2></div>
    <div class="sb ai-text">{tech_html}</div>
    <div class="sec-foot">
      <a href="https://www.controleng.com" target="_blank" rel="noopener">Control Engineering &#8599;</a>
      <a href="https://www.automationworld.com" target="_blank" rel="noopener">Automation World &#8599;</a>
    </div>
  </section>

  <!-- Standards Watch -->
  <section class="s-amber">
    <div class="sh"><span class="sh-icon">&#128203;</span><h2>Standards Watch</h2></div>
    <div class="sb ai-text">{std_html}</div>
    <div class="sec-foot">
      <a href="https://www.isa.org" target="_blank" rel="noopener">ISA &#8599;</a>
      <a href="https://www.iec.ch" target="_blank" rel="noopener">IEC &#8599;</a>
      <a href="https://www.nist.gov" target="_blank" rel="noopener">NIST &#8599;</a>
    </div>
  </section>

  <!-- Incident of the Week -->
  <section class="s-red">
    <div class="sh"><span class="dot dr pulse"></span><h2>Incident of the Week</h2></div>
    <div class="sb ai-text">{inc_html}</div>
    <div class="sec-foot">
      <a href="https://www.cisa.gov/topics/industrial-control-systems" target="_blank" rel="noopener">CISA ICS &#8599;</a>
    </div>
  </section>

  <!-- News Digest -->
  <div class="span2">
    <section class="s-green">
      <div class="sh"><span class="dot dg"></span><h2>ICS / OT News Digest</h2></div>
      <div class="sb ai-text">{news_html}</div>
      <div class="sec-foot">
        <a href="https://www.controleng.com" target="_blank" rel="noopener">Control Engineering &#8599;</a>
        <a href="https://www.automationworld.com" target="_blank" rel="noopener">Automation World &#8599;</a>
        <a href="https://www.securityweek.com" target="_blank" rel="noopener">SecurityWeek &#8599;</a>
      </div>
    </section>
  </div>

  <!-- Collapsed Feed -->
  <div class="span2">
    <section class="s-green">
      <div class="sh">
        <span class="sh-icon">&#128240;</span>
        <h2>Today&#39;s Feed &mdash; {article_count} articles</h2>
      </div>
      <div class="news-list">{_article_items(articles)}</div>
    </section>
  </div>

  <!-- CISA Digest -->
  <div class="span2">
    <section class="s-amber">
      <div class="sh"><span class="dot da"></span><h2>CISA Vulnerability Digest</h2></div>
      <div class="sb ai-text">{cisa_html}</div>
      <div class="sec-foot">
        <a href="https://www.cisa.gov/topics/industrial-control-systems" target="_blank" rel="noopener">CISA ICS &#8599;</a>
      </div>
    </section>
  </div>

  <!-- CISA KEV Table -->
  <div class="span2">
    <section class="s-red">
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
      <div class="sec-foot">
        <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">CISA KEV Catalog &#8599;</a>
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


# ── Mock Data ─────────────────────────────────────────────────────────────────

_MOCK_SUMMARIES: dict[str, Any] = {
    "threat_level": "green",
    "threat_summary": "Quiet day on the threat front — one routine Siemens advisory issued, no active exploitation reported in OT environments.",
    "news_summary": (
        "ABB has announced a new generation of its System 800xA DCS with native edge computing nodes, allowing plant-floor analytics to run without routing data to the cloud — a significant shift for sites with strict data sovereignty requirements. "
        "Emerson's latest release of DeltaV v16 introduces adaptive PID auto-tuning that observes closed-loop behaviour during normal operation and adjusts parameters without requiring a dedicated bump test, cutting commissioning time on new loops by an estimated 60%. "
        "A study published in Control Engineering found that poorly tuned PID loops account for roughly 30% of energy waste in pumping systems across the process industries, with most loops running in manual or with integral windup issues that go undetected for years. "
        "Honeywell has released a retrofit wireless transmitter kit for its legacy ST 3000 pressure range that communicates over WirelessHART, extending the service life of installed bases without panel or cabling changes. "
        "Automation World reports that several large food and beverage producers are trialling AI-based soft sensors to infer product quality from existing process measurements, reducing reliance on lab sampling intervals that can lag the process by hours."
    ),
    "cisa_summary": (
        "This month's OT-relevant KEV additions are limited in scope: one Siemens advisory covers a denial-of-service condition in older S7-300 firmware that requires local network access to trigger, and a Moxa entry affects serial device servers running end-of-life firmware with no available patch. "
        "Neither has been linked to active ransomware campaigns and both require proximity to the control network to exploit. "
        "The practical action for most sites is to confirm the affected firmware versions against your asset inventory and note the Moxa devices for replacement planning in the next maintenance window."
    ),
    "interesting_fact": (
        "The PID controller was first described mathematically by Nicolas Minorsky in 1922 while studying automatic ship steering for the US Navy — he observed that a skilled helmsman corrects not just for current heading error but also anticipates drift, which maps directly to the derivative term. "
        "Despite being over a century old, PID remains the dominant control algorithm in industry, with estimates suggesting it handles more than 95% of all closed-loop control in the process industries worldwide."
    ),
    "tech_spotlight": (
        "Model Predictive Control (MPC) has moved well beyond its origins in refinery optimisation and is now being deployed on mid-tier DCS platforms for applications like boiler combustion, compressor anti-surge, and batch reactor temperature — tasks previously handled by standalone PID loops with override logic. "
        "The key advantage for controls engineers is that MPC handles multivariable interactions explicitly: instead of tuning three separate loops that fight each other, a single MPC controller coordinates all three manipulated variables against a set of constraints simultaneously. "
        "Modern implementations from vendors like Emerson, Honeywell, and ABB run directly on the DCS controller card, removing the need for a separate optimisation server and making MPC practical for sites without a dedicated advanced controls team."
    ),
    "standards_watch": (
        "IEC 61511 Edition 2 Amendment 1 has been published, clarifying how AI-based systems can be used within a Safety Instrumented System — specifically restricting ML models from acting as the final element in a safety function but permitting their use for diagnostics and proof-test scheduling. "
        "ISA-101 on HMI design has been gaining traction in new plant projects, with several EPC contractors now mandating high-performance HMI principles (muted colours, abnormal situation highlighting) as a standard deliverable in FEED packages. "
        "The IEC 60079 series covering equipment for explosive atmospheres is mid-revision, with the working group proposing updates to intrinsic safety calculations to better account for modern lithium battery chemistries used in wireless field devices."
    ),
    "incident_of_week": (
        "In late 2023, a petrochemical plant in South Korea experienced an unplanned shutdown of a distillation column after a level transmitter impulse line froze during an unseasonably cold snap — the transmitter continued to output a steady mid-range signal rather than a fault indication, and the control system had no means to distinguish a frozen impulse line from a genuine process reading. "
        "Operators noticed the anomaly only when a downstream flow meter showed feed had stopped, by which time the column had flooded and required a 36-hour recovery. "
        "Key lessons: impulse line heat tracing interlocks should be monitored in the DCS alarm system, transmitter diagnostics such as HART device status should be wired into the asset management system and acted on, and critical level loops in cold climates should have redundant measurement principles such as pairing a dp transmitter with a guided wave radar."
    ),
    "morning_briefing": (
        "The most important development for controls engineers today is ABB's System 800xA edge compute release, which shifts analytics capability directly onto the controller chassis and removes the cloud dependency that has blocked DCS modernisation at data-sensitive and air-gapped sites. "
        "This directly challenges Emerson and Honeywell's edge strategies and is likely to accelerate competitive responses from both vendors in the coming months. "
        "If your site is evaluating a DCS refresh or greenfield build within the next 18 months, request a benchmark demo before finalising your vendor shortlist — early adopters typically have more leverage on licensing terms than they will once the product is established."
    ),
    "engineering_curiosity": (
        "The pneumatic controller — the direct mechanical ancestor of today's PID — performed all three control actions using only air pressure, springs, and bellows, with no electronics whatsoever. "
        "Developed in the 1930s by companies like Fisher Controls and Taylor Instruments, these devices used tiny air pressure changes of a few PSI through copper tubing to carry signals across the plant floor, with proportional band and integral time set physically by adjusting spring tensions and restrictor sizes — the original tuning knobs. "
        "They were so reliable that several major oil refineries ran pneumatic controllers continuously for over 60 years before finally converting to electronic DCS systems, with some units reportedly still operational into the 2000s."
    ),
}

_MOCK_ARTICLES = [
    {"source": "Control Engineering",  "title": "ABB System 800xA Next Generation Brings Edge Computing to the DCS", "link": "#", "summary": "ABB's updated 800xA platform embeds edge compute nodes directly into the controller chassis, enabling real-time analytics and soft sensor calculations without cloud connectivity. The architecture targets sites with data sovereignty constraints and high-latency network connections.", "published": "2026-04-23"},
    {"source": "Automation World",     "title": "Emerson DeltaV v16 Adds Adaptive PID Auto-Tuning During Normal Operation", "link": "#", "summary": "The new release eliminates the need for open-loop bump tests by observing closed-loop variability and adjusting PID parameters on the fly. Early adopters report commissioning time reductions of over 50% on new loop installations.", "published": "2026-04-23"},
    {"source": "Control Engineering",  "title": "Study: 30% of Pumping System Energy Waste Traced to Poorly Tuned PID Loops", "link": "#", "summary": "A multi-site audit across 14 process facilities found that integral windup and manual overrides on flow and pressure loops were the leading causes of avoidable energy consumption in pumping systems. The authors recommend a structured loop audit programme as a low-cost energy reduction initiative.", "published": "2026-04-22"},
    {"source": "Automation World",     "title": "AI Soft Sensors Reduce Lab Sampling Dependency in Food and Beverage", "link": "#", "summary": "Several major producers are using machine learning models trained on existing process historian data to infer product quality in near real-time, replacing hourly lab grabs with continuous estimates. The approach is proving most effective for viscosity and concentration measurements.", "published": "2026-04-22"},
    {"source": "CISA ICS Advisories",  "title": "ICSA-26-113-01: Siemens S7-300 Denial of Service via Crafted Packet", "link": "#", "summary": "A denial-of-service vulnerability in Siemens S7-300 PLC firmware versions prior to v3.3.17 allows a network-adjacent attacker to cause a CPU stop condition by sending a malformed S7 communication packet. Siemens recommends updating firmware and restricting network access to the PLC.", "published": "2026-04-23"},
    {"source": "SecurityWeek",         "title": "Honeywell Wireless Retrofit Kit Extends ST 3000 Transmitter Life by a Decade", "link": "#", "summary": "The new WirelessHART adapter clips onto existing ST 3000 pressure transmitters without wiring changes, adding remote configuration and diagnostic capability to installed bases that would otherwise require full replacement. Battery life is rated at five years under standard polling intervals.", "published": "2026-04-21"},
    {"source": "Automation World",     "title": "MPC Deployments Expanding Beyond Refining Into Mid-Tier Process Applications", "link": "#", "summary": "Model predictive control is being adopted for boiler combustion optimisation, compressor anti-surge, and batch reactor control at sites that previously considered it out of reach. Tighter integration with modern DCS platforms has removed the need for standalone optimisation servers.", "published": "2026-04-21"},
]

_MOCK_KEV = [
    {"cveID": "CVE-2026-0041", "dateAdded": "2026-04-23", "vendorProject": "Siemens", "product": "S7-300 PLC", "vulnerabilityName": "Siemens S7-300 Denial of Service via Crafted Packet", "shortDescription": "Malformed S7 communication packet causes CPU stop condition on affected firmware versions.", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-0038", "dateAdded": "2026-04-18", "vendorProject": "Moxa", "product": "NPort 5000 Series", "vulnerabilityName": "Moxa NPort End-of-Life Firmware Unauthenticated Access", "shortDescription": "End-of-life firmware on NPort serial device servers allows unauthenticated configuration changes. No patch available.", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-0031", "dateAdded": "2026-04-10", "vendorProject": "Rockwell Automation", "product": "Logix 5000", "vulnerabilityName": "Rockwell Logix 5000 EtherNet/IP Message Handling Flaw", "shortDescription": "Improper handling of malformed EtherNet/IP messages can cause a major fault requiring a manual controller restart.", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-0024", "dateAdded": "2026-04-04", "vendorProject": "Schneider Electric", "product": "EcoStruxure Operator Terminal Expert", "vulnerabilityName": "Schneider HMI Project File Path Traversal", "shortDescription": "A path traversal flaw in project file import allows an attacker to write arbitrary files to the HMI engineering workstation.", "knownRansomwareCampaignUse": "Unknown"},
]


# ── Entry Point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Controls Engineering Dashboard Generator")
    parser.add_argument("--mock", action="store_true", help="Skip API calls and use placeholder data (fast local iteration)")
    args = parser.parse_args()

    if args.mock:
        print("Mock mode — skipping RSS, CISA, and Claude calls.")
        articles   = _MOCK_ARTICLES
        cisa_vulns = _MOCK_KEV
        summaries  = _MOCK_SUMMARIES
    else:
        if anthropic is None or feedparser is None:
            print("Error: run  pip install anthropic feedparser  first.", file=sys.stderr)
            sys.exit(1)

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
