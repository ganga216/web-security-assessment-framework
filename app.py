import streamlit as st
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import time

from modules.recon import gather_info
from modules.fingerprint import fingerprint
from modules.headers import analyze_headers
from modules.attack_surface import discover_attack_surface
from modules.risk_engine import calculate_score
from modules.owasp_mapper import map_owasp
from modules.mitre_mapper import map_mitre
from modules.recommendations import generate_recommendations
from modules.summary import generate_summary

# ─── PAGE CONFIG ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebSec Assessment Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── DARK SOC THEME ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Exo+2:wght@300;400;600;700&display=swap');

    /* Base */
    html, body, [class*="css"] {
        font-family: 'Exo 2', sans-serif;
        background-color: #050d1a;
        color: #c8d8e8;
    }

    .stApp {
        background: linear-gradient(135deg, #050d1a 0%, #0a1628 50%, #050d1a 100%);
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #070f1e 0%, #0c1830 100%);
        border-right: 1px solid #1a3a5c;
    }
    [data-testid="stSidebar"] * { color: #a8c8e8 !important; }

    /* Main header */
    .soc-header {
        background: linear-gradient(90deg, #0a1f3d 0%, #0d2847 50%, #0a1f3d 100%);
        border: 1px solid #1e4d8c;
        border-radius: 8px;
        padding: 20px 28px;
        margin-bottom: 24px;
        position: relative;
        overflow: hidden;
    }
    .soc-header::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, #00c8ff, #0080ff, #00c8ff, transparent);
        animation: scan 3s linear infinite;
    }
    @keyframes scan {
        0% { transform: translateX(-100%); }
        100% { transform: translateX(100%); }
    }
    .soc-title {
        font-family: 'Rajdhani', sans-serif;
        font-size: 2rem;
        font-weight: 700;
        color: #00d4ff;
        letter-spacing: 3px;
        text-transform: uppercase;
        margin: 0;
    }
    .soc-subtitle {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.75rem;
        color: #5a8ab0;
        letter-spacing: 2px;
        margin-top: 4px;
    }
    .status-badge {
        display: inline-block;
        padding: 3px 12px;
        border-radius: 20px;
        font-size: 0.7rem;
        font-family: 'Share Tech Mono', monospace;
        letter-spacing: 1px;
        font-weight: 600;
    }
    .badge-online { background: #0a3a1a; color: #00e676; border: 1px solid #00e676; }
    .badge-scanning { background: #1a2a00; color: #aeea00; border: 1px solid #aeea00; }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #0a1e38 0%, #0d2545 100%);
        border: 1px solid #1a3f6f;
        border-radius: 10px;
        padding: 18px 20px;
        position: relative;
        overflow: hidden;
        transition: border-color 0.3s;
    }
    .metric-card::after {
        content: '';
        position: absolute;
        bottom: 0; left: 0; right: 0;
        height: 2px;
    }
    .metric-card.critical::after { background: #ff1744; }
    .metric-card.high::after { background: #ff6d00; }
    .metric-card.medium::after { background: #ffd600; }
    .metric-card.low::after { background: #00e676; }
    .metric-card.score::after { background: linear-gradient(90deg, #0080ff, #00d4ff); }

    .metric-label {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.68rem;
        color: #4a7ab0;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 8px;
    }
    .metric-value {
        font-family: 'Rajdhani', sans-serif;
        font-size: 2.6rem;
        font-weight: 700;
        line-height: 1;
    }
    .metric-value.critical { color: #ff4444; }
    .metric-value.high { color: #ff8c00; }
    .metric-value.medium { color: #ffd700; }
    .metric-value.low { color: #00e676; }
    .metric-value.score { color: #00d4ff; }

    /* Section headers */
    .section-header {
        font-family: 'Rajdhani', sans-serif;
        font-size: 1.1rem;
        font-weight: 600;
        color: #00d4ff;
        letter-spacing: 2px;
        text-transform: uppercase;
        padding: 10px 0 10px 14px;
        border-left: 3px solid #0066cc;
        margin: 24px 0 16px 0;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    /* Finding rows */
    .finding-row {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 6px;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.82rem;
        border: 1px solid transparent;
        transition: all 0.2s;
    }
    .finding-row.HIGH {
        background: rgba(255, 23, 68, 0.06);
        border-color: rgba(255, 23, 68, 0.25);
        color: #ff6b8a;
    }
    .finding-row.MEDIUM {
        background: rgba(255, 214, 0, 0.06);
        border-color: rgba(255, 214, 0, 0.2);
        color: #ffd700;
    }
    .finding-row.LOW {
        background: rgba(0, 230, 118, 0.04);
        border-color: rgba(0, 230, 118, 0.15);
        color: #69f0ae;
    }
    .severity-tag {
        font-size: 0.65rem;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 3px;
        letter-spacing: 1px;
        white-space: nowrap;
    }
    .tag-HIGH { background: rgba(255,23,68,0.2); color: #ff4444; border: 1px solid #ff4444; }
    .tag-MEDIUM { background: rgba(255,214,0,0.15); color: #ffd700; border: 1px solid #ffd700; }
    .tag-LOW { background: rgba(0,230,118,0.1); color: #00e676; border: 1px solid #00e676; }

    /* OWASP/MITRE cards */
    .map-card {
        background: linear-gradient(135deg, #091828 0%, #0c2038 100%);
        border: 1px solid #1a3a5c;
        border-radius: 8px;
        padding: 14px 16px;
        margin-bottom: 8px;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.8rem;
        color: #88b8d8;
    }
    .map-card .label {
        font-size: 0.65rem;
        color: #4a7ab0;
        letter-spacing: 1px;
        margin-bottom: 4px;
    }
    .map-card .value {
        color: #b8d8f0;
    }

    /* Recommendation cards */
    .rec-card {
        background: linear-gradient(135deg, #091a12 0%, #0c2218 100%);
        border: 1px solid #1a4a2a;
        border-left: 3px solid #00e676;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 8px;
        font-size: 0.85rem;
        color: #80d8a0;
    }

    /* Summary box */
    .summary-box {
        background: linear-gradient(135deg, #0a1f3d 0%, #0d2847 100%);
        border: 1px solid #1e4d8c;
        border-radius: 10px;
        padding: 20px 24px;
        font-family: 'Exo 2', sans-serif;
        color: #a8cce8;
        line-height: 1.7;
    }
    .summary-box .risk-level {
        font-family: 'Rajdhani', sans-serif;
        font-size: 1.2rem;
        font-weight: 600;
        margin-bottom: 8px;
    }

    /* Tech fingerprint */
    .tech-tag {
        display: inline-block;
        background: rgba(0, 128, 255, 0.12);
        border: 1px solid rgba(0, 128, 255, 0.3);
        border-radius: 4px;
        padding: 4px 12px;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.78rem;
        color: #80b8f0;
        margin: 4px 4px 4px 0;
    }

    /* Scan history table */
    .history-row {
        display: flex;
        align-items: center;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 4px;
        background: rgba(10, 30, 56, 0.5);
        border: 1px solid #122840;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.78rem;
        color: #7a9ab8;
        gap: 16px;
    }
    .history-row:hover { border-color: #1e4d8c; background: rgba(14, 35, 65, 0.7); }

    /* Input + button overrides */
    .stTextInput input {
        background: #0a1e38 !important;
        border: 1px solid #1a3f6f !important;
        border-radius: 6px !important;
        color: #c8d8e8 !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.9rem !important;
    }
    .stTextInput input:focus {
        border-color: #0080ff !important;
        box-shadow: 0 0 0 2px rgba(0,128,255,0.15) !important;
    }
    .stButton button {
        background: linear-gradient(135deg, #003880 0%, #0055cc 100%) !important;
        color: #ffffff !important;
        border: 1px solid #0066ff !important;
        border-radius: 6px !important;
        font-family: 'Rajdhani', sans-serif !important;
        font-weight: 600 !important;
        font-size: 1rem !important;
        letter-spacing: 1px !important;
        padding: 6px 20px !important;
        transition: all 0.2s !important;
        text-transform: uppercase !important;
    }
    .stButton button:hover {
        background: linear-gradient(135deg, #0044a0 0%, #0066e8 100%) !important;
        box-shadow: 0 0 20px rgba(0,128,255,0.3) !important;
    }
    .stDownloadButton button {
        background: linear-gradient(135deg, #002a14 0%, #004020 100%) !important;
        border: 1px solid #00aa55 !important;
        color: #00e676 !important;
        font-family: 'Rajdhani', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: 1px !important;
        text-transform: uppercase !important;
    }

    /* Plotly charts dark background */
    .js-plotly-plot { background: transparent !important; }

    /* Progress bar */
    .stProgress > div > div { background: linear-gradient(90deg, #0066ff, #00d4ff) !important; }

    /* Divider */
    hr { border-color: #1a3a5c !important; }

    /* Sidebar nav items */
    .nav-item {
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 4px;
        cursor: pointer;
        font-family: 'Rajdhani', sans-serif;
        font-size: 0.95rem;
        font-weight: 600;
        letter-spacing: 1px;
        color: #6a9ab8;
        border: 1px solid transparent;
        transition: all 0.2s;
    }
    .nav-item.active, .nav-item:hover {
        background: rgba(0,100,255,0.1);
        border-color: rgba(0,100,255,0.3);
        color: #00d4ff;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #070f1e; }
    ::-webkit-scrollbar-thumb { background: #1a3f6f; border-radius: 3px; }

    /* Hide streamlit branding */
    #MainMenu, footer, header { visibility: hidden; }
    .block-container { padding: 1.5rem 2rem !important; }
</style>
""", unsafe_allow_html=True)

# ─── SESSION STATE ────────────────────────────────────────────────────────────
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "active_page" not in st.session_state:
    st.session_state.active_page = "Dashboard"

# ─── SIDEBAR ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 16px 0 24px 0;'>
        <div style='font-family: Rajdhani, sans-serif; font-size:1.4rem; font-weight:700;
                    color:#00d4ff; letter-spacing:3px;'>🛡️ WEBSEC</div>
        <div style='font-family: Share Tech Mono, monospace; font-size:0.65rem;
                    color:#3a6a9a; letter-spacing:2px; margin-top:4px;'>ASSESSMENT PLATFORM v2.0</div>
        <div style='margin-top:10px;'>
            <span class='status-badge badge-online'>● ONLINE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("<div style='font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#3a6a9a; letter-spacing:2px; padding:0 4px 8px 4px;'>NAVIGATION</div>", unsafe_allow_html=True)

    pages = [
        ("🖥️", "Dashboard"),
        ("🔍", "Scanner"),
        ("📊", "Analytics"),
        ("📋", "History"),
        ("📁", "Reports"),
    ]

    for icon, page in pages:
        is_active = st.session_state.active_page == page
        style = "background: rgba(0,100,255,0.12); border: 1px solid rgba(0,100,255,0.3); color: #00d4ff;" if is_active else "border: 1px solid transparent; color: #6a9ab8;"
        if st.button(f"{icon}  {page}", key=f"nav_{page}", use_container_width=True):
            st.session_state.active_page = page
            st.rerun()

    st.markdown("---")

    if st.session_state.scan_history:
        st.markdown("<div style='font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#3a6a9a; letter-spacing:2px; padding:0 4px 8px 4px;'>LAST SCAN</div>", unsafe_allow_html=True)
        last = st.session_state.scan_history[-1]
        score = last["score"]
        color = "#ff4444" if score < 40 else "#ffd700" if score < 70 else "#00e676"
        st.markdown(f"""
        <div style='padding:12px; background:rgba(10,30,56,0.5); border-radius:8px;
                    border:1px solid #1a3a5c; font-family:Share Tech Mono,monospace; font-size:0.75rem;'>
            <div style='color:#4a7ab0; font-size:0.65rem; margin-bottom:6px;'>TARGET</div>
            <div style='color:#88b8d8; word-break:break-all; margin-bottom:10px;'>{last["target"][:40]}</div>
            <div style='color:#4a7ab0; font-size:0.65rem; margin-bottom:4px;'>SCORE</div>
            <div style='font-family:Rajdhani,sans-serif; font-size:1.8rem; font-weight:700; color:{color};'>{score}/100</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='position:absolute; bottom:16px; left:0; right:0; text-align:center; font-family:Share Tech Mono,monospace; font-size:0.6rem; color:#1e3a5c; letter-spacing:1px;'>ANTHROPIC SOC TOOLS</div>", unsafe_allow_html=True)


# ─── HELPERS ─────────────────────────────────────────────────────────────────
def severity_color(score):
    if score >= 80: return "#00e676"
    if score >= 60: return "#ffd700"
    if score >= 40: return "#ff8c00"
    return "#ff4444"

def parse_severity(finding):
    if "[HIGH]" in finding: return "HIGH"
    if "[MEDIUM]" in finding: return "MEDIUM"
    if "[LOW]" in finding: return "LOW"
    return "INFO"

def make_gauge(score):
    color = severity_color(score)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"font": {"size": 52, "color": color, "family": "Rajdhani"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#2a5a8a", "tickfont": {"color": "#4a7ab0", "size": 10}},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "#0a1e38",
            "bordercolor": "#1a3f6f",
            "borderwidth": 1,
            "steps": [
                {"range": [0, 40],   "color": "rgba(255,23,68,0.08)"},
                {"range": [40, 60],  "color": "rgba(255,140,0,0.06)"},
                {"range": [60, 80],  "color": "rgba(255,214,0,0.05)"},
                {"range": [80, 100], "color": "rgba(0,230,118,0.06)"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.8, "value": score},
        },
        title={"text": "SECURITY SCORE", "font": {"size": 13, "color": "#4a7ab0", "family": "Share Tech Mono"}},
        domain={"x": [0, 1], "y": [0, 1]}
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=30, r=30, t=60, b=20), height=260,
        font={"family": "Exo 2"}
    )
    return fig

def make_severity_bar(high, medium, low):
    fig = go.Figure()
    categories = ["HIGH", "MEDIUM", "LOW"]
    values = [high, medium, low]
    colors = ["#ff1744", "#ffd600", "#00e676"]
    for cat, val, col in zip(categories, values, colors):
        fig.add_trace(go.Bar(
            name=cat, x=[cat], y=[val],
            marker_color=col, marker_line_color=col,
            marker_line_width=1, opacity=0.85,
            text=[val], textposition="outside",
            textfont={"color": col, "family": "Rajdhani", "size": 18},
        ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False, margin=dict(l=10, r=10, t=30, b=10), height=220,
        xaxis={"showgrid": False, "tickfont": {"color": "#4a7ab0", "family": "Share Tech Mono"}, "linecolor": "#1a3a5c"},
        yaxis={"showgrid": True, "gridcolor": "#1a3a5c", "tickfont": {"color": "#4a7ab0"}, "linecolor": "#1a3a5c"},
        barmode="group",
    )
    return fig

def make_owasp_radar(owasp_items):
    owasp_categories = [
        "A01: Broken Access", "A02: Crypto Failures", "A03: Injection",
        "A04: Insecure Design", "A05: Misconfiguration", "A06: Vuln Components",
        "A07: Auth Failures", "A08: Integrity Failures",
    ]
    scores = []
    for cat in owasp_categories:
        hit = any(cat.split(":")[1].strip() in item or cat.split(" ")[0] in item for item in owasp_items)
        scores.append(8 if hit else 1)

    fig = go.Figure(go.Scatterpolar(
        r=scores,
        theta=owasp_categories,
        fill="toself",
        fillcolor="rgba(255,23,68,0.08)",
        line={"color": "#ff4444", "width": 2},
        marker={"color": "#ff1744", "size": 6},
    ))
    fig.update_layout(
        polar={
            "bgcolor": "rgba(5,13,26,0.8)",
            "radialaxis": {"visible": True, "range": [0, 10], "gridcolor": "#1a3a5c", "tickcolor": "#1a3a5c", "tickfont": {"color": "#3a6a9a", "size": 9}},
            "angularaxis": {"gridcolor": "#1a3a5c", "tickcolor": "#4a7ab0", "tickfont": {"color": "#5a8ab0", "size": 10}},
        },
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=40, r=40, t=30, b=30),
        height=320,
        showlegend=False,
    )
    return fig

def make_attack_surface_chart(surface):
    labels = ["Forms", "Inputs", "Links"]
    vals = [surface.get("forms", 0), surface.get("inputs", 0), surface.get("links", 0)]
    colors = ["#0066ff", "#00aaff", "#00d4ff"]
    fig = go.Figure(go.Bar(
        x=vals, y=labels, orientation="h",
        marker_color=colors, marker_line_color=colors,
        marker_line_width=1, opacity=0.8,
        text=vals, textposition="outside",
        textfont={"color": "#88b8d8", "family": "Rajdhani", "size": 16},
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=40, t=20, b=10), height=160,
        xaxis={"showgrid": True, "gridcolor": "#1a3a5c", "tickfont": {"color": "#4a7ab0"}, "linecolor": "#1a3a5c"},
        yaxis={"showgrid": False, "tickfont": {"color": "#88b8d8", "family": "Share Tech Mono", "size": 11}, "linecolor": "#1a3a5c"},
    )
    return fig

def make_score_history_chart(history):
    if not history:
        return None
    targets = [h["target"][:20] + "…" if len(h["target"]) > 20 else h["target"] for h in history]
    scores = [h["score"] for h in history]
    colors = [severity_color(s) for s in scores]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=list(range(len(scores))), y=scores,
        mode="lines+markers+text",
        line={"color": "#0080ff", "width": 2},
        marker={"color": colors, "size": 10, "line": {"color": "#050d1a", "width": 2}},
        text=scores, textposition="top center",
        textfont={"color": "#88b8d8", "family": "Rajdhani", "size": 13},
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=20, b=40), height=220,
        xaxis={"showgrid": False, "tickvals": list(range(len(targets))), "ticktext": targets,
               "tickfont": {"color": "#4a7ab0", "family": "Share Tech Mono", "size": 9},
               "tickangle": -20, "linecolor": "#1a3a5c"},
        yaxis={"range": [0, 105], "showgrid": True, "gridcolor": "#1a3a5c",
               "tickfont": {"color": "#4a7ab0"}, "linecolor": "#1a3a5c"},
        showlegend=False,
    )
    return fig

def run_scan(url):
    """Execute all scan modules and return consolidated result dict."""
    progress = st.progress(0)
    status = st.empty()

    steps = [
        (10, "🔍 Initializing recon..."),
        (25, "🌐 Gathering target intelligence..."),
        (40, "🔬 Fingerprinting technologies..."),
        (55, "🛡️ Analyzing security headers..."),
        (70, "🕵️ Mapping attack surface..."),
        (82, "⚖️ Calculating risk score..."),
        (90, "🗺️ Mapping OWASP & MITRE..."),
        (97, "📝 Generating report..."),
        (100, "✅ Scan complete"),
    ]

    for pct, msg in steps:
        status.markdown(f"<div style='font-family:Share Tech Mono,monospace; font-size:0.8rem; color:#4a9ab8;'>{msg}</div>", unsafe_allow_html=True)
        progress.progress(pct)
        time.sleep(0.3)

    data = gather_info(url)
    if "error" in data:
        progress.empty(); status.empty()
        return None, data["error"]

    tech = fingerprint(data["headers"])
    findings = analyze_headers(data["headers"])
    surface = discover_attack_surface(url)

    score = calculate_score(findings, {"links": surface.get("links", 0)})
    owasp = map_owasp(findings)
    mitre = map_mitre(findings)
    recommendations = generate_recommendations(findings)
    summary = generate_summary(score)

    progress.empty(); status.empty()

    result = {
        "target": url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status_code": data["status_code"],
        "tech": tech,
        "findings": findings,
        "surface": surface,
        "score": score,
        "owasp": owasp,
        "mitre": mitre,
        "recommendations": recommendations,
        "summary": summary,
    }
    return result, None


# ─── MAIN HEADER ─────────────────────────────────────────────────────────────
st.markdown("""
<div class='soc-header'>
    <div style='display:flex; justify-content:space-between; align-items:center;'>
        <div>
            <div class='soc-title'>🛡️ WebSec Assessment Platform</div>
            <div class='soc-subtitle'>ENTERPRISE SECURITY INTELLIGENCE FRAMEWORK — SOC EDITION</div>
        </div>
        <div style='text-align:right;'>
            <span class='status-badge badge-online'>● SYSTEM ONLINE</span>
            <div style='font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#2a5a8a; margin-top:6px;'>""" + datetime.now().strftime("%Y-%m-%d %H:%M") + """</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
if st.session_state.active_page == "Dashboard":
    if not st.session_state.last_result:
        st.markdown("""
        <div style='text-align:center; padding: 60px 20px;'>
            <div style='font-size:4rem; margin-bottom:16px;'>🔭</div>
            <div style='font-family:Rajdhani,sans-serif; font-size:1.8rem; font-weight:600; color:#1e4d8c; letter-spacing:2px;'>NO SCAN DATA</div>
            <div style='font-family:Share Tech Mono,monospace; font-size:0.8rem; color:#1a3a5c; margin-top:8px; letter-spacing:1px;'>Run a scan from the Scanner tab to populate the dashboard</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        r = st.session_state.last_result
        high   = len([f for f in r["findings"] if "[HIGH]" in f])
        medium = len([f for f in r["findings"] if "[MEDIUM]" in f])
        low    = len([f for f in r["findings"] if "[LOW]" in f])

        # KPI metrics row
        c1, c2, c3, c4, c5 = st.columns(5)
        for col, label, val, cls in [
            (c1, "SECURITY SCORE", r["score"], "score"),
            (c2, "CRITICAL HIGH", high, "critical"),
            (c3, "MEDIUM RISK", medium, "medium"),
            (c4, "LOW RISK", low, "low"),
            (c5, "TOTAL FINDINGS", len(r["findings"]), "score"),
        ]:
            col.markdown(f"""
            <div class='metric-card {cls}'>
                <div class='metric-label'>{label}</div>
                <div class='metric-value {cls}'>{val}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Gauge + Severity bar
        col_g, col_b, col_r = st.columns([1.2, 1, 1])
        with col_g:
            st.markdown("<div class='section-header'>📡 RISK GAUGE</div>", unsafe_allow_html=True)
            st.plotly_chart(make_gauge(r["score"]), use_container_width=True, config={"displayModeBar": False})
        with col_b:
            st.markdown("<div class='section-header'>📊 SEVERITY BREAKDOWN</div>", unsafe_allow_html=True)
            st.plotly_chart(make_severity_bar(high, medium, low), use_container_width=True, config={"displayModeBar": False})
        with col_r:
            st.markdown("<div class='section-header'>🌐 ATTACK SURFACE</div>", unsafe_allow_html=True)
            st.plotly_chart(make_attack_surface_chart(r["surface"]), use_container_width=True, config={"displayModeBar": False})
            for key, icon in [("forms","📋"), ("inputs","🔡"), ("links","🔗")]:
                v = r["surface"].get(key, 0)
                st.markdown(f"<div style='font-family:Share Tech Mono,monospace; font-size:0.78rem; color:#5a8ab0; padding:2px 0;'>{icon} {key.upper()}: <span style='color:#88b8d8;'>{v}</span></div>", unsafe_allow_html=True)

        # OWASP + Target info
        col_o, col_t = st.columns([1.3, 1])
        with col_o:
            st.markdown("<div class='section-header'>🕸️ OWASP RADAR</div>", unsafe_allow_html=True)
            st.plotly_chart(make_owasp_radar(r["owasp"]), use_container_width=True, config={"displayModeBar": False})
        with col_t:
            st.markdown("<div class='section-header'>🎯 TARGET SUMMARY</div>", unsafe_allow_html=True)
            sc = r["score"]
            risk_label = "CRITICAL" if sc < 40 else "HIGH" if sc < 60 else "MODERATE" if sc < 80 else "LOW"
            risk_color = "#ff1744" if sc < 40 else "#ff8c00" if sc < 60 else "#ffd700" if sc < 80 else "#00e676"
            st.markdown(f"""
            <div class='summary-box'>
                <div class='risk-level' style='color:{risk_color};'>⚠️ RISK LEVEL: {risk_label}</div>
                <div style='font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#3a6a9a; margin-bottom:12px;'>
                    {r['timestamp']}
                </div>
                <div style='color:#88b8d8; font-size:0.82rem; word-break:break-all; margin-bottom:10px;'>
                    🎯 {r['target']}
                </div>
                <div style='color:#5a8ab0; font-size:0.8rem; margin-bottom:12px;'>
                    HTTP {r.get('status_code','N/A')} · {len(r['findings'])} findings · {len(r['recommendations'])} recommendations
                </div>
                <div style='border-top:1px solid #1a3a5c; padding-top:12px; color:#a8c8e0; font-size:0.85rem; line-height:1.6;'>
                    {r['summary']}
                </div>
            </div>
            """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SCANNER
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.active_page == "Scanner":
    st.markdown("<div class='section-header'>🔍 TARGET SCANNER</div>", unsafe_allow_html=True)

    col_in, col_btn = st.columns([4, 1])
    with col_in:
        url = st.text_input("", placeholder="https://target-domain.com", label_visibility="collapsed")
    with col_btn:
        scan_clicked = st.button("⚡ SCAN", use_container_width=True)

    if scan_clicked:
        if not url:
            st.warning("Enter a target URL to begin assessment.")
        else:
            st.markdown(f"""
            <div style='padding:12px 16px; background:rgba(0,40,100,0.2); border:1px solid #1a3a5c;
                        border-radius:8px; margin-bottom:16px; font-family:Share Tech Mono,monospace; font-size:0.8rem;'>
                <span style='color:#3a6a9a;'>TARGET:</span>
                <span style='color:#00d4ff; margin-left:8px;'>{url}</span>
                <span class='status-badge badge-scanning' style='float:right;'>● SCANNING</span>
            </div>
            """, unsafe_allow_html=True)

            result, err = run_scan(url)

            if err:
                st.error(f"Scan failed: {err}")
            else:
                st.session_state.last_result = result
                st.session_state.scan_history.append(result)

                high   = len([f for f in result["findings"] if "[HIGH]" in f])
                medium = len([f for f in result["findings"] if "[MEDIUM]" in f])
                low    = len([f for f in result["findings"] if "[LOW]" in f])

                # KPIs
                c1, c2, c3, c4 = st.columns(4)
                for col, lbl, val, cls in [
                    (c1, "SECURITY SCORE", result["score"], "score"),
                    (c2, "HIGH SEVERITY", high, "critical"),
                    (c3, "MEDIUM SEVERITY", medium, "medium"),
                    (c4, "LOW SEVERITY", low, "low"),
                ]:
                    col.markdown(f"""
                    <div class='metric-card {cls}'>
                        <div class='metric-label'>{lbl}</div>
                        <div class='metric-value {cls}'>{val}</div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # Gauge + findings side-by-side
                cg, cf = st.columns([1, 1.8])
                with cg:
                    st.markdown("<div class='section-header'>📡 RISK GAUGE</div>", unsafe_allow_html=True)
                    st.plotly_chart(make_gauge(result["score"]), use_container_width=True, config={"displayModeBar": False})
                with cf:
                    st.markdown("<div class='section-header'>⚠️ FINDINGS</div>", unsafe_allow_html=True)
                    for finding in result["findings"]:
                        sev = parse_severity(finding)
                        text = finding.replace(f"[{sev}] ", "")
                        st.markdown(f"""
                        <div class='finding-row {sev}'>
                            <span class='severity-tag tag-{sev}'>{sev}</span>
                            <span>{text}</span>
                        </div>
                        """, unsafe_allow_html=True)

                # Tech fingerprint
                if result["tech"]:
                    st.markdown("<div class='section-header'>🔬 TECHNOLOGY FINGERPRINT</div>", unsafe_allow_html=True)
                    tags_html = "".join(f"<span class='tech-tag'>{t}</span>" for t in result["tech"])
                    st.markdown(f"<div>{tags_html}</div>", unsafe_allow_html=True)

                st.markdown("<div class='section-header'>💡 RECOMMENDATIONS</div>", unsafe_allow_html=True)
                for rec in result["recommendations"]:
                    st.markdown(f"<div class='rec-card'>✅ {rec}</div>", unsafe_allow_html=True)

                # Download JSON report
                report_data = {
                    "target": result["target"],
                    "timestamp": result["timestamp"],
                    "status_code": result.get("status_code"),
                    "score": result["score"],
                    "findings": result["findings"],
                    "attack_surface": result["surface"],
                    "owasp": result["owasp"],
                    "mitre": result["mitre"],
                    "recommendations": result["recommendations"],
                    "executive_summary": result["summary"],
                }
                st.markdown("<br>", unsafe_allow_html=True)
                st.download_button(
                    "⬇️ DOWNLOAD JSON REPORT",
                    json.dumps(report_data, indent=4),
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                )

                st.success(f"✅ Assessment complete — navigate to **Dashboard** for full analytics.")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: ANALYTICS
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.active_page == "Analytics":
    if not st.session_state.last_result:
        st.info("Run a scan first to view analytics.")
    else:
        r = st.session_state.last_result

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("<div class='section-header'>🕸️ OWASP TOP 10 RADAR</div>", unsafe_allow_html=True)
            st.plotly_chart(make_owasp_radar(r["owasp"]), use_container_width=True, config={"displayModeBar": False})

            st.markdown("<div class='section-header'>🗺️ OWASP MAPPING</div>", unsafe_allow_html=True)
            for item in r["owasp"]:
                st.markdown(f"""
                <div class='map-card'>
                    <div class='label'>OWASP CATEGORY</div>
                    <div class='value'>🔴 {item}</div>
                </div>
                """, unsafe_allow_html=True)

        with col2:
            high   = len([f for f in r["findings"] if "[HIGH]" in f])
            medium = len([f for f in r["findings"] if "[MEDIUM]" in f])
            low    = len([f for f in r["findings"] if "[LOW]" in f])
            st.markdown("<div class='section-header'>📊 SEVERITY DISTRIBUTION</div>", unsafe_allow_html=True)
            st.plotly_chart(make_severity_bar(high, medium, low), use_container_width=True, config={"displayModeBar": False})

            st.markdown("<div class='section-header'>🗡️ MITRE ATT&CK TECHNIQUES</div>", unsafe_allow_html=True)
            if r["mitre"]:
                for item in r["mitre"]:
                    tid = item.split(" - ")[0] if " - " in item else item
                    tname = item.split(" - ")[1] if " - " in item else ""
                    st.markdown(f"""
                    <div class='map-card'>
                        <div class='label'>TECHNIQUE ID</div>
                        <div class='value' style='color:#ff8888;'>{tid}
                            <span style='color:#6a9ab8; font-size:0.75rem;'> — {tname}</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("<div style='color:#2a5a8a; font-family:Share Tech Mono,monospace; font-size:0.8rem; padding:12px;'>No MITRE techniques mapped.</div>", unsafe_allow_html=True)

        # Full findings table
        st.markdown("<div class='section-header'>📋 FINDINGS DETAIL TABLE</div>", unsafe_allow_html=True)
        rows = []
        for f in r["findings"]:
            sev = parse_severity(f)
            text = f.replace(f"[{sev}] ", "")
            rows.append({"Severity": sev, "Finding": text, "Category": "Header Security"})
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Severity": st.column_config.TextColumn(width="small"),
                    "Finding": st.column_config.TextColumn(width="large"),
                    "Category": st.column_config.TextColumn(width="medium"),
                }
            )


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: HISTORY
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.active_page == "History":
    st.markdown("<div class='section-header'>📋 SCAN HISTORY</div>", unsafe_allow_html=True)

    if not st.session_state.scan_history:
        st.markdown("""
        <div style='text-align:center; padding:40px;'>
            <div style='font-size:2.5rem; margin-bottom:12px;'>🗂️</div>
            <div style='font-family:Rajdhani,sans-serif; font-size:1.2rem; color:#1e4d8c; letter-spacing:2px;'>NO SCAN HISTORY</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Score trend
        if len(st.session_state.scan_history) > 1:
            st.markdown("<div class='section-header'>📈 SCORE TREND</div>", unsafe_allow_html=True)
            chart = make_score_history_chart(st.session_state.scan_history)
            if chart:
                st.plotly_chart(chart, use_container_width=True, config={"displayModeBar": False})

        st.markdown("<div class='section-header'>🗃️ SCAN LOG</div>", unsafe_allow_html=True)
        for i, scan in enumerate(reversed(st.session_state.scan_history)):
            sc = scan["score"]
            col = severity_color(sc)
            high = len([f for f in scan["findings"] if "[HIGH]" in f])
            medium = len([f for f in scan["findings"] if "[MEDIUM]" in f])
            low = len([f for f in scan["findings"] if "[LOW]" in f])
            st.markdown(f"""
            <div class='history-row'>
                <span style='color:#2a5a8a; min-width:24px;'>#{len(st.session_state.scan_history) - i}</span>
                <span style='color:#88b8d8; flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis;'>{scan['target']}</span>
                <span style='color:#3a6a9a; font-size:0.7rem; white-space:nowrap;'>{scan['timestamp']}</span>
                <span style='color:#ff6b8a; white-space:nowrap;'>H:{high}</span>
                <span style='color:#ffd700; white-space:nowrap;'>M:{medium}</span>
                <span style='color:#69f0ae; white-space:nowrap;'>L:{low}</span>
                <span style='font-family:Rajdhani,sans-serif; font-size:1.1rem; font-weight:700; color:{col}; min-width:60px; text-align:right;'>{sc}/100</span>
            </div>
            """, unsafe_allow_html=True)

        if st.button("🗑️ Clear History"):
            st.session_state.scan_history = []
            st.session_state.last_result = None
            st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: REPORTS
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.active_page == "Reports":
    st.markdown("<div class='section-header'>📁 REPORT EXPORT</div>", unsafe_allow_html=True)

    if not st.session_state.last_result:
        st.info("No scan data available. Run a scan first.")
    else:
        r = st.session_state.last_result
        sc = r["score"]
        risk = "CRITICAL" if sc < 40 else "HIGH" if sc < 60 else "MODERATE" if sc < 80 else "LOW"
        risk_col = "#ff1744" if sc < 40 else "#ff8c00" if sc < 60 else "#ffd700" if sc < 80 else "#00e676"

        # Report preview
        st.markdown(f"""
        <div style='background: linear-gradient(135deg, #070f1e 0%, #0c1830 100%);
                    border: 1px solid #1a3a5c; border-radius:10px; padding:24px; margin-bottom:20px;'>
            <div style='font-family:Rajdhani,sans-serif; font-size:1.4rem; font-weight:700;
                        color:#00d4ff; letter-spacing:2px; margin-bottom:4px;'>SECURITY ASSESSMENT REPORT</div>
            <div style='font-family:Share Tech Mono,monospace; font-size:0.7rem; color:#3a6a9a; margin-bottom:20px;'>
                GENERATED: {r['timestamp']}
            </div>

            <div style='display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px;'>
                <div>
                    <div style='font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#3a6a9a; margin-bottom:4px;'>TARGET</div>
                    <div style='color:#88b8d8; font-size:0.85rem; word-break:break-all;'>{r['target']}</div>
                </div>
                <div>
                    <div style='font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#3a6a9a; margin-bottom:4px;'>RISK LEVEL</div>
                    <div style='font-family:Rajdhani,sans-serif; font-size:1rem; font-weight:700; color:{risk_col};'>{risk}</div>
                </div>
            </div>

            <div style='border-top:1px solid #1a3a5c; padding-top:16px;'>
                <div style='font-family:Share Tech Mono,monospace; font-size:0.65rem; color:#3a6a9a; margin-bottom:8px;'>EXECUTIVE SUMMARY</div>
                <div style='color:#a8c8e0; font-size:0.88rem; line-height:1.6;'>{r['summary']}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col_j, col_h = st.columns(2)

        with col_j:
            report_json = json.dumps({
                "report_metadata": {"generator": "WebSec Assessment Platform v2.0", "timestamp": r["timestamp"]},
                "target": r["target"],
                "status_code": r.get("status_code"),
                "security_score": r["score"],
                "risk_level": risk,
                "technologies": r["tech"],
                "findings": r["findings"],
                "attack_surface": r["surface"],
                "owasp_mapping": r["owasp"],
                "mitre_mapping": r["mitre"],
                "recommendations": r["recommendations"],
                "executive_summary": r["summary"],
            }, indent=4)
            st.download_button(
                "⬇️ DOWNLOAD JSON REPORT",
                report_json,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )

        with col_h:
            # HTML report
            html_report = f"""<!DOCTYPE html>
<html><head><meta charset='UTF-8'>
<title>Security Report - {r['target']}</title>
<style>
  body {{ font-family: monospace; background: #050d1a; color: #c8d8e8; margin: 0; padding: 32px; }}
  h1 {{ color: #00d4ff; font-size: 1.5rem; letter-spacing: 3px; border-bottom: 1px solid #1a3a5c; padding-bottom: 12px; }}
  h2 {{ color: #5a8ab0; font-size: 0.9rem; letter-spacing: 2px; margin-top: 28px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th {{ background: #0a1e38; color: #4a7ab0; padding: 8px 12px; text-align: left; font-size: 0.75rem; letter-spacing: 1px; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #122840; font-size: 0.85rem; }}
  .HIGH {{ color: #ff4444; }} .MEDIUM {{ color: #ffd700; }} .LOW {{ color: #00e676; }}
  .score {{ font-size: 2rem; font-weight: bold; color: {risk_col}; }}
</style></head><body>
<h1>🛡️ SECURITY ASSESSMENT REPORT</h1>
<p>Target: {r['target']}<br>Generated: {r['timestamp']}<br>Status: HTTP {r.get('status_code','N/A')}</p>
<p>Security Score: <span class='score'>{r['score']}/100</span> &nbsp; Risk: <span style='color:{risk_col};'>{risk}</span></p>
<h2>FINDINGS</h2>
<table><tr><th>SEVERITY</th><th>FINDING</th></tr>
{''.join(f"<tr><td class='{parse_severity(f)}'>{parse_severity(f)}</td><td>{f.replace(f'[{parse_severity(f)}] ','')}</td></tr>" for f in r['findings'])}
</table>
<h2>OWASP MAPPING</h2>
<ul>{''.join(f'<li>{o}</li>' for o in r['owasp'])}</ul>
<h2>MITRE ATT&CK</h2>
<ul>{''.join(f'<li>{m}</li>' for m in r['mitre'])}</ul>
<h2>RECOMMENDATIONS</h2>
<ul>{''.join(f'<li>{rec}</li>' for rec in r['recommendations'])}</ul>
<h2>EXECUTIVE SUMMARY</h2>
<p>{r['summary']}</p>
</body></html>"""
            st.download_button(
                "⬇️ DOWNLOAD HTML REPORT",
                html_report,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html",
                use_container_width=True,
            )

        # All scans export
        if len(st.session_state.scan_history) > 1:
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<div class='section-header'>📦 BULK EXPORT</div>", unsafe_allow_html=True)
            all_reports = json.dumps(st.session_state.scan_history, indent=4)
            st.download_button(
                f"⬇️ EXPORT ALL {len(st.session_state.scan_history)} SCANS",
                all_reports,
                file_name=f"all_scans_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json",
                use_container_width=True,
            )