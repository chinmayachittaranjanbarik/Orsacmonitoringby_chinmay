# orsac_monitor_ui.py
# ORSAC WEBSITE MONITORING DASHBOARD
# Headings: no glow, bold solid color + optional background pill; headline/background options in Appearance
import os
import sys
import logging
import subprocess
import yaml
import numpy as np
import pandas as pd
import streamlit as st
from datetime import datetime
from filelock import FileLock
from dotenv import load_dotenv, dotenv_values
from streamlit_echarts import st_echarts
from streamlit_autorefresh import st_autorefresh
from dateutil import parser as dateutil_parser
import math

# ==================================================================================================
# CORE CONFIGURATION & SETUP
# ==================================================================================================
try:
    env_vars = dotenv_values()
    for key, value in env_vars.items():
        if key is not None and value is not None:
            os.environ[key] = value
except Exception as e:
    logging.warning("Failed to load environment variables from .env: %s", e)

CONFIG_FILE = os.getenv("SITES_YAML", "sites.yaml")
LOG_FILE = os.getenv("LOG_FILE", "website_monitor_log.csv")
LOCK_FILE = LOG_FILE + ".lock"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))

IST_TZ = "Asia/Kolkata"
IST_LABEL = "IST"

# Runtime overrides
try:
    MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL", 1800))
except Exception:
    MONITOR_INTERVAL = 1800
try:
    SSL_ALERT_DAYS = int(os.getenv("SSL_ALERT_DAYS", 30))
except Exception:
    SSL_ALERT_DAYS = 30
try:
    RESPONSE_TIME_THRESHOLD = float(os.getenv("RESPONSE_TIME_THRESHOLD", 3000))
except Exception:
    RESPONSE_TIME_THRESHOLD = 3000.0
try:
    DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", 10))
except Exception:
    DEFAULT_TIMEOUT = 10

USE_ICMP_BY_DEFAULT = os.getenv("USE_ICMP_BY_DEFAULT", "true").lower() in ("1", "true", "yes")
START_BACKEND = os.getenv("START_BACKEND", "true").lower() in ("1", "true", "yes")

# Load YAML config
try:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f) or {}
except FileNotFoundError:
    config_data = {}
except Exception as e:
    st.error(f"Failed to read config '{CONFIG_FILE}': {e}")
    config_data = {}

sites = config_data.get("sites", []) or []
settings = config_data.get("settings", {}) or {}

# ------------------------------
# Helper: sanitize options to JSON-serializable types
# ------------------------------
def _to_native(x):
    """Convert numpy / pandas scalar to native python types."""
    if x is None:
        return None
    # pandas NaT -> None
    try:
        if pd.isna(x):
            return None
    except Exception:
        pass
    # numpy scalar types
    if isinstance(x, (np.integer, np.int64, np.int32)):
        return int(x)
    if isinstance(x, (np.floating, np.float64, np.float32)):
        return float(x)
    if isinstance(x, (np.bool_, bool)):
        return bool(x)
    # pandas Timestamp or datetime
    if isinstance(x, (pd.Timestamp, datetime)):
        try:
            return str(x)
        except Exception:
            return x.isoformat() if hasattr(x, "isoformat") else str(x)
    # numpy arrays
    if isinstance(x, np.ndarray):
        return [_to_native(y) for y in x.tolist()]
    # pandas Series
    if isinstance(x, pd.Series):
        return [_to_native(y) for y in x.tolist()]
    # other numbers/strings - ensure python types
    if isinstance(x, (int, float, str, bool)):
        return x
    # fallback - attempt to cast to Python primitive
    try:
        return int(x)
    except Exception:
        try:
            return float(x)
        except Exception:
            return str(x)

def sanitize_for_json(obj):
    """Recursively convert an object (dict/list) to JSON-serializable Python builtins."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[str(k)] = sanitize_for_json(v)
        return out
    elif isinstance(obj, list):
        return [sanitize_for_json(v) for v in obj]
    elif isinstance(obj, tuple):
        return [sanitize_for_json(v) for v in obj]
    else:
        return _to_native(obj)

# ------------------------------
# Backend Control Functions (Stable)
# ------------------------------
def run_monitor_in_background(instant_check=False):
    """Starts the backend script with optional instant check flag."""
    if 'monitor_process' in st.session_state and st.session_state.monitor_process.poll() is None:
        logging.info("Backend process is already running.")
        if instant_check:
            try:
                st.session_state.monitor_process.terminate()
                del st.session_state.monitor_process
                logging.info("Terminated existing background process for instant run.")
            except Exception as term_e:
                logging.warning("Could not terminate existing process: %s", term_e)
            st.rerun()
        return

    try:
        cmd = [sys.executable, "monitor_backend.py"]
        if instant_check:
            cmd.append("--run-now")
            logging.info("Starting instant check...")
            p = subprocess.Popen(cmd)
            p.wait()
            st.rerun()
        else:
            logging.info("Starting continuous backend monitor...")
            p = subprocess.Popen(cmd)
            st.session_state.monitor_process = p
            logging.info("Started monitor_backend.py with PID %s", p.pid)
    except Exception as e:
        st.error(f"Failed to start monitoring backend: {e}")
        logging.error("Failed to start backend: %s", e)

if START_BACKEND and 'monitor_process' not in st.session_state:
    run_monitor_in_background()

# ------------------------------
# Data Loading and Utility Functions (Stable)
# ------------------------------
def parse_dt_flexible_scalar(x):
    try:
        if pd.isna(x):
            return pd.NaT
        t = pd.to_datetime(x, utc=True, errors="coerce")
        if not pd.isna(t):
            return t
    except Exception:
        pass
    try:
        dt = dateutil_parser.parse(str(x), fuzzy=True)
        ts = pd.Timestamp(dt)
        ts = ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")
        return ts
    except Exception:
        return pd.NaT

def parse_dt_flexible_series(series):
    try:
        parsed = pd.to_datetime(series, utc=True, errors="coerce")
    except Exception:
        parsed = pd.Series([pd.NaT]*len(series), index=series.index)
    mask = parsed.isna()
    if mask.any():
        parsed_fallback = series[mask].apply(parse_dt_flexible_scalar)
        parsed.loc[mask] = parsed_fallback
    return parsed

def to_ist_string(ts):
    try:
        t = parse_dt_flexible_scalar(ts)
        if pd.isna(t):
            return "N/A"
        t_ist = t.tz_convert(IST_TZ)
        return t_ist.strftime("%Y-%m-%d %H:%M:%S ") + IST_LABEL
    except Exception:
        return str(ts)

@st.cache_data(ttl=20)
def load_data():
    if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
        return pd.DataFrame()
    try:
        with FileLock(LOCK_FILE, timeout=5):
            df = pd.read_csv(LOG_FILE, keep_default_na=True)
    except Exception:
        try:
            df = pd.read_csv(LOG_FILE, keep_default_na=True)
        except Exception:
            return pd.DataFrame()

    df.columns = df.columns.str.strip()
    if "DateTime" in df.columns:
        df["DateTime"] = parse_dt_flexible_series(df["DateTime"])
    for c in df.select_dtypes(include=["object"]).columns:
        df[c] = df[c].astype(str).str.strip().replace({"nan": ""})
    if "Status" not in df.columns: df["Status"] = "Unknown"
    if "Website Name" not in df.columns:
        if "Website" in df.columns: df = df.rename(columns={"Website": "Website Name"})
        elif "URL" in df.columns: df["Website Name"] = df["URL"].astype(str)
        else: df["Website Name"] = df.index.astype(str)
    
    if "SSL Expiry Date" in df.columns: df["SSL Expiry Date Parsed"] = parse_dt_flexible_series(df["SSL Expiry Date"])
    else: df["SSL Expiry Date Parsed"] = pd.NaT
    if "Domain Expiry Date" in df.columns: df["Domain Expiry Date Parsed"] = parse_dt_flexible_series(df["Domain Expiry Date"])
    else: df["Domain Expiry Date Parsed"] = pd.NaT
    return df

def status_color(status):
    """Returns a color hex code based on site status (Green/Red/Orange)."""
    if isinstance(status, str):
        s = status.strip().lower()
        if s.startswith("up") or s in ("up", "ok", "online"):
            return "#1ef287"  # neon-lime
        if "slow" in s or "warning" in s:
            return "#ffd166"  # amber
        if s.startswith("down") or s in ("down", "offline", "error", "fail", "failed"):
            return "#ff4d6d"  # neon-red
    return "#6c7680"  # muted gray

def safe_float_or_none(x):
    """Converts value to float, returns None if conversion fails (e.g., if x is 'Failed' or 'N/A')."""
    try:
        if isinstance(x, (str, bytes)):
            s = str(x).strip().lower()
            if s in ["n/a", "failed", "error", "whois failed", "nan", ""]:
                return None
        val = pd.to_numeric(x, errors='coerce')
        return float(val) if pd.notna(val) else None
    except (ValueError, TypeError):
        return None

# --- Chart Utility Function ---
def create_line_chart_options(metric_name, data_points, color, site_names, y_name="Time (ms)"):
    """Generates stable ECharts options for a single metric line graph with dark theme styling."""
    formatter = "{{b}} <br/> {}: {{c}} {}".format(metric_name, y_name.split(' ')[0])
    return {
        "tooltip": {
            "trigger": "axis", 
            "formatter": formatter,
            "backgroundColor": "rgba(10, 10, 10, 0.95)",
            "borderColor": color,
            "borderWidth": 1,
            "textStyle": {"color": "#FFF"}
        },
        "xAxis": {"type": "category", "data": site_names, "axisLabel": {"rotate": 25, "interval": 0, "margin": 10, "color": "#E6F9FF"}},
        "yAxis": {"type": "value", "name": y_name, "nameTextStyle": {"color": "#E6F9FF"}, "axisLabel": {"color": "#FFFFFF"}},
        "series": [ {
            "name": metric_name, 
            "type": "line", 
            "data": data_points, 
            "smooth": True,
            "lineStyle": {"color": color, "width": 3},
            "symbol": "circle",
            "symbolSize": 8,
            "showSymbol": True,
            "areaStyle": {"opacity": 0.06}
        } ],
        "grid": {"bottom": "25%", "top": "15%", "containLabel": True},
        "dataZoom": [{"type": 'slider', "xAxisIndex": 0, "filterMode": 'none', "backgroundColor": "#333", "dataBackground": {"areaStyle": {"color": "#555"}}, "fillerColor": "rgba(0, 255, 255, 0.4)"}],
        "backgroundColor": "transparent"
    }

# ==================================================================================================
# UI: LAYOUT AND RENDERING
# ==================================================================================================
st.set_page_config(page_title="ORSAC Monitor", layout="wide", initial_sidebar_state="auto")

# Sidebar controls
with st.sidebar:
    st.markdown("## Appearance")
    accent = st.selectbox("Accent Color", options=["Cyan", "Magenta", "Lime"], index=0)
    compact = st.checkbox("Compact mode (denser layout)", value=False)
    # Watch control: default off to avoid page pressure
    show_watch = st.checkbox("Show lightweight digital watch (low-impact)", value=False, help="Only digital time; updates at chosen interval. Off by default to reduce page pressure.")
    watch_interval_label = st.selectbox("Watch update interval", options=["5 seconds", "10 seconds", "30 seconds"], index=1) if show_watch else None

    st.markdown("---")
    st.markdown("### Headline styling")
    headline_color_choice = st.selectbox("Headline color", options=["White", "Cyan", "Magenta", "Lime", "Yellow", "Orange", "LightGray", "Black"], index=0)
    headline_bg_choice = st.selectbox("Headline background (pill)", options=["None", "Subtle Dark", "Subtle Light", "Accent Muted"], index=0)
    st.caption("Headlines will be bold and solid color. Background pill helps them stand out if you choose one.")
    st.markdown("---")
 

ACENT_MAP = {
    "Cyan": {"neon": "#00FFFF", "muted": "#00AAB5"},
    "Magenta": {"neon": "#FF33CC", "muted": "#AA2E84"},
    "Lime": {"neon": "#B7FF33", "muted": "#6EA200"}
}
accent_neon = ACENT_MAP.get(accent, ACENT_MAP["Cyan"])["neon"]
accent_muted = ACENT_MAP.get(accent, ACENT_MAP["Cyan"])["muted"]

HEADLINE_COLOR_MAP = {
    "White": "#FFFFFF",
    "Cyan": "#00FFFF",
    "Magenta": "#FF33CC",
    "Lime": "#B7FF33",
    "Yellow": "#FFD166",
    "Orange": "#FF8C42",
    "LightGray": "#D8DFE6",
    "Black": "#000000"
}
headline_color = HEADLINE_COLOR_MAP.get(headline_color_choice, "#FFFFFF")

# headline background mapping
if headline_bg_choice == "None":
    headline_bg = "transparent"
    headline_bg_padding = "0"
    headline_bg_radius = "0"
elif headline_bg_choice == "Subtle Dark":
    headline_bg = "rgba(255,255,255,0.03)"
    headline_bg_padding = "6px 10px"
    headline_bg_radius = "6px"
elif headline_bg_choice == "Subtle Light":
    headline_bg = "rgba(255,255,255,0.06)"
    headline_bg_padding = "6px 10px"
    headline_bg_radius = "6px"
else:  # Accent Muted
    headline_bg = accent_muted
    headline_bg_padding = "6px 10px"
    headline_bg_radius = "6px"

# ------------------------------
# 0. CUSTOM CSS (VISUAL SHELL) - headings solid color, bold, optional background pill
# ------------------------------
css = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

:root {{
  --bg: #05060a;
  --panel: #071225;
  --glass: rgba(255,255,255,0.03);
  --accent: {accent_neon};
  --accent-muted: {accent_muted};
  --headline-color: {headline_color};
  --headline-bg: {headline_bg};
  --headline-bg-padding: {headline_bg_padding};
  --headline-bg-radius: {headline_bg_radius};
}}

body {{
    background: var(--bg);
    color: #F5FBFF;
    font-family: 'Inter', system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
}}

.stApp .block-container {{
    background: linear-gradient(180deg, var(--panel), rgba(7,18,37,0.98));
    border-radius: 10px;
    padding: 18px;
    border: 1px solid rgba(255,255,255,0.02);
    box-shadow: 0 8px 30px rgba(0,0,0,0.7);
}}

/* Main title: solid color, bold, optional pill background */
.futuristic-title {{
    font-size: 28px;
    font-weight: 800;
    letter-spacing: 0.6px;
    color: var(--headline-color);
    display:inline-block;
    line-height:1;
    text-transform:uppercase;
    padding: var(--headline-bg-padding);
    border-radius: var(--headline-bg-radius);
    background: var(--headline-bg);
}}

/* Subtitles and subheaders: same color and background pill */
.futuristic-sub, h2, h3, h4, .stMarkdown h2, .stMarkdown h3 {{
    color: var(--headline-color) !important;
    font-weight: 700;
    padding: var(--headline-bg-padding);
    border-radius: var(--headline-bg-radius);
    background: var(--headline-bg);
}}

/* KPI cards, buttons, tables (unchanged) */
.kpi-row {{
  display:flex;
  gap:12px;
  align-items:stretch;
}}

.kpi-card {{
  flex:1;
  background: rgba(255,255,255,0.02);
  border-radius: 8px;
  padding: 10px 14px;
  border: 1px solid rgba(255,255,255,0.03);
  box-shadow: 0 6px 18px rgba(0,0,0,0.7);
  transition: transform 160ms ease, box-shadow 160ms ease;
  display:flex;
  flex-direction:column;
  justify-content:center;
}}

.kpi-card:hover {{
  transform: translateY(-6px);
  box-shadow: 0 14px 34px rgba(0,0,0,0.75), 0 0 26px var(--accent);
}}

.kpi-value {{
  font-size: 26px;
  font-weight: 800;
  color: #FFFFFF;
  letter-spacing: 0.4px;
}}

.kpi-label {{
  font-size:12px;
  color:#C7EAF2;
  margin-top:6px;
}}

.stButton>button {{
    background: linear-gradient(90deg, var(--accent), var(--accent-muted));
    color: black;
    font-weight:700;
    border-radius:8px;
    padding:10px 18px;
    box-shadow: 0 8px 20px rgba(0,0,0,0.5), 0 0 18px var(--accent);
    border: none;
}}
.stButton>button:hover {{
    transform: translateY(-3px);
}}

.stDataFrame {{
    border-radius: 8px;
    overflow: hidden;
    background: rgba(0,0,0,0.15);
}}

table.dataframe thead th {{
    background: rgba(255,255,255,0.02) !important;
    color: #E9FBFF !important;
    border-bottom: 1px solid rgba(255,255,255,0.03) !important;
}}
table.dataframe tbody td {{
    color: #E6F9FF !important;
    border-bottom: 1px dashed rgba(255,255,255,0.02) !important;
}}

.caption, .stCaption {{
    color: var(--accent) !important;
    font-weight: 600;
}}

/* header watch (simple digital only) */
.header-watch {{
  display:flex;
  gap:8px;
  align-items:center;
  justify-content:flex-end;
  padding-right:6px;
}}
.watch-digital {{
  font-weight:700;
  font-size:14px;
  color:#FFFFFF;
  background: rgba(255,255,255,0.02);
  padding:6px 8px;
  border-radius:6px;
  border:1px solid rgba(255,255,255,0.03);
}}
</style>
"""

st.markdown(css, unsafe_allow_html=True)

# Autorefresh: keep default low-pressure UI refresh
st_autorefresh(interval=60 * 1000, key="refresh_ui_hidden")

# If user enables watch, create a lightweight watch refresh interval (low-impact)
watch_interval_ms = None
if show_watch:
    if watch_interval_label == "5 seconds":
        watch_interval_ms = 5 * 1000
    elif watch_interval_label == "10 seconds":
        watch_interval_ms = 10 * 1000
    else:
        watch_interval_ms = 30 * 1000
    # this autorefresh runs in addition to the 60s one; user opted in so they accept more runs
    st_autorefresh(interval=watch_interval_ms, key="refresh_ui_watch")

# --- Load Data ---
df = load_data()
if df.empty:
    st.info("Monitoring process has started — waiting for first metrics. Check logs if it takes longer than one run.")
    st.stop()

# Prepare latest data snapshot
if "DateTime" in df.columns and df["DateTime"].notna().any():
    df_latest = df.sort_values("DateTime", ascending=False).drop_duplicates(subset=["Website Name"], keep="first").reset_index(drop=True)
else:
    df_latest = df.drop_duplicates(subset=["Website Name"], keep="last").reset_index(drop=True)

now_utc = pd.Timestamp.now(tz="UTC")
df_latest["_Status_norm"] = df_latest["Status"].astype(str).str.strip().str.lower()

# Calculate dynamic metrics
up_count = int(df_latest["_Status_norm"].str.contains("up", na=False).sum())
down_count = int(df_latest["_Status_norm"].str.contains("down", na=False).sum())
slow_count = int(df_latest["_Status_norm"].str.contains("slow", na=False).sum())
monitor_interval_str = f"{MONITOR_INTERVAL//60} min"

# Calculate display time
if "DateTime" in df.columns and df["DateTime"].notna().any():
    last_monitored = df["DateTime"].max()
    last_monitored_str = to_ist_string(last_monitored)
else:
    last_monitored_str = "N/A"

# --- HEADER ROW: TITLE | METRICS | BUTTON (+ optional lightweight watch) ---
col_title, col_sep1, kpi_up_col, kpi_down_col, kpi_slow_col, col_sep2, col_right = st.columns([0.30, 0.01, 0.16, 0.16, 0.16, 0.01, 0.20])

with col_title:
    # Use the custom class for the main title so it receives the solid color and optional background
    st.markdown(f"<div class='futuristic-title'>ORSAC Monitor</div><div class='futuristic-sub'>Last Check: {last_monitored_str} • Interval: {monitor_interval_str}</div>", unsafe_allow_html=True)

with col_sep1:
    st.markdown("<div style='border-left:2px solid var(--accent);height:48px;margin:0 6px;'></div>", unsafe_allow_html=True)

# KPI HTML
kpi_html = f"""
<div class="kpi-row" style="margin-bottom:6px;">
  <div class="kpi-card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <div class="kpi-value">🟢 {up_count}</div>
        <div class="kpi-label">Sites UP</div>
      </div>
      <div style="font-size:12px;color:#BFEFFF">Stable</div>
    </div>
  </div>
  <div class="kpi-card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <div class="kpi-value">🔴 {down_count}</div>
        <div class="kpi-label">Sites DOWN</div>
      </div>
      <div style="font-size:12px;color:#FFCFD6">Attention</div>
    </div>
  </div>
  <div class="kpi-card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div>
        <div class="kpi-value">🟡 {slow_count}</div>
        <div class="kpi-label">Sites SLOW</div>
      </div>
      <div style="font-size:12px;color:#FFF3BF">Warning</div>
    </div>
  </div>
</div>
"""
st.markdown(kpi_html, unsafe_allow_html=True)

# Right column: optional lightweight digital watch + Run button
with col_right:
    if show_watch:
        now_ist = pd.Timestamp.now(tz="UTC").tz_convert(IST_TZ)
        digital_time = now_ist.strftime("%Y-%m-%d %H:%M:%S ") + IST_LABEL
        watch_html = f"<div class='header-watch'><div class='watch-digital'>{digital_time}</div></div>"
        st.markdown(watch_html, unsafe_allow_html=True)
    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
    if st.button("RUN INSTANT CHECK", key="instant_check_button", help="Triggers a one-time monitoring run now.", type="secondary", use_container_width=True):
        run_monitor_in_background(instant_check=True)

st.markdown("---")

# ==========================================================
# 1. DETAILED EVENT LOG (Table with stable colors and Arrows)
# ==========================================================
# Use a solid-colored subheader
st.markdown("<h2 class='futuristic-sub'>DETAILED EVENT LOG</h2>", unsafe_allow_html=True)
N_ROWS = 200
if "DateTime" in df.columns and df["DateTime"].notna().any():
    last_n = df.sort_values("DateTime", ascending=False).head(N_ROWS).copy()
else:
    last_n = df.tail(N_ROWS).copy()

# Format numeric columns (leaving 'Failed' as strings)
def format_numeric_columns(df_obj, cols):
    for col in cols:
        if col in df_obj.columns:
            def _fmt(x):
                try:
                    sx = str(x)
                    if sx.replace('.', '', 1).lstrip('-').isdigit():
                        return f"{float(x):.2f}"
                    return sx
                except Exception:
                    return str(x)
            df_obj[col] = df_obj[col].apply(_fmt)
    return df_obj

last_n = format_numeric_columns(last_n, ["Ping (ms)", "HTTP Time (ms)", "DNS Time (ms)", "Content Size (KB)", "Redirects"])
for col in ["SSL Days Left", "Domain Days Left"]:
    if col in last_n.columns:
        last_n[col] = last_n[col].apply(lambda x: str(x).strip())

if "DateTime" in last_n.columns:
    try:
        last_n["DateTime"] = last_n["DateTime"].apply(lambda x: x.tz_convert(IST_TZ).strftime("%Y-%m-%d %H:%M:%S ") + IST_LABEL if pd.notna(x) else "N/A")
    except Exception:
        last_n["DateTime"] = last_n["DateTime"].astype(str)

def style_status_cell_with_arrow(v):
    status_str = str(v)
    color = status_color(status_str)
    if "up" in status_str.lower() or status_str.lower() == 'ok':
        arrow = " ⬆️"
    elif "down" in status_str.lower() or "error" in status_str.lower() or "fail" in status_str.lower():
        arrow = " ⬇️"
    else:
        arrow = ""
    return f"background-color: {color}; color: black; font-weight: bold; text-align:center", status_str + arrow

if not last_n.empty:
    display_cols = [c for c in [
        "DateTime", "Website Name", "URL", "Status", "Ping (ms)", "HTTP Time (ms)",
        "DNS Time (ms)", "Content Size (KB)", "Redirects", "Keyword Check",
        "SSL Days Left", "SSL Expiry Date", "Domain Days Left", "Domain Expiry Date", "Notes"
    ] if c in last_n.columns]

    if "Website Name" not in display_cols:
        if "URL" in last_n.columns:
            display_cols.insert(1, "URL")
        else:
            last_n.insert(0, "Website Name", last_n.index.astype(str))
            display_cols.insert(1, "Website Name")

    last_n = last_n[display_cols].copy()
    display_statuses = [style_status_cell_with_arrow(v)[1] for v in last_n["Status"]]
    last_n["Status"] = display_statuses

    def apply_status_color(col):
        if col.name == "Status":
            status_colors = []
            for status in col:
                original_status = status.replace(" ⬆️", "").replace(" ⬇️", "")
                color = status_color(original_status)
                status_colors.append(f"background-color: {color}; color: black;")
            return status_colors
        return [''] * len(col)

    try:
        styled = last_n.style.apply(apply_status_color, axis=0, subset=["Status"])
        styled = styled.set_properties(**{"font-family": "Inter, Arial", "font-size": "12px", "color": "#DDD", "background-color": "#071826"})
        st.dataframe(styled, use_container_width=True)
    except Exception:
        st.warning("Could not apply cell-level styling in this environment — showing unstyled table.")
        st.dataframe(last_n, use_container_width=True)
else:
    st.info("No log data to show.")

st.markdown("---")

# ==========================================================
# 2. PERFORMANCE CHARTS (Metrics Separated and Stacked Vertically)
# ==========================================================
st.markdown("<h2 class='futuristic-sub'>PERFORMANCE TIMES (ms) — LATEST SNAPSHOT</h2>", unsafe_allow_html=True)

site_names = df_latest["Website Name"].astype(str).tolist()

def get_series_data(metric_name, color):
    data_points = []
    for _, row in df_latest.iterrows():
        value = safe_float_or_none(row.get(metric_name))
        # ensure native python types (float or None)
        if value is None:
            data_points.append(None)
        else:
            data_points.append(float(value))
    return data_points

# Ping
ping_data = get_series_data("Ping (ms)", accent_neon)
st.caption("Ping Time (ms) per Site")
ping_options = create_line_chart_options("Ping (ms)", ping_data, accent_neon, site_names)
st_echarts(options=sanitize_for_json(ping_options), height="280px")

# DNS
dns_data = get_series_data("DNS Time (ms)", "#1ef287")
st.caption("DNS Time (ms) per Site")
dns_options = create_line_chart_options("DNS Time (ms)", dns_data, "#1ef287", site_names)
st_echarts(options=sanitize_for_json(dns_options), height="280px")

# HTTP
http_data = get_series_data("HTTP Time (ms)", "#ffd166")
st.caption("HTTP Time (ms) per Site")
http_options = create_line_chart_options("HTTP Time (ms)", http_data, "#ffd166", site_names)
st_echarts(options=sanitize_for_json(http_options), height="280px")

st.markdown("---")

# ==========================================================
# 3. EXPIRY CHARTS (Line Charts Separated)
# ==========================================================
st.markdown("<h2 class='futuristic-sub'>CERTIFICATE AND DOMAIN EXPIRY STATUS</h2>", unsafe_allow_html=True)

st.caption("SSL Days Left per Site (Gold line = Alert Threshold)")
ssl_data = get_series_data("SSL Days Left", "#ff4d6d")
ssl_options = create_line_chart_options("SSL Days Left", ssl_data, "#ff4d6d", site_names, y_name="Days Left")
ssl_options["series"][0]["markLine"] = {
    "silent": True,
    "lineStyle": {"type": "dashed", "color": "#FFD700"},
    "data": [{"yAxis": int(SSL_ALERT_DAYS), "name": "Alert Threshold"}]
}
st_echarts(options=sanitize_for_json(ssl_options), height="300px")

st.caption("Domain Days Left per Site (Gold line = Alert Threshold)")
dom_data = get_series_data("Domain Days Left", accent_neon)
dom_options = create_line_chart_options("Domain Days Left", dom_data, accent_neon, site_names, y_name="Days Left")
dom_options["series"][0]["markLine"] = {
    "silent": True,
    "lineStyle": {"type": "dashed", "color": "#FFD700"},
    "data": [{"yAxis": int(SSL_ALERT_DAYS), "name": "Alert Threshold"}]
}
st_echarts(options=sanitize_for_json(dom_options), height="300px")

st.markdown("---")
st.caption("Status Colors: Neon Lime = Up, Amber = Slow/Warning, Neon Red = Down/Error. Chart lines show individual site metrics clearly.")
