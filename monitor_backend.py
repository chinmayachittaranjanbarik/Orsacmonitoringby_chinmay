"""
monitor_backend.py
Improved monitoring backend for ORSAC.

- Adds domain (WHOIS) expiry lookup: "Domain Expiry Date" and "Domain Days Left".
- Other features: DNS timing, ICMP ping (optional), HTTP request, SSL expiry, CSV logging with filelock.
- **CORRECTION:** Fixed the WHOIS import conflict that caused 'AttributeError: module 'whois' has no attribute 'whois''.
- **CORRECTION:** Ensures failed checks log 'Failed' instead of '0' for accurate UI plotting.
"""
import os
import csv
import time
import ssl
import socket
import logging
import sys
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import smtplib
from email.mime.text import MIMEText
from dateutil import tz as dateutil_tz

import requests
import yaml
import icmplib
import dns.resolver
from filelock import FileLock
from dotenv import load_dotenv, dotenv_values

# --------------------------------------------------------
# WHOIS Import Correction (Fixes AttributeError)
# --------------------------------------------------------
# The original 'import whois as whois_lookup' was causing an error.
# We import directly and assign to whois_lookup for compatibility with the rest of the script.
try:
    import whois # Import the module directly
    whois_lookup = whois
except Exception:
    whois_lookup = None
    logging.warning("Python 'whois' package is not correctly installed/imported. Domain expiry checks will be skipped.")

# Load environment overrides
try:
    env_vars = dotenv_values()
    for key, value in env_vars.items():
        if key is not None and value is not None:
            os.environ[key] = value
except Exception as e:
    logging.warning(f"Failed to load environment variables from .env: {e}")

# ------------------------------
# Config files / env defaults
# ------------------------------
CONFIG_FILE = os.getenv("SITES_YAML", "sites.yaml")
LOG_FILE = os.getenv("LOG_FILE", "website_monitor_log.csv")
LOCK_FILE = LOG_FILE + ".lock"

# Logging level from env or default INFO
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Load YAML config
try:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f) or {}
except FileNotFoundError:
    logging.error(f"Config file '{CONFIG_FILE}' not found. Exiting.")
    raise SystemExit(1)

settings = config_data.get("settings", {}) or {}
sites = config_data.get("sites", []) or []

# Runtime overrides (env preferred)
MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL", settings.get("monitor_interval", 1800)))
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", settings.get("default_timeout", 10)))
USE_ICMP_BY_DEFAULT = os.getenv("USE_ICMP_BY_DEFAULT", str(settings.get("use_icmp_by_default", True))).lower() in ("1", "true", "yes")
RESPONSE_TIME_THRESHOLD = float(os.getenv("RESPONSE_TIME_THRESHOLD", settings.get("response_time_threshold", 3000)))
SSL_ALERT_DAYS = int(os.getenv("SSL_ALERT_DAYS", settings.get("ssl_alert_days", 30)))
SCHEDULED_TIMES_STR = os.getenv("SCHEDULED_TIMES", "").strip()

# Email config
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() in ("true", "1", "yes")
EMAIL_SMTP = os.getenv("EMAIL_SMTP", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", EMAIL_USER)
EMAIL_TO = os.getenv("EMAIL_TO", "").split(",")

# Helper: extract hostname (without port)
def get_hostname(url):
    """Extracts hostname from a URL."""
    try:
        netloc = urlparse(url).netloc
        return netloc.split(":")[0]
    except Exception:
        return url

# WHOIS helper: returns (expiry_date (datetime) or None, days_left int or "N/A")
def get_domain_expiry(hostname):
    """Performs a WHOIS lookup to get domain expiry date."""
    if whois_lookup is None:
        return None, "N/A"
    try:
        w = whois_lookup.whois(hostname)
        exp = w.expiration_date
        if isinstance(exp, (list, tuple)):
            exp_dates = [e for e in exp if e is not None and isinstance(e, datetime)]
            exp = exp_dates[0] if exp_dates else None
        
        if isinstance(exp, datetime):
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            else:
                exp = exp.astimezone(timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
            return exp, int(days_left)
        else:
            return None, "N/A"
    except Exception as e:
        logging.debug(f"WHOIS lookup failed for {hostname}: {e}")
        return None, "WHOIS Failed" # Log explicit failure

# Email helper
def send_email(subject, body):
    """Sends a formatted email alert."""
    if not EMAIL_ENABLED or not EMAIL_TO or not EMAIL_USER or not EMAIL_PASS:
        logging.info("Email alerts are not enabled or configured. Skipping email.")
        return
    
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(EMAIL_TO)

    try:
        # Check if the SMTP server is Gmail to use SSL
        # Note: The URL in EMAIL_SMTP in the .env file needs to be corrected to 'smtp.gmail.com' for this to work.
        smtp_server = EMAIL_SMTP.split('?')[-1].split('=')[-1] if '?' in EMAIL_SMTP else EMAIL_SMTP
        if "gmail.com" in smtp_server:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(EMAIL_USER, EMAIL_PASS)
                server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, EMAIL_PORT) as server:
                server.starttls()
                server.login(EMAIL_USER, EMAIL_PASS)
                server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# Core site check
def check_site(site):
    """
    Returns a dict of results for a site.
    """
    name = site.get("name", "")
    url = site.get("url", "")
    enabled = bool(site.get("enabled", True))
    if not enabled:
        return None 

    timeout = int(site.get("timeout", DEFAULT_TIMEOUT))
    use_icmp = bool(site.get("use_icmp", USE_ICMP_BY_DEFAULT))
    expected_status = int(site.get("expected_status", 200))
    check_keyword_flag = bool(site.get("check_keyword", bool(site.get("keyword"))))
    notes = ""

    # Initialize results with 'Failed' or 'N/A' to avoid logging 0 for failed checks
    results = {
        "DateTime": datetime.now(timezone.utc).isoformat(),
        "Website Name": name,
        "URL": url,
        "Status": "Down",
        "Ping (ms)": "Failed",
        "HTTP Time (ms)": "Failed",
        "DNS Time (ms)": "Failed",
        "Content Size (KB)": "Failed",
        "Redirects": 0,
        "Keyword Check": "Skipped",
        "SSL Days Left": "N/A",
        "SSL Expiry Date": "N/A",
        "Domain Days Left": "N/A",
        "Domain Expiry Date": "N/A",
        "Notes": ""
    }

    hostname = get_hostname(url)

    # DNS timing
    ip_addr = None
    try:
        start = time.perf_counter()
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(hostname, "A", lifetime=5)
        dns_time = round((time.perf_counter() - start) * 1000, 2)
        results["DNS Time (ms)"] = dns_time
        ip_addr = answers[0].to_text()
    except Exception as e:
        notes += f"DNS lookup failed. "
        results["DNS Time (ms)"] = "Failed" # Explicit failure logging

    # ICMP ping (optional)
    if use_icmp and ip_addr:
        try:
            ping_res = icmplib.ping(ip_addr, count=1, timeout=2)
            if getattr(ping_res, "is_alive", False) and getattr(ping_res, "avg_rtt", None) is not None:
                results["Ping (ms)"] = round(ping_res.avg_rtt, 2)
            else:
                results["Ping (ms)"] = "Failed"
        except Exception as e:
            notes += f"ICMP ping failed. "
            results["Ping (ms)"] = "Error"
    else:
        results["Ping (ms)"] = "N/A" # Explicit N/A when skipped

    # HTTP request + keyword + redirects + content size
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        http_ms = round(r.elapsed.total_seconds() * 1000, 2)
        results["HTTP Time (ms)"] = http_ms
        results["Redirects"] = len(r.history)
        results["Content Size (KB)"] = round(len(r.content) / 1024, 2)

        # Determine Up/Down based on expected_status
        if r.status_code == expected_status:
            results["Status"] = "Up"
        else:
            results["Status"] = f"Down ({r.status_code})"
            notes += f"Expected status {expected_status}, but got {r.status_code}. "
            subject = f"Alert: Website '{name}' is Down"
            body = f"The website '{name}' ({url}) returned a status code of {r.status_code} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. "
            send_email(subject, body)

        # Keyword check (optional)
        if check_keyword_flag and site.get("keyword"):
            try:
                kw = site.get("keyword", "")
                if kw.lower() in r.text.lower():
                    results["Keyword Check"] = "Pass"
                else:
                    results["Keyword Check"] = "Fail"
                    notes += f"Keyword '{kw}' not found in content. "
            except Exception:
                results["Keyword Check"] = "Error"
    except requests.exceptions.RequestException as e:
        logging.warning(f"[{name}] HTTP request error: {e}")
        results["Status"] = "Down (HTTP Error)"
        notes += f"HTTP request failed. "
        subject = f"Alert: Website '{name}' is Down"
        body = f"The website '{name}' ({url}) could not be reached at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} due to an HTTP error: {e}"
        send_email(subject, body)

    # SSL check (attempt)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                # Handle different time zones in cert, default to UTC for parsing
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry_utc = expiry.replace(tzinfo=timezone.utc)
                days_left = (expiry_utc - datetime.now(timezone.utc)).days
                results["SSL Expiry Date"] = expiry_utc.isoformat()
                results["SSL Days Left"] = int(days_left)
    except Exception as e:
        notes += f"SSL check failed. "
        results["SSL Days Left"] = "Failed"

    # Domain (WHOIS) expiry
    exp_dt, days_left_dom = get_domain_expiry(hostname)
    if isinstance(exp_dt, datetime):
        results["Domain Expiry Date"] = exp_dt.isoformat()
    results["Domain Days Left"] = days_left_dom
    if days_left_dom in ("N/A", "WHOIS Failed"):
        notes += f"Domain check failed: {days_left_dom}. "

    # Mark slow if HTTP time exceeds threshold
    try:
        # Check for numeric type, excluding strings like 'Failed'
        if isinstance(results["HTTP Time (ms)"], (int, float)) and results["HTTP Time (ms)"] > RESPONSE_TIME_THRESHOLD:
            if results["Status"].startswith("Up"):
                results["Status"] = "Up (Slow)"
    except Exception:
        pass

    results["Notes"] = notes.strip()

    return results

def run_checks_and_log():
    """Runs a single round of checks and writes results to log file."""
    rows = []
    for site in sites:
        try:
            res = check_site(site)
            if res is None:
                logging.debug(f"Skipping disabled site: {site.get('name')}")
                continue
            rows.append(res)
        except Exception as e:
            logging.error(f"Unexpected error checking site {site.get('name')}: {e}")
    
    if not rows:
        logging.info("No sites to check. Exiting.")
        return

    try:
        with FileLock(LOCK_FILE, timeout=15):
            write_header = not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0
            with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                fieldnames = [
                    "DateTime", "Website Name", "URL", "Status", "Ping (ms)",
                    "HTTP Time (ms)", "DNS Time (ms)", "Content Size (KB)", "Redirects",
                    "Keyword Check", "SSL Days Left", "SSL Expiry Date",
                    "Domain Days Left", "Domain Expiry Date", "Notes"
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                if write_header:
                    writer.writeheader()
                for r in rows:
                    writer.writerow(r)
    except Exception as e:
        logging.error(f"Failed to write log file: {e}")

# Main scheduling loop
def monitor_loop():
    """Manages the main monitoring loop based on a schedule or instant check."""
    
    is_scheduled_run = bool(os.getenv("SCHEDULED_TIMES", "").strip())
    
    if is_scheduled_run:
        try:
            scheduled_times = [datetime.strptime(t.strip(), "%H:%M").time() for t in os.getenv("SCHEDULED_TIMES", "").split(",") if t.strip()]
            if not scheduled_times:
                raise ValueError("No valid times found in SCHEDULED_TIMES")
        except Exception as e:
            logging.error(f"Error parsing SCHEDULED_TIMES: {e}. Falling back to interval monitoring.")
            is_scheduled_run = False

    if is_scheduled_run:
        logging.info(f"Starting scheduled monitor loop. Next checks at: {[t.strftime('%H:%M') for t in scheduled_times]}")
        
        last_run_date_times = {time_obj: None for time_obj in scheduled_times}
        kolkata_tz = dateutil_tz.gettz('Asia/Kolkata')
        
        while True:
            now = datetime.now(kolkata_tz)
            
            for scheduled_time, last_run in last_run_date_times.items():
                target_datetime = now.replace(hour=scheduled_time.hour, minute=scheduled_time.minute, second=0, microsecond=0)
                
                # Check if it's within a 60-second window of the scheduled time
                if abs((now - target_datetime).total_seconds()) < 30:
                    # And if it hasn't been run today
                    if last_run is None or last_run.date() != now.date():
                        logging.info(f"Running scheduled check for {now.strftime('%H:%M')}...")
                        run_checks_and_log()
                        last_run_date_times[scheduled_time] = now
            
            time.sleep(10)
    else:
        logging.info("SCHEDULED_TIMES not set or invalid. Running as a continuous interval-based monitor.")
        last_run_time = None
        while True:
            now = datetime.now()
            if last_run_time is None or (now - last_run_time).total_seconds() >= MONITOR_INTERVAL:
                logging.info("Running interval-based check...")
                run_checks_and_log()
                last_run_time = now
            time.sleep(10)

if __name__ == "__main__":
    if "--run-now" in sys.argv:
        logging.info("Running a single, instant check as requested.")
        run_checks_and_log()
        sys.exit(0)
    else:
        monitor_loop()