# system_whois_check.py
import whois as whois_lookup
import sys
from urllib.parse import urlparse
from datetime import datetime, timezone

DOMAIN = "odishaforest.in" # Use one of your monitored domains

def get_hostname(url):
    try:
        # Tries to handle URL like https://example.com/path
        netloc = urlparse(url).netloc
        return netloc.split(":")[0]
    except Exception:
        return url

hostname = get_hostname(f"https://{DOMAIN}")

print(f"--- WHOIS System Diagnostic for {hostname} ---")
print("Attempting WHOIS lookup using installed Python library...")

try:
    # Use the imported library with a clear name
    w = whois_lookup.whois(hostname)
    
    if w.expiration_date:
        if isinstance(w.expiration_date, list):
            expiry = w.expiration_date[0]
        else:
            expiry = w.expiration_date

        if isinstance(expiry, datetime):
            days_left = (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            print("\n✅ SUCCESS: Found Expiration Date:")
            print(f"   Expiry Date (UTC): {expiry}")
            print(f"   Days Left: {days_left}")
        else:
            print("\n❌ FAILURE: Lookup was successful but returned an unparsed date format.")
            print(f"   Raw Expiry Value: {w.expiration_date}")
            
    else:
        print("\n❌ FAILURE: Lookup successful, but no Expiration Date was found in the record.")
        print("   This is common for .gov.in or rate-limited TLDs.")
        print(f"   Raw WHOIS Text (Partial): \n{w.text[:500]}")
        
except Exception as e:
    print("\n❌ CRITICAL FAILURE: WHOIS library threw an exception.")
    print(f"   Error Type: {type(e).__name__}")
    print(f"   Error Message: {e}")
    print("   Suggestion: Check network connection/firewall or library version.")
    
print("\n--- Diagnostic Complete ---")