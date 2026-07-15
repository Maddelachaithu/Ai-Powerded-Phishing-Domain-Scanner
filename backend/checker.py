import socket
import time
import requests
import whois
import os
from datetime import datetime

# Query timeout for crt.sh from environment variable (default 8.0 seconds)
CRTSH_TIMEOUT = float(os.environ.get("CRTSH_TIMEOUT_SECONDS", 8.0))
from dateutil import parser
from threading import Semaphore
from concurrent.futures import ThreadPoolExecutor, as_completed

# Rate limit: cap concurrent crt.sh requests to 5 at a time
CRT_SEMAPHORE = Semaphore(5)

# Set global default socket timeout for DNS resolution
socket.setdefaulttimeout(3.0)

def resolve_dns(domain: str) -> bool:
    """
    Performs DNS resolution on the domain.
    Catches gaierror and timeout, treating them as not resolved.
    """
    try:
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False

def check_crt_sh(domain: str) -> str:
    """
    Queries crt.sh for Certificate Transparency logs of the domain.
    Implements retry + exponential backoff.
    Returns "confirmed", "not_found", or "unknown".
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    attempts = 3
    delay = 1.0
    
    with CRT_SEMAPHORE:
        for attempt in range(attempts):
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelDomainWatch/1.0"}
                response = requests.get(url, timeout=CRTSH_TIMEOUT, headers=headers)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list) and len(data) > 0:
                            return "confirmed"
                        else:
                            return "not_found"
                    except ValueError:
                        # crt.sh can return HTML/DB connection errors with 200 status code
                        pass
            except (requests.RequestException, Exception):
                pass
            
            if attempt < attempts - 1:
                time.sleep(delay)
                delay *= 2.0
                
    return "unknown"

def normalize_date(date_val) -> datetime | None:
    """
    Normalizes different potential structures returned by python-whois creation_date.
    """
    if not date_val:
        return None
    if isinstance(date_val, list):
        dates = [normalize_date(d) for d in date_val]
        valid_dates = [d for d in dates if d is not None]
        return min(valid_dates) if valid_dates else None
    if isinstance(date_val, datetime):
        return date_val
    if isinstance(date_val, str):
        try:
            return parser.parse(date_val)
        except Exception:
            return None
    return None

def query_whois(domain: str) -> tuple[str | None, str | None]:
    """
    Performs a WHOIS query on the domain.
    Returns (registered_date, registrar).
    """
    try:
        w = whois.whois(domain)
        
        # Extract and normalize creation date
        raw_date = w.get('creation_date')
        if not raw_date:
            # Fallback to updated_date or expiration_date if creation is missing
            raw_date = w.get('updated_date')
            
        norm_date = normalize_date(raw_date)
        registered_date = norm_date.strftime('%Y-%m-%d') if norm_date else None
        
        # Extract registrar
        reg = w.get('registrar')
        if isinstance(reg, list):
            registrar = reg[0] if reg else None
        else:
            registrar = reg
            
        if registrar:
            registrar = str(registrar).strip()
            
        return registered_date, registrar
    except Exception:
        # Gracefully handle WHOIS failures (connection refused, timeouts, etc.)
        return None, None

def check_domain(domain: str, techniques: list[str]) -> dict:
    """
    Runs full verification suite (DNS + Cert status + WHOIS if flagged) for a domain.
    """
    dns_resolves = resolve_dns(domain)
    certificate_status = check_crt_sh(domain)
    
    # Flagged if DNS resolves OR a certificate was found
    is_flagged = dns_resolves or (certificate_status == "confirmed")
    
    registered_date = None
    registrar = None
    if is_flagged:
        registered_date, registrar = query_whois(domain)
        
    return {
        "domain": domain,
        "dns_resolves": dns_resolves,
        "certificate_status": certificate_status,
        "registered_date": registered_date,
        "registrar": registrar,
        "techniques": techniques
    }

def scan_domains(variants: dict[str, list[str]], progress_callback=None) -> list[dict]:
    """
    Orchestrates parallel verification for all variants.
    """
    results = []
    total_variants = len(variants)
    if total_variants == 0:
        return results

    # Set default socket timeout for this run
    socket.setdefaulttimeout(3.0)
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        # Submit tasks
        future_to_domain = {
            executor.submit(check_domain, domain, techniques): domain
            for domain, techniques in variants.items()
        }
        
        checked_count = 0
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                res = future.result()
                results.append(res)
            except Exception:
                # Treat execution failure of checking task as unknown
                results.append({
                    "domain": domain,
                    "dns_resolves": False,
                    "certificate_status": "unknown",
                    "registered_date": None,
                    "registrar": None,
                    "techniques": variants[domain]
                })
            
            checked_count += 1
            if progress_callback:
                progress_callback(checked_count, total_variants)
                
    return results
