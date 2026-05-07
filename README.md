# legitimate-bug-bounty-reconnaissance-tool


## 🛠 What the Tool Does

| Module | What It Covers |
|---|---|
| **1. WHOIS & DNS Recon** | WHOIS, A/MX/NS/TXT records, SPF/DMARC check |
| **2. Subdomain Enumeration** | crt.sh, HackerTarget, brute-force (200+ wordlist), zone transfer |
| **3. Real IP Finder** | CDN/Cloudflare bypass, SPF leaks, mail server IP |
| **4. Port Scanning** | 30+ critical ports, flags exposed Redis/MongoDB/Docker |
| **5. WAF Detection** | Cloudflare, Akamai, AWS WAF, Incapsula, ModSecurity, F5 etc. |
| **6. CMS Detection** | WordPress, Joomla, Laravel, Django, ASP.NET, Shopify etc. |
| **7. URL Gathering** | 60+ sensitive paths, robots.txt, Wayback Machine URLs |
| **8. JS File Analysis** | Secret hunting: AWS keys, JWT, GitHub tokens, API keys, S3 |
| **9. Header & SSL Analysis** | Missing security headers, CORS, info disclosure |
| **10. Vuln Probing** | Open redirect, XSS reflection, path traversal, CORS, subdomain takeover |
| **11. Manual Guide** | Full manual testing guide generated based on your scan results |

---

## 🚀 How to Run

```bash
python3 bugbounty_recon.py example.com
```

It will ask for confirmation, then run all 11 modules automatically and save two report files: `report_example_com_DATE.json` and `.txt`.

---

## 📦 Recommended Extra Tools (install for more power)

```bash
# Ubuntu/Kali
sudo apt install whois nmap dnsutils

# Python tools
pip install sqlmap

# Go tools (optional but powerful)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
```

---

⚠️ **Legal reminder:** Only run this on domains you have explicit written permission to test (your own domains, bug bounty program scope, or lab environments). Unauthorized use is illegal.
