<h1 align="center">SecurityTellers</h1>
<h3 align="center">Domain & IP Intelligence Gathering Framework</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python_3-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Phase-Reconnaissance-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Cloudflare-Bypass-orange?style=for-the-badge&logo=cloudflare&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<p align="center">
  <b>IP History</b> · <b>Subdomain Enumeration</b> · <b>Reverse IP</b> · <b>Cloudflare Bypass</b> · <b>Multi-API</b>
</p>

---

## What It Does

**SecurityTellers** gathers intelligence about domains and IP addresses from multiple sources in a single command. It discovers historical IPs, enumerates subdomains, finds associated sites, and attempts to uncover origin IPs hidden behind Cloudflare — all organized in per-target output folders.

```
┌─────────────────────────────────────────────────────────┐
│                    SecurityTellers                       │
├─────────────┬───────────────────────────────────────────┤
│ IP History  │ Historical A records, DNS timeline        │
│ Subdomains  │ 7 sources: crt.sh, ST, VT, Shodan...     │
│ Reverse IP  │ Associated domains on same server         │
│ CF Bypass   │ 6 methods to find origin behind CDN       │
└─────────────┴───────────────────────────────────────────┘
```

## Features

### IP History
- Current DNS resolution (A, MX, TXT, NS, CNAME)
- Historical A records via SecurityTrails, ViewDNS, HackerTarget
- MX record IP leak detection
- Geolocation and ASN data via ip-api, Shodan, VirusTotal

### Subdomain Enumeration
- **7 data sources**: crt.sh, HackerTarget, AlienVault OTX, RapidDNS, SecurityTrails, VirusTotal, Shodan
- Works without API keys (crt.sh, HackerTarget, AlienVault, RapidDNS are free)
- Automatic deduplication and sorting

### Reverse IP (Associated Sites)
- Discover all domains hosted on the same IP
- Sources: HackerTarget, SecurityTrails, VirusTotal, Shodan

### Cloudflare Bypass (6 Methods)
| # | Method | How It Works |
|---|--------|--------------|
| 1 | Historical DNS | Check pre-Cloudflare A records |
| 2 | MX Records | Mail servers often point to origin |
| 3 | SPF Records | SPF ip4: entries leak origin IP |
| 4 | Subdomain Bypass | Subdomains not proxied through CF |
| 5 | SecurityTrails | Historical DNS database |
| 6 | Censys Certs | SSL certificate → IP mapping |

Each candidate is **automatically verified** by sending an HTTP request with the target's Host header.

---

## Installation

```bash
git clone https://github.com/0xAlshalahi/SecurityTellers.git
cd SecurityTellers
pip install -r requirements.txt
cp api_keys.yaml.example api_keys.yaml
# Edit api_keys.yaml with your API keys (optional)
```

## Usage

```bash
# Scan a domain (all modules)
python3 main.py -d example.com

# Scan an IP address
python3 main.py -ip 93.184.216.34

# Run specific module
python3 main.py -d example.com -m subs      # Subdomains only
python3 main.py -d example.com -m history    # IP history only
python3 main.py -d example.com -m reverse    # Reverse IP only
python3 main.py -d example.com -m cf-bypass  # Cloudflare bypass only

# Cloudflare bypass focus
python3 main.py -d target.com --cf-bypass

# Custom output directory
python3 main.py -d target.com -o /path/to/output

# Verbose mode
python3 main.py -d target.com -v

# Use specific config file
python3 main.py -d target.com --config my_keys.yaml

# Use environment variables instead of config file
export ST_API_KEY="your_securitytrails_key"
export SHODAN_API_KEY="your_shodan_key"
export VT_API_KEY="your_virustotal_key"
python3 main.py -d target.com
```

## API Keys

All keys are **optional**. Without any keys, SecurityTellers uses 4 free sources (crt.sh, HackerTarget, AlienVault, RapidDNS). Add keys for more coverage.

| Provider | Free Tier | Get Key |
|----------|-----------|---------|
| SecurityTrails | 50 req/month | [securitytrails.com](https://securitytrails.com/app/account) |
| Shodan | Free tier | [shodan.io](https://account.shodan.io/) |
| VirusTotal | 4 req/min | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| ViewDNS | Free trial | [viewdns.info](https://viewdns.info/api/) |
| Censys | 250 req/month | [censys.io](https://search.censys.io/account/api) |

Configure via `api_keys.yaml` or environment variables (`ST_API_KEY`, `SHODAN_API_KEY`, `VT_API_KEY`, `VIEWDNS_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET`).

## Output Structure

```
results/
└── example.com/
    ├── ip_history.json        # Historical IP records
    ├── subdomains.json        # All discovered subdomains
    ├── subdomains.txt         # Plain text subdomain list
    ├── reverse_ip.json        # Associated domains
    ├── cloudflare_bypass.json # CF bypass analysis
    ├── full_results.json      # Combined results
    └── report.md              # Markdown report
```

## Example Output

```
  ──────────────────────────────────────────────────
    CLOUDFLARE BYPASS ANALYSIS
  ──────────────────────────────────────────────────
  [!] target.com IS behind Cloudflare (IP: 104.21.xx.xx)
  [*] Attempting origin IP discovery...

  [*] [Method 1] Historical DNS records
   ↳ Pre-CF IP: 185.xx.xx.xx (ViewDNS)
  [*] [Method 2] MX record analysis
   ↳ MX leak: 185.xx.xx.xx (mail.target.com)
  [*] [Method 4] Subdomain direct resolution
   ↳ Direct sub: cpanel.target.com → 185.xx.xx.xx
   ↳ Direct sub: ftp.target.com → 185.xx.xx.xx

  [+] Found 2 origin IP candidates
  [*] Verifying candidates...
   ↳ 185.xx.xx.xx — CONFIRMED (via historical_dns)
```

## Project Structure

```
SecurityTellers/
├── main.py                    # CLI entry point
├── core/
│   ├── banner.py              # ASCII banner
│   ├── config.py              # API key loader
│   └── logger.py              # Colored logging
├── modules/
│   ├── ip_history.py          # IP history module
│   ├── subdomains.py          # Subdomain enumeration
│   ├── reverse_ip.py          # Reverse IP / associated sites
│   ├── cloudflare.py          # Cloudflare bypass engine
│   └── report.py              # Report generator
├── api_keys.yaml.example      # API key template
├── requirements.txt
├── LICENSE
└── README.md
```

## Author

**Abdulelah Al-shalahi** — [@0xAlshalahi](https://github.com/0xAlshalahi)

## Disclaimer

This tool is for **authorized security testing and research only**. Always obtain proper authorization before scanning targets you do not own. The author is not responsible for misuse.

## License

MIT
