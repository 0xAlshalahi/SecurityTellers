"""Subdomain Enumeration Module — Multi-source subdomain discovery."""

import json
import requests


class SubdomainModule:
    def __init__(self, config, log, timeout=15):
        self.config = config
        self.log = log
        self.timeout = timeout

    def enumerate(self, domain):
        self.log.info(f"Enumerating subdomains for {domain}")
        all_subs = set()
        sources_used = []

        # crt.sh (Certificate Transparency — always free)
        crt_subs = self._crtsh(domain)
        if crt_subs:
            all_subs.update(crt_subs)
            sources_used.append(f"crt.sh ({len(crt_subs)})")

        # HackerTarget (free tier)
        ht_subs = self._hackertarget(domain)
        if ht_subs:
            all_subs.update(ht_subs)
            sources_used.append(f"HackerTarget ({len(ht_subs)})")

        # AlienVault OTX (free)
        otx_subs = self._alienvault(domain)
        if otx_subs:
            all_subs.update(otx_subs)
            sources_used.append(f"AlienVault ({len(otx_subs)})")

        # Rapiddns (free)
        rd_subs = self._rapiddns(domain)
        if rd_subs:
            all_subs.update(rd_subs)
            sources_used.append(f"RapidDNS ({len(rd_subs)})")

        # SecurityTrails API
        if self.config.securitytrails:
            st_subs = self._securitytrails(domain)
            if st_subs:
                all_subs.update(st_subs)
                sources_used.append(f"SecurityTrails ({len(st_subs)})")

        # VirusTotal API
        if self.config.virustotal:
            vt_subs = self._virustotal(domain)
            if vt_subs:
                all_subs.update(vt_subs)
                sources_used.append(f"VirusTotal ({len(vt_subs)})")

        # Shodan API
        if self.config.shodan:
            sh_subs = self._shodan(domain)
            if sh_subs:
                all_subs.update(sh_subs)
                sources_used.append(f"Shodan ({len(sh_subs)})")

        # Clean and sort
        cleaned = sorted(s.lower().strip().rstrip(".") for s in all_subs
                         if s.endswith(domain) or s.endswith(f".{domain}"))

        self.log.success(f"Total unique subdomains: {len(cleaned)}")
        for src in sources_used:
            self.log.found(src)

        return {
            "domain": domain,
            "total": len(cleaned),
            "subdomains": cleaned,
            "sources": sources_used,
        }

    def _crtsh(self, domain):
        subs = set()
        try:
            self.log.info("Querying crt.sh (Certificate Transparency)...")
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                for entry in r.json():
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lstrip("*.").lower()
                        if line and domain in line:
                            subs.add(line)
        except Exception as e:
            self.log.debug(f"crt.sh error: {e}")
        return subs

    def _hackertarget(self, domain):
        subs = set()
        try:
            self.log.info("Querying HackerTarget...")
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.strip().split("\n"):
                    if "," in line:
                        host = line.split(",")[0].strip().lower()
                        if host and domain in host:
                            subs.add(host)
        except Exception as e:
            self.log.debug(f"HackerTarget error: {e}")
        return subs

    def _alienvault(self, domain):
        subs = set()
        try:
            self.log.info("Querying AlienVault OTX...")
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                for entry in r.json().get("passive_dns", []):
                    hostname = entry.get("hostname", "").lower()
                    if hostname and domain in hostname:
                        subs.add(hostname)
        except Exception as e:
            self.log.debug(f"AlienVault error: {e}")
        return subs

    def _rapiddns(self, domain):
        subs = set()
        try:
            self.log.info("Querying RapidDNS...")
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            r = requests.get(url, timeout=self.timeout,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                import re
                pattern = r"[\w.-]+\." + re.escape(domain)
                matches = re.findall(pattern, r.text)
                subs.update(m.lower() for m in matches)
        except Exception as e:
            self.log.debug(f"RapidDNS error: {e}")
        return subs

    def _securitytrails(self, domain):
        subs = set()
        try:
            self.log.info("Querying SecurityTrails API...")
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": self.config.securitytrails}
            r = requests.get(url, headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                for sub in r.json().get("subdomains", []):
                    subs.add(f"{sub}.{domain}")
        except Exception as e:
            self.log.debug(f"SecurityTrails error: {e}")
        return subs

    def _virustotal(self, domain):
        subs = set()
        try:
            self.log.info("Querying VirusTotal API...")
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
            headers = {"x-apikey": self.config.virustotal}
            r = requests.get(url, headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    sub_id = item.get("id", "").lower()
                    if sub_id:
                        subs.add(sub_id)
        except Exception as e:
            self.log.debug(f"VirusTotal error: {e}")
        return subs

    def _shodan(self, domain):
        subs = set()
        try:
            self.log.info("Querying Shodan API...")
            url = f"https://api.shodan.io/dns/domain/{domain}?key={self.config.shodan}"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                for record in r.json().get("data", []):
                    sub = record.get("subdomain", "")
                    if sub:
                        subs.add(f"{sub}.{domain}")
        except Exception as e:
            self.log.debug(f"Shodan error: {e}")
        return subs
