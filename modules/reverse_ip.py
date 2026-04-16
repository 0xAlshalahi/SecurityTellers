"""Reverse IP Module — Find domains hosted on the same IP."""

import socket
import requests


class ReverseIPModule:
    def __init__(self, config, log, timeout=15):
        self.config = config
        self.log = log
        self.timeout = timeout

    def lookup_domain(self, domain):
        self.log.info(f"Reverse IP lookup for {domain}")
        try:
            ip = socket.gethostbyname(domain)
            self.log.found(f"Resolved to {ip}")
        except socket.gaierror:
            self.log.error(f"Could not resolve {domain}")
            return {"error": "DNS resolution failed"}
        return self.lookup_ip(ip)

    def lookup_ip(self, ip):
        self.log.info(f"Finding associated sites on {ip}")
        results = {
            "ip": ip,
            "associated_domains": [],
            "sources_used": [],
        }

        # HackerTarget reverse IP (free)
        ht = self._hackertarget(ip)
        if ht:
            results["associated_domains"].extend(ht)
            results["sources_used"].append(f"HackerTarget ({len(ht)})")

        # SecurityTrails
        if self.config.securitytrails:
            st = self._securitytrails(ip)
            if st:
                results["associated_domains"].extend(st)
                results["sources_used"].append(f"SecurityTrails ({len(st)})")

        # VirusTotal
        if self.config.virustotal:
            vt = self._virustotal(ip)
            if vt:
                results["associated_domains"].extend(vt)
                results["sources_used"].append(f"VirusTotal ({len(vt)})")

        # Shodan
        if self.config.shodan:
            sh = self._shodan(ip)
            if sh:
                results["associated_domains"].extend(sh)
                results["sources_used"].append(f"Shodan ({len(sh)})")

        # Deduplicate
        seen = set()
        unique = []
        for d in results["associated_domains"]:
            domain = d.get("domain", "").lower()
            if domain and domain not in seen:
                seen.add(domain)
                unique.append(d)
        results["associated_domains"] = unique
        results["total"] = len(unique)

        self.log.success(f"Found {len(unique)} associated domains")
        for d in unique[:15]:
            self.log.found(d.get("domain", ""))
        if len(unique) > 15:
            self.log.info(f"  ... and {len(unique) - 15} more (see JSON output)")

        return results

    def _hackertarget(self, ip):
        domains = []
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200 and "error" not in r.text.lower() and "API count" not in r.text:
                for line in r.text.strip().split("\n"):
                    domain = line.strip().lower()
                    if domain and "." in domain:
                        domains.append({"domain": domain, "source": "HackerTarget"})
        except Exception as e:
            self.log.debug(f"HackerTarget reverse error: {e}")
        return domains

    def _securitytrails(self, ip):
        domains = []
        try:
            url = f"https://api.securitytrails.com/v1/ips/nearby/{ip}"
            headers = {"APIKEY": self.config.securitytrails}
            r = requests.get(url, headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                for block in r.json().get("blocks", []):
                    for host in block.get("hostnames", []):
                        domains.append({"domain": host, "source": "SecurityTrails"})
        except Exception as e:
            self.log.debug(f"SecurityTrails reverse error: {e}")
        return domains

    def _virustotal(self, ip):
        domains = []
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=40"
            headers = {"x-apikey": self.config.virustotal}
            r = requests.get(url, headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    host = item.get("attributes", {}).get("host_name", "")
                    if host:
                        domains.append({"domain": host.lower(), "source": "VirusTotal"})
        except Exception as e:
            self.log.debug(f"VirusTotal reverse error: {e}")
        return domains

    def _shodan(self, ip):
        domains = []
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.config.shodan}"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                for host in r.json().get("hostnames", []):
                    domains.append({"domain": host.lower(), "source": "Shodan"})
        except Exception as e:
            self.log.debug(f"Shodan reverse error: {e}")
        return domains
