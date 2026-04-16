"""Cloudflare Bypass Module — Attempt to discover origin IP behind Cloudflare."""

import ipaddress
import socket
import requests


# Cloudflare IP ranges (ASN 13335)
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]


class CloudflareBypass:
    def __init__(self, config, log, timeout=15):
        self.config = config
        self.log = log
        self.timeout = timeout
        self.cf_networks = [ipaddress.ip_network(r) for r in CF_RANGES]

    def analyze(self, domain):
        results = {
            "domain": domain,
            "is_cloudflare": False,
            "current_ip": None,
            "origin_candidates": [],
            "methods_used": [],
        }

        # Step 1: Check if behind Cloudflare
        try:
            ip = socket.gethostbyname(domain)
            results["current_ip"] = ip
        except socket.gaierror:
            self.log.error(f"Cannot resolve {domain}")
            return results

        results["is_cloudflare"] = self._is_cloudflare_ip(ip)

        if not results["is_cloudflare"]:
            self.log.info(f"{domain} is NOT behind Cloudflare (IP: {ip})")
            self.log.found(f"Direct origin IP: {ip}")
            results["origin_candidates"].append({
                "ip": ip, "method": "direct_resolution", "confidence": "confirmed"
            })
            return results

        self.log.warn(f"{domain} IS behind Cloudflare (IP: {ip})")
        self.log.info("Attempting origin IP discovery...\n")

        # Method 1: Historical DNS records
        self.log.info("[Method 1] Historical DNS records")
        hist_ips = self._check_historical_dns(domain)
        for entry in hist_ips:
            if not self._is_cloudflare_ip(entry["ip"]):
                entry["confidence"] = "medium"
                results["origin_candidates"].append(entry)
                self.log.found(f"Pre-CF IP: {entry['ip']} ({entry.get('source', '?')})")
        results["methods_used"].append("historical_dns")

        # Method 2: MX record IP leak
        self.log.info("[Method 2] MX record analysis")
        mx_ips = self._check_mx_records(domain)
        for entry in mx_ips:
            if not self._is_cloudflare_ip(entry["ip"]):
                entry["confidence"] = "medium"
                results["origin_candidates"].append(entry)
                self.log.found(f"MX leak: {entry['ip']} ({entry.get('mx_host', '?')})")
        results["methods_used"].append("mx_records")

        # Method 3: SPF record IP leak
        self.log.info("[Method 3] SPF record analysis")
        spf_ips = self._check_spf_records(domain)
        for entry in spf_ips:
            if not self._is_cloudflare_ip(entry["ip"]):
                entry["confidence"] = "medium"
                results["origin_candidates"].append(entry)
                self.log.found(f"SPF leak: {entry['ip']}")
        results["methods_used"].append("spf_records")

        # Method 4: Common subdomain bypass
        self.log.info("[Method 4] Subdomain direct resolution")
        sub_ips = self._check_subdomains(domain)
        for entry in sub_ips:
            if not self._is_cloudflare_ip(entry["ip"]):
                entry["confidence"] = "high"
                results["origin_candidates"].append(entry)
                self.log.found(f"Direct sub: {entry['subdomain']} → {entry['ip']}")
        results["methods_used"].append("subdomain_bypass")

        # Method 5: SecurityTrails historical data
        if self.config.securitytrails:
            self.log.info("[Method 5] SecurityTrails history")
            st_ips = self._securitytrails_history(domain)
            for entry in st_ips:
                if not self._is_cloudflare_ip(entry["ip"]):
                    entry["confidence"] = "medium"
                    results["origin_candidates"].append(entry)
                    self.log.found(f"ST history: {entry['ip']} ({entry.get('last_seen', '?')})")
            results["methods_used"].append("securitytrails")

        # Method 6: Censys search for SSL certificate
        if self.config.censys_id:
            self.log.info("[Method 6] Censys certificate search")
            censys_ips = self._censys_cert_search(domain)
            for entry in censys_ips:
                if not self._is_cloudflare_ip(entry["ip"]):
                    entry["confidence"] = "high"
                    results["origin_candidates"].append(entry)
                    self.log.found(f"Censys cert: {entry['ip']}")
            results["methods_used"].append("censys")

        # Deduplicate candidates
        seen = set()
        unique = []
        for c in results["origin_candidates"]:
            if c["ip"] not in seen:
                seen.add(c["ip"])
                unique.append(c)
        results["origin_candidates"] = unique

        if unique:
            self.log.success(f"Found {len(unique)} origin IP candidates")

            # Verify candidates
            self.log.info("\nVerifying candidates...")
            for candidate in unique:
                verified = self._verify_origin(domain, candidate["ip"])
                candidate["verified"] = verified
                status = "CONFIRMED" if verified else "unverified"
                self.log.found(f"{candidate['ip']} — {status} (via {candidate.get('method', '?')})")
        else:
            self.log.warn("No origin IP candidates found. Cloudflare bypass unsuccessful.")

        return results

    def _is_cloudflare_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in self.cf_networks)
        except ValueError:
            return False

    def _check_historical_dns(self, domain):
        candidates = []
        try:
            url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                for line in r.text.strip().split("\n"):
                    parts = line.strip().split()
                    for p in parts:
                        if self._is_valid_ip(p):
                            candidates.append({
                                "ip": p, "method": "historical_dns",
                                "source": "HackerTarget"
                            })
        except Exception:
            pass

        # ViewDNS IP history
        if self.config.viewdns:
            try:
                url = f"https://api.viewdns.info/iphistory/?domain={domain}&apikey={self.config.viewdns}&output=json"
                r = requests.get(url, timeout=self.timeout)
                if r.status_code == 200:
                    for record in r.json().get("response", {}).get("records", []):
                        ip = record.get("ip", "")
                        if ip:
                            candidates.append({
                                "ip": ip, "method": "historical_dns",
                                "source": "ViewDNS",
                                "last_seen": record.get("lastseen", ""),
                            })
            except Exception:
                pass
        return candidates

    def _check_mx_records(self, domain):
        candidates = []
        try:
            url = f"https://dns.google/resolve?name={domain}&type=MX"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                for answer in r.json().get("Answer", []):
                    mx_host = answer.get("data", "").split()[-1].rstrip(".")
                    if mx_host:
                        try:
                            mx_ip = socket.gethostbyname(mx_host)
                            candidates.append({
                                "ip": mx_ip, "method": "mx_record",
                                "mx_host": mx_host,
                            })
                        except socket.gaierror:
                            pass
        except Exception:
            pass
        return candidates

    def _check_spf_records(self, domain):
        candidates = []
        try:
            url = f"https://dns.google/resolve?name={domain}&type=TXT"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                for answer in r.json().get("Answer", []):
                    txt = answer.get("data", "")
                    if "v=spf1" in txt:
                        import re
                        # Extract ip4: entries
                        ips = re.findall(r"ip4:(\d+\.\d+\.\d+\.\d+(?:/\d+)?)", txt)
                        for ip in ips:
                            ip_clean = ip.split("/")[0]
                            candidates.append({
                                "ip": ip_clean, "method": "spf_record",
                            })
                        # Extract include: and resolve
                        includes = re.findall(r"include:(\S+)", txt)
                        for inc in includes[:3]:
                            try:
                                inc_ip = socket.gethostbyname(inc)
                                candidates.append({
                                    "ip": inc_ip, "method": "spf_include",
                                    "include_domain": inc,
                                })
                            except socket.gaierror:
                                pass
        except Exception:
            pass
        return candidates

    def _check_subdomains(self, domain):
        """Many sites only proxy the main domain through CF, not subdomains."""
        candidates = []
        bypass_subs = [
            "direct", "origin", "server", "backend", "real", "mail", "smtp",
            "ftp", "cpanel", "webmail", "ns1", "ns2", "dns", "mx", "pop",
            "imap", "old", "dev", "staging", "test", "api", "admin",
            "panel", "portal", "direct-connect", "host", "node",
        ]
        for sub in bypass_subs:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                candidates.append({
                    "ip": ip, "method": "subdomain_bypass",
                    "subdomain": fqdn,
                })
            except socket.gaierror:
                pass
        return candidates

    def _securitytrails_history(self, domain):
        candidates = []
        try:
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            headers = {"APIKEY": self.config.securitytrails}
            r = requests.get(url, headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                for record in r.json().get("records", []):
                    for val in record.get("values", []):
                        ip = val.get("ip", "")
                        if ip:
                            candidates.append({
                                "ip": ip, "method": "securitytrails_history",
                                "first_seen": record.get("first_seen"),
                                "last_seen": record.get("last_seen"),
                            })
        except Exception:
            pass
        return candidates

    def _censys_cert_search(self, domain):
        candidates = []
        try:
            url = "https://search.censys.io/api/v2/hosts/search"
            params = {"q": f"services.tls.certificates.leaf.names: {domain}", "per_page": 25}
            r = requests.get(url, params=params,
                             auth=(self.config.censys_id, self.config.censys_secret),
                             timeout=self.timeout)
            if r.status_code == 200:
                for hit in r.json().get("result", {}).get("hits", []):
                    ip = hit.get("ip", "")
                    if ip:
                        candidates.append({
                            "ip": ip, "method": "censys_certificate",
                        })
        except Exception:
            pass
        return candidates

    def _verify_origin(self, domain, ip):
        """Verify by sending HTTP request with Host header to the candidate IP."""
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{ip}/"
                r = requests.get(url, headers={"Host": domain},
                                 timeout=8, verify=False, allow_redirects=False)
                if r.status_code < 500 and len(r.text) > 100:
                    return True
            except Exception:
                pass
        return False

    @staticmethod
    def _is_valid_ip(s):
        parts = s.split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
