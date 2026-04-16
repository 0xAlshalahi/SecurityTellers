"""IP History Module — Fetch historical DNS/IP records for a domain."""

import json
import socket
import requests


class IPHistoryModule:
    def __init__(self, config, log, timeout=15):
        self.config = config
        self.log = log
        self.timeout = timeout

    def get_domain_ip_history(self, domain):
        self.log.info(f"Fetching IP history for {domain}")
        results = {
            "current_ip": None,
            "current_dns": {},
            "history": [],
            "sources_used": [],
        }

        # Current resolution
        try:
            ip = socket.gethostbyname(domain)
            results["current_ip"] = ip
            self.log.found(f"Current IP: {ip}")
        except socket.gaierror:
            self.log.warn("Could not resolve current IP")

        # Current DNS records
        results["current_dns"] = self._fetch_dns_records(domain)

        # SecurityTrails history
        if self.config.securitytrails:
            st_history = self._securitytrails_history(domain)
            if st_history:
                results["history"].extend(st_history)
                results["sources_used"].append("SecurityTrails")

        # ViewDNS history
        if self.config.viewdns:
            vd_history = self._viewdns_history(domain)
            if vd_history:
                results["history"].extend(vd_history)
                results["sources_used"].append("ViewDNS")

        # Free: HackerTarget
        ht_history = self._hackertarget_dns(domain)
        if ht_history:
            results["history"].extend(ht_history)
            results["sources_used"].append("HackerTarget")

        # Free: DNS history via common records
        mx_ips = self._mx_record_ips(domain)
        if mx_ips:
            results["mx_ips"] = mx_ips
            results["sources_used"].append("MX-Records")

        # Deduplicate history by IP
        seen = set()
        unique = []
        for entry in results["history"]:
            ip = entry.get("ip", "")
            if ip and ip not in seen:
                seen.add(ip)
                unique.append(entry)
        results["history"] = unique

        self.log.success(f"Found {len(results['history'])} historical IP records from {len(results['sources_used'])} sources")
        return results

    def get_ip_info(self, ip):
        self.log.info(f"Fetching info for IP {ip}")
        results = {"ip": ip, "info": {}, "sources_used": []}

        # Shodan
        if self.config.shodan:
            info = self._shodan_ip(ip)
            if info:
                results["info"]["shodan"] = info
                results["sources_used"].append("Shodan")

        # VirusTotal
        if self.config.virustotal:
            info = self._virustotal_ip(ip)
            if info:
                results["info"]["virustotal"] = info
                results["sources_used"].append("VirusTotal")

        # Free: ip-api.com
        info = self._ipapi_lookup(ip)
        if info:
            results["info"]["geolocation"] = info
            results["sources_used"].append("ip-api")

        return results

    def _fetch_dns_records(self, domain):
        records = {}
        try:
            url = f"https://dns.google/resolve?name={domain}&type=A"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                records["A"] = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]

            for rtype in ["MX", "TXT", "NS", "CNAME"]:
                type_map = {"MX": 15, "TXT": 16, "NS": 2, "CNAME": 5}
                url = f"https://dns.google/resolve?name={domain}&type={rtype}"
                r = requests.get(url, timeout=self.timeout)
                if r.status_code == 200:
                    data = r.json()
                    answers = [a["data"] for a in data.get("Answer", [])
                               if a.get("type") == type_map.get(rtype)]
                    if answers:
                        records[rtype] = answers
        except Exception as e:
            self.log.debug(f"DNS fetch error: {e}")
        return records

    def _securitytrails_history(self, domain):
        history = []
        try:
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            headers = {"APIKEY": self.config.securitytrails}
            r = requests.get(url, headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                for record in data.get("records", []):
                    for val in record.get("values", []):
                        ip = val.get("ip", "")
                        if ip:
                            entry = {
                                "ip": ip,
                                "first_seen": record.get("first_seen", ""),
                                "last_seen": record.get("last_seen", ""),
                                "source": "SecurityTrails",
                            }
                            history.append(entry)
                            self.log.found(f"{ip} ({record.get('first_seen', '?')} → {record.get('last_seen', '?')})")
            elif r.status_code == 429:
                self.log.warn("SecurityTrails rate limit hit")
            else:
                self.log.debug(f"SecurityTrails: {r.status_code}")
        except Exception as e:
            self.log.debug(f"SecurityTrails error: {e}")
        return history

    def _viewdns_history(self, domain):
        history = []
        try:
            url = f"https://api.viewdns.info/iphistory/?domain={domain}&apikey={self.config.viewdns}&output=json"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                for record in data.get("response", {}).get("records", []):
                    entry = {
                        "ip": record.get("ip", ""),
                        "last_seen": record.get("lastseen", ""),
                        "location": record.get("location", ""),
                        "source": "ViewDNS",
                    }
                    if entry["ip"]:
                        history.append(entry)
                        self.log.found(f"{entry['ip']} (last: {entry['last_seen']})")
        except Exception as e:
            self.log.debug(f"ViewDNS error: {e}")
        return history

    def _hackertarget_dns(self, domain):
        history = []
        try:
            url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.strip().split("\n"):
                    if "A" in line and "." in line:
                        parts = line.strip().split()
                        for p in parts:
                            if self._is_ip(p):
                                history.append({
                                    "ip": p,
                                    "source": "HackerTarget",
                                    "record_type": "A",
                                })
                                self.log.found(f"{p} (HackerTarget DNS)")
        except Exception as e:
            self.log.debug(f"HackerTarget error: {e}")
        return history

    def _mx_record_ips(self, domain):
        """MX records sometimes reveal origin IPs behind CDN."""
        ips = []
        try:
            url = f"https://dns.google/resolve?name={domain}&type=MX"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                for answer in data.get("Answer", []):
                    mx_host = answer.get("data", "").split()[-1].rstrip(".")
                    if mx_host:
                        try:
                            mx_ip = socket.gethostbyname(mx_host)
                            ips.append({"mx_host": mx_host, "ip": mx_ip})
                            self.log.found(f"MX: {mx_host} → {mx_ip}")
                        except socket.gaierror:
                            pass
        except Exception as e:
            self.log.debug(f"MX lookup error: {e}")
        return ips

    def _shodan_ip(self, ip):
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.config.shodan}"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                info = {
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                }
                self.log.found(f"Shodan: {info['org']} | Ports: {info['ports']}")
                return info
        except Exception as e:
            self.log.debug(f"Shodan error: {e}")
        return None

    def _virustotal_ip(self, ip):
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.config.virustotal}
            r = requests.get(url, headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                return {
                    "country": attrs.get("country"),
                    "as_owner": attrs.get("as_owner"),
                    "network": attrs.get("network"),
                    "reputation": attrs.get("reputation"),
                }
        except Exception as e:
            self.log.debug(f"VirusTotal error: {e}")
        return None

    def _ipapi_lookup(self, ip):
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    info = {
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as"),
                    }
                    self.log.found(f"Geo: {info['country']}, {info['city']} — {info['isp']}")
                    return info
        except Exception as e:
            self.log.debug(f"ip-api error: {e}")
        return None

    @staticmethod
    def _is_ip(s):
        parts = s.split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
