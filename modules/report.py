"""Report Generator — Markdown and terminal report output."""

import os
from datetime import datetime


class ReportGenerator:
    def __init__(self, log):
        self.log = log

    def generate(self, results, output_dir):
        self.log.section("REPORT")
        report_path = os.path.join(output_dir, "report.md")
        target = results["target"]
        scan_date = results.get("scan_date", datetime.now().isoformat())

        with open(report_path, "w") as f:
            f.write(f"# SecurityTellers Report\n\n")
            f.write(f"| Field | Value |\n")
            f.write(f"|-------|-------|\n")
            f.write(f"| **Target** | `{target}` |\n")
            f.write(f"| **Type** | {results.get('type', 'N/A')} |\n")
            f.write(f"| **Date** | {scan_date} |\n")
            f.write(f"| **Tool** | SecurityTellers v1.0.0 |\n\n")
            f.write(f"---\n\n")

            modules = results.get("modules", {})

            # IP History
            if "ip_history" in modules:
                hist = modules["ip_history"]
                f.write(f"## IP History\n\n")
                f.write(f"**Current IP**: `{hist.get('current_ip', 'N/A')}`\n\n")

                dns = hist.get("current_dns", {})
                if dns:
                    f.write("**Current DNS Records**:\n")
                    for rtype, records in dns.items():
                        f.write(f"- **{rtype}**: {', '.join(str(r) for r in records)}\n")
                    f.write("\n")

                history = hist.get("history", [])
                if history:
                    f.write("**Historical IPs**:\n\n")
                    f.write("| IP | First Seen | Last Seen | Source |\n")
                    f.write("|----|-----------:|----------:|--------|\n")
                    for h in history:
                        f.write(f"| `{h.get('ip', '')}` | {h.get('first_seen', '-')} | {h.get('last_seen', '-')} | {h.get('source', '-')} |\n")
                    f.write("\n")

                mx_ips = hist.get("mx_ips", [])
                if mx_ips:
                    f.write("**MX Record IPs** (potential origin leak):\n")
                    for mx in mx_ips:
                        f.write(f"- `{mx['mx_host']}` → `{mx['ip']}`\n")
                    f.write("\n")
                f.write("---\n\n")

            # Subdomains
            if "subdomains" in modules:
                subs = modules["subdomains"]
                f.write(f"## Subdomains ({subs.get('total', 0)})\n\n")
                f.write("**Sources**: " + ", ".join(subs.get("sources", [])) + "\n\n")
                sub_list = subs.get("subdomains", [])
                if sub_list:
                    f.write("| # | Subdomain |\n")
                    f.write("|---|----------|\n")
                    for i, s in enumerate(sub_list[:100], 1):
                        f.write(f"| {i} | `{s}` |\n")
                    if len(sub_list) > 100:
                        f.write(f"\n*... and {len(sub_list) - 100} more (see subdomains.txt)*\n")
                f.write("\n---\n\n")

            # Reverse IP
            if "reverse_ip" in modules:
                rev = modules["reverse_ip"]
                domains = rev.get("associated_domains", [])
                f.write(f"## Associated Sites ({rev.get('total', len(domains))})\n\n")
                if domains:
                    f.write("| # | Domain | Source |\n")
                    f.write("|---|--------|--------|\n")
                    for i, d in enumerate(domains[:50], 1):
                        f.write(f"| {i} | `{d.get('domain', '')}` | {d.get('source', '')} |\n")
                    if len(domains) > 50:
                        f.write(f"\n*... and {len(domains) - 50} more*\n")
                f.write("\n---\n\n")

            # Cloudflare Bypass
            if "cloudflare_bypass" in modules:
                cf = modules["cloudflare_bypass"]
                f.write("## Cloudflare Analysis\n\n")
                f.write(f"**Behind Cloudflare**: {'Yes' if cf.get('is_cloudflare') else 'No'}\n")
                f.write(f"**Current IP**: `{cf.get('current_ip', 'N/A')}`\n")
                f.write(f"**Methods Used**: {', '.join(cf.get('methods_used', []))}\n\n")

                candidates = cf.get("origin_candidates", [])
                if candidates:
                    f.write("**Origin IP Candidates**:\n\n")
                    f.write("| IP | Method | Confidence | Verified |\n")
                    f.write("|----|--------|------------|----------|\n")
                    for c in candidates:
                        verified = "YES" if c.get("verified") else "no"
                        f.write(f"| `{c['ip']}` | {c.get('method', '')} | {c.get('confidence', '')} | {verified} |\n")
                f.write("\n")

        self.log.success(f"Report: {report_path}")

        # Terminal summary
        self._print_summary(results)

    def _print_summary(self, results):
        modules = results.get("modules", {})
        print()
        self.log.info("── Summary ──")

        if "ip_history" in modules:
            hist = modules["ip_history"]
            self.log.found(f"IP History: {len(hist.get('history', []))} records | Current: {hist.get('current_ip', '?')}")

        if "subdomains" in modules:
            self.log.found(f"Subdomains: {modules['subdomains'].get('total', 0)}")

        if "reverse_ip" in modules:
            self.log.found(f"Associated Sites: {modules['reverse_ip'].get('total', 0)}")

        if "cloudflare_bypass" in modules:
            cf = modules["cloudflare_bypass"]
            cf_status = "YES" if cf.get("is_cloudflare") else "NO"
            candidates = len(cf.get("origin_candidates", []))
            verified = sum(1 for c in cf.get("origin_candidates", []) if c.get("verified"))
            self.log.found(f"Cloudflare: {cf_status} | Candidates: {candidates} | Verified: {verified}")
