#!/usr/bin/env python3
"""
SecurityTellers — Domain & IP Intelligence Gathering Framework
Author: Abdulelah Al-shalahi (@0xAlshalahi)

Fetches IP history, subdomains, reverse IP (associated sites),
and attempts Cloudflare origin-IP bypass via historical DNS records.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

from core.banner import print_banner
from core.config import load_config, Config
from core.logger import Logger
from modules.ip_history import IPHistoryModule
from modules.subdomains import SubdomainModule
from modules.reverse_ip import ReverseIPModule
from modules.cloudflare import CloudflareBypass
from modules.report import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description="SecurityTellers — Domain & IP Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -d example.com
  python3 main.py -d example.com --module subs
  python3 main.py -ip 93.184.216.34
  python3 main.py -d example.com --cf-bypass
  python3 main.py -d example.com --all --output ./results
  python3 main.py --config api_keys.yaml
        """
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--domain", help="Target domain")
    target.add_argument("-ip", "--ip-address", help="Target IP address")

    parser.add_argument("-m", "--module", choices=["history", "subs", "reverse", "cf-bypass", "all"],
                        default="all", help="Module to run (default: all)")
    parser.add_argument("--cf-bypass", action="store_true", help="Attempt Cloudflare bypass")
    parser.add_argument("-o", "--output", default="results", help="Output directory (default: results/)")
    parser.add_argument("--config", default="api_keys.yaml", help="API keys config file")
    parser.add_argument("--json", action="store_true", help="Output as JSON only")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    return parser.parse_args()


def main():
    args = parse_args()
    print_banner()

    config = load_config(args.config)
    target = args.domain or args.ip_address
    target_type = "domain" if args.domain else "ip"
    safe_name = target.replace("/", "_").replace(":", "_")
    output_dir = os.path.join(args.output, safe_name)
    os.makedirs(output_dir, exist_ok=True)

    log = Logger(verbose=args.verbose, no_color=args.no_color)
    log.info(f"Target: {target} ({target_type})")
    log.info(f"Output: {output_dir}/")

    api_count = sum(1 for k in ["securitytrails", "shodan", "virustotal"]
                    if getattr(config, k, None))
    if api_count == 0:
        log.warn("No API keys configured. Using free sources only (crt.sh, HackerTarget).")
        log.warn(f"Add keys to {args.config} for full coverage.")
    else:
        log.info(f"API keys loaded: {api_count} providers")
    print()

    results = {
        "target": target,
        "type": target_type,
        "scan_date": datetime.now().isoformat(),
        "modules": {}
    }

    run_all = args.module == "all"

    # ── IP History ──
    if run_all or args.module == "history":
        log.section("IP HISTORY")
        hist = IPHistoryModule(config, log, timeout=args.timeout)
        if target_type == "domain":
            ip_results = hist.get_domain_ip_history(target)
        else:
            ip_results = hist.get_ip_info(target)
        results["modules"]["ip_history"] = ip_results
        _save(output_dir, "ip_history.json", ip_results)

    # ── Subdomains ──
    if target_type == "domain" and (run_all or args.module == "subs"):
        log.section("SUBDOMAIN ENUMERATION")
        subs = SubdomainModule(config, log, timeout=args.timeout)
        sub_results = subs.enumerate(target)
        results["modules"]["subdomains"] = sub_results
        _save(output_dir, "subdomains.json", sub_results)

        with open(os.path.join(output_dir, "subdomains.txt"), "w") as f:
            for s in sub_results.get("subdomains", []):
                f.write(s + "\n")

    # ── Reverse IP / Associated Sites ──
    if run_all or args.module == "reverse":
        log.section("REVERSE IP / ASSOCIATED SITES")
        rev = ReverseIPModule(config, log, timeout=args.timeout)
        if target_type == "domain":
            rev_results = rev.lookup_domain(target)
        else:
            rev_results = rev.lookup_ip(target)
        results["modules"]["reverse_ip"] = rev_results
        _save(output_dir, "reverse_ip.json", rev_results)

    # ── Cloudflare Bypass ──
    if target_type == "domain" and (args.cf_bypass or run_all or args.module == "cf-bypass"):
        log.section("CLOUDFLARE BYPASS ANALYSIS")
        cf = CloudflareBypass(config, log, timeout=args.timeout)
        cf_results = cf.analyze(target)
        results["modules"]["cloudflare_bypass"] = cf_results
        _save(output_dir, "cloudflare_bypass.json", cf_results)

    # ── Report ──
    print()
    report = ReportGenerator(log)
    report.generate(results, output_dir)

    _save(output_dir, "full_results.json", results)

    log.success(f"All results saved to: {output_dir}/")
    print()


def _save(directory, filename, data):
    path = os.path.join(directory, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


if __name__ == "__main__":
    main()
