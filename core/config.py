"""Configuration loader for API keys."""

import os
from dataclasses import dataclass, field

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class Config:
    securitytrails: str = ""
    shodan: str = ""
    virustotal: str = ""
    viewdns: str = ""
    censys_id: str = ""
    censys_secret: str = ""


def load_config(path: str) -> Config:
    config = Config()

    # Environment variables take priority
    config.securitytrails = os.environ.get("ST_API_KEY", "")
    config.shodan = os.environ.get("SHODAN_API_KEY", "")
    config.virustotal = os.environ.get("VT_API_KEY", "")
    config.viewdns = os.environ.get("VIEWDNS_API_KEY", "")
    config.censys_id = os.environ.get("CENSYS_API_ID", "")
    config.censys_secret = os.environ.get("CENSYS_API_SECRET", "")

    if os.path.exists(path):
        if HAS_YAML:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            config.securitytrails = config.securitytrails or data.get("securitytrails", "")
            config.shodan = config.shodan or data.get("shodan", "")
            config.virustotal = config.virustotal or data.get("virustotal", "")
            config.viewdns = config.viewdns or data.get("viewdns", "")
            config.censys_id = config.censys_id or data.get("censys_id", "")
            config.censys_secret = config.censys_secret or data.get("censys_secret", "")
        else:
            # Fallback: simple key=value parsing
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        key, val = line.split(":", 1)
                        key = key.strip().lower()
                        val = val.strip().strip('"').strip("'")
                        if hasattr(config, key) and val:
                            setattr(config, key, val)

    return config
