"""
src/capture/config.py
Scope configuration loader for jxs.

Each scope defines:
  - scope_name      : unique identifier (e.g. 'infomaniak', 'linkedin')
  - host_whitelist  : list of root domains — subdomain matching automatic.
                      Cukup tulis "infomaniak.com", semua subdomain
                      (api.infomaniak.com, kchat.infomaniak.com, dll) otomatis
                      di-cover karena is_in_scope() pakai suffix match.
                      Matching logic: host == entry OR host.endswith(f".{entry}")
  - test_only_hosts : (opsional) host yang boleh di-capture TAPI findings-nya
                      perlu manual verifikasi apakah in-scope program sebelum
                      di-report. Auto-tagged 'verify_scope' di findings.
  - auth_cookie     : optional session cookie string for authenticated crawl
  - host_list_file  : optional path to a file with one host per line

Config is loaded from scope_config.json in the project root.
Multiple scopes can coexist; the active scope is selected at runtime.

Example scope_config.json:
{
  "scopes": [
    {
      "scope_name": "infomaniak",
      "host_whitelist": ["infomaniak.com"],
      "test_only_hosts": ["legacy.infomaniak.com"],
      "auth_cookie": null,
      "host_list_file": null
    },
    {
      "scope_name": "linkedin",
      "host_whitelist": ["linkedin.com"],
      "test_only_hosts": [],
      "auth_cookie": "li_at=AQEDATxxxxxx...",
      "host_list_file": null
    }
  ]
}
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "scope_config.json"


@dataclass
class ScopeConfig:
    """Represents one bug bounty program scope."""

    scope_name: str
    host_whitelist: list[str] = field(default_factory=list)
    # test_only_hosts: host yang boleh di-capture TAPI findings-nya perlu verifikasi
    # apakah benar-benar in-scope program sebelum di-report.
    # Matching logic: SAMA dengan host_whitelist (suffix match).
    # Findings dari host ini auto-tagged 'verify_scope' di DB.
    test_only_hosts: list[str] = field(default_factory=list)
    auth_cookie: Optional[str] = None
    host_list_file: Optional[str] = None

    def __post_init__(self) -> None:
        # Normalize hosts to lowercase, strip trailing dots/slashes
        self.host_whitelist = [
            h.lower().rstrip("./") for h in self.host_whitelist
        ]
        self.test_only_hosts = [
            h.lower().rstrip("./") for h in self.test_only_hosts
        ]
        # If host_list_file is provided and exists, merge hosts from file
        if self.host_list_file:
            p = Path(self.host_list_file)
            if p.exists():
                extra = [
                    line.strip().lower()
                    for line in p.read_text().splitlines()
                    if line.strip() and not line.startswith("#")
                ]
                self.host_whitelist = list(set(self.host_whitelist + extra))
                logger.debug(
                    "Loaded %d hosts from %s for scope '%s'",
                    len(extra), self.host_list_file, self.scope_name,
                )

    def is_in_scope(self, host: str) -> bool:
        """Return True if host matches any entry in host_whitelist OR test_only_hosts.

        Matching is suffix-based: entry 'infomaniak.com' covers both
        'infomaniak.com' and '*.infomaniak.com' automatically.
        test_only_hosts are in-scope for capture but need program scope
        verification before reporting — call is_test_only_host() to check.
        """
        host = host.lower().split(":")[0]  # strip port if present
        return self._matches_list(host, self.host_whitelist) \
            or self._matches_list(host, self.test_only_hosts)

    def is_test_only_host(self, host: str) -> bool:
        """Return True if host is in test_only_hosts (suffix match).

        Findings from test_only_hosts are capturable but auto-tagged
        'verify_scope' — reporter must confirm the host is in-scope
        for the program before submitting.
        """
        host = host.lower().split(":")[0]
        return self._matches_list(host, self.test_only_hosts)

    @staticmethod
    def _matches_list(host: str, host_list: list[str]) -> bool:
        """Suffix-match host against a list of root domains."""
        for entry in host_list:
            if host == entry or host.endswith(f".{entry}"):
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "scope_name":     self.scope_name,
            "host_whitelist": self.host_whitelist,
            "test_only_hosts": self.test_only_hosts,
            "auth_cookie":    self.auth_cookie,
            "host_list_file": self.host_list_file,
        }


class ScopeRegistry:
    """In-memory registry of all configured scopes, loaded from JSON."""

    def __init__(self, config_path: str | Path = DEFAULT_CONFIG_PATH) -> None:
        self._scopes: dict[str, ScopeConfig] = {}
        self._path = Path(config_path)
        if self._path.exists():
            self.load(self._path)
        else:
            logger.warning(
                "scope_config.json not found at %s — using empty registry. "
                "Create it or add scopes via the API.",
                self._path,
            )

    def load(self, config_path: Path) -> None:
        """(Re-)load scopes from a JSON file."""
        try:
            raw = json.loads(config_path.read_text())
            scopes_raw = raw.get("scopes", [])
            for s in scopes_raw:
                sc = ScopeConfig(**s)
                self._scopes[sc.scope_name] = sc
            logger.info("Loaded %d scope(s) from %s", len(self._scopes), config_path)
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            logger.error("Failed to parse scope config: %s", exc)

    def get(self, scope_name: str) -> Optional[ScopeConfig]:
        return self._scopes.get(scope_name)

    def all(self) -> list[ScopeConfig]:
        return list(self._scopes.values())

    def add(self, scope: ScopeConfig) -> None:
        self._scopes[scope.scope_name] = scope

    def save(self, config_path: Path | None = None) -> None:
        """Persist current scopes back to JSON."""
        path = config_path or self._path
        data = {"scopes": [s.to_dict() for s in self._scopes.values()]}
        path.write_text(json.dumps(data, indent=2))
        logger.info("Saved %d scope(s) to %s", len(self._scopes), path)

    def resolve_scope_for_host(self, host: str) -> Optional[str]:
        """Return the first scope_name whose whitelist matches `host`."""
        for sc in self._scopes.values():
            if sc.is_in_scope(host):
                return sc.scope_name
        return None
