"""Package registry lookups (PyPI JSON API, npm registry) - contract §4.7.

The registry is the only source of "which versions actually exist"; the
candidate selection uses it to snap an OSV *fixed* version to a version that
can really be installed and to learn the latest release.  A registry that
cannot be reached is reported as ``available=False`` (never as "no versions").
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

from app.core.logging import get_stage_logger
from app.core.versions import max_version, normalize_package_name, sort_versions
from app.models.enums import Ecosystem

log = get_stage_logger("Remediation")

PYPI_BASE_URL = "https://pypi.org/pypi"
NPM_BASE_URL = "https://registry.npmjs.org"
USER_AGENT = "sentinel-chain/1.0 (+https://github.com/sentinel-chain)"
NOT_FOUND = "package not found"


@dataclass
class RegistryInfo:
    """Versions published for one package as reported by its registry.

    ``versions`` lists every installable release (ascending, pre-releases
    included, yanked/empty PyPI releases excluded); ``latest`` is the highest
    non-pre-release entry.  ``available=False`` means the registry could not
    be consulted (``error`` says why) - a *not found* package is
    ``available=True`` with an empty list and ``error="package not found"``.
    """

    ecosystem: str
    package_name: str
    versions: list[str] = field(default_factory=list)
    latest: str | None = None
    available: bool = True
    error: str | None = None
    #: What the registry itself calls the latest release (``info.version`` / ``dist-tags.latest``).
    registry_latest: str | None = None
    #: Versions excluded because every file of the release is yanked (PyPI) or the
    #: version is marked ``deprecated`` on npm ("Bad release" style withdrawals).
    yanked: list[str] = field(default_factory=list)
    #: npm ``deprecated`` messages per excluded version (evidence for the report).
    deprecations: dict[str, str] = field(default_factory=dict)

    @property
    def found(self) -> bool:
        return self.available and bool(self.versions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "versions": list(self.versions),
            "latest": self.latest,
            "available": self.available,
            "error": self.error,
            "registry_latest": self.registry_latest,
            "yanked": list(self.yanked),
        }


class PackageRegistryClient:
    """Reads published versions from PyPI / npm over HTTPS (``httpx.Client`` injectable)."""

    def __init__(
        self,
        timeout: float | None = None,
        client: httpx.Client | None = None,
        *,
        pypi_base_url: str = PYPI_BASE_URL,
        npm_base_url: str = NPM_BASE_URL,
    ) -> None:
        self.timeout = float(timeout) if timeout is not None else 20.0
        self.pypi_base_url = pypi_base_url.rstrip("/")
        self.npm_base_url = npm_base_url.rstrip("/")
        self._client = client
        self._owns_client = client is None

    # ------------------------------------------------------------------ public API

    def versions(self, ecosystem: str, name: str) -> RegistryInfo:
        """Published versions of ``name``; never raises (see :class:`RegistryInfo`)."""
        try:
            url = self.url_for(ecosystem, name)
        except ValueError as exc:
            log.warning("Registry lookup skipped for %s %s: %s", ecosystem, name, exc)
            return RegistryInfo(ecosystem=ecosystem, package_name=name, available=False, error=str(exc))

        payload, error, available = self._fetch_json(url)
        if payload is None:
            info = RegistryInfo(ecosystem=ecosystem, package_name=name, available=available, error=error)
            log.warning("Registry %s for %s %s: %s", "unavailable" if not available else "answered", ecosystem, name, error)
            return info
        try:
            info = self._parse(ecosystem, name, payload)
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            log.warning("Registry response for %s %s could not be parsed: %s", ecosystem, name, exc)
            return RegistryInfo(ecosystem=ecosystem, package_name=name, available=False, error=f"malformed registry response: {exc}")
        log.info(
            "Registry %s %s: %d versions, latest %s (registry says %s)",
            ecosystem, name, len(info.versions), info.latest, info.registry_latest,
        )
        return info

    def url_for(self, ecosystem: str, name: str) -> str:
        """Registry URL for ``name``; ``ValueError`` for an unsupported ecosystem."""
        if ecosystem == Ecosystem.PYPI:
            return f"{self.pypi_base_url}/{quote(normalize_package_name(name, ecosystem), safe='')}/json"
        if ecosystem == Ecosystem.NPM:
            # Scoped packages keep their "@" and get the "/" percent-encoded (registry canonical form).
            return f"{self.npm_base_url}/{quote(name.strip(), safe='@')}"
        raise ValueError(f"unsupported ecosystem for registry lookup: {ecosystem}")

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    # ------------------------------------------------------------------ HTTP

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            )
        return self._client

    def _fetch_json(self, url: str) -> tuple[dict[str, Any] | None, str | None, bool]:
        """``(payload, error, available)``; a 404 is *available* with ``payload=None``."""
        try:
            response = self.client.get(url)
        except httpx.TimeoutException as exc:
            return None, f"registry timeout after {self.timeout:.0f}s: {exc or exc.__class__.__name__}", False
        except httpx.HTTPError as exc:
            return None, f"registry unreachable: {exc or exc.__class__.__name__}", False
        if response.status_code == 404:
            return None, NOT_FOUND, True
        if response.status_code >= 400:
            return None, f"registry returned HTTP {response.status_code}", False
        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            return None, f"malformed registry response: {exc}", False
        if not isinstance(payload, dict):
            return None, "malformed registry response: expected a JSON object", False
        return payload, None, True

    # ------------------------------------------------------------------ parsing

    def _parse(self, ecosystem: str, name: str, payload: dict[str, Any]) -> RegistryInfo:
        if ecosystem == Ecosystem.PYPI:
            return parse_pypi(name, payload)
        return parse_npm(name, payload)


# ---------------------------------------------------------------------- pure parsers


def parse_pypi(name: str, payload: dict[str, Any]) -> RegistryInfo:
    """``releases`` keys whose file list is non-empty and not entirely yanked."""
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        raise ValueError("missing 'releases' object")
    installable: list[str] = []
    yanked: list[str] = []
    for version, files in releases.items():
        if not isinstance(files, list) or not files:
            continue  # a release without files cannot be installed
        if all(isinstance(f, dict) and f.get("yanked") for f in files):
            yanked.append(str(version))
            continue
        installable.append(str(version))
    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    registry_latest = info.get("version") if isinstance(info.get("version"), str) else None
    return _build_info(Ecosystem.PYPI, name, installable, registry_latest, yanked)


def parse_npm(name: str, payload: dict[str, Any]) -> RegistryInfo:
    """``versions`` keys plus ``dist-tags.latest``; deprecated versions are excluded like yanked ones."""
    versions = payload.get("versions")
    if not isinstance(versions, dict):
        raise ValueError("missing 'versions' object")
    tags = payload.get("dist-tags") if isinstance(payload.get("dist-tags"), dict) else {}
    registry_latest = tags.get("latest") if isinstance(tags.get("latest"), str) else None
    installable: list[str] = []
    deprecated: dict[str, str] = {}
    for version, meta in versions.items():
        message = meta.get("deprecated") if isinstance(meta, dict) else None
        if message:
            deprecated[str(version)] = str(message)
            continue
        installable.append(str(version))
    info = _build_info(Ecosystem.NPM, name, installable, registry_latest, list(deprecated))
    info.deprecations = deprecated
    return info


def _build_info(ecosystem: str, name: str, raw: list[str], registry_latest: str | None, yanked: list[str]) -> RegistryInfo:
    ordered = sort_versions(raw, ecosystem)  # drops unparsable entries silently
    latest = max_version(ordered, ecosystem)  # highest non-pre-release
    return RegistryInfo(
        ecosystem=ecosystem,
        package_name=name,
        versions=ordered,
        latest=latest,
        available=True,
        error=None if ordered else "no installable versions listed",
        registry_latest=registry_latest,
        yanked=sort_versions(yanked, ecosystem),
    )


__all__ = ["NOT_FOUND", "PackageRegistryClient", "RegistryInfo", "parse_npm", "parse_pypi"]
