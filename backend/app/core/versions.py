"""Version parsing and comparison helpers for the supported ecosystems.

* PyPI  -> PEP 440 via ``packaging.version``
* npm   -> a small, dependency-free SemVer 2.0 implementation

All public helpers take the ecosystem name ("PyPI" | "npm") so callers never
need to branch on ecosystem themselves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Any

from packaging.version import InvalidVersion, Version as Pep440Version

_SEMVER_RE = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+(?P<build>[0-9A-Za-z.-]+))?$"
)
_LOOSE_SEMVER_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$")


class InvalidVersionError(ValueError):
    pass


@total_ordering
@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str) -> "SemVer":
        text = text.strip()
        match = _SEMVER_RE.match(text)
        if match:
            pre = tuple(match.group("pre").split(".")) if match.group("pre") else ()
            return cls(int(match.group("major")), int(match.group("minor")), int(match.group("patch")), pre)
        loose = _LOOSE_SEMVER_RE.match(text)
        if loose:  # e.g. "4.17" or "4"
            return cls(int(loose.group(1)), int(loose.group(2) or 0), int(loose.group(3) or 0))
        raise InvalidVersionError(f"Invalid semver: {text!r}")

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def _pre_key(self) -> tuple:
        # A version without prerelease sorts AFTER one with (1.0.0-alpha < 1.0.0).
        if not self.prerelease:
            return (1,)
        parts: list[tuple[int, Any]] = []
        for ident in self.prerelease:
            parts.append((0, int(ident)) if ident.isdigit() else (1, ident))
        return (0, tuple(parts))

    def _key(self) -> tuple:
        return (self.major, self.minor, self.patch, self._pre_key())

    def __lt__(self, other: "SemVer") -> bool:
        return self._key() < other._key()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SemVer) and self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{'.'.join(self.prerelease)}" if self.prerelease else base


def parse_version(version: str, ecosystem: str) -> Pep440Version | SemVer:
    """Parse ``version`` according to the ecosystem; raises InvalidVersionError."""
    if ecosystem == "PyPI":
        try:
            return Pep440Version(version.strip())
        except InvalidVersion as exc:
            raise InvalidVersionError(str(exc)) from exc
    if ecosystem == "npm":
        return SemVer.parse(version)
    raise InvalidVersionError(f"Unsupported ecosystem: {ecosystem}")


def is_valid_version(version: str | None, ecosystem: str) -> bool:
    if not version:
        return False
    try:
        parse_version(version, ecosystem)
        return True
    except InvalidVersionError:
        return False


def compare_versions(a: str, b: str, ecosystem: str) -> int:
    """Return -1, 0 or 1 like ``cmp``."""
    va, vb = parse_version(a, ecosystem), parse_version(b, ecosystem)
    return (va > vb) - (va < vb)


def is_prerelease(version: str, ecosystem: str) -> bool:
    parsed = parse_version(version, ecosystem)
    return bool(parsed.is_prerelease)


def sort_versions(versions: list[str], ecosystem: str) -> list[str]:
    """Sort ascending, silently dropping unparsable entries."""
    parsed: list[tuple[Any, str]] = []
    for v in versions:
        try:
            parsed.append((parse_version(v, ecosystem), v))
        except InvalidVersionError:
            continue
    parsed.sort(key=lambda item: item[0])
    return [v for _, v in parsed]


def major_of(version: str, ecosystem: str) -> int | None:
    try:
        parsed = parse_version(version, ecosystem)
    except InvalidVersionError:
        return None
    return parsed.major if isinstance(parsed, SemVer) else parsed.major


def min_version_at_least(candidates: list[str], floor: str, ecosystem: str, *, allow_prerelease: bool = False) -> str | None:
    """Smallest candidate that is >= ``floor`` (ignoring pre-releases unless allowed)."""
    try:
        floor_parsed = parse_version(floor, ecosystem)
    except InvalidVersionError:
        return None
    best: tuple[Any, str] | None = None
    for candidate in candidates:
        try:
            parsed = parse_version(candidate, ecosystem)
        except InvalidVersionError:
            continue
        if parsed.is_prerelease and not allow_prerelease:
            continue
        if parsed >= floor_parsed and (best is None or parsed < best[0]):
            best = (parsed, candidate)
    return best[1] if best else None


def max_version(candidates: list[str], ecosystem: str, *, allow_prerelease: bool = False) -> str | None:
    ordered = [v for v in sort_versions(candidates, ecosystem) if allow_prerelease or not is_prerelease(v, ecosystem)]
    return ordered[-1] if ordered else None


def normalize_package_name(name: str, ecosystem: str) -> str:
    """Canonical package name used for identity and OSV queries."""
    if ecosystem == "PyPI":
        # PEP 503 normalisation: case-insensitive, runs of -_. collapse to "-"
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.strip()
