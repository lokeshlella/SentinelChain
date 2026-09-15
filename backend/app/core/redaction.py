"""Redaction of credentials embedded in repository-controlled text (audit finding V2-04).

Dependency manifests are allowed to carry credentials — ``--extra-index-url
https://deploy:token@pypi.internal/simple`` in ``requirements.txt``,
``git+https://token@github.com/org/repo.git`` requirements, ``_authToken=``
lines — and Sentinel Chain copies manifest text into places the repository
owner did not put it: dependency rows (``version_spec``), analysis warnings,
the stored ``proposed_change`` (before / after / unified diff), the evidence
report and the body of the draft pull request pushed to GitHub.

Everything that stores or renders manifest-derived text passes it through
:func:`redact_secrets` first. The file rewritten in the working copy keeps
its real content — redaction is applied to what is *reported*, never to what
is installed.
"""

from __future__ import annotations

import re

REDACTED = "***"

# ``scheme://userinfo@host`` — the whole userinfo (user or user:password) is a
# credential as far as reporting is concerned; ``https://token@github.com`` is
# the common form for personal access tokens.
_URL_USERINFO_RE = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<userinfo>[^/\s@]+)@")
# Environment placeholders are not secrets and are kept so the reader can see the mechanism.
_PLACEHOLDER_RE = re.compile(r"^\$\{[^}]*\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|^%[A-Za-z_][A-Za-z0-9_]*%$")
# ``key=value`` / ``key: value`` credential assignments as found in .npmrc, pip.conf, .netrc-like text.
_KEY_VALUE_RE = re.compile(
    r"(?i)(?P<key>(?<![A-Za-z0-9_])(?:_authToken|_auth|_password|password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\s*[=:](?!=)\s*)(?P<value>[^\s,;\"']+)"
)
# Well-known token shapes (GitHub, GitLab, PyPI, npm, AWS access key ids, Slack).
_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}"
    r"|pypi-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)


def _redact_userinfo(match: re.Match[str]) -> str:
    userinfo = match.group("userinfo")
    if _PLACEHOLDER_RE.match(userinfo):
        return match.group(0)
    return f"{match.group('scheme')}{REDACTED}@"


def _redact_key_value(match: re.Match[str]) -> str:
    value = match.group("value")
    if _PLACEHOLDER_RE.match(value):
        return match.group(0)
    return f"{match.group('key')}{REDACTED}"


def redact_secrets(text: str | None) -> str | None:
    """``text`` with URL credentials, credential assignments and known token shapes replaced by ``***``.

    Never changes the number of lines (line numbers computed on the original stay valid);
    ``None`` and empty strings pass through unchanged.
    """
    if not text:
        return text
    redacted = _URL_USERINFO_RE.sub(_redact_userinfo, text)
    redacted = _KEY_VALUE_RE.sub(_redact_key_value, redacted)
    return _TOKEN_RE.sub(REDACTED, redacted)


def contains_secret(text: str | None) -> bool:
    """True when :func:`redact_secrets` would change ``text``."""
    return bool(text) and redact_secrets(text) != text
