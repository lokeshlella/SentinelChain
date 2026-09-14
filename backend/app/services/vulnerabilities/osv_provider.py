"""OSV.dev vulnerability provider.

Real integration with https://api.osv.dev/v1:

* ``POST /query``       one package version -> full vulnerability records
* ``POST /querybatch``  many package versions -> vulnerability ids only
* ``GET  /vulns/{id}``  full record for one id

Every failure mode (network, timeout, rate limit, server error, malformed
JSON) degrades to ``VulnerabilityStatus.UNKNOWN`` with a human readable
reason.  A query is reported ``SAFE`` only when OSV answered HTTP 200 with an
empty result for that exact package version.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import datetime, timezone

import httpx

from app.core.config import get_settings
from app.core.logging import get_stage_logger
from app.core.versions import normalize_package_name, sort_versions
from app.models.enums import Severity, VulnerabilityStatus
from app.services.vulnerabilities.base import (
    AffectedPackage,
    AffectedRange,
    PackageQuery,
    PackageVulnerabilityResult,
    VulnerabilityProvider,
    VulnerabilityProviderError,
    VulnerabilityRecord,
)
from app.services.vulnerabilities.cvss import cvss_v3_base_score, severity_from_score

log = get_stage_logger("Vulnerability")

UNAVAILABLE_PREFIX = "Vulnerability check unavailable"
MAX_BATCH_SIZE = 1000  # documented OSV limit for /querybatch
_MAX_PAGES = 50  # safety cap when following next_page_token
_RETRY_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRY_AFTER = 30.0

# GHSA / OSV qualitative labels -> app Severity
_SEVERITY_LABELS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
_ISO_FRACTION_RE = re.compile(r"(\.\d{1,6})\d*")


# --------------------------------------------------------------------------
# Record parsing (pure functions, unit-tested against real OSV responses)
# --------------------------------------------------------------------------


def parse_osv_timestamp(value: object) -> datetime | None:
    """Parse an OSV ISO 8601 timestamp (``2023-05-22T20:36:32Z``) to an aware datetime.

    OSV emits up to nine fractional-second digits; they are trimmed to the six
    Python supports.  Unparsable values yield ``None`` rather than raising.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _ISO_FRACTION_RE.sub(r"\1", text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _string_list(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    return [v for v in values if isinstance(v, str) and v]


def _pick_reference_url(references: object) -> tuple[str | None, list[str]]:
    """Return (preferred url, all urls): first ADVISORY, else first WEB, else first."""
    if not isinstance(references, list):
        return None, []
    urls: list[str] = []
    first_advisory: str | None = None
    first_web: str | None = None
    for ref in references:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if not isinstance(url, str) or not url:
            continue
        urls.append(url)
        ref_type = str(ref.get("type", "")).upper()
        if ref_type == "ADVISORY" and first_advisory is None:
            first_advisory = url
        elif ref_type == "WEB" and first_web is None:
            first_web = url
    return first_advisory or first_web or (urls[0] if urls else None), urls


def _numeric(value: object) -> float | None:
    """Float value of ``value`` when it is a plain number (or numeric string)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _parse_severity_entries(entries: object) -> tuple[str | None, float | None]:
    """Extract (cvss_vector, cvss_score) from an OSV ``severity[]`` list.

    CVSS_V3 entries win because their score can be computed exactly.  A
    CVSS_V4 entry only provides the vector (no local v4 calculator); a score
    is taken from it only when the source provided a numeric value.
    """
    if not isinstance(entries, list):
        return None, None
    v3_vector: str | None = None
    v3_score: float | None = None
    v4_vector: str | None = None
    v4_score: float | None = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("type", "")).upper()
        raw = entry.get("score")
        if kind == "CVSS_V3" and v3_vector is None:
            if isinstance(raw, str) and raw.upper().startswith("CVSS:3"):
                v3_vector = raw.strip()
                v3_score = cvss_v3_base_score(v3_vector)
            elif _numeric(raw) is not None:
                v3_score = _numeric(raw)
        elif kind == "CVSS_V4" and v4_vector is None:
            if isinstance(raw, str) and raw.upper().startswith("CVSS:4"):
                v4_vector = raw.strip()
            elif _numeric(raw) is not None:
                v4_score = _numeric(raw)
    if v3_vector is not None or v3_score is not None:
        return v3_vector, v3_score
    return v4_vector, v4_score


def _severity_label(raw: dict, score: float | None) -> Severity:
    """``database_specific.severity`` label first, else the score band, else UNKNOWN."""
    specific = raw.get("database_specific")
    if isinstance(specific, dict):
        label = specific.get("severity")
        if isinstance(label, str) and label.strip().upper() in _SEVERITY_LABELS:
            return _SEVERITY_LABELS[label.strip().upper()]
    return severity_from_score(score)


def _parse_ranges(ranges: object) -> tuple[list[AffectedRange], list[str]]:
    """Split OSV ranges/events into flat ``AffectedRange`` objects.

    An OSV range holds an ordered ``events`` list where every ``introduced``
    opens a new interval closed by the following ``fixed`` / ``last_affected``.
    GIT ranges are kept for evidence but their ``fixed`` values are commit
    hashes, so they never contribute to ``fixed_versions``.
    """
    parsed: list[AffectedRange] = []
    fixed_versions: list[str] = []
    if not isinstance(ranges, list):
        return parsed, fixed_versions
    for rng in ranges:
        if not isinstance(rng, dict):
            continue
        range_type = str(rng.get("type") or "ECOSYSTEM").upper()
        current: AffectedRange | None = None
        events = rng.get("events")
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict):
                continue
            introduced = event.get("introduced")
            fixed = event.get("fixed")
            last_affected = event.get("last_affected")
            if isinstance(introduced, str):
                current = AffectedRange(range_type=range_type, introduced=introduced)
                parsed.append(current)
                continue
            if current is None:
                current = AffectedRange(range_type=range_type)
                parsed.append(current)
            if isinstance(fixed, str) and fixed:
                current.fixed = fixed
                if range_type != "GIT" and fixed not in fixed_versions:
                    fixed_versions.append(fixed)
            if isinstance(last_affected, str) and last_affected:
                current.last_affected = last_affected
    return parsed, fixed_versions


def _parse_affected(entries: object) -> list[AffectedPackage]:
    packages: list[AffectedPackage] = []
    if not isinstance(entries, list):
        return packages
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if not isinstance(package, dict):
            continue
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str) or not name:
            continue
        ranges, fixed = _parse_ranges(entry.get("ranges"))
        ordered_fixed = sort_versions(fixed, ecosystem)
        ordered_fixed.extend(v for v in fixed if v not in ordered_fixed)  # keep unparsable ones too
        packages.append(
            AffectedPackage(
                ecosystem=ecosystem,
                package_name=name,
                ranges=ranges,
                versions=_string_list(entry.get("versions")),
                fixed_versions=ordered_fixed,
            )
        )
    return packages


def parse_osv_record(raw: dict, *, source: str = "osv") -> VulnerabilityRecord:
    """Convert one raw OSV vulnerability object into a ``VulnerabilityRecord``.

    ``affected`` contains every package listed by OSV; use
    :func:`filter_record_for_package` to narrow it to the queried package.
    Raises ``VulnerabilityProviderError`` when the object has no ``id``.
    """
    if not isinstance(raw, dict):
        raise VulnerabilityProviderError("OSV record is not a JSON object")
    identifier = raw.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise VulnerabilityProviderError("OSV record without an 'id' field")
    vector, score = _parse_severity_entries(raw.get("severity"))
    reference_url, references = _pick_reference_url(raw.get("references"))
    summary = raw.get("summary") if isinstance(raw.get("summary"), str) else None
    details = raw.get("details") if isinstance(raw.get("details"), str) else None
    return VulnerabilityRecord(
        identifier=identifier.strip(),
        source=source,
        aliases=_string_list(raw.get("aliases")),
        summary=summary or None,
        description=details or None,
        severity=_severity_label(raw, score),
        cvss_score=score,
        cvss_vector=vector,
        published_at=parse_osv_timestamp(raw.get("published")),
        modified_at=parse_osv_timestamp(raw.get("modified")),
        reference_url=reference_url,
        references=references,
        affected=_parse_affected(raw.get("affected")),
    )


def filter_record_for_package(record: VulnerabilityRecord, ecosystem: str, package_name: str) -> VulnerabilityRecord:
    """Copy of ``record`` whose ``affected`` only lists the queried ecosystem + package."""
    wanted = normalize_package_name(package_name, ecosystem)
    affected = [
        pkg
        for pkg in record.affected
        if pkg.ecosystem == ecosystem and normalize_package_name(pkg.package_name, ecosystem) == wanted
    ]
    return replace(record, aliases=list(record.aliases), references=list(record.references), affected=affected)


def minimal_record(identifier: str, modified: object = None, *, source: str = "osv") -> VulnerabilityRecord:
    """Record carrying only what ``/querybatch`` returned (id + modified) when details could not be fetched."""
    return VulnerabilityRecord(identifier=identifier, source=source, modified_at=parse_osv_timestamp(modified))


# --------------------------------------------------------------------------
# Provider
# --------------------------------------------------------------------------


class OSVProvider(VulnerabilityProvider):
    """``VulnerabilityProvider`` backed by the public OSV.dev REST API."""

    name = "osv"

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
        client: httpx.Client | None = None,
        *,
        max_attempts: int = 3,
        backoff_seconds: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
        batch_size: int = MAX_BATCH_SIZE,
    ) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.osv_api_url).rstrip("/")
        self.timeout = float(timeout if timeout is not None else settings.osv_timeout)
        self._client = client
        self._owns_client = client is None
        self.max_attempts = max(1, int(max_attempts))
        self.backoff_seconds = max(0.0, float(backoff_seconds))
        self._sleep = sleep
        self.batch_size = max(1, min(int(batch_size), MAX_BATCH_SIZE))

    # -- transport -----------------------------------------------------------

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, headers={"User-Agent": "sentinel-chain/1.0"})
        return self._client

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def _retry_delay(self, attempt: int, response: httpx.Response | None) -> float:
        """Exponential backoff, honouring a small ``Retry-After`` header when present."""
        delay = self.backoff_seconds * (2**attempt)
        if response is not None:
            retry_after = _numeric(response.headers.get("Retry-After"))
            if retry_after is not None and 0 < retry_after <= _MAX_RETRY_AFTER:
                delay = max(delay, retry_after)
        return delay

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        """Perform one API call with retries; raise ``VulnerabilityProviderError`` on failure.

        Retries HTTP 429 and 5xx with exponential backoff (``max_attempts`` in
        total).  Transport errors and timeouts fail immediately with a clear
        cause so a slow network never multiplies the configured timeout.
        """
        url = f"{self.base_url}{path}"
        last_error = ""
        for attempt in range(self.max_attempts):
            try:
                response = self.client.request(method, url, json=payload, timeout=self.timeout)
            except httpx.TimeoutException as exc:
                raise VulnerabilityProviderError(
                    f"timeout after {self.timeout:g}s calling {method} {path}"
                ) from exc
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                raise VulnerabilityProviderError(
                    f"connection error calling {method} {path}: {exc.__class__.__name__}: {exc}"
                ) from exc
            if response.status_code in _RETRY_STATUS:
                last_error = f"HTTP {response.status_code} from {method} {path}"
                if attempt + 1 < self.max_attempts:
                    delay = self._retry_delay(attempt, response)
                    log.warning("%s; retrying in %.1fs (attempt %d/%d)", last_error, delay, attempt + 1, self.max_attempts)
                    self._sleep(delay)
                    continue
                raise VulnerabilityProviderError(f"{last_error} after {self.max_attempts} attempts")
            if response.status_code >= 400:
                raise VulnerabilityProviderError(
                    f"HTTP {response.status_code} from {method} {path}: {_error_message(response)}"
                )
            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError) as exc:
                raise VulnerabilityProviderError(f"malformed JSON response from {method} {path}") from exc
            if not isinstance(data, dict):
                raise VulnerabilityProviderError(f"unexpected response shape from {method} {path}")
            return data
        raise VulnerabilityProviderError(last_error or f"request to {path} failed")  # pragma: no cover

    # -- VulnerabilityProvider API --------------------------------------------

    def query(self, query: PackageQuery) -> PackageVulnerabilityResult:
        """``POST /query`` for one package version (full records in the answer, all pages).

        Any failure while paging - including a malformed entry inside a 200
        answer - makes the whole query UNKNOWN rather than a partial answer.
        """
        try:
            records = [
                filter_record_for_package(_parse_record_safely(raw), query.ecosystem, query.package_name)
                for raw in self._query_pages(query)
            ]
        except VulnerabilityProviderError as exc:
            return _unknown(query, str(exc))
        return _classified(query, records)

    def query_batch(self, queries: list[PackageQuery]) -> list[PackageVulnerabilityResult]:
        """``POST /querybatch`` (ids only) followed by ``GET /vulns/{id}`` per unique id."""
        if not queries:
            return []
        unique = list(dict.fromkeys(queries))
        ids_by_query: dict[PackageQuery, list[dict] | None] = {}
        errors_by_query: dict[PackageQuery, str] = {}

        for start in range(0, len(unique), self.batch_size):
            chunk = unique[start : start + self.batch_size]
            try:
                chunk_ids, chunk_errors = self._batch_ids(chunk)
            except VulnerabilityProviderError as exc:
                for q in chunk:
                    errors_by_query[q] = str(exc)
                continue
            ids_by_query.update(chunk_ids)
            errors_by_query.update(chunk_errors)

        wanted_ids = {entry["id"] for hits in ids_by_query.values() for entry in (hits or [])}
        details, detail_errors = self._fetch_details(sorted(wanted_ids))

        results: dict[PackageQuery, PackageVulnerabilityResult] = {}
        for q in unique:
            if q in errors_by_query:
                results[q] = _unknown(q, errors_by_query[q])
                continue
            records: list[VulnerabilityRecord] = []
            notes: list[str] = []
            for entry in ids_by_query.get(q) or []:
                vuln_id = entry["id"]
                full = details.get(vuln_id)
                if full is not None:
                    records.append(filter_record_for_package(full, q.ecosystem, q.package_name))
                else:
                    records.append(minimal_record(vuln_id, entry.get("modified")))
                    notes.append(f"{vuln_id}: {detail_errors.get(vuln_id, 'details unavailable')}")
            result = _classified(q, records)
            if notes:
                result.reason = "Details could not be fetched for " + "; ".join(notes)
            results[q] = result

        ordered = [results[q] for q in queries]
        log.info(
            "OSV batch: %d queries (%d unique), %d unknown, %d vulnerability ids fetched (%d failed)",
            len(queries),
            len(unique),
            sum(1 for r in ordered if r.status == VulnerabilityStatus.UNKNOWN),
            len(details),
            len(detail_errors),
        )
        return ordered

    def health(self) -> tuple[bool, str]:
        """Reachability probe: a harmless ``POST /query`` for a well-known package."""
        payload = {"package": {"name": "six", "ecosystem": "PyPI"}, "version": "1.16.0"}
        try:
            response = self.client.post(f"{self.base_url}/query", json=payload, timeout=min(self.timeout, 10.0))
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            return False, f"unreachable at {self.base_url}: {exc.__class__.__name__}: {str(exc)[:120]}"
        if response.status_code in (200, 400):
            return True, f"reachable at {self.base_url} (HTTP {response.status_code})"
        return False, f"unexpected HTTP {response.status_code} from {self.base_url}/query"

    # -- helpers ---------------------------------------------------------------

    def _query_pages(self, query: PackageQuery) -> list[dict]:
        """Raw ``vulns`` objects of ``POST /query`` across every ``next_page_token`` page.

        Raises ``VulnerabilityProviderError`` for a malformed page (wrong
        ``vulns`` shape, an entry that is not an object) or when the token
        chain exceeds ``_MAX_PAGES``.
        """
        raw_vulns: list[dict] = []
        token: str | None = None
        for _page in range(_MAX_PAGES):
            data = self._request("POST", "/query", _query_payload(query, token))
            vulns = data.get("vulns", [])
            if not isinstance(vulns, list):
                raise VulnerabilityProviderError("unexpected 'vulns' shape in /query response")
            if not all(isinstance(raw, dict) for raw in vulns):
                raise VulnerabilityProviderError("malformed vulns entry in /query response")
            raw_vulns.extend(vulns)
            token = _next_page_token(data)
            if token is None:
                return raw_vulns
        raise VulnerabilityProviderError("too many /query result pages")

    def _batch_ids(self, chunk: list[PackageQuery]) -> tuple[dict[PackageQuery, list[dict]], dict[PackageQuery, str]]:
        """Run ``/querybatch`` for ``chunk`` following ``next_page_token`` per query.

        Returns ``(ids by query, error by query)``: a query whose result entry
        is malformed is reported in the second dict (it becomes UNKNOWN) instead
        of being silently treated as SAFE.  A response that cannot be matched to
        the queries at all raises for the whole chunk.
        """
        collected: dict[PackageQuery, list[dict]] = {q: [] for q in chunk}
        errors: dict[PackageQuery, str] = {}
        pending: list[tuple[PackageQuery, str | None]] = [(q, None) for q in chunk]
        for _page in range(_MAX_PAGES):
            payload = {"queries": [_query_payload(q, token) for q, token in pending]}
            data = self._request("POST", "/querybatch", payload)
            results = data.get("results")
            if not isinstance(results, list) or len(results) != len(pending):
                raise VulnerabilityProviderError(
                    f"malformed /querybatch response: expected {len(pending)} results, got "
                    f"{len(results) if isinstance(results, list) else type(results).__name__}"
                )
            next_pending: list[tuple[PackageQuery, str | None]] = []
            for (q, _token), item in zip(pending, results):
                try:
                    collected[q].extend(_batch_entries(item))
                except VulnerabilityProviderError as exc:
                    errors[q] = str(exc)
                    del collected[q]
                    continue
                token = _next_page_token(item)
                if token is not None:
                    next_pending.append((q, token))
            if not next_pending:
                break
            pending = next_pending
        else:
            raise VulnerabilityProviderError("too many /querybatch result pages")
        return collected, errors

    def _fetch_details(self, ids: Iterable[str]) -> tuple[dict[str, VulnerabilityRecord], dict[str, str]]:
        """``GET /vulns/{id}`` for each id with a per-call cache; failures are collected, not raised."""
        cache: dict[str, VulnerabilityRecord] = {}
        errors: dict[str, str] = {}
        for vuln_id in ids:
            if vuln_id in cache or vuln_id in errors:
                continue
            try:
                cache[vuln_id] = _parse_record_safely(self._request("GET", f"/vulns/{vuln_id}"))
            except VulnerabilityProviderError as exc:
                errors[vuln_id] = str(exc)
                log.warning("could not fetch OSV details for %s: %s", vuln_id, exc)
        return cache, errors


# --------------------------------------------------------------------------
# Small module-level helpers
# --------------------------------------------------------------------------


def _parse_record_safely(raw: object) -> VulnerabilityRecord:
    """Parse one OSV record, scoping any parser crash to that record.

    A malformed field (e.g. ``events`` that is not a list) becomes a
    ``VulnerabilityProviderError`` so the caller marks only the affected
    query/id as UNKNOWN instead of aborting the whole batch.
    """
    if not isinstance(raw, dict):
        raise VulnerabilityProviderError(f"malformed OSV record: expected an object, got {type(raw).__name__}")
    try:
        return parse_osv_record(raw)
    except VulnerabilityProviderError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed data must not escape the provider
        raise VulnerabilityProviderError(f"malformed OSV record {raw.get('id', '?')}: {exc}") from exc


def _query_payload(query: PackageQuery, page_token: str | None = None) -> dict:
    payload: dict = {
        "package": {"name": query.package_name, "ecosystem": query.ecosystem},
        "version": query.version,
    }
    if page_token:
        payload["page_token"] = page_token
    return payload


def _next_page_token(data: dict) -> str | None:
    """Non-empty ``next_page_token`` of a ``/query`` answer or ``/querybatch`` result entry, else ``None``."""
    token = data.get("next_page_token")
    return token if isinstance(token, str) and token else None


def _batch_entries(item: object) -> list[dict]:
    """``[{"id", "modified"}, ...]`` of one ``/querybatch`` result entry, strictly validated.

    OSV answers ``{}`` for a clean package and ``{"vulns": [{"id": ..., "modified": ...}]}``
    otherwise.  Anything else (a non-object entry, a ``vulns`` item without a
    string ``id``) is malformed and raises so the query becomes UNKNOWN - it
    must never be mistaken for an empty (SAFE) answer.
    """
    if not isinstance(item, dict):
        raise VulnerabilityProviderError("malformed /querybatch result entry")
    vulns = item.get("vulns")
    if vulns is None:
        return []
    if not isinstance(vulns, list):
        raise VulnerabilityProviderError("unexpected 'vulns' shape in /querybatch result entry")
    entries: list[dict] = []
    for entry in vulns:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"].strip():
            raise VulnerabilityProviderError("malformed vulns entry in /querybatch response")
        entries.append({"id": entry["id"].strip(), "modified": entry.get("modified")})
    return entries


def _error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
        if isinstance(body, dict) and isinstance(body.get("message"), str):
            return body["message"]
    except (json.JSONDecodeError, ValueError):
        pass
    return (response.text or "").strip()[:160] or "no error message"


def _unknown(query: PackageQuery, cause: str) -> PackageVulnerabilityResult:
    return PackageVulnerabilityResult(
        query=query,
        status=VulnerabilityStatus.UNKNOWN,
        vulnerabilities=[],
        reason=f"{UNAVAILABLE_PREFIX}: {cause}",
    )


def _classified(query: PackageQuery, records: list[VulnerabilityRecord]) -> PackageVulnerabilityResult:
    """SAFE only for an answered query with no records; VULNERABLE otherwise."""
    if records:
        return PackageVulnerabilityResult(query=query, status=VulnerabilityStatus.VULNERABLE, vulnerabilities=records)
    return PackageVulnerabilityResult(query=query, status=VulnerabilityStatus.SAFE, vulnerabilities=[])
