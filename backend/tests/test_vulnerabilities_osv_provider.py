"""OSVProvider: parsing of real OSV responses and graceful failure handling.

Fixtures under tests/fixtures/vulnerabilities/ are verbatim responses of the
public OSV API (see the file names for the requests that produced them).
No network access: httpx.MockTransport serves the fixtures.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from app.models.enums import Severity, VulnerabilityStatus
from app.services.vulnerabilities.base import PackageQuery, VulnerabilityProviderError
from app.services.vulnerabilities.osv_provider import (
    UNAVAILABLE_PREFIX,
    OSVProvider,
    filter_record_for_package,
    parse_osv_record,
    parse_osv_timestamp,
)

FIXTURES = Path(__file__).parent / "fixtures" / "vulnerabilities"
BASE = "https://osv.test/v1"

REQUESTS = PackageQuery("PyPI", "requests", "2.25.1")
LODASH = PackageQuery("npm", "lodash", "4.17.15")
SIX = PackageQuery("PyPI", "six", "1.16.0")
MISSING = PackageQuery("PyPI", "this-package-does-not-exist-sentinel-xyz", "1.0.0")


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture(scope="module")
def fixtures() -> dict:
    requests_query = load("osv_query_requests_2.25.1.json")
    lodash_query = load("osv_query_lodash_4.17.15.json")
    records = {v["id"]: v for v in requests_query["vulns"] + lodash_query["vulns"]}
    return {
        "query": {
            ("PyPI", "requests", "2.25.1"): requests_query,
            ("npm", "lodash", "4.17.15"): lodash_query,
            ("PyPI", "six", "1.16.0"): load("osv_query_six_1.16.0.json"),
        },
        "querybatch": load("osv_querybatch.json"),
        "records": records,
        "ghsa_j8r2": load("osv_vuln_GHSA-j8r2-6x86-q33q.json"),
    }


class OSVStub:
    """Routes requests to fixture data; records calls; can inject failures."""

    def __init__(self, fixtures: dict) -> None:
        self.fixtures = fixtures
        self.calls: list[tuple[str, str, dict | None]] = []
        self.overrides: dict[str, Callable[[httpx.Request, int], httpx.Response | None]] = {}
        self.counts: dict[str, int] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        request.read()
        payload = json.loads(request.content) if request.content else None
        path = request.url.path.removeprefix("/v1")
        self.calls.append((request.method, path, payload))
        self.counts[path] = self.counts.get(path, 0) + 1
        for prefix, override in self.overrides.items():
            if path.startswith(prefix):
                response = override(request, self.counts[path])
                if response is not None:
                    return response
        if path == "/query":
            key = (payload["package"]["ecosystem"], payload["package"]["name"], payload["version"])
            return httpx.Response(200, json=self.fixtures["query"].get(key, {}))
        if path == "/querybatch":
            results = []
            for q in payload["queries"]:
                key = (q["package"]["ecosystem"], q["package"]["name"], q["version"])
                vulns = self.fixtures["query"].get(key, {}).get("vulns", [])
                results.append({"vulns": [{"id": v["id"], "modified": v["modified"]} for v in vulns]} if vulns else {})
            return httpx.Response(200, json={"results": results})
        if path.startswith("/vulns/"):
            vuln_id = path.rsplit("/", 1)[1]
            record = self.fixtures["records"].get(vuln_id)
            if record is None:
                return httpx.Response(404, json={"code": 5, "message": "Vulnerability not found"})
            return httpx.Response(200, json=record)
        return httpx.Response(404, json={"code": 5, "message": "not found"})

    def provider(self, **kwargs) -> OSVProvider:
        client = httpx.Client(transport=httpx.MockTransport(self.handler), base_url="https://unused")
        kwargs.setdefault("sleep", lambda _s: None)
        return OSVProvider(BASE, 5, client, **kwargs)


@pytest.fixture
def stub(fixtures: dict) -> OSVStub:
    return OSVStub(fixtures)


# ---------------------------------------------------------------------------
# Pure parsing against real records
# ---------------------------------------------------------------------------


def test_parse_ghsa_record(fixtures: dict) -> None:
    record = parse_osv_record(fixtures["ghsa_j8r2"])
    assert record.identifier == "GHSA-j8r2-6x86-q33q"
    assert record.source == "osv"
    assert record.aliases == ["CVE-2023-32681", "PYSEC-2023-74"]
    assert record.summary == "Unintended leak of Proxy-Authorization header in requests"
    assert record.description.startswith("### Impact")
    assert record.cvss_vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"
    assert record.cvss_score == 6.1
    assert record.severity is Severity.MEDIUM  # database_specific.severity "MODERATE"
    assert record.published_at == datetime(2023, 5, 22, 20, 36, 32, tzinfo=timezone.utc)
    assert record.modified_at == datetime(2026, 9, 10, 3, 50, 1, 756149, tzinfo=timezone.utc)
    # ADVISORY reference preferred over the WEB one that is listed first.
    assert record.reference_url == "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
    assert len(record.references) == 10
    assert len(record.affected) == 1
    affected = record.affected[0]
    assert (affected.ecosystem, affected.package_name) == ("PyPI", "requests")
    assert [(r.range_type, r.introduced, r.fixed) for r in affected.ranges] == [("ECOSYSTEM", "2.3.0", "2.31.0")]
    assert affected.fixed_versions == ["2.31.0"]
    assert "2.25.1" in affected.versions
    assert record.fixed_versions_for("PyPI", "Requests") == ["2.31.0"]


def test_parse_pysec_record_without_label_uses_git_and_ecosystem_ranges(fixtures: dict) -> None:
    record = parse_osv_record(fixtures["records"]["PYSEC-2023-74"])
    assert record.aliases == ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"]
    assert record.severity is Severity.UNKNOWN  # no severity[] and no database_specific label
    assert record.cvss_score is None and record.cvss_vector is None
    assert record.summary is None
    assert record.reference_url == "https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q"
    ranges = record.affected[0].ranges
    assert [r.range_type for r in ranges] == ["GIT", "ECOSYSTEM"]
    # The GIT "fixed" value is a commit hash and must not be reported as a fixed version.
    assert record.affected[0].fixed_versions == ["2.31.0"]


def test_parse_pysec_record_with_cvss_but_no_label_falls_back_to_score_band(fixtures: dict) -> None:
    record = parse_osv_record(fixtures["records"]["PYSEC-2026-2275"])
    assert record.cvss_vector == "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"
    assert record.cvss_score == 5.5
    assert record.severity is Severity.MEDIUM


def test_parse_lodash_records_labels_scores_and_v4(fixtures: dict) -> None:
    by_id = {v["id"]: parse_osv_record(v) for v in fixtures["query"][("npm", "lodash", "4.17.15")]["vulns"]}
    high = by_id["GHSA-35jh-r3h4-6jhm"]
    assert high.severity is Severity.HIGH and high.cvss_score == 7.2
    assert high.aliases == ["CVE-2021-23337", "CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"]
    # Record with both CVSS_V3 and CVSS_V4 entries: V3 vector/score win.
    both = by_id["GHSA-xxjr-mmjv-4gpg"]
    assert both.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
    assert both.cvss_score == 6.5
    assert both.severity is Severity.MEDIUM
    # Affected lists several lodash.* packages and a RubyGems one before filtering.
    assert {(p.ecosystem, p.package_name) for p in by_id["GHSA-29mw-wpgm-hmr9"].affected} >= {
        ("npm", "lodash"),
        ("npm", "lodash-es"),
        ("RubyGems", "lodash-rails"),
    }


def test_filter_record_for_package_keeps_only_queried_package(fixtures: dict) -> None:
    record = parse_osv_record(fixtures["records"]["GHSA-p6mc-m468-83gw"])
    filtered = filter_record_for_package(record, "npm", "lodash")
    assert [(p.ecosystem, p.package_name) for p in filtered.affected] == [("npm", "lodash")]
    assert filtered.affected[0].fixed_versions == ["4.17.19"]
    assert filtered.affected[0].ranges[0].introduced == "3.7.0"
    assert filtered.fixed_versions_for("npm", "lodash") == ["4.17.19"]
    assert filtered.fixed_versions_for("npm", "lodash-es") == []
    # Original record is untouched.
    assert len(record.affected) == 8


def test_filter_normalises_pypi_names(fixtures: dict) -> None:
    record = parse_osv_record(fixtures["ghsa_j8r2"])
    assert filter_record_for_package(record, "PyPI", "Requests").affected
    assert not filter_record_for_package(record, "npm", "requests").affected


def test_cvss_v4_only_record_keeps_vector_without_score() -> None:
    raw = {
        "id": "OSV-TEST-1",
        "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
    }
    record = parse_osv_record(raw)
    assert record.cvss_vector.startswith("CVSS:4.0/")
    assert record.cvss_score is None
    assert record.severity is Severity.UNKNOWN
    raw["severity"] = [{"type": "CVSS_V4", "score": 9.3}]
    numeric = parse_osv_record(raw)
    assert numeric.cvss_score == 9.3 and numeric.cvss_vector is None
    assert numeric.severity is Severity.CRITICAL


def test_label_takes_precedence_over_score_band() -> None:
    raw = {
        "id": "GHSA-test",
        "database_specific": {"severity": "CRITICAL"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
    }
    record = parse_osv_record(raw)
    assert record.cvss_score == 5.3
    assert record.severity is Severity.CRITICAL
    raw["database_specific"]["severity"] = "weird"
    assert parse_osv_record(raw).severity is Severity.MEDIUM


def test_multiple_introduced_fixed_pairs_become_separate_ranges() -> None:
    raw = {
        "id": "OSV-TEST-2",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"fixed": "2.1"}],
                    },
                    {"type": "ECOSYSTEM", "events": [{"introduced": "3.0"}, {"last_affected": "3.4"}]},
                ],
            }
        ],
    }
    pkg = parse_osv_record(raw).affected[0]
    assert [(r.introduced, r.fixed, r.last_affected) for r in pkg.ranges] == [
        ("0", "1.2", None),
        ("2.0", "2.1", None),
        ("3.0", None, "3.4"),
    ]
    assert pkg.fixed_versions == ["1.2", "2.1"]


def test_parse_record_without_id_is_rejected() -> None:
    with pytest.raises(VulnerabilityProviderError):
        parse_osv_record({"summary": "no id"})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2023-05-22T20:36:32Z", datetime(2023, 5, 22, 20, 36, 32, tzinfo=timezone.utc)),
        ("2026-09-10T03:50:01.756149727Z", datetime(2026, 9, 10, 3, 50, 1, 756149, tzinfo=timezone.utc)),
        ("2026-03-25T17:16:52.97Z", datetime(2026, 3, 25, 17, 16, 52, 970000, tzinfo=timezone.utc)),
        ("garbage", None),
        (None, None),
        (12, None),
    ],
)
def test_parse_osv_timestamp(value, expected) -> None:
    assert parse_osv_timestamp(value) == expected


# ---------------------------------------------------------------------------
# query()
# ---------------------------------------------------------------------------


def test_query_returns_vulnerable_with_parsed_records(stub: OSVStub) -> None:
    result = stub.provider().query(REQUESTS)
    assert result.status is VulnerabilityStatus.VULNERABLE
    assert result.reason is None
    ids = {r.identifier for r in result.vulnerabilities}
    assert {"GHSA-j8r2-6x86-q33q", "PYSEC-2023-74", "GHSA-9hjg-9r4m-mvj7"} <= ids
    assert all(all(p.package_name == "requests" for p in r.affected) for r in result.vulnerabilities)
    assert stub.calls[0][0:2] == ("POST", "/query")
    assert stub.calls[0][2] == {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.25.1"}


def test_query_empty_answer_is_safe(stub: OSVStub) -> None:
    result = stub.provider().query(SIX)
    assert result.status is VulnerabilityStatus.SAFE
    assert result.vulnerabilities == [] and result.reason is None


def test_query_uses_version_verbatim(stub: OSVStub) -> None:
    stub.provider().query(PackageQuery("npm", "lodash", "v4.17.15"))
    assert stub.calls[-1][2]["version"] == "v4.17.15"


@pytest.mark.parametrize(
    ("failure", "expected_fragment"),
    [
        (lambda req, n: (_ for _ in ()).throw(httpx.ReadTimeout("read timed out", request=req)), "timeout after 5s"),
        (lambda req, n: (_ for _ in ()).throw(httpx.ConnectError("connection refused", request=req)), "connection error"),
        (lambda req, n: httpx.Response(200, content=b"<html>not json</html>"), "malformed JSON"),
        (lambda req, n: httpx.Response(200, json=["not", "an", "object"]), "unexpected response shape"),
        (lambda req, n: httpx.Response(400, json={"code": 3, "message": "invalid query"}), "HTTP 400"),
        (lambda req, n: httpx.Response(503, text="unavailable"), "HTTP 503"),
    ],
)
def test_query_failures_are_unknown_never_safe(stub: OSVStub, failure, expected_fragment: str) -> None:
    stub.overrides["/query"] = failure
    result = stub.provider().query(SIX)
    assert result.status is VulnerabilityStatus.UNKNOWN
    assert result.vulnerabilities == []
    assert result.reason.startswith(f"{UNAVAILABLE_PREFIX}: ")
    assert expected_fragment in result.reason


def test_query_retries_429_then_succeeds(stub: OSVStub) -> None:
    sleeps: list[float] = []

    def rate_limited(request: httpx.Request, call: int) -> httpx.Response | None:
        if call == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return None  # fall through to the fixture

    stub.overrides["/query"] = rate_limited
    provider = stub.provider(sleep=sleeps.append, backoff_seconds=0.5)
    result = provider.query(REQUESTS)
    assert result.status is VulnerabilityStatus.VULNERABLE
    assert stub.counts["/query"] == 2
    assert sleeps == [2.0]  # Retry-After honoured because it exceeds the 0.5 s backoff


def test_query_gives_up_after_three_5xx_attempts(stub: OSVStub) -> None:
    sleeps: list[float] = []
    stub.overrides["/query"] = lambda req, n: httpx.Response(502, text="bad gateway")
    result = stub.provider(sleep=sleeps.append, backoff_seconds=0.1).query(REQUESTS)
    assert result.status is VulnerabilityStatus.UNKNOWN
    assert "HTTP 502" in result.reason and "3 attempts" in result.reason
    assert stub.counts["/query"] == 3
    assert sleeps == [0.1, 0.2]  # exponential backoff between the three attempts


def test_timeouts_are_not_retried(stub: OSVStub) -> None:
    def timeout(request: httpx.Request, call: int):
        raise httpx.ReadTimeout("slow", request=request)

    stub.overrides["/query"] = timeout
    result = stub.provider().query(REQUESTS)
    assert result.status is VulnerabilityStatus.UNKNOWN
    assert stub.counts["/query"] == 1


def test_query_follows_next_page_token(stub: OSVStub, fixtures: dict) -> None:
    page_1 = fixtures["records"]["GHSA-j8r2-6x86-q33q"]
    page_2 = fixtures["records"]["PYSEC-2023-74"]

    def paginated(request: httpx.Request, call: int) -> httpx.Response:
        payload = json.loads(request.content)
        if call == 1:
            assert "page_token" not in payload
            return httpx.Response(200, json={"vulns": [page_1], "next_page_token": "tok-1"})
        assert payload == {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.25.1", "page_token": "tok-1"}
        return httpx.Response(200, json={"vulns": [page_2]})

    stub.overrides["/query"] = paginated
    result = stub.provider().query(REQUESTS)
    assert result.status is VulnerabilityStatus.VULNERABLE
    assert result.reason is None
    assert [r.identifier for r in result.vulnerabilities] == ["GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"]
    assert stub.counts["/query"] == 2


def test_query_page_failure_is_unknown_not_partial(stub: OSVStub, fixtures: dict) -> None:
    page_1 = fixtures["records"]["GHSA-j8r2-6x86-q33q"]

    def broken_second_page(request: httpx.Request, call: int) -> httpx.Response:
        if call == 1:
            return httpx.Response(200, json={"vulns": [page_1], "next_page_token": "tok-1"})
        return httpx.Response(400, json={"code": 3, "message": "bad page token"})

    stub.overrides["/query"] = broken_second_page
    result = stub.provider().query(REQUESTS)
    assert result.status is VulnerabilityStatus.UNKNOWN
    assert result.vulnerabilities == []
    assert result.reason.startswith(UNAVAILABLE_PREFIX) and "HTTP 400" in result.reason


def test_query_endless_pagination_is_unknown(stub: OSVStub, fixtures: dict) -> None:
    page = fixtures["records"]["GHSA-j8r2-6x86-q33q"]
    stub.overrides["/query"] = lambda req, n: httpx.Response(200, json={"vulns": [page], "next_page_token": f"tok-{n}"})
    result = stub.provider().query(REQUESTS)
    assert result.status is VulnerabilityStatus.UNKNOWN
    assert "too many /query result pages" in result.reason
    assert stub.counts["/query"] == 50


@pytest.mark.parametrize(
    "body",
    [
        {"vulns": ["GHSA-not-a-dict", 42]},
        {"vulns": [None]},
        {"vulns": "GHSA-not-a-list"},
        {"vulns": [{"summary": "record without an id"}]},
    ],
)
def test_query_malformed_entries_are_unknown_never_safe(stub: OSVStub, fixtures: dict, body: dict) -> None:
    stub.overrides["/query"] = lambda req, n: httpx.Response(200, json=body)
    result = stub.provider().query(SIX)
    assert result.status is VulnerabilityStatus.UNKNOWN
    assert result.vulnerabilities == []
    assert result.reason.startswith(f"{UNAVAILABLE_PREFIX}: ")
    # A malformed entry poisons the whole answer even when other entries parse.
    valid = fixtures["records"]["GHSA-j8r2-6x86-q33q"]
    stub.overrides["/query"] = lambda req, n: httpx.Response(200, json={"vulns": [valid, "GHSA-not-a-dict"]})
    mixed = stub.provider().query(REQUESTS)
    assert mixed.status is VulnerabilityStatus.UNKNOWN and "malformed" in mixed.reason


# ---------------------------------------------------------------------------
# query_batch()
# ---------------------------------------------------------------------------


def test_query_batch_with_real_fixture_shape(stub: OSVStub, fixtures: dict) -> None:
    queries = [REQUESTS, LODASH, SIX, MISSING]

    def verbatim(request: httpx.Request, call: int) -> httpx.Response:
        payload = json.loads(request.content)
        assert [q["package"]["name"] for q in payload["queries"]] == [q.package_name for q in queries]
        return httpx.Response(200, json=fixtures["querybatch"])

    stub.overrides["/querybatch"] = verbatim
    results = stub.provider().query_batch(queries)

    assert [r.query for r in results] == queries
    assert [r.status for r in results] == [
        VulnerabilityStatus.VULNERABLE,
        VulnerabilityStatus.VULNERABLE,
        VulnerabilityStatus.SAFE,
        VulnerabilityStatus.SAFE,
    ]
    requests_ids = {r.identifier for r in results[0].vulnerabilities}
    assert requests_ids == {
        "GHSA-9hjg-9r4m-mvj7", "GHSA-9wx4-h78v-vm56", "GHSA-gc5v-m9x4-r6x2", "GHSA-j8r2-6x86-q33q",
        "PYSEC-2023-74", "PYSEC-2026-1872", "PYSEC-2026-1873", "PYSEC-2026-2275",
    }
    ghsa = next(r for r in results[0].vulnerabilities if r.identifier == "GHSA-j8r2-6x86-q33q")
    assert ghsa.cvss_score == 6.1 and ghsa.severity is Severity.MEDIUM
    assert ghsa.fixed_versions_for("PyPI", "requests") == ["2.31.0"]
    lodash_fixed = sorted({v for r in results[1].vulnerabilities for v in r.fixed_versions_for("npm", "lodash")})
    assert lodash_fixed == ["4.17.19", "4.17.21", "4.17.23", "4.18.0"]
    # Every record was fetched exactly once (8 + 6 unique ids, none shared).
    detail_calls = [c for c in stub.calls if c[1].startswith("/vulns/")]
    assert len(detail_calls) == 14 and len({c[1] for c in detail_calls}) == 14


def test_query_batch_dedupes_identical_queries_and_caches_details(stub: OSVStub) -> None:
    results = stub.provider().query_batch([REQUESTS, LODASH, REQUESTS])
    assert stub.counts["/querybatch"] == 1
    assert len(json.loads(json.dumps(stub.calls[0][2]))["queries"]) == 2
    assert results[0].status is VulnerabilityStatus.VULNERABLE
    assert [r.identifier for r in results[0].vulnerabilities] == [r.identifier for r in results[2].vulnerabilities]
    assert len([c for c in stub.calls if c[1].startswith("/vulns/")]) == 14


def test_query_batch_empty_input(stub: OSVStub) -> None:
    assert stub.provider().query_batch([]) == []
    assert stub.calls == []


def test_query_batch_chunks_requests(stub: OSVStub) -> None:
    queries = [PackageQuery("PyPI", f"pkg{i}", "1.0") for i in range(5)]
    results = stub.provider(batch_size=2).query_batch(queries)
    assert stub.counts["/querybatch"] == 3
    assert [len(c[2]["queries"]) for c in stub.calls] == [2, 2, 1]
    assert all(r.status is VulnerabilityStatus.SAFE for r in results)


def test_query_batch_follows_next_page_token(stub: OSVStub, fixtures: dict) -> None:
    def paginated(request: httpx.Request, call: int) -> httpx.Response:
        payload = json.loads(request.content)
        if call == 1:
            assert len(payload["queries"]) == 2 and "page_token" not in payload["queries"][0]
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-j8r2-6x86-q33q", "modified": "x"}], "next_page_token": "tok-1"},
                        {},
                    ]
                },
            )
        assert payload["queries"] == [
            {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.25.1", "page_token": "tok-1"}
        ]
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "PYSEC-2023-74", "modified": "y"}]}]})

    stub.overrides["/querybatch"] = paginated
    results = stub.provider().query_batch([REQUESTS, SIX])
    assert stub.counts["/querybatch"] == 2
    assert [r.identifier for r in results[0].vulnerabilities] == ["GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"]
    assert results[1].status is VulnerabilityStatus.SAFE


def test_query_batch_transport_failure_marks_all_unknown(stub: OSVStub) -> None:
    def down(request: httpx.Request, call: int):
        raise httpx.ConnectError("dns failure", request=request)

    stub.overrides["/querybatch"] = down
    results = stub.provider().query_batch([REQUESTS, SIX])
    assert all(r.status is VulnerabilityStatus.UNKNOWN for r in results)
    assert all(r.reason.startswith(UNAVAILABLE_PREFIX) and "dns failure" in r.reason for r in results)
    assert not any(c[1].startswith("/vulns/") for c in stub.calls)


def test_query_batch_malformed_results_marks_unknown(stub: OSVStub) -> None:
    stub.overrides["/querybatch"] = lambda req, n: httpx.Response(200, json={"results": [{}]})  # 1 result for 2 queries
    results = stub.provider().query_batch([REQUESTS, SIX])
    assert [r.status for r in results] == [VulnerabilityStatus.UNKNOWN, VulnerabilityStatus.UNKNOWN]
    assert "malformed /querybatch response" in results[0].reason


@pytest.mark.parametrize(
    "entry",
    [
        {"vulns": ["GHSA-not-a-dict", {"id": 12}]},
        {"vulns": [{"modified": "2024-01-01T00:00:00Z"}]},
        {"vulns": [{"id": ""}]},
        {"vulns": "GHSA-not-a-list"},
        "not-an-object",
        None,
    ],
)
def test_query_batch_malformed_entry_marks_only_that_query_unknown(stub: OSVStub, entry) -> None:
    stub.overrides["/querybatch"] = lambda req, n: httpx.Response(200, json={"results": [entry, {}]})
    results = stub.provider().query_batch([REQUESTS, SIX])
    assert results[0].status is VulnerabilityStatus.UNKNOWN
    assert results[0].vulnerabilities == []
    assert results[0].reason.startswith(f"{UNAVAILABLE_PREFIX}: ") and "/querybatch" in results[0].reason
    assert results[1].status is VulnerabilityStatus.SAFE and results[1].reason is None
    assert not any(c[1].startswith("/vulns/") for c in stub.calls)


def test_query_batch_malformed_later_page_marks_query_unknown(stub: OSVStub) -> None:
    def paginated(request: httpx.Request, call: int) -> httpx.Response:
        if call == 1:
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "GHSA-j8r2-6x86-q33q", "modified": "x"}], "next_page_token": "tok"}, {}]},
            )
        return httpx.Response(200, json={"results": [{"vulns": [42]}]})

    stub.overrides["/querybatch"] = paginated
    results = stub.provider().query_batch([REQUESTS, SIX])
    assert results[0].status is VulnerabilityStatus.UNKNOWN and "malformed" in results[0].reason
    assert results[1].status is VulnerabilityStatus.SAFE
    assert stub.counts["/querybatch"] == 2
    assert not any(c[1].startswith("/vulns/") for c in stub.calls)  # ids of a broken query are never fetched


def test_query_batch_retries_429_then_succeeds(stub: OSVStub) -> None:
    sleeps: list[float] = []
    stub.overrides["/querybatch"] = lambda req, n: httpx.Response(429) if n == 1 else None
    results = stub.provider(sleep=sleeps.append).query_batch([SIX])
    assert results[0].status is VulnerabilityStatus.SAFE
    assert stub.counts["/querybatch"] == 2 and len(sleeps) == 1


def test_query_batch_keeps_known_ids_when_details_fail(stub: OSVStub) -> None:
    stub.overrides["/vulns/GHSA-j8r2-6x86-q33q"] = lambda req, n: httpx.Response(500, text="boom")
    results = stub.provider().query_batch([REQUESTS])
    result = results[0]
    assert result.status is VulnerabilityStatus.VULNERABLE  # OSV said the version is affected
    minimal = next(r for r in result.vulnerabilities if r.identifier == "GHSA-j8r2-6x86-q33q")
    assert minimal.summary is None and minimal.affected == [] and minimal.severity is Severity.UNKNOWN
    assert minimal.modified_at is not None  # taken from the batch answer
    assert "GHSA-j8r2-6x86-q33q" in result.reason and "HTTP 500" in result.reason
    full = next(r for r in result.vulnerabilities if r.identifier == "PYSEC-2023-74")
    assert full.fixed_versions_for("PyPI", "requests") == ["2.31.0"]
    # The failing id was retried (5xx) but never re-fetched after giving up.
    assert stub.counts["/vulns/GHSA-j8r2-6x86-q33q"] == 3


def test_query_batch_records_are_filtered_per_query(stub: OSVStub, fixtures: dict) -> None:
    # lodash-es shares GHSA-29mw-wpgm-hmr9 with lodash: the cached record must be filtered per query.
    lodash_es = PackageQuery("npm", "lodash-es", "4.17.15")
    fixtures["query"][("npm", "lodash-es", "4.17.15")] = {"vulns": [fixtures["records"]["GHSA-29mw-wpgm-hmr9"]]}
    try:
        results = stub.provider().query_batch([LODASH, lodash_es])
    finally:
        del fixtures["query"][("npm", "lodash-es", "4.17.15")]
    lodash_rec = next(r for r in results[0].vulnerabilities if r.identifier == "GHSA-29mw-wpgm-hmr9")
    es_rec = results[1].vulnerabilities[0]
    assert [p.package_name for p in lodash_rec.affected] == ["lodash"]
    assert [p.package_name for p in es_rec.affected] == ["lodash-es"]
    assert stub.counts["/vulns/GHSA-29mw-wpgm-hmr9"] == 1


# ---------------------------------------------------------------------------
# health()
# ---------------------------------------------------------------------------


def test_health_reachable(stub: OSVStub) -> None:
    ok, detail = stub.provider().health()
    assert ok and BASE in detail
    assert stub.calls[0][1] == "/query"


def test_health_unreachable(stub: OSVStub) -> None:
    def down(request: httpx.Request, call: int):
        raise httpx.ConnectError("refused", request=request)

    stub.overrides["/query"] = down
    ok, detail = stub.provider().health()
    assert not ok and "unreachable" in detail
    stub.overrides["/query"] = lambda req, n: httpx.Response(503)
    ok, detail = stub.provider().health()
    assert not ok and "503" in detail


def test_provider_defaults_come_from_settings() -> None:
    from app.core.config import get_settings

    settings = get_settings()
    provider = OSVProvider()
    assert provider.base_url == settings.osv_api_url.rstrip("/")
    assert provider.timeout == float(settings.osv_timeout)
    assert provider.name == "osv"
    assert OSVProvider("https://osv.test/v1/", 7).base_url == "https://osv.test/v1"


def test_malformed_events_field_is_scoped_to_that_record() -> None:
    """A non-list ``events`` must not crash the provider; the query becomes UNKNOWN (never SAFE)."""
    import httpx

    from app.services.vulnerabilities.base import PackageQuery
    from app.services.vulnerabilities.osv_provider import OSVProvider

    bad = {"id": "GHSA-bad", "affected": [{"package": {"ecosystem": "PyPI", "name": "x"}, "ranges": [{"type": "ECOSYSTEM", "events": 5}]}]}
    good = {"id": "GHSA-good", "affected": [{"package": {"ecosystem": "PyPI", "name": "y"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/query"):
            return httpx.Response(200, json={"vulns": [bad]})
        if path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-bad"}]}, {"vulns": [{"id": "GHSA-good"}]}]})
        return httpx.Response(200, json=bad if path.endswith("GHSA-bad") else good)

    provider = OSVProvider("https://osv.test/v1", 5, httpx.Client(transport=httpx.MockTransport(handler)))
    # The malformed ranges are skipped, the advisory itself is still real → VULNERABLE, no fixed versions.
    single = provider.query(PackageQuery("PyPI", "x", "1"))
    assert single.status == "VULNERABLE"
    assert single.vulnerabilities[0].identifier == "GHSA-bad"
    assert single.vulnerabilities[0].fixed_versions_for("PyPI", "x") == []


def test_parser_crash_is_scoped_to_the_affected_query(monkeypatch) -> None:
    """An unexpected parser exception for one record must not abort the whole batch."""
    import httpx

    from app.services.vulnerabilities import osv_provider as module
    from app.services.vulnerabilities.base import PackageQuery

    good = {"id": "GHSA-good", "affected": [{"package": {"ecosystem": "PyPI", "name": "y"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}
    bad = {"id": "GHSA-bad"}
    original = module.parse_osv_record

    def exploding(raw, **kwargs):
        if raw.get("id") == "GHSA-bad":
            raise TypeError("'int' object is not iterable")
        return original(raw, **kwargs)

    monkeypatch.setattr(module, "parse_osv_record", exploding)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/query"):
            return httpx.Response(200, json={"vulns": [bad]})
        if path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-bad"}]}, {"vulns": [{"id": "GHSA-good"}]}]})
        return httpx.Response(200, json=bad if path.endswith("GHSA-bad") else good)

    provider = module.OSVProvider("https://osv.test/v1", 5, httpx.Client(transport=httpx.MockTransport(handler)))
    single = provider.query(PackageQuery("PyPI", "x", "1"))
    assert single.status == "UNKNOWN" and "malformed OSV record GHSA-bad" in (single.reason or "")
    batch = provider.query_batch([PackageQuery("PyPI", "x", "1"), PackageQuery("PyPI", "y", "1")])
    # The id is known from /querybatch, so the batch keeps a minimal record (never SAFE)
    # and the other query is unaffected.
    assert batch[0].status == "VULNERABLE" and batch[0].vulnerabilities[0].identifier == "GHSA-bad"
    assert batch[1].status == "VULNERABLE" and batch[1].vulnerabilities[0].identifier == "GHSA-good"
