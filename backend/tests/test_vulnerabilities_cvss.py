"""CVSS v3.x base score computation and severity banding."""

from __future__ import annotations

import pytest

from app.models.enums import Severity
from app.services.vulnerabilities.cvss import (
    cvss_v3_base_score,
    parse_cvss_v3_vector,
    roundup,
    severity_from_score,
)


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        # Real OSV vectors, values cross-checked with NVD.
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.1),  # CVE-2023-32681 (requests)
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),  # CVE-2026-4800 (lodash)
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),  # CVE-2021-23337 (lodash)
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N", 5.6),  # CVE-2024-35195 (requests)
        # Scope changed uses the changed PR weights (PR:H -> 0.50 instead of 0.27).
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        # Perfect 10 is capped at 10.0.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        # Physical access, low everything.
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ],
)
def test_known_vectors(vector: str, expected: float) -> None:
    assert cvss_v3_base_score(vector) == expected


def test_no_impact_scores_zero() -> None:
    assert cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N") == 0.0


def test_vector_is_case_insensitive_and_ignores_temporal_metrics() -> None:
    assert cvss_v3_base_score("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h") == 9.8
    assert cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C") == 9.8


@pytest.mark.parametrize(
    "vector",
    [
        None,
        "",
        "not a vector",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",  # CVSS v2
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:H/SA:H",  # CVSS v4
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad value
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicate metric
        "CVSS:3.1/AV/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # malformed part
    ],
)
def test_invalid_vectors_return_none(vector) -> None:
    assert cvss_v3_base_score(vector) is None
    assert parse_cvss_v3_vector(vector) is None


def test_roundup_uses_integer_arithmetic() -> None:
    # 4.000000000000001 must not become 4.1 (the reason CVSS 3.1 redefined Roundup).
    assert roundup(4.000000000000001) == 4.0
    assert roundup(4.02) == 4.1
    assert roundup(4.0) == 4.0
    assert roundup(0.0) == 0.0
    assert roundup(9.95) == 10.0


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, Severity.UNKNOWN),
        (0.0, Severity.LOW),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
        (-1.0, Severity.UNKNOWN),
        (10.5, Severity.UNKNOWN),
        (float("nan"), Severity.UNKNOWN),
        ("7.5", Severity.HIGH),
        ("high", Severity.UNKNOWN),
    ],
)
def test_severity_from_score(score, expected: Severity) -> None:
    assert severity_from_score(score) is expected
