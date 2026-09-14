"""Manual pull-request instructions shown when Sentinel Chain cannot open the PR itself.

The same text is produced whether GitHub is not configured (``UNAVAILABLE``) or
the automated flow failed (``FAILED``): a fenced shell block the reviewer can
paste, followed by the hint that ``GITHUB_TOKEN`` enables the automated path.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from pathlib import Path

UNAVAILABLE_HEADLINE = "GitHub PR creation unavailable"
TOKEN_HINT = "Set GITHUB_TOKEN in .env to let Sentinel Chain do this automatically."
DEFAULT_BODY_FILE = "pull-request-body.md"


def build_manual_instructions(
    *,
    workspace_path: Path | str,
    branch: str,
    changed_files: Sequence[str],
    title: str,
    body_file: Path | str | None = None,
    reason: str | None = None,
    failed: bool = False,
) -> str:
    """Render the manual branch / commit / push / ``gh pr create --draft`` steps.

    ``body_file`` is the Markdown file to use as the PR description (the evidence
    report when it exists); when unknown a placeholder name is used and the reader
    is told to save the generated description under that name. ``reason`` explains
    why the automated path was not taken; ``failed`` switches the headline from
    "unavailable" to "failed".
    """
    files = list(changed_files) or ["<changed files>"]
    body_path = str(body_file) if body_file else DEFAULT_BODY_FILE
    headline = "GitHub PR creation failed" if failed else UNAVAILABLE_HEADLINE
    if reason:
        headline = f"{headline}: {reason.rstrip('.')}."
    else:
        headline = f"{headline}."

    commands = [
        f"cd {shlex.quote(str(workspace_path))}",
        f"git checkout -b {shlex.quote(branch)}",
        "git add " + " ".join(shlex.quote(f) for f in files),
        f"git commit -m {shlex.quote(title)}",
        f"git push -u origin {shlex.quote(branch)}",
        f"gh pr create --draft --title {shlex.quote(title)} --body-file {shlex.quote(body_path)}",
    ]
    lines = [headline, "Create the draft pull request manually:", "", "```sh", *commands, "```", ""]
    if not body_file:
        lines.append(f"Save the generated pull request description as `{DEFAULT_BODY_FILE}` before the last step.")
    lines.append(TOKEN_HINT)
    return "\n".join(lines)
