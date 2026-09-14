"""Neutralise repository-controlled git configuration in working copies.

Sentinel Chain copies local repositories *including* ``.git`` so that a
remediation can later be committed and pushed. A ``.git`` directory is
attacker-controlled data for a local source: hooks, ``core.fsmonitor``,
``core.sshCommand``, ``filter.*.clean``, ``diff.external`` and friends all run
arbitrary commands on the host as soon as git touches the tree, and
``url.*.insteadOf`` can redirect a push. GitHub clones never carry hooks or
config, but the same hardening is applied to every working copy for
consistency (audit finding F-02).
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from app.core.logging import get_stage_logger

log = get_stage_logger("Repository")

#: Command-line overrides applied to every git process Sentinel Chain runs in a working copy.
#: ``-c`` beats repository config, so even a config we failed to sanitise cannot run hooks or
#: helper commands.
SAFE_GIT_OPTIONS: tuple[str, ...] = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "core.sshCommand=",
    "-c", "core.gitProxy=",
    "-c", "core.pager=cat",
    "-c", "credential.helper=",
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
)

#: Config keys that survive sanitisation (everything else is dropped).
_SAFE_CORE_KEYS = {"repositoryformatversion", "filemode", "bare", "logallrefupdates", "ignorecase", "precomposeunicode", "symlinks"}
_SECTION_RE = re.compile(r'^\s*\[(?P<section>[A-Za-z0-9.-]+)(?:\s+"(?P<sub>[^"\n]*)")?\]\s*$')
_KEY_RE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9-]*)\s*=\s*(?P<value>.*?)\s*$")
_REMOTE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_FETCH_REFSPEC_RE = re.compile(r"^\+?refs/heads/(\*|[A-Za-z0-9._/-]+):refs/remotes/[A-Za-z0-9._-]+/(\*|[A-Za-z0-9._/-]+)$")
_URL_RE = re.compile(r"^(https?://|git@|ssh://|git://)[^\s]+$")


def harden_git_dir(repo_path: Path | str) -> list[str]:
    """Make the ``.git`` of a working copy safe to run git commands in. Returns human notes.

    * ``.git`` that is a symlink or a ``gitdir:`` file is removed: it would point at
      another repository (typically the user's original), and commits would land there.
    * ``.git/hooks`` is deleted.
    * ``.git/config`` is rewritten keeping only harmless keys (core basics, remote
      ``url``/``fetch``, branch ``remote``/``merge``).
    """
    root = Path(repo_path)
    git_dir = root / ".git"
    notes: list[str] = []
    if not git_dir.exists() and not git_dir.is_symlink():
        return notes
    if git_dir.is_symlink() or not git_dir.is_dir():
        git_dir.unlink()
        notes.append(".git was a symlink or gitdir pointer to another repository and was removed from the working copy")
        log.warning("%s: removed .git pointer (not a self-contained repository)", root)
        return notes
    hooks = git_dir / "hooks"
    if hooks.is_symlink() or hooks.exists():
        if hooks.is_symlink():
            hooks.unlink()
        else:
            shutil.rmtree(hooks, ignore_errors=True)
        notes.append("git hooks removed from the working copy")
    config = git_dir / "config"
    if config.is_symlink():
        config.unlink()
        notes.append(".git/config was a symlink and was replaced")
        config.write_text(_render_config({}, {}), encoding="utf-8")
        return notes
    if config.exists():
        dropped = sanitize_git_config(config)
        if dropped:
            notes.append(f"{len(dropped)} git config entries removed: {', '.join(sorted(dropped)[:8])}")
    return notes


def sanitize_git_config(config_path: Path) -> list[str]:
    """Rewrite ``config_path`` with only the allow-listed keys; returns the dropped ``section.key`` names."""
    original = config_path.read_text(encoding="utf-8", errors="replace")
    remotes: dict[str, dict[str, str]] = {}
    branches: dict[str, dict[str, str]] = {}
    core: dict[str, str] = {}
    user: dict[str, str] = {}
    dropped: list[str] = []
    section, sub = "", None
    for raw in original.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0] if not raw.lstrip().startswith(("#", ";")) else ""
        if not line.strip():
            continue
        header = _SECTION_RE.match(line)
        if header:
            section, sub = header.group("section").lower(), header.group("sub")
            continue
        item = _KEY_RE.match(line)
        if not item:
            continue
        key, value = item.group("key").lower(), item.group("value").strip().strip('"')
        name = f"{section}{'.' + sub if sub else ''}.{key}"
        if section == "core" and sub is None and key in _SAFE_CORE_KEYS and value.lower() in {"true", "false", "0", "1"}:
            core[key] = value
        elif section == "remote" and sub and _REMOTE_NAME_RE.match(sub) and key == "url" and _URL_RE.match(value):
            remotes.setdefault(sub, {})["url"] = value
        elif section == "remote" and sub and _REMOTE_NAME_RE.match(sub) and key == "fetch" and _FETCH_REFSPEC_RE.match(value):
            remotes.setdefault(sub, {})["fetch"] = value
        elif section == "branch" and sub and key in {"remote", "merge"} and re.match(r"^[A-Za-z0-9._/-]+$", value):
            branches.setdefault(sub, {})[key] = value
        elif section == "user" and sub is None and key in {"name", "email"} and "\n" not in value and len(value) < 200:
            user[key] = value  # plain identity strings; commits use their own identity anyway
        else:
            dropped.append(name)
    sections = {"core": core, "user": user, **{f"remote.{k}": v for k, v in remotes.items()}}
    config_path.write_text(_render_config(sections, branches), encoding="utf-8")
    return dropped


def _render_config(sections: dict[str, dict[str, str]], branches: dict[str, dict[str, str]]) -> str:
    core = sections.get("core", {})
    lines = ["[core]", "\trepositoryformatversion = 0", "\tfilemode = " + core.get("filemode", "true"), "\tbare = false", "\tlogallrefupdates = true"]
    for key in ("ignorecase", "precomposeunicode", "symlinks"):
        if key in core:
            lines.append(f"\t{key} = {core[key]}")
    user = sections.get("user", {})
    if user:
        lines.append("[user]")
        lines += [f"\t{key} = {user[key]}" for key in ("name", "email") if key in user]
    for name, values in sections.items():
        if not name.startswith("remote."):
            continue
        remote = name[len("remote."):]
        if "url" not in values:
            continue
        lines.append(f'[remote "{remote}"]')
        lines.append(f"\turl = {values['url']}")
        lines.append(f"\tfetch = {values.get('fetch', f'+refs/heads/*:refs/remotes/{remote}/*')}")
    for branch, values in branches.items():
        if not re.match(r"^[A-Za-z0-9._/-]+$", branch):
            continue
        lines.append(f'[branch "{branch}"]')
        for key in ("remote", "merge"):
            if key in values:
                lines.append(f"\t{key} = {values[key]}")
    return "\n".join(lines) + "\n"


__all__ = ["SAFE_GIT_OPTIONS", "harden_git_dir", "sanitize_git_config"]
