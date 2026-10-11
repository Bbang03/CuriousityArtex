#!/usr/bin/env python3
"""Create a public source folder and ZIP from the current Git working tree.

Uses tracked and non-ignored untracked files, not Git history. Path exclusions
are enforced even for tracked files. This is not a content-based secret scanner;
scan and review the resulting folder before publishing it.
"""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile


MANIFEST = "SOURCE_MANIFEST.sha256"
EXCLUDED_DIRS = frozenset({
    ".git", ".aws", ".codex", ".agents", ".claude", ".local-runtime",
    ".playwright-mcp", ".playwright-cli", ".idea", ".vscode", ".next",
    "__pycache__", "node_modules", "release-artifacts", "evidence-local",
    "work", "test-results", "scan-output", "demo-data", "transcripts",
})
EXCLUDED_ROOTS = frozenset({"data", "dist", "bench"})
EXCLUDED_PATH_PREFIXES = ("web/out/", "server/webui/dist/")
EXCLUDED_NAMES = frozenset({
    "config.json", "scheduler_state.json", "jwt.key", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", "privatekey", "private_key", "private-key",
    "credentials", ".npmrc", ".netrc", ".pypirc",
    ".ds_store", "thumbs.db", "dump.sql", "backup.sql",
})
EXCLUDED_SUFFIXES = (
    ".env", ".har", ".har.json", ".db", ".db-wal", ".db-shm", ".dump",
    ".sqlite", ".sqlite3", ".sqlite-wal", ".sqlite-shm", ".sqlite3-wal",
    ".sqlite3-shm", ".sql.gz", ".sql.bz2", ".sql.xz", ".pem", ".key",
    ".p12", ".pfx", ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2",
    ".tbz2", ".tar.xz", ".txz", ".7z", ".rar", ".pyc", ".pyo",
    ".tsbuildinfo", ".swp", ".swo",
)


class ReleaseError(Exception):
    """A release cannot be safely assembled."""


def git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if result.returncode:
        raise ReleaseError(result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def exclusion_reason(relative):
    """Return a public-release exclusion reason, or None for source files."""
    parts = PurePosixPath(relative).parts
    lowered = tuple(part.lower() for part in parts)
    name = lowered[-1]
    if any(part in EXCLUDED_DIRS for part in lowered[:-1]):
        return "local state, generated files, or dependencies"
    if lowered[0] in EXCLUDED_ROOTS or relative.lower().startswith(EXCLUDED_PATH_PREFIXES):
        return "runtime data or build output"
    if name in EXCLUDED_NAMES:
        return "runtime configuration or authentication file"
    if name != ".env.example" and (name == ".env" or name.startswith(".env.")):
        return "environment values"
    if name.endswith(EXCLUDED_SUFFIXES):
        return "environment, capture, database, private key, archive, or generated file"
    if len(parts) == 1 and name in {
        "artex", "artex.new", "artex.new.sha256", "artex.old", "artex.failed", "artex.upgrade.json",
    }:
        return "local executable or upgrade output"
    if name == MANIFEST.lower():
        return "release manifest is regenerated"
    return None


def checked_source(root, relative):
    """Reject unsafe paths, links (including parent links), and special files."""
    path = PurePosixPath(relative)
    if (not relative or path.is_absolute() or ".." in path.parts
            or "\\" in relative or any(ord(char) < 32 or ord(char) == 127 for char in relative)):
        raise ReleaseError(f"Unsafe source path: {relative!r}")
    current = root
    for index, part in enumerate(path.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            # git ls-files --cached also lists files deleted in the working tree.
            return None
        if stat.S_ISLNK(mode):
            raise ReleaseError(f"Symbolic links are not allowed: {relative}")
        last = index == len(path.parts) - 1
        if not (stat.S_ISREG(mode) if last else stat.S_ISDIR(mode)):
            raise ReleaseError(f"Not a regular source file: {relative}")
    try:
        current.resolve().relative_to(root)
    except ValueError as error:
        raise ReleaseError(f"Source is outside repository: {relative}") from error
    return current


def inventory(root):
    candidates = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    included, excluded = [], []
    for relative in sorted({os.fsdecode(item) for item in candidates.split(b"\0") if item}):
        source = checked_source(root, relative)
        reason = exclusion_reason(relative)
        if source is None:
            excluded.append((relative, "deleted from working tree"))
        elif reason:
            excluded.append((relative, reason))
        else:
            included.append(relative)
    if not included:
        raise ReleaseError("No public source files remain after exclusions.")
    return included, excluded


def copy_source(root, relative, destination):
    source = checked_source(root, relative)
    if source is None:
        raise ReleaseError(f"Source disappeared during packaging: {relative}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(source, flags), "rb") as reader:
        metadata = os.fstat(reader.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseError(f"Not a regular source file: {relative}")
        digest = hashlib.sha256()
        with destination.open("xb") as writer:
            while chunk := reader.read(1024 * 1024):
                writer.write(chunk)
                digest.update(chunk)
        # Retain ordinary permissions (especially executable scripts), not setuid.
        destination.chmod(stat.S_IMODE(metadata.st_mode) & 0o777)
        os.utime(destination, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    return digest.hexdigest()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as reader:
        while chunk := reader.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_release(root, output, name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name):
        raise ReleaseError("Name must contain 1–100 ASCII letters, digits, dots, underscores, or hyphens.")
    root = Path(root).resolve()
    output = Path(output).absolute()
    release = output / name
    archive = output / f"{name}.zip"
    checksum = output / f"{name}.zip.sha256"
    for path in (release, archive, checksum):
        if os.path.lexists(path):
            raise ReleaseError(f"Output already exists; choose a new name: {path}")
    included, excluded = inventory(root)
    output.mkdir(parents=True, exist_ok=True)
    published = []
    with tempfile.TemporaryDirectory(prefix=f".{name}-", dir=output) as temporary:
        staging = Path(temporary)
        source_folder = staging / name
        source_folder.mkdir()
        records = []
        for relative in included:
            digest = copy_source(root, relative, source_folder / relative)
            records.append(f"{digest}  {relative}\n")
        # The manifest covers every copied source file, excluding itself.
        (source_folder / MANIFEST).write_text("".join(records), encoding="utf-8")
        staged_zip = staging / archive.name
        with zipfile.ZipFile(staged_zip, "x", zipfile.ZIP_DEFLATED,
                             compresslevel=6, strict_timestamps=False) as bundle:
            for relative in sorted([*included, MANIFEST]):
                bundle.write(source_folder / relative, f"{name}/{relative}")
        staged_checksum = staging / checksum.name
        staged_checksum.write_text(f"{sha256(staged_zip)}  {archive.name}\n", encoding="utf-8")
        try:
            # Exclusive creation prevents replacing existing release artifacts.
            release.mkdir()
            published.append(release)
            for child in source_folder.iterdir():
                child.rename(release / child.name)
            os.link(staged_zip, archive)
            published.append(archive)
            os.link(staged_checksum, checksum)
            published.append(checksum)
        except Exception:
            for path in reversed(published):
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            raise
    return {
        "folder": release, "archive": archive, "checksum": checksum,
        "included": included, "excluded": excluded,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Example: python3 scripts/package-release.py --name aegisloop-public-20261011-api-discovery",
    )
    parser.add_argument("--name", required=True, help="new folder and ZIP base name; never overwritten")
    parser.add_argument("--output", type=Path, default=Path.cwd() / "release-artifacts",
                        help="output directory (default: ./release-artifacts)")
    parser.add_argument("--dry-run", action="store_true", help="list included/excluded paths without writing files")
    args = parser.parse_args(argv)
    try:
        root = Path(os.fsdecode(git(Path.cwd(), "rev-parse", "--show-toplevel")).strip()).resolve()
        if args.dry_run:
            included, excluded = inventory(root)
            for relative in included:
                print(f"INCLUDE {relative}")
            for relative, reason in excluded:
                print(f"EXCLUDE {relative}: {reason}")
            print(f"Files: {len(included)} included, {len(excluded)} excluded")
        else:
            result = build_release(root, args.output, args.name)
            print(f"Files: {len(result['included'])} included, {len(result['excluded'])} excluded")
            for key in ("folder", "archive", "checksum"):
                print(f"{key.capitalize()}: {result[key]}")
            print("Review and secret-scan the release folder before publishing.")
        return 0
    except (ReleaseError, OSError, ValueError) as error:
        print(f"Release failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
