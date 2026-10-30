"""Build a deterministic AstrBot plugin archive from an explicit file manifest.

The manifest below is the single source of truth for what ships: nothing is
picked up by wildcard, so a stray database, log, or cookie dump cannot leak into
a release by accident. The version comes from ``metadata.yaml`` only, and the
finished ZIP is passed through :func:`privacy_gate.assert_archive_clean`.

Usage::

    python scripts/build_release.py --output-dir dist
    python scripts/build_release.py --output-dir dist --skip-privacy

The archive is written through a temporary file and atomically renamed, so a
failed build never leaves a half-written ZIP behind. Two runs over identical
inputs produce byte-identical output (fixed timestamps, sorted entries, fixed
compression level).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

try:  # ``python -m scripts.build_release``
    from .privacy_gate import assert_archive_clean
except ImportError:  # ``python scripts/build_release.py``
    from privacy_gate import assert_archive_clean

PLUGIN_NAME = "astrbot_plugin_Tricy_huawei_health"

# Flat files that live in the repository root.
ROOT_FILES = (
    "_conf_schema.json",
    "CHANGELOG_v0.4.1.md",
    "CHANGELOG_v0.4.2.md",
    "CHANGELOG_v0.5.0.md",
    "LICENSE",
    "README.md",
    "logo.png",
    "main.py",
    "metadata.yaml",
    "requirements.txt",
)

# Flat runtime modules (this plugin has no sub-packages).
RUNTIME_MODULES = (
    "hw_auth.py",
    "hw_client.py",
    "hw_credentials.py",
    "hw_login.py",
    "hw_privacy.py",
    "hw_store.py",
    "hw_webapi.py",
)

# WebUI assets; everything below these directories ships except filtered names.
RUNTIME_DIRS = ("pages",)

TEXT_SUFFIXES = frozenset(
    {".css", ".html", ".js", ".json", ".md", ".py", ".txt", ".yaml", ".yml"}
)
VERSION_PATTERN = re.compile(
    r"^version:\s*"
    r"(v\d+\.\d+\.\d+"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)"
    r"\s*$",
    re.MULTILINE,
)
FORBIDDEN_SUFFIXES = (
    "-shm",
    "-wal",
    ".bak",
    ".db",
    ".log",
    ".pyc",
    ".pyo",
    ".zip",
)
REQUIRED_ARCHIVE_ENTRIES = (
    "_conf_schema.json",
    "main.py",
    "metadata.yaml",
    "requirements.txt",
)


def metadata_version(repository_root: Path) -> str:
    """Return the semantic version declared by ``metadata.yaml``."""
    metadata_path = repository_root / "metadata.yaml"
    if not metadata_path.is_file():
        raise FileNotFoundError("metadata.yaml 不存在，无法确定版本号")
    text = metadata_path.read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(text)
    if match is None:
        raise ValueError("metadata.yaml 缺少有效的语义化版本号（形如 v0.4.2）")
    return match.group(1)


def release_files(repository_root: Path) -> list[Path]:
    """Return the explicit runtime manifest in stable archive order."""
    files = [repository_root / name for name in ROOT_FILES]
    files.extend(repository_root / name for name in RUNTIME_MODULES)
    for directory in RUNTIME_DIRS:
        directory_root = repository_root / directory
        if not directory_root.is_dir():
            raise FileNotFoundError(f"缺少运行时目录：{directory}")
        files.extend(path for path in directory_root.rglob("*") if path.is_file())

    missing = [
        path.relative_to(repository_root).as_posix()
        for path in files
        if not path.is_file()
    ]
    if missing:
        raise FileNotFoundError("发布文件缺失：" + "、".join(missing))

    selected: list[Path] = []
    for path in files:
        relative = path.relative_to(repository_root)
        if "__pycache__" in relative.parts:
            continue
        if relative.name.lower().endswith(FORBIDDEN_SUFFIXES):
            continue
        if path.is_symlink():
            raise ValueError(f"发布文件不能是符号链接：{relative.as_posix()}")
        selected.append(path)
    return sorted(set(selected), key=lambda item: item.relative_to(repository_root).as_posix())


def _archive_payload(path: Path) -> bytes:
    """Read one file, normalising text line endings for reproducible archives."""
    payload = path.read_bytes()
    if path.suffix.lower() in TEXT_SUFFIXES or path.name in {
        "LICENSE",
        "requirements.txt",
    }:
        payload = payload.replace(b"\r\n", b"\n")
    return payload


def validate_archive(archive_path: Path) -> None:
    """Reject a nested root, missing entrypoints, and forbidden artefacts."""
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
    if not names:
        raise ValueError("安装包是空的")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"安装包路径不安全：{name}")
        if path.parts[0] != PLUGIN_NAME:
            raise ValueError(f"安装包顶层目录必须是 {PLUGIN_NAME}/：{name}")
        if "__pycache__" in path.parts:
            raise ValueError(f"安装包含有缓存目录：{name}")
        if path.name.lower().endswith(FORBIDDEN_SUFFIXES):
            raise ValueError(f"安装包含有禁止文件：{name}")
    expected = {f"{PLUGIN_NAME}/{name}" for name in REQUIRED_ARCHIVE_ENTRIES}
    missing = expected.difference(names)
    if missing:
        raise ValueError("安装包缺少：" + "、".join(sorted(missing)))


def build_release(
    repository_root: Path,
    output_directory: Path,
    *,
    verify_privacy: bool = True,
) -> Path:
    """Create and validate one deterministic AstrBot installation ZIP."""
    repository_root = repository_root.resolve()
    version = metadata_version(repository_root)
    sources = release_files(repository_root)
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / f"{PLUGIN_NAME}-{version}.zip"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_directory,
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        with zipfile.ZipFile(
            temporary_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for source in sources:
                relative = source.relative_to(repository_root).as_posix()
                info = zipfile.ZipInfo(
                    f"{PLUGIN_NAME}/{relative}", date_time=(1980, 1, 1, 0, 0, 0)
                )
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, _archive_payload(source), compresslevel=9)
        validate_archive(temporary_path)
        if verify_privacy:
            assert_archive_clean(temporary_path)
        else:
            print("warning: privacy gate skipped (--skip-privacy)", file=sys.stderr)
        temporary_path.replace(output_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return output_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic release archive for the plugin."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist"),
        help="directory for the generated installation ZIP (default: dist)",
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=None,
        help="repository root (default: the parent of this script's directory)",
    )
    parser.add_argument(
        "--skip-privacy",
        action="store_true",
        help="skip the privacy gate (only for bootstrapping before it exists)",
    )
    arguments = parser.parse_args(argv)
    repository_root = (
        arguments.repository
        if arguments.repository is not None
        else Path(__file__).resolve().parents[1]
    )
    try:
        archive_path = build_release(
            repository_root,
            arguments.output_dir,
            verify_privacy=not arguments.skip_privacy,
        )
    except (FileNotFoundError, ValueError, OSError) as error:
        print(f"build_release: {error}", file=sys.stderr)
        return 1
    print(archive_path.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
