"""Resolve the AstrBot git ref used by the ``astrbot-runner-contract`` CI job.

Two channels are supported, matching the job matrix:

``--field minimum``
    Read ``astrbot_version`` from ``metadata.yaml`` and turn its ``>=X.Y.Z``
    lower bound into the git tag ``vX.Y.Z``.  This keeps the declared
    compatibility floor and the CI reference version from ever drifting apart:
    ``metadata.yaml`` stays the single source of truth.

``--field latest-stable-4x``
    Ask the GitHub releases API for the newest stable ``v4.x`` tag.  Requires
    network access; the CI job runs it with ``GITHUB_TOKEN`` set.

Only the standard library is used, because this script runs in CI *before*
``pip install -r requirements.txt``.

Usage::

    python scripts/resolve_astrbot_ref.py --field minimum
    python scripts/resolve_astrbot_ref.py --field latest-stable-4x
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
METADATA_FILE = REPO_ROOT / "metadata.yaml"

UPSTREAM_REPOSITORY = "AstrBotDevs/AstrBot"
RELEASES_API = (
    f"https://api.github.com/repos/{UPSTREAM_REPOSITORY}/releases?per_page=100"
)

SPEC_FIELD_PATTERN = re.compile(r"^astrbot_version:\s*(.+?)\s*$", re.MULTILINE)
LOWER_BOUND_PATTERN = re.compile(r">=\s*v?(\d+\.\d+\.\d+)")
TAG_PATTERN = re.compile(r"v(\d+)\.(\d+)\.(\d+)")


def declared_spec(metadata_file: Path = METADATA_FILE) -> str:
    """Return the raw ``astrbot_version`` constraint declared in metadata.yaml."""
    try:
        text = metadata_file.read_text(encoding="utf-8")
    except OSError as error:
        raise SystemExit(f"无法读取 {metadata_file}：{error}") from error
    match = SPEC_FIELD_PATTERN.search(text)
    if match is None:
        raise SystemExit(f"{metadata_file} 缺少 astrbot_version 字段")
    return match.group(1).strip().strip("\"'").strip()


def minimum_ref(metadata_file: Path = METADATA_FILE) -> str:
    """Return the git tag for the declared lower bound of the AstrBot range."""
    spec = declared_spec(metadata_file)
    match = LOWER_BOUND_PATTERN.search(spec)
    if match is None:
        raise SystemExit(
            f"astrbot_version 里找不到 >=X.Y.Z 下限，无法确定最低支持版本：{spec!r}"
        )
    return "v" + match.group(1)


def _fetch_releases(url: str, timeout: float) -> list[dict]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "astrbot-plugin-tricy-huawei-health-ci",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise SystemExit(f"查询 GitHub releases 失败（需要网络）：{error}") from error
    if not isinstance(payload, list):
        raise SystemExit("GitHub releases API 返回了非预期结构")
    return payload


def latest_stable_4x(timeout: float = 30.0) -> str:
    """Return the newest stable AstrBot ``v4.x`` release tag."""
    candidates: list[tuple[tuple[int, int, int], str]] = []
    for release in _fetch_releases(RELEASES_API, timeout):
        if release.get("draft") or release.get("prerelease"):
            continue
        tag = str(release.get("tag_name") or "")
        match = TAG_PATTERN.fullmatch(tag)
        if match is None:
            continue
        version = tuple(int(part) for part in match.groups())
        if version[0] != 4:
            continue
        candidates.append((version, tag))
    if not candidates:
        raise SystemExit("没有找到任何稳定的 AstrBot v4.x release")
    return max(candidates)[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="解析 astrbot-runner-contract job 使用的 AstrBot git ref。",
    )
    parser.add_argument(
        "--field",
        choices=("minimum", "latest-stable-4x"),
        required=True,
        help="minimum：取 metadata.yaml 声明下限；latest-stable-4x：取最新稳定 v4.x",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        default=METADATA_FILE,
        help="metadata.yaml 路径（缺省为仓库根）",
    )
    arguments = parser.parse_args(argv)

    if arguments.field == "minimum":
        print(minimum_ref(arguments.metadata))
    else:
        print(latest_stable_4x())
    return 0


if __name__ == "__main__":
    sys.exit(main())
