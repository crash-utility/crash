#!/usr/bin/env python3
"""Generate the crash changelog from the git log.

Each tagged release gets a section with the commits since the previous
tag, followed by the unreleased changes.

Usage:
    scripts/gen-changelog.py --repo . --out doc/changelog.rst
"""
import argparse
import os
import re
import subprocess
import sys


def git(repo, *args):
    result = subprocess.run(["git"] + list(args), cwd=repo,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
        raise SystemExit("failed to run: git %s" % " ".join(args))
    return result.stdout.decode("utf-8", "replace")


def esc(text):
    text = text.replace("\\", "\\\\")
    return re.sub(r"([*`|_])", r"\\\1", text)


def version(tag):
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", tag)
    return tuple(int(x) for x in match.groups()) if match else (0, 0, 0)


def entries(repo, rev):
    out = git(repo, "log", "--no-merges", "--date=short",
              "--pretty=format:%ad  %an  %s", rev)
    return [line for line in out.splitlines() if line.strip()]


def section(title, lines, out):
    out.append(title)
    out.append("-" * len(title))
    out.append("")
    for line in lines:
        out.append("* " + esc(line))
    out.append("")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".", help="crash git repository")
    parser.add_argument("--out", required=True, help="output RST file")
    args = parser.parse_args()

    repo = os.path.abspath(args.repo)
    tags = git(repo, "tag", "--sort=creatordate").split()
    tags = [tag for tag in tags if version(tag) > (0, 0, 0)]

    parts = []
    if tags:
        section("unreleased", entries(repo, "%s..HEAD" % tags[-1]), parts)
    for i in range(len(tags) - 1, -1, -1):
        tag = tags[i]
        rev = tag if i == 0 else "%s..%s" % (tags[i - 1], tag)
        section(tag, entries(repo, rev), parts)

    header = [
        "Crash changelog",
        "=" * len("Crash changelog"),
        "",
    ]
    text = "\n".join(header + parts).rstrip() + "\n"
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    count = len(tags) + 1 if tags else 0
    print("generated %s (%d releases)" % (args.out, count))


if __name__ == "__main__":
    main()
