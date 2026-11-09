#!/usr/bin/env python3
"""Generate the crash command help pages as Sphinx sources.

The crash binary is the single source of truth for the command help: this
script asks it for the help menu and for each command's help page, then
writes an index page (the command list, used as the toctree) and one RST
page per command.

Usage:
    scripts/gen-help-rst.py --crash ./crash --out doc/help
"""
import argparse
import os
import subprocess
import sys


def run_help(crash, what):
    """Return the text of "crash -h <what>"."""
    cmd = [crash, "--no_scroll", "--no_crashrc", "-h", what]
    result = subprocess.run(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
        raise SystemExit("failed to run: %s" % " ".join(cmd))
    return result.stdout.decode("utf-8", "replace")


def parse_menu(text):
    """Split the "help commands" output (names, with BREAK row markers)."""
    rows = []
    row = []
    for line in text.splitlines():
        line = line.strip()
        if line == "BREAK":
            if row:
                rows.append(row)
                row = []
        elif line:
            row.append(line)
    if row:
        rows.append(row)
    return rows


def page_name(cmd):
    if cmd == "*":
        return "pointer"
    return cmd


def strip_text(text):
    lines = text.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def literal(text):
    return "\n".join("   " + line if line.strip() else ""
                     for line in text.split("\n"))


def write_page(path, cmd, text):
    title = page_name(cmd)
    body = [title, "=" * len(title), "", "::", "", literal(text), ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(body))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--crash", required=True, help="path to the crash binary")
    parser.add_argument("--out", required=True, help="output directory")
    args = parser.parse_args()

    crash = os.path.abspath(args.crash)
    out = os.path.abspath(args.out)
    if not os.path.isfile(crash):
        raise SystemExit("no such crash binary: %s" % crash)
    os.makedirs(out, exist_ok=True)

    menu_rows = parse_menu(run_help(crash, "commands"))
    commands = [cmd for row in menu_rows for cmd in row]

    entries = []
    for cmd in commands:
        name = page_name(cmd)
        write_page(os.path.join(out, name + ".rst"), cmd,
                   strip_text(run_help(crash, cmd)))
        entries.append(name)

    index = ["Crash command help", "=" * len("crash command help"), "",
             ".. toctree::", "   :maxdepth: 1", ""]
    index += ["   " + e for e in entries]
    index.append("")
    with open(os.path.join(out, "index.rst"), "w", encoding="utf-8") as f:
        f.write("\n".join(index))

    print("generated %d help pages in %s" % (len(entries), out))


if __name__ == "__main__":
    main()
