#!/usr/bin/env python3
"""Generate the crash command help pages for the documentation site.

The crash binary is the single source of truth for the command help: this
script asks it for the help menu and for each command's help page, then wraps
the text in small HTML pages.

Usage:
    scripts/gen-help-site.py --crash ./crash --out _site
"""
import argparse
import html
import os
import subprocess
import sys

CSS = """
body { font-family: sans-serif; max-width: 60em; margin: 2em auto;
       padding: 0 1em; color: #222; line-height: 1.4; }
h1 { font-size: 1.35em; }
h1 tt, td tt { font-family: monospace; }
pre { background: #f5f5f5; border: 1px solid #ddd; padding: 1em;
      overflow-x: auto; font-size: .9em; line-height: 1.35; }
a { color: #005a9c; }
table.menu { border-collapse: collapse; }
table.menu td { padding: .2em 1.8em .2em 0; white-space: nowrap; }
""".strip()

HELP_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>crash help: {cmd}</title>
<style>{css}</style>
</head>
<body>
<h1>crash utility help page: <tt>{cmd}</tt></h1>
<pre>{text}</pre>
<p><a href="../help.html">&larr; back to the crash help menu</a></p>
</body>
</html>
"""

MENU_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>crash utility help pages</title>
<style>{css}</style>
</head>
<body>
<h1>crash utility help pages</h1>
<p><a href="index.html">&larr; back to the crash documentation</a></p>
<table class="menu">
{rows}
</table>
</body>
</html>
"""


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--crash", required=True, help="path to the crash binary")
    parser.add_argument("--out", required=True, help="output directory")
    args = parser.parse_args()

    crash = os.path.abspath(args.crash)
    out = os.path.abspath(args.out)
    if not os.path.isfile(crash):
        raise SystemExit("no such crash binary: %s" % crash)

    pages_dir = os.path.join(out, "help_pages")
    os.makedirs(pages_dir, exist_ok=True)

    menu_rows = parse_menu(run_help(crash, "commands"))
    commands = [cmd for row in menu_rows for cmd in row]

    table = []
    for row in menu_rows:
        cells = []
        for cmd in row:
            target = "help_pages/%s.html" % page_name(cmd)
            cells.append('<td><a href="%s">%s</a></td>'
                         % (html.escape(target), html.escape(cmd)))
        table.append("<tr>%s</tr>" % "".join(cells))

    with open(os.path.join(out, "help.html"), "w", encoding="utf-8") as f:
        f.write(MENU_PAGE.format(css=CSS, rows="\n".join(table)))

    for cmd in commands:
        text = strip_text(run_help(crash, cmd))
        path = os.path.join(pages_dir, page_name(cmd) + ".html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(HELP_PAGE.format(cmd=html.escape(cmd),
                                     css=CSS,
                                     text=html.escape(text)))
    print("generated help.html and %d help pages in %s"
          % (len(commands), out))


if __name__ == "__main__":
    main()
