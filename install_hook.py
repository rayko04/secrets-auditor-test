"""
install_hook.py
---------------
Installs the pre-commit hook into your git repo.
Run this once from inside your repo.

Usage: python install_hook.py
"""

import stat
import sys
from pathlib import Path


def find_git_root():
    current = Path.cwd().resolve()
    while True:
        if (current / ".git").is_dir():
            return current
        if current.parent == current:
            return None
        current = current.parent


def main():
    root = find_git_root()
    if not root:
        print("Error: not inside a git repository.")
        sys.exit(1)

    hook_script = Path(__file__).parent.resolve() / "pre_commit_hook.py"
    dest = root / ".git" / "hooks" / "pre-commit"

    if sys.platform == "win32":
        # Windows: write a .cmd file that calls Python
        dest_cmd = root / ".git" / "hooks" / "pre-commit.cmd"
        dest_cmd.write_text(f'@echo off\npython "{hook_script}" %*\n', encoding="utf-8")
        print(f"Installed (Windows): {dest_cmd}")
    else:
        # Linux/macOS: write a bash script that calls Python
        dest.write_text(
            f'#!/bin/sh\nexec python3 "{hook_script}" "$@"\n',
            encoding="utf-8"
        )
        dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        print(f"Installed (Linux/macOS): {dest}")

    print("Done. The hook will now run before every git commit.")


if __name__ == "__main__":
    main()
