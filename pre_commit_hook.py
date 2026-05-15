"""
pre_commit_hook.py
------------------
Git runs this automatically before every commit.
Scans only the staged files using detect-secrets Python API.
Blocks the commit if any secrets are found.

Install with: python install_hook.py
Requires:     pip install detect-secrets
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".env", ".cfg",
    ".ini", ".yaml", ".yml", ".json", ".toml", ".sh",
}


def get_staged_files():
    r = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True,
    )
    return r.stdout.strip().splitlines()


def get_file_content_as_staged(filepath):
    r = subprocess.run(["git", "show", f":{filepath}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def main():
    try:
        from detect_secrets import SecretsCollection
        from detect_secrets.settings import default_settings
    except ImportError:
        print("[hook] detect-secrets not installed, skipping. Run: pip install detect-secrets")
        sys.exit(0)

    staged_files = get_staged_files()
    if not staged_files:
        sys.exit(0)

    all_findings = []

    for filepath in staged_files:
        ext = Path(filepath).suffix.lower()
        name = Path(filepath).name
        if ext not in SCANNABLE_EXTENSIONS and not name.startswith(".env"):
            continue

        content = get_file_content_as_staged(filepath)
        if not content:
            continue

        # Write staged content to a temp file and scan it
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext or ".txt",
            delete=False, encoding="utf-8",
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            with default_settings():
                secrets = SecretsCollection()
                secrets.scan_file(tmp_path)
                for secret_list in secrets.json().values():
                    for s in secret_list:
                        all_findings.append({
                            "file": filepath,
                            "line": s.get("line_number"),
                            "type": s.get("type"),
                        })
        except Exception:
            pass
        finally:
            os.unlink(tmp_path)

    if not all_findings:
        print("[hook] No secrets found in staged files.")
        sys.exit(0)

    print("\n[hook] COMMIT BLOCKED — secrets detected:\n")
    for f in all_findings:
        print(f"  {f['type']}  ->  {f['file']} line {f['line']}")
    print("\nRemove the secrets and use environment variables instead.\n")
    sys.exit(1)


if __name__ == "__main__":
    main()
