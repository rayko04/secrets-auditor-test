"""
audit.py
--------
Scans a git repository for hardcoded secrets using three tools:
  1. truffleHog     - scans git commit history (entropy + regex)
  2. gitleaks       - scans git commit history (rule-based)
  3. detect-secrets - scans current files in the repo

Output: results.json saved inside the scanned repo folder.

USAGE:
  python audit.py                        # scan current folder
  python audit.py --path /path/to/repo   # scan a specific repo

REQUIREMENTS:
  Arch Linux:
    trufflehog     -> yay -S trufflehog
    gitleaks       -> sudo pacman -S gitleaks
    detect-secrets -> pip install detect-secrets  (Python library, not CLI)

  Windows:
    trufflehog     -> download from https://github.com/trufflesecurity/trufflehog/releases
    gitleaks       -> download from https://github.com/gitleaks/gitleaks/releases
    detect-secrets -> pip install detect-secrets
"""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


# ─── Tool 1: truffleHog ──────────────────────────────────────────────────────
# Scans every git commit looking for high-entropy strings and regex matches.
# Uses trufflehog v2 CLI: trufflehog --json --regex <repo_path>

def run_trufflehog(repo_path):
    if not shutil.which("trufflehog"):
        return [], "not found on PATH"

    if not (Path(repo_path) / ".git").exists():
        return [], "not a git repository"

    try:
        result = subprocess.run(
            ["trufflehog", "--json", "--regex", repo_path],
            capture_output=True,
            text=True,
            timeout=120,
        )

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Pull added lines from the diff as the snippet
            added = [
                l[1:].strip()
                for l in item.get("diff", "").splitlines()
                if l.startswith("+") and not l.startswith("+++")
            ]

            findings.append({
                "file":    item.get("path", "unknown"),
                "commit":  item.get("commitHash", "")[:12],
                "reason":  item.get("reason", ""),
                "snippet": " | ".join(added)[:150],
            })

        return findings, None

    except Exception as e:
        return [], str(e)


# ─── Tool 2: gitleaks ────────────────────────────────────────────────────────
# Scans git history with a large built-in ruleset (AWS, Slack, GitHub, etc.)
# Uses CLI: gitleaks git --source <repo> --report-format json

def run_gitleaks(repo_path):
    if not shutil.which("gitleaks"):
        return [], "not found on PATH"

    if not (Path(repo_path) / ".git").exists():
        return [], "not a git repository"

    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()

    try:
        subprocess.run(
            [
                "gitleaks", "git",
                "--source", repo_path,
                "--report-format", "json",
                "--report-path", tmp.name,
                "--no-banner",
                "--exit-code", "0",
            ],
            capture_output=True,
            timeout=120,
            cwd=repo_path,
        )

        content = Path(tmp.name).read_text(encoding="utf-8").strip()
        if not content or content == "null":
            return [], None

        findings = []
        for item in json.loads(content):
            findings.append({
                "file":    item.get("File", "unknown"),
                "commit":  (item.get("Commit") or "")[:12],
                "reason":  item.get("RuleID", ""),
                "snippet": (item.get("Secret") or item.get("Match") or "")[:150],
            })
        return findings, None

    except Exception as e:
        return [], str(e)
    finally:
        os.unlink(tmp.name)


# ─── Tool 3: detect-secrets ──────────────────────────────────────────────────
# Scans actual files in the repo using its Python API.
# We use the API (not CLI) because the CLI in v1.5+ filters out unverified
# secrets by default, which causes 0 findings even when secrets exist.

def run_detect_secrets(repo_path):
    try:
        from detect_secrets import SecretsCollection
        from detect_secrets.settings import default_settings
    except ImportError:
        return [], "not installed — run: pip install detect-secrets"

    findings = []

    try:
        with default_settings():
            secrets = SecretsCollection()

            for root, dirs, files in os.walk(repo_path):
                # Skip git internals and common non-source folders
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        secrets.scan_file(fpath)
                    except Exception:
                        continue

            for file_path, secret_list in secrets.json().items():
                for s in secret_list:
                    findings.append({
                        "file":    file_path,
                        "line":    s.get("line_number"),
                        "reason":  s.get("type", ""),
                        "snippet": "[value redacted]",
                    })

    except Exception as e:
        return [], str(e)

    return findings, None


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scan a repo for hardcoded secrets.")
    parser.add_argument("--path", default=".", help="Path to the repo (default: current folder)")
    args = parser.parse_args()

    repo = str(Path(args.path).resolve())
    print(f"Scanning: {repo}\n")

    results = {}

    for tool_name, tool_fn in [
        ("truffleHog",     run_trufflehog),
        ("gitleaks",       run_gitleaks),
        ("detect-secrets", run_detect_secrets),
    ]:
        print(f"  Running {tool_name}...", end=" ", flush=True)
        findings, error = tool_fn(repo)

        if error:
            print(f"skipped ({error})")
        else:
            print(f"{len(findings)} finding(s)")

        results[tool_name] = {
            "findings": findings,
            "error":    error or "",
        }

    output_path = Path(repo) / "results.json"
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    total = sum(len(v["findings"]) for v in results.values())
    print(f"\nDone. {total} total finding(s) -> {output_path}")


if __name__ == "__main__":
    main()
