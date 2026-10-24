"""Generic release hygiene checks. Device-specific checks run privately outside the repo."""
import argparse
import re
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml", ".txt"}
ROOT_FILES = {"LICENSE", ".gitignore", ".gitattributes", "README.md", "README.en.md",
              "NOTICE.md", "SECURITY.md", "CONTRIBUTING.md", "pyproject.toml"}
SAFE_EMAIL_DOMAINS = {"example.invalid", "example.com", "users.noreply.github.com"}
ALLOWED_PREFIXES = ("src/xiaomi_nas_ssh/", "tests/", "tools/", "docs/", ".github/")


def problems(name, data):
    found = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ["non-text content"]
    if re.search(r"-----BEGIN (?:[A-Z ]+ )?(?:PRIVATE KEY|CERTIFICATE)-----", text):
        found.append("key/certificate material")
    if re.search(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,})", text):
        found.append("credential-shaped token")
    if re.search(r"(?:/Users/[A-Za-z0-9_.-]+|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+)", text):
        found.append("personal home path")
    for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        if email.rsplit("@", 1)[1].lower() not in SAFE_EMAIL_DOMAINS and email.lower() != "noreply@github.com":
            found.append("non-example contact address")
    return sorted(set(found))


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def source_files():
    try:
        if Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() == ROOT:
            return [p.decode() for p in git("ls-files", "-z").split(b"\0") if p]
    except (OSError, subprocess.CalledProcessError):
        pass
    return [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file()
            and not any(x.startswith(".") and x not in {".github", ".gitignore", ".gitattributes"} for x in p.relative_to(ROOT).parts)
            and not any(x in {"__pycache__", "dist", "build"} or x.endswith(".egg-info") for x in p.relative_to(ROOT).parts)]


def check_source():
    errors = []
    files = source_files()
    if not files:
        return [("source", "empty source manifest")], 0
    for name in files:
        path = ROOT / name
        approved = (name in ROOT_FILES or (name.startswith(ALLOWED_PREFIXES) and path.suffix in TEXT_SUFFIXES))
        if not approved or path.is_symlink():
            errors.append((name, "outside source allowlist"))
        for reason in problems(name, path.read_bytes()):
            errors.append((name, reason))
    return errors, len(files)


def check_history():
    errors = []
    count = 0
    objects = git("rev-list", "--objects", "--all").decode().splitlines()
    for line in objects:
        oid = line.split(" ", 1)[0]
        kind = git("cat-file", "-t", oid).strip()
        if kind in (b"blob", b"commit", b"tag"):
            count += 1
            data = git("cat-file", "-p", oid)
            for reason in problems(oid, data):
                errors.append(("git-object", reason))
    return errors, count


def check_archive(path):
    errors = []
    count = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            count += 1
            name = PurePosixPath(member.filename)
            if name.is_absolute() or ".." in name.parts or "\\" in member.filename:
                errors.append((member.filename, "unsafe archive path"))
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                errors.append((member.filename, "archive symlink"))
            for reason in problems(member.filename, archive.read(member)):
                errors.append((member.filename, reason))
    return errors, count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-history", action="store_true")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    errors, count = check_archive(args.archive) if args.archive else check_source()
    if args.git_history:
        extra, n = check_history()
        errors.extend(extra)
        count += n
    if errors:
        for name, reason in errors:
            print(f"FAIL {name}: {reason}", file=sys.stderr)
        return 1
    print(f"Release hygiene passed: {count} text files/objects checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
