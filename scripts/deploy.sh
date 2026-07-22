#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

ACTION="${1:-help}"
ARGUMENT="${2:-}"

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

TOKEN_FILE="${AIDAC_TOKEN_FILE:-$HOME/.config/aidac/publish.env}"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON="$ROOT/.venv/bin/python"
else
    PYTHON="$(command -v python3 || true)"
fi

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '\n==> %s\n' "$*"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 ||
        die "Required command not found: $1"
}

[[ -n "$PYTHON" ]] || die "Python 3 was not found."

mapfile -t PROJECT_METADATA < <(
    "$PYTHON" - <<'PY'
import tomllib
from pathlib import Path

with Path("pyproject.toml").open("rb") as stream:
    project = tomllib.load(stream)["project"]

print(project["name"])
print(project["version"])
PY
)

PACKAGE_NAME="${PROJECT_METADATA[0]}"
VERSION="${PROJECT_METADATA[1]}"
TAG="v${VERSION}"

cleanup_secrets() {
    unset TESTPYPI_TOKEN PYPI_TOKEN TWINE_USERNAME TWINE_PASSWORD
}

trap cleanup_secrets EXIT

show_help() {
    cat <<EOF
AI-DAC deployment utility

Usage:
  ./scripts/deploy.sh configure
  ./scripts/deploy.sh bump VERSION
  ./scripts/deploy.sh verify
  ./scripts/deploy.sh github
  ./scripts/deploy.sh testpypi
  ./scripts/deploy.sh pypi
  ./scripts/deploy.sh all-test
  ./scripts/deploy.sh all

Commands:
  configure  Store TestPyPI/PyPI tokens outside the repository
  bump       Change the package version
  verify     Run tests, quality checks and build distributions
  github     Verify, push Git and create/update the GitHub release
  testpypi   Verify, build and publish to TestPyPI
  pypi       Verify, build and publish to production PyPI
  all-test   GitHub push, GitHub release and TestPyPI publication
  all        GitHub, TestPyPI and production PyPI publication

Current package: ${PACKAGE_NAME}
Current version: ${VERSION}
EOF
}

configure_tokens() {
    local test_token
    local production_token

    mkdir -p "$(dirname "$TOKEN_FILE")"
    umask 077

    printf 'Tokens will be stored outside Git at:\n%s\n\n' "$TOKEN_FILE"

    read -rsp "Paste the TestPyPI token: " test_token
    printf '\n'

    [[ "$test_token" == pypi-* ]] ||
        die "The TestPyPI token must start with pypi-."

    read -rsp \
        "Paste the production PyPI token, or press Enter to skip: " \
        production_token
    printf '\n'

    if [[ -n "$production_token" && "$production_token" != pypi-* ]]; then
        die "The production PyPI token must start with pypi-."
    fi

    {
        printf 'TESTPYPI_TOKEN=%q\n' "$test_token"
        printf 'PYPI_TOKEN=%q\n' "$production_token"
    } > "$TOKEN_FILE"

    chmod 600 "$TOKEN_FILE"

    unset test_token production_token

    info "Token configuration saved with permission 600."
}

load_tokens() {
    [[ -f "$TOKEN_FILE" ]] ||
        die "Token configuration missing. Run: ./scripts/deploy.sh configure"

    chmod 600 "$TOKEN_FILE"

    # The file is controlled by the current user and protected with mode 600.
    # shellcheck disable=SC1090
    source "$TOKEN_FILE"
}

bump_version() {
    local new_version="$1"

    [[ -n "$new_version" ]] ||
        die "Usage: ./scripts/deploy.sh bump 0.1.1"

    [[ "$new_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.]+)?$ ]] ||
        die "Invalid version format: $new_version"

    "$PYTHON" - "$new_version" <<'PY'
import re
import sys
from pathlib import Path

new_version = sys.argv[1]

pyproject = Path("pyproject.toml")
text = pyproject.read_text(encoding="utf-8")
updated, count = re.subn(
    r'(?m)^version\s*=\s*"[^"]+"\s*$',
    f'version = "{new_version}"',
    text,
    count=1,
)

if count != 1:
    raise SystemExit("Could not update project.version in pyproject.toml")

pyproject.write_text(updated, encoding="utf-8")

init_file = Path("src/aidac/__init__.py")
if init_file.exists():
    init_text = init_file.read_text(encoding="utf-8")
    init_updated, init_count = re.subn(
        r'(?m)^__version__\s*=\s*"[^"]+"\s*$',
        f'__version__ = "{new_version}"',
        init_text,
        count=1,
    )

    if init_count == 1:
        init_file.write_text(init_updated.rstrip() + "\n", encoding="utf-8")

print(f"Version updated to {new_version}")
PY

    info "Review the modifications, then commit them before deployment."
    git diff -- pyproject.toml src/aidac/__init__.py
}

verify_and_build() {
    info "Installing deployment tools"

    "$PYTHON" -m pip install --quiet --upgrade \
        -e ".[api]" \
        build \
        twine \
        ruff \
        mypy \
        pytest \
        pytest-cov

    info "Checking source code"

    "$PYTHON" -m ruff check .
    "$PYTHON" -m ruff format --check .
    "$PYTHON" -m mypy src

    local test_home
    test_home="$(mktemp -d)"
    env \
        -u AIDAC_API_TOKEN \
        -u AIDAC_API_VIEWER_TOKEN \
        -u AIDAC_API_ANALYST_TOKEN \
        -u AIDAC_API_ADMIN_TOKEN \
        -u AIDAC_DASHBOARD_TOKEN \
        -u AIDAC_ALERT_STORE_DSN \
        -u AIDAC_ALERT_STORE_SCHEMA \
        HOME="$test_home" \
        "$PYTHON" -m pytest -v
    rm -rf "$test_home"

    if [[ ! -s README.md ]]; then
        printf 'WARNING: README.md is empty; package metadata will be incomplete.\n'
    fi

    info "Building clean distributions"

    rm -rf build dist
    find src -maxdepth 1 -type d -name '*.egg-info' -exec rm -rf {} +

    "$PYTHON" -m build

    info "Checking distributions"

    "$PYTHON" -m twine check dist/*

    ls -lh dist/
}

check_staged_secrets() {
    if git diff --cached -U0 |
        grep -E \
            'pypi-[A-Za-z0-9_-]{20,}|github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+' \
            >/dev/null; then
        git reset
        die "A possible token was detected in staged files. Commit cancelled."
    fi
}

commit_if_needed() {
    local answer
    local commit_message

    if [[ -z "$(git status --porcelain)" ]]; then
        return
    fi

    info "Uncommitted modifications detected"
    git status --short

    read -r -p "Commit all these modifications? [y/N] " answer

    [[ "$answer" =~ ^[Yy]$ ]] ||
        die "Deployment stopped because the working tree is not clean."

    read -r -p "Commit message: " commit_message
    [[ -n "$commit_message" ]] || die "Commit message cannot be empty."

    git add -A
    check_staged_secrets
    git commit -m "$commit_message"
}

push_github() {
    local branch
    local head_commit
    local tag_commit

    require_command git
    require_command gh

    gh auth status --hostname github.com >/dev/null ||
        die "GitHub CLI is not authenticated."

    gh auth setup-git >/dev/null

    commit_if_needed

    branch="$(git branch --show-current)"
    [[ -n "$branch" ]] || die "Detached Git HEAD is not supported."

    info "Pushing branch ${branch}"
    git push -u origin "$branch"

    head_commit="$(git rev-parse HEAD)"

    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        tag_commit="$(git rev-list -n 1 "$TAG")"

        if [[ "$tag_commit" != "$head_commit" ]]; then
            die \
                "Tag $TAG already points to another commit. " \
                "Increase the package version before publishing."
        fi
    else
        git tag -a "$TAG" -m "${PACKAGE_NAME} ${VERSION}"
    fi

    info "Pushing tag ${TAG}"
    git push origin "$TAG"
}

publish_github_release() {
    require_command gh

    if gh release view "$TAG" >/dev/null 2>&1; then
        info "Updating existing GitHub release ${TAG}"
        gh release upload "$TAG" dist/* --clobber
    else
        info "Creating GitHub release ${TAG}"
        gh release create "$TAG" \
            dist/* \
            --title "AI-DAC Python Library ${TAG}" \
            --generate-notes \
            --latest
    fi
}

publish_testpypi() {
    load_tokens

    [[ "${TESTPYPI_TOKEN:-}" == pypi-* ]] ||
        die "A valid TestPyPI token is not configured."

    info "Publishing ${PACKAGE_NAME} ${VERSION} to TestPyPI"

    TWINE_USERNAME="__token__" \
    TWINE_PASSWORD="$TESTPYPI_TOKEN" \
        "$PYTHON" -m twine upload \
            --repository testpypi \
            --non-interactive \
            dist/*
}

publish_pypi() {
    local expected
    local confirmation

    load_tokens

    [[ "${PYPI_TOKEN:-}" == pypi-* ]] ||
        die "A production PyPI token is not configured."

    expected="PUBLISH ${PACKAGE_NAME} ${VERSION} TO PYPI"

    printf '\nProduction publication is irreversible.\n'
    printf 'Type exactly: %s\n' "$expected"
    read -r confirmation

    [[ "$confirmation" == "$expected" ]] ||
        die "Production publication cancelled."

    info "Publishing ${PACKAGE_NAME} ${VERSION} to production PyPI"

    TWINE_USERNAME="__token__" \
    TWINE_PASSWORD="$PYPI_TOKEN" \
        "$PYTHON" -m twine upload \
            --repository pypi \
            --non-interactive \
            dist/*
}

case "$ACTION" in
    configure)
        configure_tokens
        ;;

    bump)
        bump_version "$ARGUMENT"
        ;;

    verify)
        verify_and_build
        ;;

    github)
        verify_and_build
        push_github
        publish_github_release
        ;;

    testpypi)
        verify_and_build
        publish_testpypi
        ;;

    pypi)
        verify_and_build
        publish_pypi
        ;;

    all-test)
        verify_and_build
        push_github
        publish_github_release
        publish_testpypi
        ;;

    all)
        verify_and_build
        push_github
        publish_github_release
        publish_testpypi
        publish_pypi
        ;;

    help|-h|--help)
        show_help
        ;;

    *)
        show_help
        die "Unknown action: $ACTION"
        ;;
esac