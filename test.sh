#!/usr/bin/env bash
#
# test.sh - Manual unit-test runner for the upload-security hardening:
#
#   1. Type whitelist + magic byte (content) validation
#   2. Post-upload checksum (integrity) verification
#   3. Safe path handling on file deletion
#
# Usage:
#   ./test.sh                 # run all upload security unit tests
#   ./test.sh security        # same: only the new security test module
#   ./test.sh uploaders       # run the pre-existing uploader tests too
#   ./test.sh all             # run every test under tests/
#   PYTHON=.venv/bin/python ./test.sh
#
set -euo pipefail

cd "$(dirname "$0")"

# Pick a Python interpreter that has the project test dependencies installed.
PYTHON="${PYTHON:-}"
if [[ -z "${PYTHON}" ]]; then
    for candidate in ".venv/bin/python" "python3" "python"; do
        if command -v "${candidate}" >/dev/null 2>&1 \
            && "${candidate}" -c "import flask, boto3, moto, pytest" >/dev/null 2>&1; then
            PYTHON="${candidate}"
            break
        fi
    done
fi

if [[ -z "${PYTHON}" ]]; then
    echo "ERROR: could not find a Python interpreter with flask, boto3, moto and pytest."
    echo "       Install the development requirements first, e.g.:"
    echo "         python3 -m pip install -r requirements.txt -r development.txt"
    echo "       or point this script at an existing virtualenv:"
    echo "         PYTHON=.venv/bin/python ./test.sh"
    exit 1
fi

MODE="${1:-security}"

run() {
    local title="$1"
    shift
    echo
    echo "=================================================================="
    echo "  ${title}"
    echo "  ${PYTHON} -m pytest $*"
    echo "=================================================================="
    "${PYTHON}" -m pytest -v "$@"
}

case "${MODE}" in
    security)
        run "Upload security: type whitelist, integrity, path safety" \
            tests/utils/test_upload_security.py
        ;;
    uploaders)
        run "Uploader tests (filesystem + S3)" \
            tests/utils/test_upload_security.py \
            tests/utils/test_uploaders.py
        ;;
    all)
        run "Full test suite" tests/
        ;;
    *)
        echo "Unknown mode: ${MODE}"
        echo "Usage: ./test.sh [security|uploaders|all]"
        exit 2
        ;;
esac

echo
echo "All requested unit tests finished successfully."
