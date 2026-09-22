#!/usr/bin/env bash
# Runs the unit tests covering the upload hardening changes:
#   1. File type whitelist + magic byte validation
#   2. Post-upload integrity verification
#   3. Safe path handling in FilesystemUploader.delete
#
# Usage:
#   ./test.sh            # run all upload-related unit tests
#   ./test.sh -k delete  # pass extra args through to pytest
set -euo pipefail

cd "$(dirname "$0")"

pytest -v \
    tests/utils/test_upload_security.py \
    tests/utils/test_uploaders.py \
    tests/api/v1/test_files.py \
    "$@"
