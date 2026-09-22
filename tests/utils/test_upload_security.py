import hashlib
import os
from io import BytesIO
from unittest.mock import patch

import boto3
import pytest
from moto import mock_s3
from werkzeug.datastructures import FileStorage

from CTFd.models import Files
from CTFd.utils.uploads import delete_file, upload_file
from CTFd.utils.uploads.uploaders import (
    FilesystemUploader,
    S3Uploader,
    UploadIntegrityError,
)
from CTFd.utils.uploads.validators import (
    UploadValidationError,
    detect_mime,
    get_allowed_extensions,
    get_file_extension,
    hash_stream,
    validate_file,
)
from tests.helpers import create_ctfd, destroy_ctfd, gen_file


# Minimal, structurally valid file payloads used across the tests.
PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
ZIP_BYTES = b"PK\x03\x04" + b"\x00" * 64
TEXT_BYTES = b"hello world\nflag{test}\n"
SCRIPT_BYTES = b"<?php system($_GET['cmd']); ?>\n"
ELF_BYTES = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32


def fs(data, name="file.bin"):
    return FileStorage(stream=BytesIO(data), filename=name)


# ---------------------------------------------------------------------------
# Dimension 1: type whitelist + magic byte validation
# ---------------------------------------------------------------------------


class TestFileValidation:
    def test_extension_whitelist_allows_default_types(self):
        assert validate_file(fs(PNG_BYTES, "logo.png"), "logo.png")[0] == "png"
        assert validate_file(fs(TEXT_BYTES, "notes.txt"), "notes.txt")[1] in (
            "text/plain",
            None,
        )

    def test_disallowed_extension_rejected(self):
        with pytest.raises(UploadValidationError, match="not allowed"):
            validate_file(fs(SCRIPT_BYTES, "shell.php"), "shell.php")

    def test_extension_without_magic_match_rejected(self):
        # Real script content renamed to .png: extension is allowed but the
        # magic bytes betray it.
        with pytest.raises(UploadValidationError, match="does not match"):
            validate_file(fs(SCRIPT_BYTES, "shell.png"), "shell.png")

    def test_polyglot_script_renamed_to_zip_rejected(self):
        with pytest.raises(UploadValidationError):
            validate_file(fs(SCRIPT_BYTES, "exploit.zip"), "exploit.zip")

    def test_missing_extension_rejected(self):
        with pytest.raises(UploadValidationError, match="no extension"):
            validate_file(fs(TEXT_BYTES, "README"), "README")

    def test_text_file_with_nul_bytes_rejected(self):
        with pytest.raises(UploadValidationError, match="NUL"):
            validate_file(fs(b"hello\x00world", "notes.txt"), "notes.txt")

    def test_text_file_with_invalid_utf8_rejected(self):
        with pytest.raises(UploadValidationError, match="UTF-8"):
            validate_file(fs(b"\xff\xfe\x80\x81binary", "data.json"), "data.json")

    def test_uppercase_extension_normalized(self):
        assert validate_file(fs(PNG_BYTES, "LOGO.PNG"), "LOGO.PNG")[0] == "png"

    def test_empty_file_rejected(self):
        with pytest.raises(UploadValidationError, match="empty"):
            validate_file(fs(b"", "empty.png"), "empty.png")

    def test_custom_allowed_extensions_argument(self):
        # Caller restricted whitelist: png no longer allowed.
        with pytest.raises(UploadValidationError):
            validate_file(
                fs(PNG_BYTES, "logo.png"),
                "logo.png",
                allowed_extensions={"txt"},
            )

    def test_wildcard_allows_any_extension(self):
        app = create_ctfd()
        with app.app_context():
            from flask import current_app

            current_app.config["UPLOAD_ALLOWED_EXTENSIONS"] = "*"
            assert get_allowed_extensions() == set()
            # Unknown extension: whitelist passes, no magic signature exists so
            # the content check is skipped by design.
            ext, _ = validate_file(fs(b"custom data"), "archive.xyz")
            assert ext == "xyz"
        destroy_ctfd(app)

    def test_detect_mime(self):
        assert detect_mime(PNG_BYTES) == "image/png"
        assert detect_mime(ZIP_BYTES) == "application/zip"
        assert detect_mime(SCRIPT_BYTES) == "text/plain"
        assert detect_mime(b"") is None

    def test_get_file_extension(self):
        assert get_file_extension("a/b.TAR.GZ") == "gz"
        assert get_file_extension("noext") == ""

    def test_hash_stream_rewinds(self):
        stream = BytesIO(b"abc")
        assert hash_stream(stream) == hashlib.sha1(b"abc").hexdigest()
        assert stream.read() == b"abc"


# ---------------------------------------------------------------------------
# Dimension 2: post-upload integrity verification
# ---------------------------------------------------------------------------


class TestIntegrityVerification:
    def test_filesystem_upload_verifies_checksum(self):
        app = create_ctfd()
        with app.app_context():
            uploader = FilesystemUploader()
            stored = uploader.upload(fs(PNG_BYTES, "logo.png"), "logo.png")
            sha1 = hashlib.sha1(PNG_BYTES).hexdigest()
            assert uploader.verify(stored, sha1) is True

            full = uploader._resolve_safe_path(stored)
            with open(full, "wb") as f:
                f.write(PNG_BYTES[:-4])  # truncate: simulate corruption
            with pytest.raises(UploadIntegrityError, match="Checksum mismatch"):
                uploader.verify(stored, sha1)
            os.remove(full)
        destroy_ctfd(app)

    def test_filesystem_verify_missing_file(self):
        app = create_ctfd()
        with app.app_context():
            uploader = FilesystemUploader()
            with pytest.raises(UploadIntegrityError, match="missing"):
                uploader.verify("deadbeef/gone.png", hashlib.sha1(b"x").hexdigest())
        destroy_ctfd(app)

    def test_upload_file_rejects_corrupt_transfer_and_cleans_up(self):
        app = create_ctfd()
        with app.app_context():
            real_verify = FilesystemUploader.verify

            def corrupting_verify(self, filename, expected_hash, algo="sha1"):
                path = self._resolve_safe_path(filename)
                with open(path, "wb") as f:
                    f.write(b"corrupted-bytes-on-wire")
                return real_verify(self, filename, expected_hash, algo)

            with patch.object(
                FilesystemUploader, "verify", corrupting_verify
            ):
                with pytest.raises(UploadIntegrityError):
                    upload_file(file=fs(PNG_BYTES, "logo.png"))

            # Corrupt object must have been deleted...
            assert Files.query.count() == 0
        destroy_ctfd(app)

    def test_upload_file_rejected_before_storage(self):
        app = create_ctfd()
        with app.app_context():
            with pytest.raises(UploadValidationError):
                upload_file(file=fs(SCRIPT_BYTES, "shell.php"))
            assert Files.query.count() == 0
            upload_dir = app.config["UPLOAD_FOLDER"]
            leftovers = [
                os.path.join(root, name)
                for root, _, files in os.walk(upload_dir)
                for name in files
            ]
            assert leftovers == []
        destroy_ctfd(app)

    @mock_s3
    def test_s3_upload_verifies_checksum(self):
        conn = boto3.resource("s3", region_name="test-region")
        conn.create_bucket(
            Bucket="bucket",
            CreateBucketConfiguration={"LocationConstraint": "test-region"},
        )
        app = create_ctfd()
        with app.app_context():
            app.config["UPLOAD_PROVIDER"] = "s3"
            app.config["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"
            app.config["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            app.config["AWS_S3_BUCKET"] = "bucket"
            app.config["AWS_S3_REGION"] = "test-region"

            uploader = S3Uploader()
            stored = uploader.upload(fs(PNG_BYTES, "logo.png"), "logo.png")
            sha1 = hashlib.sha1(PNG_BYTES).hexdigest()
            assert uploader.verify(stored, sha1) is True

            with pytest.raises(UploadIntegrityError):
                uploader.verify(stored, hashlib.sha1(b"different").hexdigest())
        destroy_ctfd(app)

    @mock_s3
    def test_s3_verify_missing_object(self):
        conn = boto3.resource("s3", region_name="test-region")
        conn.create_bucket(
            Bucket="bucket",
            CreateBucketConfiguration={"LocationConstraint": "test-region"},
        )
        app = create_ctfd()
        with app.app_context():
            app.config["UPLOAD_PROVIDER"] = "s3"
            app.config["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"
            app.config["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            app.config["AWS_S3_BUCKET"] = "bucket"
            app.config["AWS_S3_REGION"] = "test-region"

            uploader = S3Uploader()
            with pytest.raises(UploadIntegrityError, match="missing"):
                uploader.verify(
                    "abcd/nonexistent.png", hashlib.sha1(b"x").hexdigest()
                )
        destroy_ctfd(app)


# ---------------------------------------------------------------------------
# Dimension 3: safe path handling on delete
# ---------------------------------------------------------------------------


class TestDeletePathSafety:
    def test_delete_removes_file_and_empty_parent_only(self):
        app = create_ctfd()
        with app.app_context():
            uploader = FilesystemUploader()
            stored = uploader.upload(fs(PNG_BYTES, "logo.png"), "logo.png")
            full = uploader._resolve_safe_path(stored)
            parent = full.parent

            row = gen_file(app.db, location=stored)
            assert delete_file(row.id) is True
            assert not full.exists()
            # The random per-upload parent was pruned.
            assert not parent.exists()
        destroy_ctfd(app)

    def test_delete_keeps_nonempty_parent(self):
        app = create_ctfd()
        with app.app_context():
            uploader = FilesystemUploader()
            stored = uploader.upload(fs(PNG_BYTES, "logo.png"), "logo.png")
            full = uploader._resolve_safe_path(stored)
            sibling = full.parent / "sibling.png"
            with open(sibling, "wb") as f:
                f.write(PNG_BYTES)

            assert uploader.delete(stored) is True
            assert not full.exists()
            assert sibling.exists()  # rmtree must not have wiped the directory
        destroy_ctfd(app)

    def test_delete_plain_filename_without_separator(self):
        app = create_ctfd()
        with app.app_context():
            uploader = FilesystemUploader()
            base = app.config["UPLOAD_FOLDER"]
            # Legacy/location-less value: previously parts[0] == filename and
            # rmtree(base/filename) could delete arbitrary directories.
            target = os.path.join(base, "logo.png")
            with open(target, "wb") as f:
                f.write(PNG_BYTES)
            marker = os.path.join(base, "keep-me.txt")
            with open(marker, "wb") as f:
                f.write(b"keep")

            assert uploader.delete("logo.png") is True
            assert not os.path.exists(target)
            assert os.path.exists(marker)  # base directory survived
        destroy_ctfd(app)

    @pytest.mark.parametrize(
        "evil",
        [
            "../../../etc/passwd",
            "..",
            "/etc/passwd",
            "foo/../../bar.png",
            "foo//bar.png",
            "foo\x00/bar.png",
        ],
    )
    def test_delete_rejects_traversal(self, evil):
        app = create_ctfd()
        with app.app_context():
            uploader = FilesystemUploader()
            assert uploader.delete(evil) is False
        destroy_ctfd(app)

    def test_delete_missing_returns_false(self):
        app = create_ctfd()
        with app.app_context():
            uploader = FilesystemUploader()
            assert uploader.delete("0123abcd/missing.png") is False
        destroy_ctfd(app)

    @mock_s3
    def test_s3_delete_rejects_traversal(self):
        conn = boto3.resource("s3", region_name="test-region")
        conn.create_bucket(
            Bucket="bucket",
            CreateBucketConfiguration={"LocationConstraint": "test-region"},
        )
        app = create_ctfd()
        with app.app_context():
            app.config["UPLOAD_PROVIDER"] = "s3"
            app.config["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"
            app.config["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            app.config["AWS_S3_BUCKET"] = "bucket"
            app.config["AWS_S3_REGION"] = "test-region"

            uploader = S3Uploader()
            assert uploader.delete("../../../etc/passwd") is False
            assert uploader.delete("/abs/key.png") is False
        destroy_ctfd(app)


# ---------------------------------------------------------------------------
# End-to-end through upload_file()
# ---------------------------------------------------------------------------


class TestUploadFileEndToEnd:
    def test_valid_upload_records_checksum(self):
        app = create_ctfd()
        with app.app_context():
            row = upload_file(file=fs(PNG_BYTES, "logo.png"))
            assert row.sha1sum == hashlib.sha1(PNG_BYTES).hexdigest()
            assert row.location.endswith("logo.png")

            stored = Files.query.filter_by(id=row.id).first()
            assert stored is not None
        destroy_ctfd(app)

    def test_location_traversal_rejected(self):
        app = create_ctfd()
        with app.app_context():
            with pytest.raises(ValueError):
                upload_file(
                    file=fs(TEXT_BYTES, "ok.txt"),
                    location="../../escape.txt",
                )
        destroy_ctfd(app)
