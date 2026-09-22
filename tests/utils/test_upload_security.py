import os
from io import BytesIO

import pytest
from werkzeug.datastructures import FileStorage

from CTFd.models import Files
from CTFd.utils.uploads import hash_file, rmdir, upload_file
from CTFd.utils.uploads.uploaders import FilesystemUploader
from tests.helpers import create_ctfd, destroy_ctfd

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def make_file(content, filename):
    return FileStorage(stream=BytesIO(content), filename=filename)


def test_upload_file_rejects_disallowed_extension():
    """Files with extensions outside the whitelist should be rejected"""
    app = create_ctfd()
    with app.app_context():
        for filename in ("shell.php", "evil.exe", "payload.sh", "noextension"):
            with pytest.raises(ValueError):
                upload_file(file=make_file(b"harmless text", filename))
        assert Files.query.count() == 0
    destroy_ctfd(app)


def test_upload_file_rejects_dangerous_content():
    """Executable/script content should be rejected regardless of extension"""
    app = create_ctfd()
    with app.app_context():
        payloads = [
            b"#!/bin/bash\nrm -rf /\n",
            b"\x7fELF" + b"\x00" * 64,
            b"MZ" + b"\x90" * 64,
            b"<?php system($_GET['cmd']); ?>",
        ]
        for payload in payloads:
            with pytest.raises(ValueError):
                upload_file(file=make_file(payload, "innocent.txt"))
        assert Files.query.count() == 0
    destroy_ctfd(app)


def test_upload_file_rejects_extension_mismatch():
    """Content must match the magic bytes of the claimed extension"""
    app = create_ctfd()
    with app.app_context():
        with pytest.raises(ValueError):
            upload_file(file=make_file(b"definitely not a png", "fake.png"))
        assert Files.query.count() == 0
    destroy_ctfd(app)


def test_upload_file_accepts_valid_file():
    """Valid whitelisted files with matching content should upload"""
    app = create_ctfd()
    with app.app_context():
        f = upload_file(file=make_file(PNG_BYTES, "real.png"))
        try:
            assert f.sha1sum == hash_file(fp=make_file(PNG_BYTES, "real.png"))
            full_path = os.path.join(app.config["UPLOAD_FOLDER"], f.location)
            with open(full_path, "rb") as stored:
                assert stored.read() == PNG_BYTES
        finally:
            rmdir(os.path.join(app.config["UPLOAD_FOLDER"], f.location.split("/")[0]))
    destroy_ctfd(app)


def test_upload_file_allowed_extensions_override():
    """UPLOAD_ALLOWED_EXTENSIONS config should override the default whitelist"""
    app = create_ctfd()
    with app.app_context():
        app.config["UPLOAD_ALLOWED_EXTENSIONS"] = {"txt"}
        with pytest.raises(ValueError):
            upload_file(file=make_file(PNG_BYTES, "real.png"))
        f = upload_file(file=make_file(b"plain text", "notes.txt"))
        try:
            assert f.id
        finally:
            rmdir(os.path.join(app.config["UPLOAD_FOLDER"], f.location.split("/")[0]))
    destroy_ctfd(app)


def test_upload_file_integrity_verification(monkeypatch):
    """Uploads whose stored content differs from the pre-upload hash are rejected"""
    app = create_ctfd()
    with app.app_context():
        upload_folder = app.config["UPLOAD_FOLDER"]
        if os.path.isdir(upload_folder):
            preexisting = set(os.listdir(upload_folder))
        else:
            preexisting = set()

        def corrupt_store(self, fileobj, filename):
            fileobj.read()
            location = os.path.join(self.base_path, filename)
            os.makedirs(os.path.dirname(location), exist_ok=True)
            with open(location, "wb") as dst:
                dst.write(b"corrupted bits")
            return filename

        monkeypatch.setattr(FilesystemUploader, "store", corrupt_store)

        with pytest.raises(ValueError):
            upload_file(file=make_file(b"original content", "data.txt"))

        # The corrupted file must not be recorded or left on disk
        assert Files.query.count() == 0
        if os.path.isdir(upload_folder):
            assert set(os.listdir(upload_folder)) == preexisting
    destroy_ctfd(app)


def test_filesystem_delete_rejects_unsafe_paths(tmp_path):
    """Absolute paths and traversal attempts must be rejected"""
    uploader = FilesystemUploader(base_path=str(tmp_path))
    outside = tmp_path.parent / "outside.txt"
    outside.write_bytes(b"outside")
    try:
        with pytest.raises(ValueError):
            uploader.delete("../outside.txt")
        with pytest.raises(ValueError):
            uploader.delete("/etc/passwd")
        assert outside.read_bytes() == b"outside"
    finally:
        outside.unlink()


def test_filesystem_delete_only_removes_target_file(tmp_path):
    """Deleting a file must not remove unrelated files or directories"""
    uploader = FilesystemUploader(base_path=str(tmp_path))

    target_dir = tmp_path / "dir_a"
    target_dir.mkdir()
    target = target_dir / "file.txt"
    target.write_bytes(b"target")

    keep_dir = tmp_path / "dir_b"
    keep_dir.mkdir()
    keep = keep_dir / "keep.txt"
    keep.write_bytes(b"keep")

    assert uploader.delete("dir_a/file.txt") is True
    assert not target.exists()
    # The now-empty containing directory is cleaned up
    assert not target_dir.exists()
    # Unrelated files and directories are untouched
    assert keep.read_bytes() == b"keep"
    assert keep_dir.is_dir()

    # A file stored directly in the upload folder is removed by itself
    loose = tmp_path / "loose.txt"
    loose.write_bytes(b"loose")
    assert uploader.delete("loose.txt") is True
    assert not loose.exists()
    assert tmp_path.is_dir()

    # Deleting a missing file returns False
    assert uploader.delete("dir_a/file.txt") is False
