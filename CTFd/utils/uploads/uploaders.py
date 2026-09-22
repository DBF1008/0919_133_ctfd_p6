import datetime
import hashlib
import os
import posixpath
import string
import time
from pathlib import Path, PurePath
from shutil import copyfileobj
from urllib.parse import urlparse

import boto3
from botocore.client import Config
from flask import current_app, redirect, send_file
from freezegun import freeze_time
from werkzeug.utils import safe_join, secure_filename

from CTFd.utils import get_app_config
from CTFd.utils.encoding import hexencode
from CTFd.utils.uploads.validators import (
    UploadValidationError,
    hash_stream,
    validate_file,
)


class UploadIntegrityError(Exception):
    """
    Raised when a file read back from the storage backend does not match the
    hash computed before upload (bit flips / truncation during transfer).
    """


class BaseUploader(object):
    def __init__(self):
        """
        Initialize the uploader with any required information
        """
        raise NotImplementedError

    def store(self, fileobj, filename):
        """
        Directly store a file object at the specified filename
        """
        raise NotImplementedError

    def upload(self, file_obj, filename):
        """
        Upload a file while handling any security protections or file renaming
        """
        raise NotImplementedError

    def download(self, filename):
        """
        Generate a Flask response to download the requested file
        """
        raise NotImplementedError

    def delete(self, filename):
        """
        Delete an uploaded file from the file store
        """
        raise NotImplementedError

    def verify(self, filename, expected_hash, algo="sha1"):
        """
        Read the stored file back and verify that its digest matches
        `expected_hash`. Returns True on match, otherwise raises
        UploadIntegrityError.
        """
        raise NotImplementedError

    def sync(self):
        """
        Download all remotely hosted files for the purpose of exporting
        """
        raise NotImplementedError

    def open(self, mode="rb"):
        """
        Return a file pointer for an uploaded file.
        In the case of remotely hosted files, download the target file and then
        return the file pointer for the local copy.
        """
        raise NotImplementedError


class FilesystemUploader(BaseUploader):
    def __init__(self, base_path=None):
        super(BaseUploader, self).__init__()
        self.base_path = base_path or current_app.config.get("UPLOAD_FOLDER")

    def _resolve_safe_path(self, filename):
        """
        Resolve `filename` inside the upload base directory, rejecting any
        traversal attempts (absolute paths, "..", embedded NUL bytes).
        Returns the absolute filesystem path or None if it is unsafe.
        """
        if not filename or "\x00" in filename:
            return None
        # Reject any empty ("a//b") or ".." path components before
        # normalization, since normalization would otherwise hide them.
        raw_parts = filename.replace("\\", "/").split("/")
        if any(part in ("", "..") for part in raw_parts):
            return None
        # PurePath splits a normalized relative path into safe components.
        parts = PurePath(posixpath.normpath(filename)).parts
        if not parts or parts[0] == "/" or ".." in parts:
            return None
        path = safe_join(self.base_path, *parts)
        if path is None:
            return None
        base = Path(self.base_path).resolve()
        resolved = Path(path).resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            return None
        return resolved

    def store(self, fileobj, filename):
        location = os.path.join(self.base_path, filename)
        directory = os.path.dirname(location)

        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(location, "wb") as dst:
            copyfileobj(fileobj, dst, 16384)

        return filename

    def upload(self, file_obj, filename, path=None):
        if len(filename) == 0:
            raise Exception("Empty filenames cannot be used")

        # Content-based validation: the stream's magic bytes must agree with
        # the claimed extension so renaming a script cannot bypass the check.
        validate_file(file_obj, filename)

        # Sanitize directory name
        if path:
            path = secure_filename(path) or hexencode(os.urandom(16))
            path = path.replace(".", "")
        else:
            path = hexencode(os.urandom(16))

        # Sanitize file name
        filename = secure_filename(filename)
        if not filename:
            raise UploadValidationError("Filename was reduced to empty by sanitization")
        file_path = posixpath.join(path, filename)

        return self.store(file_obj, file_path)

    def download(self, filename):
        return send_file(safe_join(self.base_path, filename), as_attachment=True)

    def delete(self, filename):
        file_path = self._resolve_safe_path(filename)
        if file_path is None or not file_path.exists():
            return False
        if not file_path.is_file():
            # Never rmtree an unexpected target.
            return False

        file_path.unlink()

        # Only the single random per-upload parent directory is removed, and
        # only when it is a direct, empty child of the upload base directory.
        base = Path(self.base_path).resolve()
        parent = file_path.parent.resolve()
        if parent != base and parent.parent == base:
            try:
                parent.rmdir()
            except OSError:
                # Directory is not empty (or otherwise cannot be removed):
                # leave it in place.
                pass
        return True

    def verify(self, filename, expected_hash, algo="sha1"):
        file_path = self._resolve_safe_path(filename)
        if file_path is None or not file_path.is_file():
            raise UploadIntegrityError(
                "Uploaded file {} is missing after upload".format(filename)
            )
        with file_path.open("rb") as fp:
            actual_hash = hash_stream(fp, algo=algo)
        if actual_hash != expected_hash:
            raise UploadIntegrityError(
                "Checksum mismatch for {}: expected {}, got {}".format(
                    filename, expected_hash, actual_hash
                )
            )
        return True

    def sync(self):
        pass

    def open(self, filename, mode="rb"):
        path = self._resolve_safe_path(filename)
        if path is None:
            raise UploadValidationError("Invalid file path: {}".format(filename))
        return path.open(mode=mode)


class S3Uploader(BaseUploader):
    def __init__(self):
        super(BaseUploader, self).__init__()
        self.s3 = self._get_s3_connection()
        self.bucket = get_app_config("AWS_S3_BUCKET")
        # If the custom prefix is provided, add a slash if it's missing
        custom_prefix = get_app_config("AWS_S3_CUSTOM_PREFIX")
        if custom_prefix and custom_prefix.endswith("/") is False:
            custom_prefix += "/"
        self.s3_prefix: str = custom_prefix

    def _get_s3_connection(self):
        access_key = get_app_config("AWS_ACCESS_KEY_ID")
        secret_key = get_app_config("AWS_SECRET_ACCESS_KEY")
        endpoint = get_app_config("AWS_S3_ENDPOINT_URL")
        region = get_app_config("AWS_S3_REGION")
        addressing_style = get_app_config("AWS_S3_ADDRESSING_STYLE")
        client = boto3.client(
            "s3",
            config=Config(
                signature_version="s3v4", s3={"addressing_style": addressing_style}
            ),
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            endpoint_url=endpoint,
            region_name=region,
        )
        return client

    def _clean_filename(self, c):
        if c in string.ascii_letters + string.digits + "-" + "_" + ".":
            return True

    def _resolve_safe_key(self, filename):
        """
        Validate a relative S3 object key. Rejects absolute keys, ".."
        segments and empty path components so a stored location can never be
        turned into an object outside of the intended prefix.
        Returns (key_without_prefix, key_with_prefix) or None when unsafe.
        """
        if not filename or "\x00" in filename:
            return None
        if filename.startswith("/"):
            return None
        parts = filename.split("/")
        if ".." in parts or any(part == "" for part in parts):
            return None
        normalized = posixpath.normpath(filename)
        key = normalized
        prefixed = (self.s3_prefix or "") + key
        return key, prefixed

    def store(self, fileobj, filename):
        if self.s3_prefix:
            filename = self.s3_prefix + filename
        self.s3.upload_fileobj(fileobj, self.bucket, filename)
        return filename

    def upload(self, file_obj, filename, path=None):
        if len(filename) <= 0:
            return False

        # Content-based validation before any bytes leave the process.
        validate_file(file_obj, filename)

        # Sanitize directory name
        if path:
            path = secure_filename(path) or hexencode(os.urandom(16))
            path = path.replace(".", "")
            # Sanitize path
            path = filter(self._clean_filename, secure_filename(path).replace(" ", "_"))
            path = "".join(path)
        else:
            path = hexencode(os.urandom(16))

        # Sanitize file name
        filename = filter(
            self._clean_filename, secure_filename(filename).replace(" ", "_")
        )
        filename = "".join(filename)
        if len(filename) <= 0:
            return False

        dst = path + "/" + filename
        s3_dst = dst
        if self.s3_prefix:
            s3_dst = self.s3_prefix + dst
        self.s3.upload_fileobj(file_obj, self.bucket, s3_dst)
        return dst

    def download(self, filename):
        # S3 URLs by default are valid for one hour.
        # We round the timestamp down to the previous hour and generate the link at that time
        current_timestamp = int(time.time())
        truncated_timestamp = current_timestamp - (current_timestamp % 3600)
        if self.s3_prefix:
            filename = self.s3_prefix + filename
        key = filename
        filename = filename.split("/").pop()
        with freeze_time(datetime.datetime.utcfromtimestamp(truncated_timestamp)):
            url = self.s3.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.bucket,
                    "Key": key,
                    "ResponseContentDisposition": "attachment; filename={}".format(
                        filename
                    ),
                    "ResponseCacheControl": "max-age=3600",
                },
                ExpiresIn=3600,
            )

        custom_domain = get_app_config("AWS_S3_CUSTOM_DOMAIN")
        if custom_domain:
            url = urlparse(url)._replace(netloc=custom_domain).geturl()

        return redirect(url)

    def delete(self, filename):
        resolved = self._resolve_safe_key(filename)
        if resolved is None:
            return False
        _, key = resolved
        self.s3.delete_object(Bucket=self.bucket, Key=key)
        return True

    def verify(self, filename, expected_hash, algo="sha1"):
        resolved = self._resolve_safe_key(filename)
        if resolved is None:
            raise UploadIntegrityError("Invalid object key: {}".format(filename))
        _, key = resolved
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
        except Exception as e:
            raise UploadIntegrityError(
                "Uploaded object {} is missing after upload: {}".format(filename, e)
            )
        try:
            h = hashlib.new(algo)
            for chunk in response["Body"].iter_chunks(1024 * 1024):
                h.update(chunk)
        finally:
            response["Body"].close()
        actual_hash = h.hexdigest()
        if actual_hash != expected_hash:
            raise UploadIntegrityError(
                "Checksum mismatch for {}: expected {}, got {}".format(
                    filename, expected_hash, actual_hash
                )
            )
        return True

    def sync(self):
        local_folder = current_app.config.get("UPLOAD_FOLDER")
        # If the bucket is empty then Contents will not be in the response
        if self.s3_prefix:
            bucket_list = self.s3.list_objects(
                Bucket=self.bucket, Prefix=self.s3_prefix
            ).get("Contents", [])
        else:
            bucket_list = self.s3.list_objects(Bucket=self.bucket).get("Contents", [])

        for s3_key in bucket_list:
            s3_object = s3_key["Key"]
            # We don't want to download any directories
            if s3_object.endswith("/") is False:
                local_s3_object = s3_object
                if self.s3_prefix:
                    local_s3_object = local_s3_object.removeprefix(self.s3_prefix)
                local_path = os.path.join(local_folder, local_s3_object)
                directory = os.path.dirname(local_path)
                if not os.path.exists(directory):
                    os.makedirs(directory)

                self.s3.download_file(self.bucket, s3_object, local_path)

    def open(self, filename, mode="rb"):
        local_folder = current_app.config.get("UPLOAD_FOLDER")
        local_path = os.path.join(local_folder, filename)
        directory = os.path.dirname(local_path)
        if not os.path.exists(directory):
            os.makedirs(directory)
        self.s3.download_file(self.bucket, filename, local_path)
        return Path(local_path).open(mode=mode)
