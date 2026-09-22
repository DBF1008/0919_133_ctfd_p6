import hashlib
import os
import shutil
from pathlib import Path

from flask import current_app

from CTFd.models import ChallengeFiles, Files, PageFiles, SolutionFiles, db
from CTFd.utils import get_app_config
from CTFd.utils.uploads.uploaders import FilesystemUploader, S3Uploader

UPLOADERS = {"filesystem": FilesystemUploader, "s3": S3Uploader}

# Extensions that are allowed to be uploaded by default. Can be overridden
# with the UPLOAD_ALLOWED_EXTENSIONS Flask config value (iterable of strings).
DEFAULT_ALLOWED_EXTENSIONS = frozenset(
    {
        "txt",
        "md",
        "csv",
        "json",
        "yaml",
        "yml",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "bmp",
        "webp",
        "pdf",
        "zip",
        "tar",
        "gz",
        "tgz",
        "7z",
        "rar",
    }
)

# Magic byte signatures used to verify that a file's content matches the
# type implied by its extension.
FILE_MAGIC_SIGNATURES = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
    "bmp": (b"BM",),
    "webp": (b"RIFF",),
    "pdf": (b"%PDF-",),
    "zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    "gz": (b"\x1f\x8b",),
    "tgz": (b"\x1f\x8b",),
    "7z": (b"7z\xbc\xaf\x27\x1c",),
    "rar": (b"Rar!\x1a\x07",),
}

# Magic byte signatures of executables and scripts. Content matching any of
# these is always rejected, regardless of the claimed extension.
DANGEROUS_MAGIC_SIGNATURES = (
    b"\x7fELF",  # ELF executable
    b"MZ",  # Windows PE executable
    b"\xfe\xed\xfa\xce",  # Mach-O executable (32-bit)
    b"\xfe\xed\xfa\xcf",  # Mach-O executable (64-bit)
    b"\xce\xfa\xed\xfe",  # Mach-O executable (reverse byte order)
    b"\xcf\xfa\xed\xfe",  # Mach-O executable (reverse byte order)
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary / Java class
    b"#!",  # Script with shebang
    b"<?php",  # PHP script
)


def get_uploader():
    return UPLOADERS.get(get_app_config("UPLOAD_PROVIDER") or "filesystem")()


def get_allowed_extensions():
    configured = current_app.config.get("UPLOAD_ALLOWED_EXTENSIONS")
    if configured:
        return {ext.strip().lower().lstrip(".") for ext in configured}
    return DEFAULT_ALLOWED_EXTENSIONS


def validate_file_type(file_obj, filename):
    """
    Validate an uploaded file against the extension whitelist and verify that
    its content (magic bytes) is consistent with the claimed file type.
    """
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if not extension or extension not in get_allowed_extensions():
        raise ValueError("File type '.{}' is not allowed".format(extension))

    header = file_obj.read(512)
    file_obj.seek(0)

    for signature in DANGEROUS_MAGIC_SIGNATURES:
        if header.startswith(signature):
            raise ValueError("File content is not allowed")

    expected_signatures = FILE_MAGIC_SIGNATURES.get(extension)
    if expected_signatures and not any(
        header.startswith(signature) for signature in expected_signatures
    ):
        raise ValueError("File content does not match its extension")

    return True


def verify_upload(uploader, location, expected_sha1sum):
    """
    Re-read an uploaded file from the uploader and verify that its sha1sum
    matches the value computed before the upload. Deletes the stored file and
    raises ValueError if the integrity check fails.
    """
    try:
        with uploader.open(location) as stored_file:
            stored_sha1sum = hash_file(fp=stored_file)
    except Exception as e:
        raise ValueError("Uploaded file could not be verified") from e
    finally:
        # S3Uploader.open() downloads a local copy which must be cleaned up
        if isinstance(uploader, S3Uploader):
            local_copy = os.path.join(
                current_app.config.get("UPLOAD_FOLDER"), location
            )
            if os.path.isfile(local_copy):
                os.remove(local_copy)
                rmdir(os.path.dirname(local_copy))

    if stored_sha1sum != expected_sha1sum:
        uploader.delete(filename=location)
        raise ValueError("Uploaded file failed integrity verification")

    return True


def upload_file(*args, **kwargs):
    file_obj = kwargs.get("file")
    challenge_id = kwargs.get("challenge_id") or kwargs.get("challenge")
    page_id = kwargs.get("page_id") or kwargs.get("page")
    solution_id = kwargs.get("solution_id") or kwargs.get("solution")
    file_type = kwargs.get("type", "standard")
    location = kwargs.get("location")

    # Validate location and default filename to uploaded file's name
    parent = None
    filename = file_obj.filename
    if location:
        path = Path(location)
        if len(path.parts) != 2:
            raise ValueError(
                "Location must contain two parts, a directory and a filename"
            )
        # Allow location to override the directory and filename
        parent = path.parts[0]
        filename = path.parts[1]
        location = parent + "/" + filename

    # Validate the file extension and content before storing anything
    validate_file_type(file_obj, filename)

    model_args = {"type": file_type, "location": location}

    model = Files
    if file_type == "challenge":
        model = ChallengeFiles
        model_args["challenge_id"] = challenge_id
    elif file_type == "page":
        model = PageFiles
        model_args["page_id"] = page_id
    elif file_type == "solution":
        model = SolutionFiles
        model_args["solution_id"] = solution_id

    # Hash is calculated before upload since S3 file upload closes file object
    sha1sum = hash_file(fp=file_obj)

    uploader = get_uploader()
    location = uploader.upload(file_obj=file_obj, filename=filename, path=parent)

    # Verify that the stored file matches the hash computed before upload
    verify_upload(uploader, location, sha1sum)

    model_args["location"] = location
    model_args["sha1sum"] = sha1sum

    existing_file = Files.query.filter_by(location=location).first()
    if existing_file:
        for k, v in model_args.items():
            setattr(existing_file, k, v)
        db.session.commit()
        file_row = existing_file
    else:
        file_row = model(**model_args)
        db.session.add(file_row)
        db.session.commit()
    return file_row


def hash_file(fp, algo="sha1"):
    fp.seek(0)
    if algo == "sha1":
        h = hashlib.sha1()  # nosec
        # https://stackoverflow.com/a/64730457
        while chunk := fp.read(1024):
            h.update(chunk)
        fp.seek(0)
        return h.hexdigest()
    else:
        raise NotImplementedError


def delete_file(file_id):
    f = Files.query.filter_by(id=file_id).first_or_404()

    uploader = get_uploader()
    uploader.delete(filename=f.location)

    db.session.delete(f)
    db.session.commit()
    return True


def rmdir(directory):
    shutil.rmtree(directory, ignore_errors=True)
