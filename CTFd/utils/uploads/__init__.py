import shutil
from pathlib import Path

from CTFd.models import ChallengeFiles, Files, PageFiles, SolutionFiles, db
from CTFd.utils import get_app_config
from CTFd.utils.uploads.uploaders import (
    FilesystemUploader,
    S3Uploader,
    UploadIntegrityError,
)
from CTFd.utils.uploads.validators import hash_stream, validate_file

UPLOADERS = {"filesystem": FilesystemUploader, "s3": S3Uploader}


def get_uploader():
    return UPLOADERS.get(get_app_config("UPLOAD_PROVIDER") or "filesystem")()


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
        # Reject traversal attempts in either component
        if ".." in path.parts or any(
            part.startswith("/") or part.startswith("\\") for part in path.parts
        ):
            raise ValueError("Location must not contain path traversal sequences")
        # Allow location to override the directory and filename
        parent = path.parts[0]
        filename = path.parts[1]
        location = parent + "/" + filename

    # Type whitelist + magic byte validation happens before anything is
    # stored. Renaming a malicious script to an allowed extension cannot pass
    # this check because the actual content is inspected as well.
    allowed_extensions = kwargs.get("allowed_extensions")
    validate_file(file_obj, filename, allowed_extensions=allowed_extensions)

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

    # Read the bytes back from the actual storage backend and compare
    # digests so that bit flips or truncation during transfer are detected.
    try:
        uploader.verify(location, expected_hash=sha1sum)
    except UploadIntegrityError:
        # Do not leave a corrupt object behind and never record a row that
        # claims a checksum the remote file does not have.
        uploader.delete(location)
        raise

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
    return hash_stream(fp, algo=algo)


def delete_file(file_id):
    f = Files.query.filter_by(id=file_id).first_or_404()

    uploader = get_uploader()
    deleted = uploader.delete(filename=f.location)
    if deleted is False:
        # The backing file was already gone or the location was unsafe; do
        # not silently report success to callers that check the result.
        return False

    db.session.delete(f)
    db.session.commit()
    return True


def rmdir(directory):
    shutil.rmtree(directory, ignore_errors=True)
