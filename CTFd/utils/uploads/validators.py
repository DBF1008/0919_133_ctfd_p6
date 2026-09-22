import hashlib
import os
import re

from CTFd.utils import get_app_config


class UploadValidationError(Exception):
    """
    Raised when an uploaded file fails security validation:
    disallowed extension, extension/content (magic bytes) mismatch, etc.
    """


# Extensions that are allowed to be uploaded by default. Can be overridden
# with the UPLOAD_ALLOWED_EXTENSIONS config value (comma separated list,
# or "*" to allow every extension).
DEFAULT_ALLOWED_EXTENSIONS = frozenset(
    {
        # Archives
        "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
        # Images
        "jpg", "jpeg", "gif", "png", "ico", "pdf", "svg",
        # Documents / text
        "txt", "md", "csv", "json", "xml", "yml", "yaml",
        "doc", "docx", "ppt", "pptx", "xls", "xlsx", "odt", "rtf",
        # Media
        "mp3", "mp4", "wav", "ogg", "webm",
        # Binaries / misc CTF artifacts
        "pcap", "pcapng", "elf", "bin", "dump", "patch", "diff",
    }
)

# Extensions for text-like formats. These are validated by attempting to
# decode the content as UTF-8 and rejecting NUL bytes.
TEXT_EXTENSIONS = frozenset(
    {
        "txt", "md", "csv", "json", "xml", "yml", "yaml",
        "svg", "rtf", "patch", "diff",
    }
)

# Mapping of extension -> (mime, tuple of magic byte signatures).
# A signature of (offset, prefix) means the prefix bytes must appear at the
# given byte offset in the file.
MAGIC_SIGNATURES = {
    "jpg": (
        ("image/jpeg", (0, b"\xff\xd8\xff")),
    ),
    "jpeg": (
        ("image/jpeg", (0, b"\xff\xd8\xff")),
    ),
    "gif": (
        ("image/gif", (0, b"GIF87a")),
        ("image/gif", (0, b"GIF89a")),
    ),
    "png": (
        ("image/png", (0, b"\x89PNG\r\n\x1a\n")),
    ),
    "ico": (
        ("image/x-icon", (0, b"\x00\x00\x01\x00")),
    ),
    "pdf": (
        ("application/pdf", (0, b"%PDF-")),
    ),
    "zip": (
        # zip / docx / pptx / xlsx / jar ...
        ("application/zip", (0, b"PK\x03\x04")),
        ("application/zip", (0, b"PK\x05\x06")),  # empty archive
        ("application/zip", (0, b"PK\x07\x08")),  # spanned archive
    ),
    "docx": (
        ("application/zip", (0, b"PK\x03\x04")),
        ("application/zip", (0, b"PK\x05\x06")),
        ("application/zip", (0, b"PK\x07\x08")),
    ),
    "pptx": (
        ("application/zip", (0, b"PK\x03\x04")),
        ("application/zip", (0, b"PK\x05\x06")),
        ("application/zip", (0, b"PK\x07\x08")),
    ),
    "xlsx": (
        ("application/zip", (0, b"PK\x03\x04")),
        ("application/zip", (0, b"PK\x05\x06")),
        ("application/zip", (0, b"PK\x07\x08")),
    ),
    "odt": (
        ("application/zip", (0, b"PK\x03\x04")),
        ("application/zip", (0, b"PK\x05\x06")),
        ("application/zip", (0, b"PK\x07\x08")),
    ),
    "jar": (
        ("application/zip", (0, b"PK\x03\x04")),
        ("application/zip", (0, b"PK\x05\x06")),
        ("application/zip", (0, b"PK\x07\x08")),
    ),
    "gz": (
        ("application/gzip", (0, b"\x1f\x8b\x08")),
    ),
    "bz2": (
        ("application/x-bzip2", (0, b"BZh")),
    ),
    "xz": (
        ("application/x-xz", (0, b"\xfd7zXZ\x00")),
    ),
    "7z": (
        ("application/x-7z-compressed", (0, b"7z\xbc\xaf\x27\x1c")),
    ),
    "rar": (
        ("application/vnd.rar", (0, b"Rar!\x1a\x07\x00")),
        ("application/vnd.rar", (0, b"Rar!\x1a\x07\x01\x00")),
    ),
    "elf": (
        ("application/x-elf", (0, b"\x7fELF")),
    ),
    "exe": (
        ("application/x-dosexec", (0, b"MZ")),
    ),
    "mp3": (
        ("audio/mpeg", (0, b"ID3")),
        ("audio/mpeg", (0, b"\xff\xfb")),
    ),
    "wav": (
        ("audio/wav", (0, b"RIFF")),
    ),
    "ogg": (
        ("audio/ogg", (0, b"OggS")),
    ),
    "webm": (
        ("video/webm", (0, b"\x1aE\xdf\xa3")),
    ),
    "mp4": (
        # ftyp box at offset 4: "....ftyp...."
        ("video/mp4", (4, b"ftyp")),
    ),
    "pcap": (
        ("application/vnd.tcpdump.pcap", (0, b"\xd4\xc3\xb2\xa1")),
        ("application/vnd.tcpdump.pcap", (0, b"\xa1\xb2\xc3\xd4")),
        ("application/vnd.tcpdump.pcap", (0, b"\x4d\x3c\xb2\xa1")),
        ("application/vnd.tcpdump.pcap", (0, b"\xa1\xb2\x3c\x4d")),
    ),
    "pcapng": (
        ("application/x-pcapng", (0, b"\x0a\x0d\x0d\x0a")),
    ),
    "doc": (
        ("application/msword", (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")),
    ),
    "ppt": (
        ("application/vnd.ms-powerpoint", (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")),
    ),
    "xls": (
        ("application/vnd.ms-excel", (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")),
    ),
}

# Extensions whose magic signatures are shared with another container. The
# content check accepts any of the shared signatures, so they need no special
# handling beyond being present in MAGIC_SIGNATURES.

_TEXT_CONTROL_CHAR_RE = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def get_allowed_extensions():
    """
    Return the set of allowed upload extensions (lower case, no dot).
    A config value of "*" allows all extensions.
    """
    configured = get_app_config("UPLOAD_ALLOWED_EXTENSIONS")
    if not configured:
        return set(DEFAULT_ALLOWED_EXTENSIONS)
    extensions = {
        ext.strip().lower().lstrip(".")
        for ext in str(configured).split(",")
        if ext.strip()
    }
    if "*" in extensions:
        return set()
    return extensions


def get_file_extension(filename):
    """Return the lower-cased extension of a filename, or '' if there is none."""
    _, ext = os.path.splitext(filename or "")
    return ext.lower().lstrip(".")


def hash_stream(fp, algo="sha1", chunk_size=1024 * 1024):
    """
    Hash the entire contents of a binary stream and rewind it afterwards.
    """
    try:
        fp.seek(0)
    except (AttributeError, OSError, ValueError):
        pass
    try:
        h = hashlib.new(algo)
    except ValueError:
        raise NotImplementedError("Unsupported hash algorithm: {}".format(algo))
    while True:
        chunk = fp.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
    try:
        fp.seek(0)
    except (AttributeError, OSError, ValueError):
        pass
    return h.hexdigest()


def _read_head(fp, size=8192):
    """Read up to `size` leading bytes and rewind the stream."""
    try:
        fp.seek(0)
        head = fp.read(size)
        fp.seek(0)
    except (AttributeError, OSError, ValueError):
        head = fp.read()
    if isinstance(head, str):
        head = head.encode("utf-8", errors="replace")
    return head


def detect_mime(head):
    """
    Best effort detection of a MIME type from magic bytes.
    Returns None when the content cannot be identified.
    """
    for signatures in MAGIC_SIGNATURES.values():
        for mime, (offset, prefix) in signatures:
            if head[offset : offset + len(prefix)] == prefix:
                return mime
    if _TEXT_CONTROL_CHAR_RE.search(head) is None:
        try:
            head.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return "text/plain"
    return None


def _validate_text_content(ext, head):
    if b"\x00" in head:
        raise UploadValidationError(
            "Text file contains NUL bytes and cannot be a valid .{} file".format(
                ext
            )
        )
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        raise UploadValidationError(
            "File content is not valid UTF-8 text but has a .{} extension".format(
                ext
            )
        )


def validate_file(file_obj, filename=None, allowed_extensions=None):
    """
    Validate an uploaded file against:
      1. The extension whitelist (file *type*).
      2. The actual file content via magic bytes / text decoding, so that an
         executable or script cannot be uploaded merely by renaming it.

    `file_obj` is any binary stream (Flask FileStorage, BytesIO, open file).
    Raises UploadValidationError on failure and always leaves the stream
    rewound.
    """
    if filename is None:
        filename = getattr(file_obj, "filename", "") or ""

    ext = get_file_extension(filename)
    if not ext:
        raise UploadValidationError(
            "Uploaded file '{}' has no extension and cannot be validated".format(
                filename
            )
        )

    if allowed_extensions is None:
        allowed_extensions = get_allowed_extensions()
    allowed_extensions = {e.lower().lstrip(".") for e in allowed_extensions}

    # An empty whitelist means "*" (allow every extension).
    if allowed_extensions and ext not in allowed_extensions:
        raise UploadValidationError(
            "File type '.{}' is not allowed to be uploaded".format(ext)
        )

    head = _read_head(file_obj)
    if not head:
        raise UploadValidationError("Uploaded file '{}' is empty".format(filename))

    if ext in TEXT_EXTENSIONS:
        _validate_text_content(ext, head)
        return ext, "text/plain"

    expected = MAGIC_SIGNATURES.get(ext)
    if expected is None:
        # We have no magic signature for this extension: there is nothing
        # content-based to check beyond extension whitelisting.
        return ext, detect_mime(head)

    matched_mime = None
    for mime, (offset, prefix) in expected:
        if head[offset : offset + len(prefix)] == prefix:
            matched_mime = mime
            break

    if matched_mime is None:
        actual_mime = detect_mime(head)
        raise UploadValidationError(
            "File content ({}) does not match its '.{}' extension".format(
                actual_mime or "unknown", ext
            )
        )

    return ext, matched_mime
