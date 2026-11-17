#!/usr/bin/env python3
"""
spectramesh_ouidb - Python bindings for oui_db.c and oui_db_cli.

Provides:
- Low-level 1:1 C API bindings matching oui_db.h:
    oui_db_init, oui_db_deinit, oui_db_lookup, oui_db_lookup_ex, oui_db_lookup_entry,
    oui_surv_category_label, oui_db_print_summary, oui_db_dump, oui_db_parse_mac
- C struct definitions (ctypes.Structure):
    soui_header_t, soui_entry32_t, soui_entry64_t, oui_db_t, oui_entry_t
- High-level Pythonic API:
    OuiDb (alias OUIDB, OuiDatabase), LookupResult, OuiHeader, OuiEntry,
    SurvCategory, OuiErr, OuiError (and specific subclasses),
    lookup, lookup_ex, lookup_entry, parse_mac, format_mac, surv_category_label,
    print_summary, summary, dump, dump_soui
- CLI bindings for oui_db_cli:
    main, c_main, run_cli (and executable module `python3 -m spectramesh_ouidb`)
"""

from __future__ import annotations

import codecs
import contextlib
import ctypes
import enum
import io
import os
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterator, NamedTuple, Sequence, TextIO, Union

__all__ = [
    # Constants
    "SOUI_MAGIC",
    "SOUI_VERSION",
    "OUI_OK",
    "OUI_ERR_INVALID_ARG",
    "OUI_ERR_NOT_FOUND",
    "OUI_ERR_IO",
    "OUI_ERR_INVALID_VERSION",
    "OUI_ERR_INVALID_SIZE",
    "ESP_OK",
    "ESP_ERR_INVALID_ARG",
    "ESP_ERR_NOT_FOUND",
    "ESP_ERR_INVALID_VERSION",
    "ESP_ERR_INVALID_SIZE",
    "OUI_SURV_NONE",
    "OUI_SURV_CAMERA",
    "OUI_SURV_ALPR",
    "OUI_SURV_DRONE",
    "OUI_SURV_TRACKER",
    "OUI_SURV_ASSISTANT",
    "OUI_SURV_BODYCAM",
    # Enums & Exceptions
    "OuiErr",
    "SurvCategory",
    "OuiError",
    "OuiInvalidArgError",
    "OuiNotFoundError",
    "OuiIOError",
    "OuiInvalidVersionError",
    "OuiInvalidSizeError",
    # ctypes Structs
    "soui_header_t",
    "soui_entry32_t",
    "soui_entry64_t",
    "oui_db_t",
    "oui_entry_t",
    # High-level Types & Classes
    "OuiHeader",
    "LookupResult",
    "OuiEntry",
    "OuiDb",
    "OUIDB",
    "OuiDatabase",
    "SOUIDatabase",
    # C API Functions
    "oui_db_init",
    "oui_db_deinit",
    "oui_db_lookup",
    "oui_db_lookup_ex",
    "oui_db_lookup_entry",
    "oui_surv_category_label",
    "oui_db_print_summary",
    "oui_db_dump",
    "oui_db_parse_mac",
    # Pythonic Helper Functions
    "init",
    "open_db",
    "parse_mac",
    "format_mac",
    "surv_category_label",
    "lookup",
    "lookup_ex",
    "lookup_entry",
    "print_summary",
    "summary",
    "dump",
    "dump_soui",
    # CLI Functions
    "main",
    "c_main",
    "run_cli",
]

_MODULE_DIR = Path(__file__).resolve().parent
_DEFAULT_DB_NAME = "oui_db.bin"
_UNSET = object()

# ============================================================================
# Constants & Enumerations (matching oui_db.h)
# ============================================================================

SOUI_MAGIC: int = 0x49554F53  # "SOUI" (little-endian)
SOUI_VERSION: int = 1

OUI_OK: int = 0
OUI_ERR_INVALID_ARG: int = -1
OUI_ERR_NOT_FOUND: int = -2
OUI_ERR_IO: int = -3
OUI_ERR_INVALID_VERSION: int = -4
OUI_ERR_INVALID_SIZE: int = -5

# Backwards-compatible ESP-IDF status aliases
ESP_OK: int = OUI_OK
ESP_ERR_INVALID_ARG: int = OUI_ERR_INVALID_ARG
ESP_ERR_NOT_FOUND: int = OUI_ERR_NOT_FOUND
ESP_ERR_INVALID_VERSION: int = OUI_ERR_INVALID_VERSION
ESP_ERR_INVALID_SIZE: int = OUI_ERR_INVALID_SIZE

# Surveillance category codes
OUI_SURV_NONE: int = 0
OUI_SURV_CAMERA: int = 1
OUI_SURV_ALPR: int = 2
OUI_SURV_DRONE: int = 3
OUI_SURV_TRACKER: int = 4
OUI_SURV_ASSISTANT: int = 5
OUI_SURV_BODYCAM: int = 6


class OuiErr(enum.IntEnum):
    """Error codes returned by oui_db C functions."""

    OK = OUI_OK
    INVALID_ARG = OUI_ERR_INVALID_ARG
    NOT_FOUND = OUI_ERR_NOT_FOUND
    IO = OUI_ERR_IO
    INVALID_VERSION = OUI_ERR_INVALID_VERSION
    INVALID_SIZE = OUI_ERR_INVALID_SIZE


class SurvCategory(enum.IntEnum):
    """Surveillance category codes stored in record flags byte."""

    NONE = OUI_SURV_NONE
    CAMERA = OUI_SURV_CAMERA
    ALPR = OUI_SURV_ALPR
    DRONE = OUI_SURV_DRONE
    TRACKER = OUI_SURV_TRACKER
    ASSISTANT = OUI_SURV_ASSISTANT
    BODYCAM = OUI_SURV_BODYCAM

    @property
    def label(self) -> str:
        return oui_surv_category_label(int(self))


# ============================================================================
# Exceptions
# ============================================================================


class OuiError(OSError, ValueError, RuntimeError):
    """Base exception for OUI database errors."""

    def __init__(self, message: str, code: int = OUI_ERR_INVALID_ARG) -> None:
        Exception.__init__(self, message)
        self.code: int = int(code)
        self.err: int = int(code)


class OuiInvalidArgError(OuiError):
    """Raised when an invalid argument is passed (OUI_ERR_INVALID_ARG)."""

    def __init__(self, message: str = "Invalid argument") -> None:
        super().__init__(message, OUI_ERR_INVALID_ARG)


class OuiNotFoundError(OuiError, FileNotFoundError):
    """Raised when the database file cannot be opened (OUI_ERR_NOT_FOUND)."""

    def __init__(self, message: str = "OUI database file not found") -> None:
        super().__init__(message, OUI_ERR_NOT_FOUND)


class OuiIOError(OuiError):
    """Raised on I/O or mmap errors (OUI_ERR_IO)."""

    def __init__(self, message: str = "OUI database I/O error") -> None:
        super().__init__(message, OUI_ERR_IO)


class OuiInvalidVersionError(OuiError):
    """Raised when the SOUI header magic or version is invalid (OUI_ERR_INVALID_VERSION)."""

    def __init__(self, message: str = "Invalid SOUI header magic or version") -> None:
        super().__init__(message, OUI_ERR_INVALID_VERSION)


class OuiInvalidSizeError(OuiError):
    """Raised when the SOUI file is truncated or corrupted (OUI_ERR_INVALID_SIZE)."""

    def __init__(self, message: str = "Invalid or corrupted SOUI database size/tables") -> None:
        super().__init__(message, OUI_ERR_INVALID_SIZE)


def _error_for_code(code: int, path: str | None = None) -> OuiError:
    suffix = f" ({path})" if path else ""
    if code == OUI_ERR_NOT_FOUND:
        return OuiNotFoundError(f"Failed to open OUI database{suffix}")
    if code == OUI_ERR_IO:
        return OuiIOError(f"I/O error accessing OUI database{suffix}")
    if code == OUI_ERR_INVALID_VERSION:
        return OuiInvalidVersionError(f"Invalid SOUI header magic or version{suffix}")
    if code == OUI_ERR_INVALID_SIZE:
        return OuiInvalidSizeError(f"Truncated or corrupted SOUI database{suffix}")
    if code == OUI_ERR_INVALID_ARG:
        return OuiInvalidArgError(f"Invalid argument{suffix}")
    return OuiError(f"OUI error {code}{suffix}", code)


# ============================================================================
# ctypes Structure Definitions (exact layout of oui_db.h)
# ============================================================================


class soui_header_t(ctypes.LittleEndianStructure):
    """Packed 40-byte SOUI binary header."""

    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("version", ctypes.c_uint32),
        ("mal_count", ctypes.c_uint32),
        ("mam_count", ctypes.c_uint32),
        ("mas_count", ctypes.c_uint32),
        ("mal_offset", ctypes.c_uint32),
        ("mam_offset", ctypes.c_uint32),
        ("mas_offset", ctypes.c_uint32),
        ("str_offset", ctypes.c_uint32),
        ("str_size", ctypes.c_uint32),
    ]


class soui_entry32_t(ctypes.LittleEndianStructure):
    """Packed 9-byte entry for MA-L (24-bit) and MA-M (28-bit) tables."""

    _pack_ = 1
    _fields_ = [
        ("prefix", ctypes.c_uint32),
        ("str_off", ctypes.c_uint32),
        ("flags", ctypes.c_uint8),
    ]


class soui_entry64_t(ctypes.LittleEndianStructure):
    """Packed 13-byte entry for MA-S (36-bit) table."""

    _pack_ = 1
    _fields_ = [
        ("prefix", ctypes.c_uint64),
        ("str_off", ctypes.c_uint32),
        ("flags", ctypes.c_uint8),
    ]


class oui_db_t(ctypes.Structure):
    """Memory-mapped OUI database context matching oui_db_t in oui_db.h."""

    _fields_ = [
        ("base", ctypes.c_void_p),
        ("size", ctypes.c_size_t),
        ("hdr", ctypes.POINTER(soui_header_t)),
        ("mal", ctypes.POINTER(soui_entry32_t)),
        ("mam", ctypes.POINTER(soui_entry32_t)),
        ("mas", ctypes.POINTER(soui_entry64_t)),
        ("str_pool", ctypes.c_void_p),
    ]


class oui_entry_t(ctypes.Structure):
    """Matched OUI record metadata matching oui_entry_t in oui_db.h."""

    _fields_ = [
        ("table", ctypes.c_char_p),
        ("prefix", ctypes.c_uint64),
        ("prefix_bits", ctypes.c_uint8),
        ("prefix_str", ctypes.c_char * 24),
        ("str_off", ctypes.c_uint32),
        ("flags", ctypes.c_uint8),
        ("category", ctypes.c_char_p),
        ("vendor", ctypes.c_char_p),
    ]


assert ctypes.sizeof(soui_header_t) == 40, "soui_header_t must be 40 bytes"
assert ctypes.sizeof(soui_entry32_t) == 9, "soui_entry32_t must be 9 bytes"
assert ctypes.sizeof(soui_entry64_t) == 13, "soui_entry64_t must be 13 bytes"


# ============================================================================
# Native C Extension & Shared Library Loader
# ============================================================================

try:
    import _spectramesh_ouidb as _cext
except ImportError:
    _cext = None


def _load_cdll() -> ctypes.CDLL:
    """Locate or build liboui_db.so / _spectramesh_ouidb*.so and configure ctypes signatures."""
    global _cext
    c_src = _MODULE_DIR / "oui_db.c"
    h_src = _MODULE_DIR / "oui_db.h"
    cext_src = _MODULE_DIR / "_spectramesh_ouidb.c"
    src_mtime = max(
        c_src.stat().st_mtime if c_src.is_file() else 0.0,
        h_src.stat().st_mtime if h_src.is_file() else 0.0,
        cext_src.stat().st_mtime if cext_src.is_file() else 0.0,
    )

    if _cext is not None and getattr(_cext, "__file__", None):
        cext_path = Path(_cext.__file__).resolve()
        if not cext_path.is_file() or cext_path.stat().st_mtime < src_mtime:
            _cext = None

    candidates: list[Path] = []
    if _cext is not None and getattr(_cext, "__file__", None):
        candidates.append(Path(_cext.__file__).resolve())
    for pattern in ("_spectramesh_ouidb*.so", "liboui_db.so"):
        for match in sorted(_MODULE_DIR.glob(pattern)):
            if match not in candidates:
                candidates.append(match)

    lib_path: Path | None = None
    for cand in candidates:
        if cand.is_file() and cand.stat().st_mtime >= src_mtime:
            lib_path = cand
            break

    if lib_path is None:
        if not c_src.is_file():
            raise RuntimeError(f"Cannot locate shared library or C source at {c_src}")
        so_out = Path(tempfile.gettempdir()) / f"liboui_db_{os.getuid()}.so"
        if not so_out.is_file() or so_out.stat().st_mtime < src_mtime:
            subprocess.run(
                ["gcc", "-O2", "-Wall", "-Wextra", "-shared", "-fPIC", str(c_src), "-o", str(so_out)],
                check=True,
                cwd=str(_MODULE_DIR),
            )
        lib_path = so_out

    lib = ctypes.CDLL(str(lib_path))

    # oui_err_t oui_db_init(const char *path, oui_db_t *out_db);
    lib.oui_db_init.argtypes = [ctypes.c_char_p, ctypes.POINTER(oui_db_t)]
    lib.oui_db_init.restype = ctypes.c_int

    # void oui_db_deinit(oui_db_t *db);
    lib.oui_db_deinit.argtypes = [ctypes.POINTER(oui_db_t)]
    lib.oui_db_deinit.restype = None

    # const char *oui_db_lookup(const oui_db_t *db, const uint8_t mac[6], uint8_t *out_flags);
    lib.oui_db_lookup.argtypes = [
        ctypes.POINTER(oui_db_t),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.oui_db_lookup.restype = ctypes.c_char_p

    # const char *oui_db_lookup_ex(const oui_db_t *db, const uint8_t mac[6],
    #                              uint8_t *out_flags, uint8_t *out_prefix_bits);
    lib.oui_db_lookup_ex.argtypes = [
        ctypes.POINTER(oui_db_t),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.oui_db_lookup_ex.restype = ctypes.c_char_p

    # const char *oui_db_lookup_entry(const oui_db_t *db, const uint8_t mac[6],
    #                                 oui_entry_t *out_entry);
    if hasattr(lib, "oui_db_lookup_entry"):
        lib.oui_db_lookup_entry.argtypes = [
            ctypes.POINTER(oui_db_t),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(oui_entry_t),
        ]
        lib.oui_db_lookup_entry.restype = ctypes.c_char_p

    # const char *oui_surv_category_label(uint8_t flags);
    lib.oui_surv_category_label.argtypes = [ctypes.c_uint8]
    lib.oui_surv_category_label.restype = ctypes.c_char_p

    # oui_err_t oui_db_print_summary(const oui_db_t *db, FILE *stream);
    lib.oui_db_print_summary.argtypes = [ctypes.POINTER(oui_db_t), ctypes.c_void_p]
    lib.oui_db_print_summary.restype = ctypes.c_int

    # oui_err_t oui_db_dump(const oui_db_t *db, FILE *stream);
    lib.oui_db_dump.argtypes = [ctypes.POINTER(oui_db_t), ctypes.c_void_p]
    lib.oui_db_dump.restype = ctypes.c_int

    # bool oui_db_parse_mac(const char *mac_str, uint8_t out_mac[6]);
    lib.oui_db_parse_mac.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8)]
    lib.oui_db_parse_mac.restype = ctypes.c_bool

    # Optional C buffer helpers (present in _spectramesh_ouidb.so)
    if hasattr(lib, "oui_db_summary_to_buf"):
        lib.oui_db_summary_to_buf.argtypes = [
            ctypes.POINTER(oui_db_t),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.oui_db_summary_to_buf.restype = ctypes.c_int

    if hasattr(lib, "oui_db_dump_to_buf"):
        lib.oui_db_dump_to_buf.argtypes = [
            ctypes.POINTER(oui_db_t),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.oui_db_dump_to_buf.restype = ctypes.c_int

    if hasattr(lib, "oui_db_free_buf"):
        lib.oui_db_free_buf.argtypes = [ctypes.c_void_p]
        lib.oui_db_free_buf.restype = None

    # Weak main(int argc, char **argv) from oui_db.c
    if hasattr(lib, "main"):
        lib.main.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
        lib.main.restype = ctypes.c_int

    return lib


_lib = _load_cdll()
_libc = ctypes.CDLL(None)
if hasattr(_libc, "open_memstream"):
    _libc.open_memstream.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t)]
    _libc.open_memstream.restype = ctypes.c_void_p
if hasattr(_libc, "fdopen"):
    _libc.fdopen.argtypes = [ctypes.c_int, ctypes.c_char_p]
    _libc.fdopen.restype = ctypes.c_void_p
if hasattr(_libc, "fflush"):
    _libc.fflush.argtypes = [ctypes.c_void_p]
    _libc.fflush.restype = ctypes.c_int
_libc.fclose.argtypes = [ctypes.c_void_p]
_libc.fclose.restype = ctypes.c_int
_libc.free.argtypes = [ctypes.c_void_p]
_libc.free.restype = None

_COOKIE_WRITE_FN = ctypes.CFUNCTYPE(
    ctypes.c_ssize_t,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_char),
    ctypes.c_size_t,
)
_COOKIE_CLOSE_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)


class _cookie_io_functions_t(ctypes.Structure):
    _fields_ = [
        ("read", ctypes.c_void_p),
        ("write", _COOKIE_WRITE_FN),
        ("seek", ctypes.c_void_p),
        ("close", _COOKIE_CLOSE_FN),
    ]


_HAS_FOPENCOOKIE = hasattr(_libc, "fopencookie")
if _HAS_FOPENCOOKIE:
    _libc.fopencookie.argtypes = [ctypes.c_void_p, ctypes.c_char_p, _cookie_io_functions_t]
    _libc.fopencookie.restype = ctypes.c_void_p

_stdio_lock = threading.RLock()


# ============================================================================
# High-Level Data Types
# ============================================================================


def _table_for_prefix_bits(prefix_bits: int) -> str:
    if prefix_bits == 36:
        return "MA-S"
    if prefix_bits == 28:
        return "MA-M"
    if prefix_bits == 24:
        return "MA-L"
    return f"/{prefix_bits}"


def _format_prefix_str(prefix: int, prefix_bits: int) -> str:
    if prefix_bits == 24:
        return f"{(prefix >> 16) & 0xFF:02X}:{(prefix >> 8) & 0xFF:02X}:{prefix & 0xFF:02X}"
    if prefix_bits == 28:
        b = prefix << 4
        return (
            f"{(b >> 24) & 0xFF:02X}:{(b >> 16) & 0xFF:02X}:"
            f"{(b >> 8) & 0xFF:02X}:{b & 0xF0:02X}/28"
        )
    if prefix_bits == 36:
        b = prefix << 4
        return (
            f"{(b >> 32) & 0xFF:02X}:{(b >> 24) & 0xFF:02X}:"
            f"{(b >> 16) & 0xFF:02X}:{(b >> 8) & 0xFF:02X}:{b & 0xF0:02X}/36"
        )
    return ""


class OuiHeader(NamedTuple):
    """Unpacked representation of soui_header_t."""

    magic: int
    version: int
    mal_count: int
    mam_count: int
    mas_count: int
    mal_offset: int
    mam_offset: int
    mas_offset: int
    str_offset: int
    str_size: int

    @property
    def magic_bytes(self) -> bytes:
        return self.magic.to_bytes(4, "little")

    @property
    def version_u8(self) -> int:
        return self.version & 0xFF

    @property
    def hdr_flags(self) -> int:
        return (self.version >> 8) & 0xFF

    @property
    def total_count(self) -> int:
        return self.mal_count + self.mam_count + self.mas_count


class OuiEntry(NamedTuple):
    """Single record from an MA-L, MA-M, or MA-S table."""

    table: str
    prefix: int
    prefix_bits: int
    prefix_str: str
    str_off: int
    flags: int
    vendor: str

    @property
    def manufacturer(self) -> str:
        """Device manufacturer / organization name from the string pool."""
        return self.vendor

    @property
    def oui(self) -> str:
        """Formatted OUI prefix string (alias for prefix_str)."""
        return self.prefix_str

    @property
    def category(self) -> str:
        """Human-readable device / surveillance category label."""
        return oui_surv_category_label(self.flags)

    @property
    def category_label(self) -> str:
        """Human-readable device / surveillance category label."""
        return oui_surv_category_label(self.flags)

    @property
    def device_type(self) -> str:
        """Human-readable device type / surveillance category label."""
        return oui_surv_category_label(self.flags)

    @property
    def surv_category(self) -> SurvCategory | int:
        try:
            return SurvCategory(self.flags)
        except ValueError:
            return self.flags

    @property
    def is_surveillance(self) -> bool:
        return self.flags != OUI_SURV_NONE

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "prefix": self.prefix,
            "prefix_bits": self.prefix_bits,
            "prefix_str": self.prefix_str,
            "oui": self.oui,
            "str_off": self.str_off,
            "flags": self.flags,
            "device_type": self.device_type,
            "category": self.category,
            "category_label": self.category_label,
            "surv_category": int(self.surv_category),
            "is_surveillance": self.is_surveillance,
            "vendor": self.vendor,
            "manufacturer": self.manufacturer,
        }


class _LookupResultBase(NamedTuple):
    vendor: str
    flags: int
    prefix_bits: int


class LookupResult(_LookupResultBase):
    """
    Result of an OUI lookup containing all device type and manufacturer metadata
    from the matched oui_db.bin entry.
    """

    prefix: int
    str_off: int

    def __new__(
        cls,
        vendor: str,
        flags: int,
        prefix_bits: int,
        prefix: int = 0,
        str_off: int = 0,
    ) -> "LookupResult":
        self = super().__new__(cls, vendor, int(flags), int(prefix_bits))
        self.prefix = int(prefix)
        self.str_off = int(str_off)
        return self

    @property
    def manufacturer(self) -> str:
        """Device manufacturer / organization name from the string pool."""
        return self.vendor

    @property
    def device_type(self) -> str:
        """Human-readable device type / surveillance category label (e.g., 'none', 'camera', 'alpr', 'drone')."""
        return oui_surv_category_label(self.flags)

    @property
    def category(self) -> str:
        """Human-readable surveillance category label (e.g., 'none', 'camera', 'drone')."""
        return oui_surv_category_label(self.flags)

    @property
    def category_label(self) -> str:
        """Human-readable surveillance category label (e.g., 'none', 'camera', 'alpr')."""
        return oui_surv_category_label(self.flags)

    @property
    def surv_category(self) -> SurvCategory | int:
        try:
            return SurvCategory(self.flags)
        except ValueError:
            return self.flags

    @property
    def table(self) -> str:
        """Matched IEEE table name ('MA-L', 'MA-M', or 'MA-S')."""
        return _table_for_prefix_bits(self.prefix_bits)

    @property
    def prefix_str(self) -> str:
        """Formatted OUI prefix string ('XX:XX:XX', 'XX:XX:XX:X0/28', or 'XX:XX:XX:XX:X0/36')."""
        return _format_prefix_str(self.prefix, self.prefix_bits)

    @property
    def oui(self) -> str:
        """Formatted OUI prefix string (alias for prefix_str)."""
        return self.prefix_str

    @property
    def is_surveillance(self) -> bool:
        return self.flags != OUI_SURV_NONE

    @property
    def entry(self) -> OuiEntry:
        """Full OuiEntry record for the matched table entry."""
        return OuiEntry(
            table=self.table,
            prefix=self.prefix,
            prefix_bits=self.prefix_bits,
            prefix_str=self.prefix_str,
            str_off=self.str_off,
            flags=self.flags,
            vendor=self.vendor,
        )

    def format_tsv(self, mac: Any = None) -> str:
        """Format full metadata as a TSV row (with optional leading MAC column)."""
        cols = [
            self.table,
            self.prefix_str,
            f"/{self.prefix_bits}",
            f"0x{self.flags:02x}",
            self.category,
            str(self.str_off),
            self.vendor,
        ]
        if mac is not None:
            cols.insert(0, format_mac(mac))
        return "\t".join(cols)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "manufacturer": self.manufacturer,
            "flags": self.flags,
            "device_type": self.device_type,
            "category": self.category,
            "category_label": self.category_label,
            "surv_category": int(self.surv_category),
            "is_surveillance": self.is_surveillance,
            "table": self.table,
            "prefix": self.prefix,
            "prefix_bits": self.prefix_bits,
            "prefix_str": self.prefix_str,
            "oui": self.oui,
            "str_off": self.str_off,
        }

    def __repr__(self) -> str:
        return (
            f"LookupResult(vendor={self.vendor!r}, flags={self.flags}, "
            f"prefix_bits={self.prefix_bits}, table={self.table!r}, "
            f"prefix_str={self.prefix_str!r}, str_off={self.str_off}, "
            f"device_type={self.device_type!r})"
        )


# ============================================================================
# Internal Coercion & Validation Helpers
# ============================================================================


def _resolve_default_path(path: Union[str, bytes, os.PathLike[Any], None]) -> str:
    if path is None:
        cwd_candidate = Path(_DEFAULT_DB_NAME)
        if cwd_candidate.is_file():
            return str(cwd_candidate)
        mod_candidate = _MODULE_DIR / _DEFAULT_DB_NAME
        if mod_candidate.is_file():
            return str(mod_candidate)
        return _DEFAULT_DB_NAME
    raw = os.fspath(path)
    if isinstance(raw, bytes):
        if b"\x00" in raw:
            raise OuiInvalidArgError("path contains embedded NUL byte")
        return os.fsdecode(raw)
    if isinstance(raw, str):
        if "\x00" in raw:
            raise OuiInvalidArgError("path contains embedded NUL byte")
        return raw
    raise TypeError(f"Expected str, bytes, or os.PathLike, got {type(path).__name__}")


def _extract_db_ptr(db: Any) -> ctypes.POINTER(oui_db_t) | None:
    if db is None:
        return None
    if isinstance(db, OuiDb):
        return ctypes.pointer(db._db)
    if isinstance(db, oui_db_t):
        return ctypes.pointer(db)
    if isinstance(db, ctypes._Pointer) and db._type_ is oui_db_t:
        if not bool(db):
            return None
        return db
    if hasattr(db, "_obj") and isinstance(db._obj, oui_db_t):
        return ctypes.pointer(db._obj)
    raise TypeError(f"Expected OuiDb or oui_db_t, got {type(db).__name__}")


def _extract_db_struct(db: Any) -> oui_db_t | None:
    if db is None:
        return None
    if isinstance(db, OuiDb):
        return db._db
    if isinstance(db, oui_db_t):
        return db
    if isinstance(db, ctypes._Pointer) and db._type_ is oui_db_t:
        if not bool(db):
            return None
        return db.contents
    if hasattr(db, "_obj") and isinstance(db._obj, oui_db_t):
        return db._obj
    raise TypeError(f"Expected OuiDb or oui_db_t, got {type(db).__name__}")


def _is_valid_db_struct(db_struct: oui_db_t | None) -> bool:
    """Validate that an oui_db_t has non-NULL, consistent section pointers within [base, base + size]."""
    if db_struct is None or not db_struct.base or int(db_struct.size) < 40:
        return False
    if not bool(db_struct.hdr):
        return False
    base_addr = int(db_struct.base)
    size = int(db_struct.size)
    hdr_addr = ctypes.cast(db_struct.hdr, ctypes.c_void_p).value or 0
    if hdr_addr != base_addr:
        return False
    h = db_struct.hdr.contents
    ver = int(h.version)
    if int(h.magic) != SOUI_MAGIC or (ver & 0xFF) != SOUI_VERSION or (ver >> 16) != 0:
        return False
    mal_off, mal_cnt = int(h.mal_offset), int(h.mal_count)
    mam_off, mam_cnt = int(h.mam_offset), int(h.mam_count)
    mas_off, mas_cnt = int(h.mas_offset), int(h.mas_count)
    str_off, str_sz = int(h.str_offset), int(h.str_size)
    for off, cnt, elem_sz in (
        (mal_off, mal_cnt, 9),
        (mam_off, mam_cnt, 9),
        (mas_off, mas_cnt, 13),
        (str_off, str_sz, 1),
    ):
        total = cnt * elem_sz
        if total > 0 and off < 40:
            return False
        if off + total > size:
            return False
    mal_addr = ctypes.cast(db_struct.mal, ctypes.c_void_p).value or 0
    mam_addr = ctypes.cast(db_struct.mam, ctypes.c_void_p).value or 0
    mas_addr = ctypes.cast(db_struct.mas, ctypes.c_void_p).value or 0
    str_addr = int(db_struct.str_pool or 0)
    if (
        mal_addr != base_addr + mal_off
        or mam_addr != base_addr + mam_off
        or mas_addr != base_addr + mas_off
        or str_addr != base_addr + str_off
    ):
        return False
    return True


def _write_out_u8(target: Any, value: int) -> None:
    """Write a uint8 output parameter to a ctypes object, bytearray, or list."""
    if target is None or target is _UNSET:
        return
    u8 = value & 0xFF
    if isinstance(target, ctypes.c_uint8):
        target.value = u8
    elif isinstance(target, ctypes._Pointer) and target._type_ is ctypes.c_uint8:
        if not bool(target):
            return
        target.contents.value = u8
    elif hasattr(target, "_obj") and isinstance(target._obj, ctypes.c_uint8):
        target._obj.value = u8
    elif isinstance(target, (bytearray, memoryview)):
        if len(target) < 1:
            raise ValueError("Output buffer must have length >= 1")
        target[0] = u8
    elif isinstance(target, list):
        if len(target) == 0:
            target.append(u8)
        else:
            target[0] = u8
    elif isinstance(target, ctypes.Array) and target._type_ is ctypes.c_uint8:
        if len(target) < 1:
            raise ValueError("Output array must have length >= 1")
        target[0] = u8
    elif (
        hasattr(target, "_obj")
        and isinstance(target._obj, ctypes.Array)
        and target._obj._type_ is ctypes.c_uint8
    ):
        if len(target._obj) < 1:
            raise ValueError("Output array must have length >= 1")
        target._obj[0] = u8
    else:
        raise TypeError(f"Unsupported out parameter type: {type(target).__name__}")


def _is_null_mac_arg(mac: Any) -> bool:
    if mac is None:
        return True
    if isinstance(mac, ctypes.c_void_p) and mac.value is None:
        return True
    if isinstance(mac, ctypes.c_char_p) and mac.value is None:
        return True
    if isinstance(mac, ctypes._Pointer) and not bool(mac):
        return True
    return False


def _coerce_mac_bytes(mac: Any) -> bytes:
    """Coerce a MAC representation (str, 6-byte bytes, int, ctypes array/ptr, or 6-int sequence) into 6 bytes."""
    if isinstance(mac, ctypes.c_char_p):
        if mac.value is None:
            raise ValueError("NULL MAC string pointer")
        return _coerce_mac_bytes(mac.value)

    if isinstance(mac, str):
        if _cext is not None:
            res = _cext.parse_mac(mac)
            if res is None:
                raise ValueError(f"Invalid MAC address string: {mac!r}")
            return res
        if "\x00" in mac:
            raise ValueError(f"Invalid MAC address string: {mac!r}")
        try:
            raw = mac.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(f"Invalid MAC address string: {mac!r}") from exc
        buf = (ctypes.c_uint8 * 6)()
        if not _lib.oui_db_parse_mac(raw, buf):
            raise ValueError(f"Invalid MAC address string: {mac!r}")
        return bytes(buf)

    if isinstance(mac, (bytes, bytearray, memoryview)):
        b = bytes(mac)
        if len(b) == 6:
            return b
        if len(b) in (12, 17):
            try:
                s = b.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError(f"Invalid MAC address bytes: {mac!r}") from exc
            return _coerce_mac_bytes(s)
        raise ValueError(f"MAC bytes must be 6 raw bytes or 12/17 ASCII hex bytes, got length {len(b)}")

    if isinstance(mac, ctypes.Array) and mac._type_ is ctypes.c_uint8:
        if len(mac) != 6:
            raise ValueError(f"MAC ctypes array must have length 6, got {len(mac)}")
        return bytes(mac)

    if hasattr(mac, "_obj") and isinstance(mac._obj, ctypes.Array) and mac._obj._type_ is ctypes.c_uint8:
        if len(mac._obj) != 6:
            raise ValueError(f"MAC ctypes array must have length 6, got {len(mac._obj)}")
        return bytes(mac._obj)

    if isinstance(mac, ctypes._Pointer) and mac._type_ is ctypes.c_uint8:
        if not bool(mac):
            raise ValueError("NULL MAC pointer")
        return ctypes.string_at(mac, 6)

    if isinstance(mac, int) and not isinstance(mac, bool):
        if mac < 0 or mac > 0xFFFFFFFFFFFF:
            raise ValueError(f"MAC integer out of 48-bit range: {mac:#x}")
        return mac.to_bytes(6, "big")

    if isinstance(mac, Sequence):
        if len(mac) != 6:
            raise ValueError(f"MAC sequence must have 6 elements, got {len(mac)}")
        out = bytearray(6)
        for idx, x in enumerate(mac):
            if not (isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 255):
                raise ValueError(f"Invalid MAC byte at index {idx}: {x!r}")
            out[idx] = x
        return bytes(out)

    raise TypeError(f"Unsupported MAC address type: {type(mac).__name__}")


def _capture_c_stream_fn(c_func_name: str, db: Any) -> tuple[int, str]:
    """Call oui_db_print_summary or oui_db_dump into a memory buffer and return (oui_err_t, text)."""
    try:
        db_struct = _extract_db_struct(db)
    except TypeError:
        return OUI_ERR_INVALID_ARG, ""

    if not _is_valid_db_struct(db_struct):
        return OUI_ERR_INVALID_ARG, ""
    assert db_struct is not None

    db_addr = ctypes.addressof(db_struct)
    if _cext is not None:
        if c_func_name == "oui_db_print_summary":
            return _cext.summary_str(db_addr)
        if c_func_name == "oui_db_dump":
            return _cext.dump_str(db_addr)

    if hasattr(_libc, "open_memstream"):
        buf_ptr = ctypes.c_void_p()
        buf_len = ctypes.c_size_t()
        mem_fp = _libc.open_memstream(ctypes.byref(buf_ptr), ctypes.byref(buf_len))
        if not mem_fp:
            return OUI_ERR_IO, ""

        c_func = getattr(_lib, c_func_name)
        err = int(c_func(ctypes.byref(db_struct), mem_fp))
        close_rc = _libc.fclose(mem_fp)
        if close_rc != 0 and err == OUI_OK:
            err = OUI_ERR_IO

        text = ""
        if buf_ptr.value:
            if err == OUI_OK and buf_len.value > 0:
                raw = ctypes.string_at(buf_ptr.value, buf_len.value)
                text = raw.decode("utf-8", errors="replace")
            _libc.free(buf_ptr)

        return err, text

    # Portable fallback when open_memstream is unavailable
    with tempfile.TemporaryFile() as tmpf:
        dup_fd = os.dup(tmpf.fileno())
        fp = _libc.fdopen(dup_fd, b"w+")
        if not fp:
            os.close(dup_fd)
            return OUI_ERR_IO, ""
        c_func = getattr(_lib, c_func_name)
        err = int(c_func(ctypes.byref(db_struct), fp))
        close_rc = _libc.fclose(fp)
        if close_rc != 0 and err == OUI_OK:
            err = OUI_ERR_IO
        if err != OUI_OK:
            return err, ""
        tmpf.seek(0)
        return OUI_OK, tmpf.read().decode("utf-8", errors="replace")


@contextlib.contextmanager
def _c_stream_for_python_stream(stream: Any) -> Iterator[tuple[ctypes.c_void_p, dict[str, Any]]]:
    """
    Create a streaming C FILE* backed by glibc fopencookie that writes in bounded
    8 KB chunks directly into a Python text or binary stream.
    """
    state: dict[str, Any] = {
        "is_binary": None,
        "decoder": codecs.getincrementaldecoder("utf-8")(errors="replace"),
        "os_error": False,
        "py_exc": None,
    }

    @_COOKIE_WRITE_FN
    def _cookie_write(_cookie: int, buf: Any, size: int) -> int:
        if size == 0:
            return 0
        if state["os_error"] or state["py_exc"] is not None:
            return -1
        data = ctypes.string_at(buf, size)
        try:
            if state["is_binary"] is not True:
                text = state["decoder"].decode(data, final=False)
                try:
                    if text:
                        stream.write(text)
                    state["is_binary"] = False
                    return size
                except TypeError:
                    if state["is_binary"] is not None:
                        raise
                    state["is_binary"] = True
                    state["decoder"].reset()
            stream.write(data)
            return size
        except OSError:
            state["os_error"] = True
            return -1
        except BaseException as exc:
            state["py_exc"] = exc
            return -1

    @_COOKIE_CLOSE_FN
    def _cookie_close(_cookie: int) -> int:
        if state["os_error"] or state["py_exc"] is not None:
            return -1
        try:
            if state["is_binary"] is False:
                tail = state["decoder"].decode(b"", final=True)
                if tail:
                    stream.write(tail)
            if hasattr(stream, "flush"):
                stream.flush()
            return 0
        except OSError:
            state["os_error"] = True
            return -1
        except BaseException as exc:
            state["py_exc"] = exc
            return -1

    funcs = _cookie_io_functions_t(None, _cookie_write, None, _cookie_close)
    fp = _libc.fopencookie(None, b"w", funcs)
    if not fp:
        raise OSError("fopencookie failed")
    try:
        yield ctypes.c_void_p(fp), state
    finally:
        close_rc = _libc.fclose(fp)
        if close_rc != 0:
            state["os_error"] = True


def _write_to_python_stream(c_func_name: str, db: Any, stream: Any) -> int:
    """Execute a FILE*-taking C function and stream output to a Python stream or C FILE*."""
    if stream is _UNSET:
        stream = sys.stdout
    if stream is None:
        return OUI_ERR_INVALID_ARG

    try:
        db_struct = _extract_db_struct(db)
    except TypeError:
        return OUI_ERR_INVALID_ARG

    if not _is_valid_db_struct(db_struct):
        return OUI_ERR_INVALID_ARG
    assert db_struct is not None

    # Support passing a raw ctypes.c_void_p FILE* directly
    if isinstance(stream, ctypes.c_void_p):
        if not stream.value:
            return OUI_ERR_INVALID_ARG
        c_func = getattr(_lib, c_func_name)
        return int(c_func(ctypes.byref(db_struct), stream))

    if not hasattr(stream, "write"):
        return OUI_ERR_INVALID_ARG

    if _HAS_FOPENCOOKIE:
        c_func = getattr(_lib, c_func_name)
        try:
            with _c_stream_for_python_stream(stream) as (fp, state):
                err = int(c_func(ctypes.byref(db_struct), fp))
        except OSError:
            return OUI_ERR_IO
        if state["py_exc"] is not None:
            raise state["py_exc"]
        if state["os_error"] and err == OUI_OK:
            return OUI_ERR_IO
        return err

    err, text = _capture_c_stream_fn(c_func_name, db_struct)
    if err != OUI_OK:
        return err

    try:
        try:
            stream.write(text)
        except TypeError:
            stream.write(text.encode("utf-8"))
        if hasattr(stream, "flush"):
            stream.flush()
    except OSError:
        return OUI_ERR_IO

    return OUI_OK


@contextlib.contextmanager
def _redirect_glibc_stdio(out_stream: Any = None, err_stream: Any = None) -> Iterator[None]:
    """
    Temporarily redirect glibc's global `stdout` and/or `stderr` FILE* pointers
    through fopencookie streams wrapping the given Python streams.
    """
    if not _HAS_FOPENCOOKIE or (out_stream is None and err_stream is None):
        yield
        return

    with _stdio_lock, contextlib.ExitStack() as stack:
        stdout_var = ctypes.c_void_p.in_dll(_libc, "stdout")
        stderr_var = ctypes.c_void_p.in_dll(_libc, "stderr")
        orig_out = stdout_var.value
        orig_err = stderr_var.value

        out_state: dict[str, Any] | None = None
        err_state: dict[str, Any] | None = None
        try:
            if out_stream is not None:
                out_fp, out_state = stack.enter_context(_c_stream_for_python_stream(out_stream))
                stdout_var.value = out_fp.value
            if err_stream is not None:
                err_fp, err_state = stack.enter_context(_c_stream_for_python_stream(err_stream))
                stderr_var.value = err_fp.value
            yield
        finally:
            if out_stream is not None and hasattr(_libc, "fflush"):
                _libc.fflush(stdout_var.value)
            if err_stream is not None and hasattr(_libc, "fflush"):
                _libc.fflush(stderr_var.value)
            stdout_var.value = orig_out
            stderr_var.value = orig_err

        if out_state is not None and out_state["py_exc"] is not None:
            raise out_state["py_exc"]
        if err_state is not None and err_state["py_exc"] is not None:
            raise err_state["py_exc"]


# ============================================================================
# Low-Level C API Bindings (matching oui_db.h)
# ============================================================================


def oui_db_init(
    path: Union[str, os.PathLike[Any], bytes, None] = _UNSET,  # type: ignore[assignment]
    out_db: Any = _UNSET,
) -> Union[int, "OuiDb"]:
    """
    Memory-map the OUI database file into the process address space.

    Supports both calling conventions:
    1. C-style 2-arg call:
         db = oui_db_t()
         err = oui_db_init("oui_db.bin", db)  # returns OUI_OK (0) or negative error code
    2. Pythonic 1-arg (or 0-arg) call:
         db = oui_db_init("oui_db.bin")       # returns initialized OuiDb or raises OuiError
    """
    if out_db is _UNSET:
        if path is _UNSET:
            return OuiDb(None)
        if path is None:
            raise OuiInvalidArgError("path cannot be None")
        return OuiDb(path)

    if path is _UNSET:
        path = _resolve_default_path(None)

    if path is None or out_db is None:
        return OUI_ERR_INVALID_ARG

    if isinstance(path, bytes):
        if b"\x00" in path:
            return OUI_ERR_INVALID_ARG
        c_path = path
    elif isinstance(path, (str, os.PathLike)):
        try:
            s_path = os.fspath(path)
        except TypeError:
            return OUI_ERR_INVALID_ARG
        if isinstance(s_path, bytes):
            if b"\x00" in s_path:
                return OUI_ERR_INVALID_ARG
            c_path = s_path
        elif isinstance(s_path, str):
            if "\x00" in s_path:
                return OUI_ERR_INVALID_ARG
            c_path = os.fsencode(s_path)
        else:
            return OUI_ERR_INVALID_ARG
    else:
        return OUI_ERR_INVALID_ARG

    try:
        db_struct = _extract_db_struct(out_db)
    except TypeError:
        return OUI_ERR_INVALID_ARG

    if db_struct is None:
        return OUI_ERR_INVALID_ARG

    lock = out_db._lock if isinstance(out_db, OuiDb) else contextlib.nullcontext()
    with lock:
        # Prevent mmap leak if re-initializing an already-mapped oui_db_t
        if db_struct.base and db_struct.size > 0:
            _lib.oui_db_deinit(ctypes.byref(db_struct))
        if isinstance(out_db, OuiDb):
            out_db._path = None

        rc = int(_lib.oui_db_init(c_path, ctypes.byref(db_struct)))
        if isinstance(out_db, OuiDb) and rc == OUI_OK:
            out_db._path = os.fsdecode(c_path)
        return rc


def oui_db_deinit(db: Any) -> None:
    """Unmap the OUI database file and clear the context (idempotent)."""
    if db is None:
        return
    if isinstance(db, OuiDb):
        db.close()
        return
    db_ptr = _extract_db_ptr(db)
    if db_ptr is not None:
        _lib.oui_db_deinit(db_ptr)


def _validate_and_write_out_mac(out_mac: Any, buf: Any | None) -> bool:
    """Validate out_mac buffer type/size, and write 6 bytes from buf if buf is not None."""
    if isinstance(out_mac, ctypes._Pointer) and out_mac._type_ is ctypes.c_uint8:
        if not bool(out_mac):
            return False
        if buf is not None:
            for i in range(6):
                out_mac[i] = buf[i]
        return True
    if isinstance(out_mac, ctypes.Array) and out_mac._type_ is ctypes.c_uint8:
        if len(out_mac) < 6:
            raise ValueError(f"out_mac ctypes array must have length >= 6, got {len(out_mac)}")
        if buf is not None:
            for i in range(6):
                out_mac[i] = buf[i]
        return True
    if (
        hasattr(out_mac, "_obj")
        and isinstance(out_mac._obj, ctypes.Array)
        and out_mac._obj._type_ is ctypes.c_uint8
    ):
        if len(out_mac._obj) < 6:
            raise ValueError(f"out_mac ctypes array must have length >= 6, got {len(out_mac._obj)}")
        if buf is not None:
            for i in range(6):
                out_mac._obj[i] = buf[i]
        return True
    if isinstance(out_mac, (bytearray, memoryview)):
        if len(out_mac) < 6:
            raise ValueError(f"out_mac buffer must have length >= 6, got {len(out_mac)}")
        if buf is not None:
            for i in range(6):
                out_mac[i] = buf[i]
        return True
    if isinstance(out_mac, list):
        if len(out_mac) != 0 and len(out_mac) < 6:
            raise ValueError("out_mac list must be empty or have length >= 6")
        if buf is not None:
            if len(out_mac) >= 6:
                for i in range(6):
                    out_mac[i] = buf[i]
            else:
                out_mac.extend(buf[i] for i in range(6))
        return True
    raise TypeError(f"Unsupported out_mac buffer type: {type(out_mac).__name__}")


def oui_db_parse_mac(
    mac_str: Union[str, bytes, bytearray, memoryview, ctypes.c_char_p, None],
    out_mac: Any = _UNSET,
) -> Union[bool, bytes, None]:
    """
    Parse a MAC string ("AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", or "AABBCCDDEEFF") into 6 bytes.

    Supports both calling conventions:
    1. C-style 2-arg call:
         ok = oui_db_parse_mac("00:00:0C:12:34:56", out_mac) -> bool
    2. Pythonic 1-arg call:
         mac_bytes = oui_db_parse_mac("00:00:0C:12:34:56") -> bytes (6B) or None if invalid
    """
    if out_mac is not _UNSET:
        if out_mac is None:
            return False
        if not _validate_and_write_out_mac(out_mac, None):
            return False

    if isinstance(mac_str, ctypes.c_char_p):
        mac_str = mac_str.value

    if mac_str is None:
        return False if out_mac is not _UNSET else None

    if isinstance(mac_str, str):
        if "\x00" in mac_str:
            return False if out_mac is not _UNSET else None
        try:
            raw = mac_str.encode("ascii")
        except UnicodeEncodeError:
            return False if out_mac is not _UNSET else None
    elif isinstance(mac_str, (bytes, bytearray, memoryview)):
        raw = bytes(mac_str)
        if b"\x00" in raw:
            return False if out_mac is not _UNSET else None
    else:
        return False if out_mac is not _UNSET else None

    buf = (ctypes.c_uint8 * 6)()
    ok = bool(_lib.oui_db_parse_mac(raw, buf))

    if out_mac is _UNSET:
        return bytes(buf) if ok else None

    if not ok:
        return False

    _validate_and_write_out_mac(out_mac, buf)
    return True


def oui_surv_category_label(flags: int) -> str:
    """Return the human-readable surveillance category label for a record flags byte."""
    if not isinstance(flags, int) or isinstance(flags, bool):
        raise TypeError(f"flags must be an int, got {type(flags).__name__}")
    if _cext is not None:
        return _cext.surv_category_label(flags)
    if flags < 0 or flags > 255:
        return "unknown"
    res = _lib.oui_surv_category_label(ctypes.c_uint8(flags))
    return res.decode("utf-8", errors="replace") if res else "unknown"


def _lookup_full_raw(db_struct: oui_db_t, mac_bytes: bytes) -> tuple[str, int, int, int, int] | None:
    """Internal helper returning (vendor, flags, prefix_bits, prefix, str_off) or None."""
    if _cext is not None:
        res = _cext.lookup_raw(ctypes.addressof(db_struct), mac_bytes)
        if res is None:
            return None
        if len(res) == 5:
            vendor, flags, prefix_bits, prefix, str_off = res
            return vendor, int(flags), int(prefix_bits), int(prefix), int(str_off)

    mac_arr = (ctypes.c_uint8 * 6).from_buffer_copy(mac_bytes)
    c_entry = oui_entry_t()
    vendor_bytes = _lib.oui_db_lookup_entry(
        ctypes.byref(db_struct),
        mac_arr,
        ctypes.byref(c_entry),
    )
    if vendor_bytes is None:
        return None
    vendor = vendor_bytes.decode("utf-8", errors="replace")
    return (
        vendor,
        int(c_entry.flags),
        int(c_entry.prefix_bits),
        int(c_entry.prefix),
        int(c_entry.str_off),
    )


def _write_out_entry(target: Any, result: LookupResult | None) -> None:
    """Write matched OUI entry metadata to an oui_entry_t struct, pointer, or dict."""
    if target is None or target is _UNSET:
        return
    if isinstance(target, ctypes._Pointer) and target._type_ is oui_entry_t:
        if not bool(target):
            return
        target = target.contents
    elif hasattr(target, "_obj") and isinstance(target._obj, oui_entry_t):
        target = target._obj

    if isinstance(target, oui_entry_t):
        ctypes.memset(ctypes.byref(target), 0, ctypes.sizeof(oui_entry_t))
        if result is not None:
            target.table = result.table.encode("ascii")
            target.prefix = result.prefix
            target.prefix_bits = result.prefix_bits
            target.prefix_str = result.prefix_str.encode("ascii")
            target.str_off = result.str_off
            target.flags = result.flags
            target.category = result.category.encode("ascii")
            target.vendor = result.vendor.encode("utf-8")
    elif isinstance(target, dict):
        target.clear()
        if result is not None:
            target.update(result.to_dict())
    else:
        raise TypeError(f"Unsupported out_entry parameter type: {type(target).__name__}")


def oui_db_lookup(
    db: Any,
    mac: Any,
    out_flags: Any = _UNSET,
) -> str | None:
    """
    Resolve a 6-byte MAC address (longest-prefix match: MA-S /36 -> MA-M /28 -> MA-L /24).
    Returns the vendor name string or None if not found.
    If out_flags is provided, writes the matched record's flags byte into out_flags.
    """
    if out_flags is not _UNSET and out_flags is not None:
        _write_out_u8(out_flags, 0)

    if db is None or _is_null_mac_arg(mac):
        return None

    lock = db._lock if isinstance(db, OuiDb) else contextlib.nullcontext()
    with lock:
        db_struct = _extract_db_struct(db)
        if not _is_valid_db_struct(db_struct):
            return None
        assert db_struct is not None

        mac_bytes = _coerce_mac_bytes(mac)
        raw = _lookup_full_raw(db_struct, mac_bytes)
        if raw is None:
            return None
        vendor, flags, _prefix_bits, _prefix, _str_off = raw
        if out_flags is not _UNSET and out_flags is not None:
            _write_out_u8(out_flags, flags)
        return vendor


def oui_db_lookup_ex(
    db: Any,
    mac: Any,
    out_flags: Any = _UNSET,
    out_prefix_bits: Any = _UNSET,
) -> Union[str, LookupResult, None]:
    """
    Extended MAC address lookup that retrieves all entry metadata from oui_db.bin.

    Supports both calling conventions:
    1. C-style with out_flags / out_prefix_bits provided:
         vendor = oui_db_lookup_ex(db, mac, out_flags, out_prefix_bits) -> str | None
    2. Pythonic 2-arg call (when both out_flags and out_prefix_bits are omitted):
         result = oui_db_lookup_ex(db, mac) -> LookupResult(vendor, flags, prefix_bits, prefix, str_off) | None
    """
    c_style = (out_flags is not _UNSET) or (out_prefix_bits is not _UNSET)
    if out_flags is not _UNSET and out_flags is not None:
        _write_out_u8(out_flags, 0)
    if out_prefix_bits is not _UNSET and out_prefix_bits is not None:
        _write_out_u8(out_prefix_bits, 0)

    if db is None or _is_null_mac_arg(mac):
        return None

    lock = db._lock if isinstance(db, OuiDb) else contextlib.nullcontext()
    with lock:
        db_struct = _extract_db_struct(db)
        if not _is_valid_db_struct(db_struct):
            return None
        assert db_struct is not None

        mac_bytes = _coerce_mac_bytes(mac)
        raw = _lookup_full_raw(db_struct, mac_bytes)
        if raw is None:
            return None
        vendor, flags, prefix_bits, prefix, str_off = raw

        if out_flags is not _UNSET and out_flags is not None:
            _write_out_u8(out_flags, flags)
        if out_prefix_bits is not _UNSET and out_prefix_bits is not None:
            _write_out_u8(out_prefix_bits, prefix_bits)

        if c_style:
            return vendor
        return LookupResult(
            vendor=vendor,
            flags=flags,
            prefix_bits=prefix_bits,
            prefix=prefix,
            str_off=str_off,
        )


def oui_db_lookup_entry(
    db: Any,
    mac: Any,
    out_entry: Any = _UNSET,
) -> Union[str, LookupResult, None]:
    """
    Full MAC address lookup retrieving all metadata from the matched OUI entry.

    Supports both calling conventions:
    1. C-style 3-arg call:
         entry = oui_entry_t()
         vendor = oui_db_lookup_entry(db, mac, entry) -> str | None
    2. Pythonic 2-arg call:
         result = oui_db_lookup_entry(db, mac) -> LookupResult | None
    """
    c_style = out_entry is not _UNSET
    if c_style and out_entry is not None:
        _write_out_entry(out_entry, None)

    if db is None or _is_null_mac_arg(mac):
        return None

    lock = db._lock if isinstance(db, OuiDb) else contextlib.nullcontext()
    with lock:
        db_struct = _extract_db_struct(db)
        if not _is_valid_db_struct(db_struct):
            return None
        assert db_struct is not None

        mac_bytes = _coerce_mac_bytes(mac)
        raw = _lookup_full_raw(db_struct, mac_bytes)
        if raw is None:
            return None
        vendor, flags, prefix_bits, prefix, str_off = raw
        res = LookupResult(
            vendor=vendor,
            flags=flags,
            prefix_bits=prefix_bits,
            prefix=prefix,
            str_off=str_off,
        )
        if c_style:
            if out_entry is not None:
                _write_out_entry(out_entry, res)
            return vendor
        return res


def oui_db_print_summary(db: Any, stream: Any = _UNSET) -> int:
    """Print header metadata and first 5 raw records per table (equivalent to final_oui_db.py)."""
    lock = db._lock if isinstance(db, OuiDb) else contextlib.nullcontext()
    with lock:
        return _write_to_python_stream("oui_db_print_summary", db, stream)


def oui_db_dump(db: Any, stream: Any = _UNSET) -> int:
    """Dump all MA-L, MA-M, and MA-S records in TSV format (equivalent to dump_ouidb.py)."""
    lock = db._lock if isinstance(db, OuiDb) else contextlib.nullcontext()
    with lock:
        return _write_to_python_stream("oui_db_dump", db, stream)


# ============================================================================
# High-Level Pythonic Database Class (OuiDb)
# ============================================================================


class OuiDb:
    """
    High-level Pythonic wrapper around oui_db_t and the C functions in oui_db.c.

    Usage:
        with OuiDb("oui_db.bin") as db:
            vendor = db.lookup("00:00:0C:12:34:56")
            res = db.lookup_ex("00:00:0C:12:34:56")
            print(res.vendor, res.prefix_bits, res.category)
    """

    def __init__(
        self,
        path: Union[str, bytes, os.PathLike[Any], None] = None,
        *,
        auto_init: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._db = oui_db_t()
        self._path: str | None = None
        if auto_init:
            resolved = _resolve_default_path(path)
            rc = oui_db_init(resolved, self._db)
            if rc != OUI_OK:
                raise _error_for_code(rc, resolved)
            self._path = resolved

    @property
    def _as_parameter_(self) -> Any:
        return ctypes.byref(self._db)

    def _ensure_open(self) -> None:
        if not _is_valid_db_struct(self._db):
            raise OuiError("OUI database is closed or uninitialized", OUI_ERR_INVALID_ARG)

    @property
    def closed(self) -> bool:
        with self._lock:
            return not _is_valid_db_struct(self._db)

    @property
    def path(self) -> str | None:
        with self._lock:
            return self._path

    @property
    def base(self) -> int | None:
        with self._lock:
            return self._db.base

    @property
    def size(self) -> int:
        with self._lock:
            return int(self._db.size) if self._db.base else 0

    @property
    def hdr(self) -> Any:
        with self._lock:
            return self._db.hdr

    @property
    def mal(self) -> Any:
        with self._lock:
            return self._db.mal

    @property
    def mam(self) -> Any:
        with self._lock:
            return self._db.mam

    @property
    def mas(self) -> Any:
        with self._lock:
            return self._db.mas

    @property
    def str_pool(self) -> int | None:
        with self._lock:
            return self._db.str_pool

    @property
    def header(self) -> OuiHeader:
        with self._lock:
            self._ensure_open()
            h = self._db.hdr.contents
            return OuiHeader(
                magic=int(h.magic),
                version=int(h.version),
                mal_count=int(h.mal_count),
                mam_count=int(h.mam_count),
                mas_count=int(h.mas_count),
                mal_offset=int(h.mal_offset),
                mam_offset=int(h.mam_offset),
                mas_offset=int(h.mas_offset),
                str_offset=int(h.str_offset),
                str_size=int(h.str_size),
            )

    @property
    def magic(self) -> int:
        return self.header.magic

    @property
    def version(self) -> int:
        return self.header.version_u8

    @property
    def mal_count(self) -> int:
        return self.header.mal_count

    @property
    def mam_count(self) -> int:
        return self.header.mam_count

    @property
    def mas_count(self) -> int:
        return self.header.mas_count

    @property
    def mal_offset(self) -> int:
        return self.header.mal_offset

    @property
    def mam_offset(self) -> int:
        return self.header.mam_offset

    @property
    def mas_offset(self) -> int:
        return self.header.mas_offset

    @property
    def str_offset(self) -> int:
        return self.header.str_offset

    @property
    def str_size(self) -> int:
        return self.header.str_size

    @property
    def total_count(self) -> int:
        return self.header.total_count

    def init(self, path: Union[str, bytes, os.PathLike[Any], None] = None) -> int:
        with self._lock:
            try:
                resolved = _resolve_default_path(path)
            except (OuiInvalidArgError, TypeError):
                return OUI_ERR_INVALID_ARG
            rc = oui_db_init(resolved, self._db)
            self._path = resolved if rc == OUI_OK else None
            return rc

    def close(self) -> None:
        lock = getattr(self, "_lock", None)
        ctx = lock if lock is not None else contextlib.nullcontext()
        with ctx:
            if getattr(self, "_db", None) is not None and self._db.base:
                _lib.oui_db_deinit(ctypes.byref(self._db))
            self._path = None

    deinit = close

    def __enter__(self) -> "OuiDb":
        with self._lock:
            self._ensure_open()
            return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __bool__(self) -> bool:
        return not self.closed

    def __len__(self) -> int:
        with self._lock:
            self._ensure_open()
            return self.total_count

    def __repr__(self) -> str:
        with self._lock:
            if self.closed:
                return "<OuiDb closed>"
            h = self.header
            return (
                f"<OuiDb path={self._path!r} size={self.size} "
                f"MA-L={h.mal_count} MA-M={h.mam_count} MA-S={h.mas_count}>"
            )

    def lookup(self, mac: Any, *, with_flags: bool = False) -> Union[LookupResult, None, tuple[str | None, int]]:
        """
        Look up a MAC address and return LookupResult(vendor, flags, prefix_bits) (or None if not found).
        If with_flags=True, returns (vendor, flags).
        """
        with self._lock:
            self._ensure_open()
            if _is_null_mac_arg(mac):
                raise ValueError("MAC address cannot be None")
            res = oui_db_lookup_ex(self._db, mac)
            assert res is None or isinstance(res, LookupResult)
            if res is None:
                return (None, 0) if with_flags else None
            return (res.vendor, res.flags) if with_flags else res

    def lookup_vendor(self, mac: Any) -> str | None:
        """Look up a MAC address and return the vendor string (or None if not found)."""
        res = self.lookup_ex(mac)
        return None if res is None else res.vendor

    def lookup_ex(self, mac: Any) -> LookupResult | None:
        """
        Extended MAC lookup returning LookupResult with all entry metadata or None.
        """
        with self._lock:
            self._ensure_open()
            if _is_null_mac_arg(mac):
                raise ValueError("MAC address cannot be None")
            res = oui_db_lookup_ex(self._db, mac)
            assert res is None or isinstance(res, LookupResult)
            return res

    def lookup_entry(self, mac: Any) -> OuiEntry | None:
        """
        Look up a MAC address and return the matched OuiEntry record (or None if not found).
        """
        res = self.lookup_ex(mac)
        return None if res is None else res.entry

    def get(self, mac: Any, default: Any = None) -> Any:
        """Return the LookupResult for mac if found, else default."""
        with self._lock:
            self._ensure_open()
            res = self.lookup_ex(mac)
            return default if res is None else res

    def __contains__(self, mac: Any) -> bool:
        with self._lock:
            self._ensure_open()
            try:
                return self.lookup(mac) is not None
            except (ValueError, TypeError):
                return False

    def __getitem__(self, mac: Any) -> LookupResult:
        with self._lock:
            self._ensure_open()
            res = self.lookup_ex(mac)
            if res is None:
                raise KeyError(mac)
            return res

    def print_summary(self, stream: Any = None) -> int:
        """Write header and raw section preview to stream (default sys.stdout)."""
        with self._lock:
            self._ensure_open()
            target = sys.stdout if stream is None else stream
            rc = oui_db_print_summary(self._db, target)
            if rc != OUI_OK:
                raise _error_for_code(rc, self._path)
            return rc

    def summary(self) -> str:
        """Return header and raw section preview as a string (equivalent to final_oui_db.py)."""
        with self._lock:
            self._ensure_open()
            err, text = _capture_c_stream_fn("oui_db_print_summary", self._db)
            if err != OUI_OK:
                raise _error_for_code(err, self._path)
            return text

    format_summary = summary

    def dump(self, stream: Any = None) -> int:
        """Write full TSV table dump to stream (default sys.stdout, equivalent to dump_ouidb.py)."""
        with self._lock:
            self._ensure_open()
            target = sys.stdout if stream is None else stream
            rc = oui_db_dump(self._db, target)
            if rc != OUI_OK:
                raise _error_for_code(rc, self._path)
            return rc

    def format_dump(self) -> str:
        """Return full TSV table dump as a string."""
        with self._lock:
            self._ensure_open()
            err, text = _capture_c_stream_fn("oui_db_dump", self._db)
            if err != OUI_OK:
                raise _error_for_code(err, self._path)
            return text

    dumps = format_dump

    def iter_mal(self) -> Iterator[OuiEntry]:
        """Iterate over all 24-bit MA-L records."""
        with self._lock:
            self._ensure_open()
        return self._iter_mal_gen()

    def _iter_mal_gen(self) -> Iterator[OuiEntry]:
        i = 0
        while True:
            with self._lock:
                self._ensure_open()
                h = self._db.hdr.contents
                if i >= int(h.mal_count):
                    break
                str_limit = int(h.str_size)
                str_pool_addr = int(self._db.str_pool or 0)
                e = self._db.mal[i]
                pfx = int(e.prefix)
                soff = int(e.str_off)
                flg = int(e.flags)
                vendor = (
                    ctypes.string_at(str_pool_addr + soff).decode("utf-8", errors="replace")
                    if str_pool_addr and soff < str_limit
                    else ""
                )
            mac_str = f"{(pfx >> 16) & 0xFF:02X}:{(pfx >> 8) & 0xFF:02X}:{pfx & 0xFF:02X}"
            yield OuiEntry("MA-L", pfx, 24, mac_str, soff, flg, vendor)
            i += 1

    def iter_mam(self) -> Iterator[OuiEntry]:
        """Iterate over all 28-bit MA-M records."""
        with self._lock:
            self._ensure_open()
        return self._iter_mam_gen()

    def _iter_mam_gen(self) -> Iterator[OuiEntry]:
        i = 0
        while True:
            with self._lock:
                self._ensure_open()
                h = self._db.hdr.contents
                if i >= int(h.mam_count):
                    break
                str_limit = int(h.str_size)
                str_pool_addr = int(self._db.str_pool or 0)
                e = self._db.mam[i]
                pfx = int(e.prefix)
                soff = int(e.str_off)
                flg = int(e.flags)
                vendor = (
                    ctypes.string_at(str_pool_addr + soff).decode("utf-8", errors="replace")
                    if str_pool_addr and soff < str_limit
                    else ""
                )
            b = pfx << 4
            mac_str = (
                f"{(b >> 24) & 0xFF:02X}:{(b >> 16) & 0xFF:02X}:"
                f"{(b >> 8) & 0xFF:02X}:{b & 0xF0:02X}/28"
            )
            yield OuiEntry("MA-M", pfx, 28, mac_str, soff, flg, vendor)
            i += 1

    def iter_mas(self) -> Iterator[OuiEntry]:
        """Iterate over all 36-bit MA-S records."""
        with self._lock:
            self._ensure_open()
        return self._iter_mas_gen()

    def _iter_mas_gen(self) -> Iterator[OuiEntry]:
        i = 0
        while True:
            with self._lock:
                self._ensure_open()
                h = self._db.hdr.contents
                if i >= int(h.mas_count):
                    break
                str_limit = int(h.str_size)
                str_pool_addr = int(self._db.str_pool or 0)
                e = self._db.mas[i]
                pfx = int(e.prefix)
                soff = int(e.str_off)
                flg = int(e.flags)
                vendor = (
                    ctypes.string_at(str_pool_addr + soff).decode("utf-8", errors="replace")
                    if str_pool_addr and soff < str_limit
                    else ""
                )
            b = pfx << 4
            mac_str = (
                f"{(b >> 32) & 0xFF:02X}:{(b >> 24) & 0xFF:02X}:"
                f"{(b >> 16) & 0xFF:02X}:{(b >> 8) & 0xFF:02X}:{b & 0xF0:02X}/36"
            )
            yield OuiEntry("MA-S", pfx, 36, mac_str, soff, flg, vendor)
            i += 1

    def iter_entries(self) -> Iterator[OuiEntry]:
        """Iterate over all records across MA-L, MA-M, and MA-S tables."""
        with self._lock:
            self._ensure_open()
        return self._iter_entries_gen()

    def _iter_entries_gen(self) -> Iterator[OuiEntry]:
        yield from self._iter_mal_gen()
        yield from self._iter_mam_gen()
        yield from self._iter_mas_gen()

    def __iter__(self) -> Iterator[OuiEntry]:
        return self.iter_entries()


OUIDB = OuiDb
OuiDatabase = OuiDb
SOUIDatabase = OuiDb


# ============================================================================
# Module-Level Convenience Functions
# ============================================================================

_default_db_cache: dict[str, OuiDb] = {}
_cache_lock = threading.RLock()


def _get_cached_db(db_or_path: Any = None) -> Any:
    if isinstance(db_or_path, (OuiDb, oui_db_t)):
        return db_or_path
    if isinstance(db_or_path, ctypes._Pointer) and db_or_path._type_ is oui_db_t:
        return db_or_path
    if hasattr(db_or_path, "_obj") and isinstance(db_or_path._obj, oui_db_t):
        return db_or_path
    with _cache_lock:
        resolved = str(Path(_resolve_default_path(db_or_path)).resolve())
        cached = _default_db_cache.get(resolved)
        if cached is None or cached.closed:
            cached = OuiDb(resolved)
            _default_db_cache[resolved] = cached
        return cached


def init(path: Union[str, bytes, os.PathLike[Any], None] = None) -> OuiDb:
    """Open and return an OuiDb instance."""
    return OuiDb(path)


open_db = init


def parse_mac(mac: Any) -> bytes:
    """Parse a MAC address string (or 6-byte buffer/int) into a 6-byte bytes object."""
    return _coerce_mac_bytes(mac)


def format_mac(mac: Any, sep: str = ":") -> str:
    """Format a MAC address as an uppercase string (e.g., 'AA:BB:CC:DD:EE:FF')."""
    b = _coerce_mac_bytes(mac)
    return sep.join(f"{byte:02X}" for byte in b)


surv_category_label = oui_surv_category_label


def lookup(
    mac: Any,
    db: Any = None,
) -> str | None:
    """Look up a MAC address using the given (or default) OUI database."""
    target = _get_cached_db(db)
    return oui_db_lookup(target, mac)


def lookup_ex(
    mac: Any,
    db: Any = None,
) -> LookupResult | None:
    """Extended MAC lookup using the given (or default) OUI database."""
    target = _get_cached_db(db)
    res = oui_db_lookup_ex(target, mac)
    assert res is None or isinstance(res, LookupResult)
    return res


def lookup_entry(
    mac: Any,
    db: Any = None,
) -> OuiEntry | None:
    """Look up a MAC address and return the matched OuiEntry record (or None if not found)."""
    res = lookup_ex(mac, db)
    return None if res is None else res.entry


def print_summary(
    db: Any = None,
    stream: Any = None,
) -> int:
    """Print the database header and raw section preview (equivalent to final_oui_db.py)."""
    target = _get_cached_db(db)
    out_stream = sys.stdout if stream is None else stream
    return oui_db_print_summary(target, out_stream)


def summary(db: Any = None) -> str:
    """Return the database header and raw section preview as a string."""
    target = _get_cached_db(db)
    lock = target._lock if isinstance(target, OuiDb) else contextlib.nullcontext()
    with lock:
        err, text = _capture_c_stream_fn("oui_db_print_summary", target)
    if err != OUI_OK:
        raise _error_for_code(err)
    return text


def dump(
    db: Any = None,
    stream: Any = None,
) -> int:
    """Dump all MA-L, MA-M, and MA-S records in TSV format (equivalent to dump_ouidb.py)."""
    target = _get_cached_db(db)
    out_stream = sys.stdout if stream is None else stream
    return oui_db_dump(target, out_stream)


def dump_soui(
    path: Union[str, bytes, os.PathLike[Any], None] = None,
    stream: Any = None,
) -> None:
    """Drop-in replacement for dump_ouidb.dump_soui(path) backed by oui_db.c."""
    with OuiDb(path) as db:
        db.dump(stream=sys.stdout if stream is None else stream)


# ============================================================================
# CLI Bindings for oui_db_cli
# ============================================================================

_CLI_PROG_NAMES = frozenset({"oui_db_cli", "spectramesh_ouidb", "spectramesh-ouidb"})


def _arg_to_str(arg: Any) -> str:
    raw = os.fspath(arg)
    if isinstance(raw, bytes):
        return os.fsdecode(raw)
    if isinstance(raw, str):
        return raw
    raise TypeError(f"Expected str, bytes, or os.PathLike, got {type(arg).__name__}")


def c_main(
    argv: Sequence[Union[str, bytes, os.PathLike[Any]]] | None = None,
    *,
    stream: Any = None,
    err_stream: Any = None,
) -> int:
    """
    Directly invoke the C `main(int argc, char **argv)` function from oui_db.c.
    Preserves Python's SIGPIPE handler and routes C stdout/stderr through Python streams.
    """
    if argv is None:
        args = ["oui_db_cli", *sys.argv[1:]]
    else:
        args = [_arg_to_str(a) for a in argv]
        if not args:
            args = ["oui_db_cli"]
        elif os.path.basename(args[0]) not in _CLI_PROG_NAMES:
            args = ["oui_db_cli", *args]

    encoded_args = [os.fsencode(a) for a in args]
    c_args = (ctypes.c_char_p * (len(encoded_args) + 1))(*encoded_args, None)

    out_target = sys.stdout if stream is None else stream
    err_target = sys.stderr if err_stream is None else err_stream

    old_sigpipe = signal.getsignal(signal.SIGPIPE) if hasattr(signal, "SIGPIPE") else None
    try:
        with _redirect_glibc_stdio(out_target, err_target):
            return int(_lib.main(len(encoded_args), c_args))
    finally:
        if hasattr(signal, "SIGPIPE") and old_sigpipe is not None:
            try:
                signal.signal(signal.SIGPIPE, old_sigpipe)
            except (OSError, ValueError):
                pass


def run_cli(
    *args: Union[str, bytes, os.PathLike[Any]],
    cli_path: Union[str, bytes, os.PathLike[Any], None] = None,
    check: bool = False,
    capture_output: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """
    Execute the compiled `oui_db_cli` binary with the given arguments and return CompletedProcess.
    Falls back to in-process `main()` if `oui_db_cli` binary is not present.
    """
    if cli_path is None:
        cand = _MODULE_DIR / "oui_db_cli"
        cli_bin = str(cand) if cand.is_file() else None
    else:
        cli_bin = _arg_to_str(cli_path)

    str_args = [_arg_to_str(a) for a in args]
    if cli_bin and os.path.isfile(cli_bin) and os.access(cli_bin, os.X_OK):
        return subprocess.run(
            [cli_bin, *str_args],
            check=check,
            capture_output=capture_output,
            text=text,
        )

    out_buf = io.StringIO()
    err_buf = io.StringIO()
    prog_name = cli_bin or "oui_db_cli"
    rc = main(str_args, stream=out_buf, err_stream=err_buf, prog=prog_name)
    stdout_val: Union[str, bytes] = out_buf.getvalue() if text else out_buf.getvalue().encode("utf-8")
    stderr_val: Union[str, bytes] = err_buf.getvalue() if text else err_buf.getvalue().encode("utf-8")
    proc = subprocess.CompletedProcess(
        args=[prog_name, *str_args],
        returncode=rc,
        stdout=stdout_val if capture_output else None,
        stderr=stderr_val if capture_output else None,
    )
    if check and rc != 0:
        raise subprocess.CalledProcessError(rc, proc.args, output=proc.stdout, stderr=proc.stderr)
    return proc


def main(
    argv: Sequence[Union[str, bytes, os.PathLike[Any]]] | None = None,
    stream: TextIO | None = None,
    err_stream: TextIO | None = None,
    *,
    prog: str | None = None,
) -> int:
    """
    Python CLI entry point mirroring `oui_db_cli` (`main` in `oui_db.c`) byte-for-byte.

    Usage: spectramesh_ouidb [--summary|--dump|--lookup <MAC>] [oui_db.bin]
    Exit codes:
      0 - Success
      1 - Database error, I/O error, or MAC address not found
      2 - CLI usage / invalid option / invalid MAC format error
    """
    prog_name = prog or "oui_db_cli"
    if argv is None:
        args = list(sys.argv[1:])
        if prog is None and sys.argv and sys.argv[0]:
            prog_name = sys.argv[0]
    else:
        args = [_arg_to_str(a) for a in argv]
        if args and os.path.basename(args[0]) in _CLI_PROG_NAMES:
            if prog is None:
                prog_name = args[0]
            args = args[1:]

    out = sys.stdout if stream is None else stream
    err = sys.stderr if err_stream is None else err_stream

    def usage(target: TextIO) -> None:
        target.write(f"Usage: {prog_name} [--summary|--dump|--lookup <MAC>] [oui_db.bin]\n")
        target.flush()

    db_path: str = _DEFAULT_DB_NAME
    lookup_mac_str: str | None = None
    mode: str | None = None
    db_path_set = False
    end_of_opts = False

    i = 0
    argc = len(args)
    while i < argc:
        arg = args[i]
        if not end_of_opts and arg == "--":
            end_of_opts = True
            i += 1
            continue
        if not end_of_opts and arg.startswith("-") and len(arg) >= 1:
            if arg in ("--dump", "-d"):
                if mode is not None and mode != "dump":
                    usage(err)
                    return 2
                mode = "dump"
            elif arg in ("--summary", "-s"):
                if mode is not None and mode != "summary":
                    usage(err)
                    return 2
                mode = "summary"
            elif arg in ("--lookup", "-l"):
                if i + 1 >= argc or (mode is not None and mode != "lookup") or lookup_mac_str is not None:
                    usage(err)
                    return 2
                mode = "lookup"
                i += 1
                lookup_mac_str = args[i]
            elif arg in ("--help", "-h"):
                usage(out)
                return 0
            else:
                err.write(f"oui_db: unrecognized option '{arg}'\n")
                usage(err)
                return 2
        else:
            if mode is None and lookup_mac_str is None and oui_db_parse_mac(arg) is not None:
                mode = "lookup"
                lookup_mac_str = arg
            elif not db_path_set:
                db_path = arg
                db_path_set = True
            else:
                err.write(f"oui_db: unexpected argument '{arg}'\n")
                usage(err)
                return 2
        i += 1

    if mode is None:
        mode = "summary"

    parsed_mac: bytes | None = None
    if mode == "lookup":
        parsed_mac = oui_db_parse_mac(lookup_mac_str) if lookup_mac_str is not None else None
        if parsed_mac is None:
            err.write(f"oui_db: invalid MAC address '{lookup_mac_str}'\n")
            err.flush()
            return 2

    if not db_path_set:
        db_path = _resolve_default_path(None)

    raw_db = oui_db_t()
    with _redirect_glibc_stdio(None, err):
        init_rc = oui_db_init(db_path, raw_db)
    if init_rc != OUI_OK:
        return 1

    rc = 0
    try:
        if mode == "dump":
            if oui_db_dump(raw_db, out) != OUI_OK:
                rc = 1
        elif mode == "lookup":
            assert parsed_mac is not None
            mac_fmt = format_mac(parsed_mac)
            res = oui_db_lookup_ex(raw_db, parsed_mac)
            try:
                if res is not None:
                    out.write(
                        f"{mac_fmt}\t{res.table}\t{res.prefix_str}\t/{res.prefix_bits}\t"
                        f"0x{res.flags:02x}\t{res.category}\t{res.str_off}\t{res.vendor}\n"
                    )
                    out.flush()
                else:
                    out.write(f"{mac_fmt}\t(not found)\n")
                    out.flush()
                    rc = 1
            except OSError:
                rc = 1
        else:
            if oui_db_print_summary(raw_db, out) != OUI_OK:
                rc = 1
    finally:
        oui_db_deinit(raw_db)

    return rc


if __name__ == "__main__":
    sys.exit(main())
