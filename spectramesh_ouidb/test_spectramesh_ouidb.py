#!/usr/bin/env python3
"""Comprehensive test suite for spectramesh_ouidb bindings (oui_db.c & oui_db_cli)."""

from __future__ import annotations

import ctypes
import io
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import spectramesh_ouidb as ouidb

HERE = Path(__file__).resolve().parent
DB_PATH = HERE / "oui_db.bin"


@pytest.fixture(scope="session")
def cli_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile oui_db.c into a temporary oui_db_cli binary for CLI parity tests."""
    out_bin = tmp_path_factory.mktemp("bin") / "oui_db_cli"
    subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-std=c11", str(HERE / "oui_db.c"), "-o", str(out_bin)],
        check=True,
        cwd=str(HERE),
    )
    return out_bin


def _reference_summary(db_path: Path = DB_PATH) -> str:
    d = db_path.read_bytes()
    magic, ver, mal_cnt, mam_cnt, mas_cnt, mal_off, mam_off, mas_off, h20, h24 = struct.unpack_from("<4s9I", d, 0)
    lines = [
        f"Magic: {magic} | Ver: {ver}",
        f"Counts  -> MA-L: {mal_cnt}, MA-M: {mam_cnt}, MA-S: {mas_cnt}",
        f"Offsets -> MA-L: 0x{mal_off:x}, MA-M: 0x{mam_off:x}, MA-S: 0x{mas_off:x}",
        f"HDR +0x20: 0x{h20:08x} ({h20}) | HDR +0x24: 0x{h24:08x} ({h24})",
        "",
    ]
    for name, off, stride, cnt in (
        ("MA-L (24b)", mal_off, 9, mal_cnt),
        ("MA-M (28b)", mam_off, 9, mam_cnt),
        ("MA-S (36b)", mas_off, 13, mas_cnt),
    ):
        lines.append(f"=== {name} @ 0x{off:x} (stride={stride}B) ===")
        for i in range(min(cnt, 5)):
            rec = d[off + i * stride : off + (i + 1) * stride]
            lines.append(f"  [{i}] raw: {rec.hex(' ')}")
    return "\n".join(lines) + "\n"


def _reference_dump(db_path: Path = DB_PATH) -> str:
    d = db_path.read_bytes()
    magic, _ver, mal_c, mam_c, mas_c, mal_o, mam_o, mas_o, str_o, _str_s = struct.unpack_from("<4s9I", d, 0)
    assert magic == b"SOUI"

    def get_str(off: int) -> str:
        end = d.find(b"\x00", str_o + off)
        return d[str_o + off : end].decode("utf-8", errors="replace")

    out: list[str] = []
    mal_end = mal_o + mal_c * 9
    for pfx, soff, flg in struct.iter_unpack("<IIB", d[mal_o:mal_end]):
        mac_str = f"{(pfx >> 16) & 0xFF:02X}:{(pfx >> 8) & 0xFF:02X}:{pfx & 0xFF:02X}"
        out.append(f"MA-L\t{mac_str:<17}\t0x{flg:02x}\t{get_str(soff)}\n")

    mam_end = mam_o + mam_c * 9
    for pfx, soff, flg in struct.iter_unpack("<IIB", d[mam_o:mam_end]):
        b = pfx << 4
        mac_str = f"{(b >> 24) & 0xFF:02X}:{(b >> 16) & 0xFF:02X}:{(b >> 8) & 0xFF:02X}:{b & 0xF0:02X}/28"
        out.append(f"MA-M\t{mac_str:<17}\t0x{flg:02x}\t{get_str(soff)}\n")

    mas_end = mas_o + mas_c * 13
    for pfx, soff, flg in struct.iter_unpack("<QIB", d[mas_o:mas_end]):
        b = pfx << 4
        mac_str = (
            f"{(b >> 32) & 0xFF:02X}:{(b >> 24) & 0xFF:02X}:"
            f"{(b >> 16) & 0xFF:02X}:{(b >> 8) & 0xFF:02X}:{b & 0xF0:02X}/36"
        )
        out.append(f"MA-S\t{mac_str:<17}\t0x{flg:02x}\t{get_str(soff)}\n")

    return "".join(out)


def _make_soui_blob(
    *,
    magic: bytes = b"SOUI",
    version: int = 1,
    mal_entries: list[tuple[int, int, int]] | None = None,
    mam_entries: list[tuple[int, int, int]] | None = None,
    mas_entries: list[tuple[int, int, int]] | None = None,
    str_pool: bytes = b"TestVendor\x00",
) -> bytes:
    mal = mal_entries or []
    mam = mam_entries or []
    mas = mas_entries or []

    mal_off = 40
    mam_off = mal_off + len(mal) * 9
    mas_off = mam_off + len(mam) * 9
    str_off = mas_off + len(mas) * 13

    hdr = struct.pack(
        "<4s9I",
        magic,
        version,
        len(mal),
        len(mam),
        len(mas),
        mal_off,
        mam_off,
        mas_off,
        str_off,
        len(str_pool),
    )
    mal_bytes = b"".join(struct.pack("<IIB", pfx, soff, flg) for pfx, soff, flg in mal)
    mam_bytes = b"".join(struct.pack("<IIB", pfx, soff, flg) for pfx, soff, flg in mam)
    mas_bytes = b"".join(struct.pack("<QIB", pfx, soff, flg) for pfx, soff, flg in mas)
    return hdr + mal_bytes + mam_bytes + mas_bytes + str_pool


class TestStructSizesAndConstants:
    def test_struct_sizes(self) -> None:
        assert ctypes.sizeof(ouidb.soui_header_t) == 40
        assert ctypes.sizeof(ouidb.soui_entry32_t) == 9
        assert ctypes.sizeof(ouidb.soui_entry64_t) == 13

    def test_constants_and_enums(self) -> None:
        assert ouidb.SOUI_MAGIC == 0x49554F53
        assert ouidb.SOUI_VERSION == 1
        assert ouidb.OUI_OK == 0
        assert ouidb.ESP_OK == 0
        assert ouidb.OUI_ERR_INVALID_ARG == -1
        assert ouidb.OUI_ERR_NOT_FOUND == -2
        assert ouidb.OUI_ERR_IO == -3
        assert ouidb.OUI_ERR_INVALID_VERSION == -4
        assert ouidb.OUI_ERR_INVALID_SIZE == -5

        expected_labels = {
            ouidb.OUI_SURV_NONE: "none",
            ouidb.OUI_SURV_CAMERA: "camera",
            ouidb.OUI_SURV_ALPR: "alpr",
            ouidb.OUI_SURV_DRONE: "drone",
            ouidb.OUI_SURV_TRACKER: "tracker",
            ouidb.OUI_SURV_ASSISTANT: "assistant",
            ouidb.OUI_SURV_BODYCAM: "bodycam",
        }
        for code, label in expected_labels.items():
            assert ouidb.oui_surv_category_label(code) == label
            assert ouidb.surv_category_label(code) == label
            assert ouidb.SurvCategory(code).label == label

        for invalid_code in (7, 42, 255, -1, 256, 9999):
            assert ouidb.oui_surv_category_label(invalid_code) == "unknown"

        with pytest.raises(TypeError):
            ouidb.oui_surv_category_label("0")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            ouidb.oui_surv_category_label(True)  # type: ignore[arg-type]


class TestMacParsingAndFormatting:
    @pytest.mark.parametrize(
        "mac_input,expected",
        [
            ("00:00:0C:12:34:56", b"\x00\x00\x0c\x12\x34\x56"),
            ("00-00-0c-12-34-56", b"\x00\x00\x0c\x12\x34\x56"),
            ("00000C123456", b"\x00\x00\x0c\x12\x34\x56"),
            ("aAbBcCdDeEfF", b"\xaa\xbb\xcc\xdd\xee\xff"),
            (b"00:00:0C:12:34:56", b"\x00\x00\x0c\x12\x34\x56"),
            (b"\x00\x00\x0c\x12\x34\x56", b"\x00\x00\x0c\x12\x34\x56"),
            (bytearray(b"\x00\x00\x0c\x12\x34\x56"), b"\x00\x00\x0c\x12\x34\x56"),
            (0x00000C123456, b"\x00\x00\x0c\x12\x34\x56"),
            ([0x00, 0x00, 0x0C, 0x12, 0x34, 0x56], b"\x00\x00\x0c\x12\x34\x56"),
            ((0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF), b"\xaa\xbb\xcc\xdd\xee\xff"),
        ],
    )
    def test_valid_mac_inputs(self, mac_input: object, expected: bytes) -> None:
        assert ouidb.parse_mac(mac_input) == expected
        assert ouidb.format_mac(mac_input) == ":".join(f"{b:02X}" for b in expected)

    def test_oui_db_parse_mac_c_and_python_modes(self) -> None:
        # 1-arg mode
        assert ouidb.oui_db_parse_mac("00:00:0C:12:34:56") == b"\x00\x00\x0c\x12\x34\x56"
        assert ouidb.oui_db_parse_mac("invalid") is None
        assert ouidb.oui_db_parse_mac(None) is None

        # 2-arg mode with ctypes array
        c_buf = (ctypes.c_uint8 * 6)()
        assert ouidb.oui_db_parse_mac("AA:BB:CC:DD:EE:FF", c_buf) is True
        assert bytes(c_buf) == b"\xaa\xbb\xcc\xdd\xee\xff"

        # 2-arg mode with bytearray
        ba = bytearray(6)
        assert ouidb.oui_db_parse_mac("11-22-33-44-55-66", ba) is True
        assert bytes(ba) == b"\x11\x22\x33\x44\x55\x66"

        # 2-arg mode with list
        lst: list[int] = []
        assert ouidb.oui_db_parse_mac("112233445566", lst) is True
        assert lst == [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]

        # 2-arg mode with explicit None out_mac
        assert ouidb.oui_db_parse_mac("00:00:0C:12:34:56", None) is False
        assert ouidb.oui_db_parse_mac(None, c_buf) is False

    @pytest.mark.parametrize(
        "bad_mac",
        [
            "",
            "00:11:22:33:44",
            "00:11:22:33:44:55:66",
            "00:11-22:33:44:55",  # mixed separators
            "00.11.22.33.44.55",  # invalid separator
            "00:11:22:33:44:GG",  # non-hex
            "00112233445G",
            "001122334455\x00extra",  # embedded NUL byte
            "00:11:22:33:44:55\x00",
            b"001122334455\x00extra",
            b"\x01\x02\x03",  # wrong length bytes
            -1,
            0x1000000000000,  # > 48-bit int
            [1, 2, 3],
            [256, 0, 0, 0, 0, 0],
        ],
    )
    def test_invalid_mac_rejected(self, bad_mac: object) -> None:
        with pytest.raises((ValueError, TypeError)):
            ouidb.parse_mac(bad_mac)
        if isinstance(bad_mac, (str, bytes)):
            assert ouidb.oui_db_parse_mac(bad_mac) is None
            c_buf = (ctypes.c_uint8 * 6)()
            assert ouidb.oui_db_parse_mac(bad_mac, c_buf) is False


class TestRealDatabaseAndParity:
    def test_header_and_metadata(self) -> None:
        with ouidb.OuiDb(DB_PATH) as db:
            assert not db.closed
            assert bool(db) is True
            assert db.magic == ouidb.SOUI_MAGIC
            assert db.header.magic_bytes == b"SOUI"
            assert db.version == 1
            assert db.mal_count == 39873
            assert db.mam_count == 6579
            assert db.mas_count == 11745
            assert db.total_count == 58197
            assert len(db) == 58197
            assert db.size == DB_PATH.stat().st_size

        assert db.closed
        assert bool(db) is False

    def test_parity_with_final_oui_db_py_and_cli(self, cli_path: Path) -> None:
        expected_summary = _reference_summary(DB_PATH)
        cli_proc = subprocess.run(
            [str(cli_path), "--summary", str(DB_PATH)],
            check=True,
            capture_output=True,
            text=True,
        )
        with ouidb.OuiDb(DB_PATH) as db:
            binding_summary = db.summary()
            sio = io.StringIO()
            assert ouidb.oui_db_print_summary(db, sio) == ouidb.OUI_OK

        assert binding_summary == expected_summary
        assert binding_summary == cli_proc.stdout
        assert sio.getvalue() == expected_summary

    def test_parity_with_dump_ouidb_py_and_cli(self, cli_path: Path) -> None:
        expected_dump = _reference_dump(DB_PATH)
        cli_proc = subprocess.run(
            [str(cli_path), "--dump", str(DB_PATH)],
            check=True,
            capture_output=True,
            text=True,
        )
        with ouidb.OuiDb(DB_PATH) as db:
            binding_dump = db.format_dump()
            bio = io.BytesIO()
            assert ouidb.oui_db_dump(db, bio) == ouidb.OUI_OK

        assert binding_dump == expected_dump
        assert binding_dump == cli_proc.stdout
        assert bio.getvalue().decode("utf-8") == expected_dump
        assert binding_dump.count("\n") == 58197

    def test_longest_prefix_match_all_tables(self) -> None:
        with ouidb.OuiDb(DB_PATH) as db:
            # 1. MA-L (24-bit) lookup: 00:00:0C -> Cisco Systems, Inc
            res_mal = db.lookup_ex("00:00:0C:12:34:56")
            assert res_mal is not None
            assert res_mal.vendor == "Cisco Systems, Inc"
            assert res_mal.manufacturer == "Cisco Systems, Inc"
            assert res_mal.prefix_bits == 24
            assert res_mal.prefix == 0x00000C
            assert res_mal.prefix_str == "00:00:0C"
            assert res_mal.oui == "00:00:0C"
            assert res_mal.str_off == 116
            assert res_mal.table == "MA-L"
            assert res_mal.flags == 0
            assert res_mal.category == "none"
            assert res_mal.device_type == "none"
            assert res_mal.entry == ouidb.OuiEntry("MA-L", 0x00000C, 24, "00:00:0C", 116, 0, "Cisco Systems, Inc")

            # 2. MA-M (28-bit) lookup: first MA-M entry in db
            first_mam = next(db.iter_mam())
            mam_mac48 = (first_mam.prefix << 20) | 0xABCDE
            res_mam = db.lookup_ex(mam_mac48)
            assert res_mam is not None
            assert res_mam.vendor == first_mam.vendor
            assert res_mam.manufacturer == first_mam.vendor
            assert res_mam.prefix_bits == 28
            assert res_mam.prefix == first_mam.prefix
            assert res_mam.prefix_str == first_mam.prefix_str
            assert res_mam.oui == first_mam.prefix_str
            assert res_mam.str_off == first_mam.str_off
            assert res_mam.table == "MA-M"
            assert res_mam.flags == first_mam.flags
            assert res_mam.device_type == first_mam.device_type
            assert res_mam.entry == first_mam

            # 3. MA-S (36-bit) lookup: first MA-S entry in db
            first_mas = next(db.iter_mas())
            mas_mac48 = (first_mas.prefix << 12) | 0xDEF
            res_mas = db.lookup_ex(mas_mac48)
            assert res_mas is not None
            assert res_mas.vendor == first_mas.vendor
            assert res_mas.manufacturer == first_mas.vendor
            assert res_mas.prefix_bits == 36
            assert res_mas.prefix == first_mas.prefix
            assert res_mas.prefix_str == first_mas.prefix_str
            assert res_mas.oui == first_mas.prefix_str
            assert res_mas.str_off == first_mas.str_off
            assert res_mas.table == "MA-S"
            assert res_mas.flags == first_mas.flags
            assert res_mas.device_type == first_mas.device_type
            assert res_mas.entry == first_mas

            # 4. Surveillance flagged entry lookup
            surv_entry = next(e for e in db.iter_mal() if e.flags != 0)
            surv_mac48 = (surv_entry.prefix << 24) | 0x000001
            res_surv = db.lookup_ex(surv_mac48)
            assert res_surv is not None
            assert res_surv.flags == surv_entry.flags
            assert res_surv.is_surveillance is True
            assert res_surv.category == ouidb.oui_surv_category_label(surv_entry.flags)
            assert res_surv.device_type == ouidb.oui_surv_category_label(surv_entry.flags)
            assert res_surv.prefix == surv_entry.prefix
            assert res_surv.prefix_str == surv_entry.prefix_str
            assert res_surv.str_off == surv_entry.str_off
            assert res_surv.entry == surv_entry
            assert db.lookup_entry(surv_mac48) == surv_entry

            # 5. Non-existent OUI (FF:FF:FF:FF:FF:FF)
            assert db.lookup("FF:FF:FF:FF:FF:FF") is None
            assert db.lookup_ex("FF:FF:FF:FF:FF:FF") is None
            assert db.lookup_entry("FF:FF:FF:FF:FF:FF") is None
            assert db. lookup("FF:FF:FF:FF:FF:FF", with_flags=True) == (None, 0)
            assert "FF:FF:FF:FF:FF:FF" not in db
            assert "00:00:0C:12:34:56" in db
            assert db["00:00:0C:12:34:56"].vendor == "Cisco Systems, Inc"
            with pytest.raises(KeyError):
                _ = db["FF:FF:FF:FF:FF:FF"]

    def test_c_api_out_parameters_and_ctypes_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        raw_db = ouidb.oui_db_t()
        assert ouidb.oui_db_init(str(DB_PATH), raw_db) == ouidb.OUI_OK
        try:
            # Test both with C extension enabled and with _cext forced to None (pure ctypes path)
            for cext_val in (ouidb._cext, None):
                monkeypatch.setattr(ouidb, "_cext", cext_val)

                flg_c = ctypes.c_uint8(99)
                pbits_c = ctypes.c_uint8(99)
                vendor = ouidb.oui_db_lookup_ex(raw_db, "00:00:0C:12:34:56", flg_c, pbits_c)
                assert vendor == "Cisco Systems, Inc"
                assert flg_c.value == 0
                assert pbits_c.value == 24

                # Test oui_db_lookup_entry with C struct and dict out parameter
                c_entry = ouidb.oui_entry_t()
                assert ouidb.oui_db_lookup_entry(raw_db, "B0:10:41:12:34:56", c_entry) == "Flock Safety"
                assert c_entry.table == b"MA-L"
                assert c_entry.prefix == 0xB01041
                assert c_entry.prefix_bits == 24
                assert c_entry.prefix_str == b"B0:10:41"
                assert c_entry.flags == ouidb.OUI_SURV_ALPR
                assert c_entry.category == b"alpr"
                assert c_entry.vendor == b"Flock Safety"
                assert c_entry.str_off > 0

                out_dict: dict[str, object] = {}
                assert ouidb.oui_db_lookup_entry(raw_db, "B0:10:41:12:34:56", out_dict) == "Flock Safety"
                assert out_dict["vendor"] == "Flock Safety"
                assert out_dict["manufacturer"] == "Flock Safety"
                assert out_dict["device_type"] == "alpr"
                assert out_dict["table"] == "MA-L"
                assert out_dict["prefix_str"] == "B0:10:41"
                assert out_dict["prefix"] == 0xB01041

                # Not found zeroes out_flags, out_prefix_bits, and out_entry
                flg_c.value = 99
                pbits_c.value = 99
                assert ouidb.oui_db_lookup_ex(raw_db, "FF:FF:FF:FF:FF:FF", flg_c, pbits_c) is None
                assert flg_c.value == 0
                assert pbits_c.value == 0
                assert ouidb.oui_db_lookup_entry(raw_db, "FF:FF:FF:FF:FF:FF", c_entry) is None
                assert c_entry.vendor is None
                assert c_entry.prefix_bits == 0

                # Test summary & dump via pure ctypes path too
                sio = io.StringIO()
                assert ouidb.oui_db_print_summary(raw_db, sio) == ouidb.OUI_OK
                assert sio.getvalue().startswith("Magic: b'SOUI' | Ver: 1\n")
        finally:
            ouidb.oui_db_deinit(raw_db)
            assert raw_db.base is None


class TestLongestPrefixOverrideAndValidation:
    def test_synthetic_longest_prefix_override(self, tmp_path: Path) -> None:
        """When a MAC matches MA-L, MA-M, and MA-S simultaneously, MA-S (/36) wins over MA-M (/28) over MA-L (/24)."""
        str_pool = b"VendorMAL\x00VendorMAM\x00VendorMAS\x00"
        blob = _make_soui_blob(
            mal_entries=[(0xAABBCC, 0, ouidb.OUI_SURV_NONE)],
            mam_entries=[(0xAABBCCD, 10, ouidb.OUI_SURV_CAMERA)],
            mas_entries=[(0xAABBCCDDE, 20, ouidb.OUI_SURV_DRONE)],
            str_pool=str_pool,
        )
        db_file = tmp_path / "override.bin"
        db_file.write_bytes(blob)

        with ouidb.OuiDb(db_file) as db:
            # Matches all 3 -> MA-S (36-bit) must win
            r36 = db.lookup_ex("AA:BB:CC:DD:EF:01")
            assert r36 == ouidb.LookupResult("VendorMAS", ouidb.OUI_SURV_DRONE, 36)
            assert r36 is not None
            assert r36.prefix == 0xAABBCCDDE
            assert r36.prefix_str == "AA:BB:CC:DD:E0/36"
            assert r36.str_off == 20
            assert r36.device_type == "drone"
            assert r36.manufacturer == "VendorMAS"

            # Matches MA-M and MA-L -> MA-M (28-bit) must win
            r28 = db.lookup_ex("AA:BB:CC:DF:00:01")
            assert r28 == ouidb.LookupResult("VendorMAM", ouidb.OUI_SURV_CAMERA, 28)
            assert r28 is not None
            assert r28.prefix == 0xAABBCCD
            assert r28.prefix_str == "AA:BB:CC:D0/28"
            assert r28.str_off == 10
            assert r28.device_type == "camera"
            assert r28.manufacturer == "VendorMAM"

            # Matches only MA-L -> MA-L (24-bit) must win
            r24 = db.lookup_ex("AA:BB:CC:00:00:01")
            assert r24 == ouidb.LookupResult("VendorMAL", ouidb.OUI_SURV_NONE, 24)
            assert r24 is not None
            assert r24.prefix == 0xAABBCC
            assert r24.prefix_str == "AA:BB:CC"
            assert r24.str_off == 0
            assert r24.device_type == "none"
            assert r24.manufacturer == "VendorMAL"

    def test_error_conditions_and_corrupt_files(self, tmp_path: Path) -> None:
        # 1. NULL / invalid args
        raw_db = ouidb.oui_db_t()
        assert ouidb.oui_db_init(None, raw_db) == ouidb.OUI_ERR_INVALID_ARG
        assert ouidb.oui_db_init("oui_db.bin", None) == ouidb.OUI_ERR_INVALID_ARG
        assert ouidb.oui_db_init("bad\x00path", raw_db) == ouidb.OUI_ERR_INVALID_ARG

        # 2. Missing file -> OUI_ERR_NOT_FOUND
        missing = tmp_path / "nonexistent.bin"
        assert ouidb.oui_db_init(missing, raw_db) == ouidb.OUI_ERR_NOT_FOUND
        with pytest.raises(ouidb.OuiNotFoundError) as exc_info:
            ouidb.OuiDb(missing)
        assert exc_info.value.code == ouidb.OUI_ERR_NOT_FOUND

        # 3. Directory (not a regular file) -> OUI_ERR_IO
        assert ouidb.oui_db_init(tmp_path, raw_db) == ouidb.OUI_ERR_IO
        with pytest.raises(ouidb.OuiIOError):
            ouidb.OuiDb(tmp_path)

        # 4. File too small (< 40 bytes) -> OUI_ERR_INVALID_SIZE
        small = tmp_path / "small.bin"
        small.write_bytes(b"SOUI" + b"\x00" * 10)
        assert ouidb.oui_db_init(small, raw_db) == ouidb.OUI_ERR_INVALID_SIZE
        with pytest.raises(ouidb.OuiInvalidSizeError):
            ouidb.OuiDb(small)

        # 5. Invalid magic -> OUI_ERR_INVALID_VERSION
        bad_magic = tmp_path / "bad_magic.bin"
        bad_magic.write_bytes(_make_soui_blob(magic=b"NOPE"))
        assert ouidb.oui_db_init(bad_magic, raw_db) == ouidb.OUI_ERR_INVALID_VERSION
        with pytest.raises(ouidb.OuiInvalidVersionError):
            ouidb.OuiDb(bad_magic)

        # 6. Invalid version -> OUI_ERR_INVALID_VERSION
        bad_ver = tmp_path / "bad_ver.bin"
        bad_ver.write_bytes(_make_soui_blob(version=2))
        assert ouidb.oui_db_init(bad_ver, raw_db) == ouidb.OUI_ERR_INVALID_VERSION

        # 7. Missing NUL terminator in string pool -> OUI_ERR_INVALID_SIZE
        no_nul = tmp_path / "no_nul.bin"
        no_nul.write_bytes(_make_soui_blob(str_pool=b"NoNullTerminator"))
        assert ouidb.oui_db_init(no_nul, raw_db) == ouidb.OUI_ERR_INVALID_SIZE

        # 8. Unsorted table entries -> OUI_ERR_INVALID_SIZE
        unsorted = tmp_path / "unsorted.bin"
        unsorted.write_bytes(
            _make_soui_blob(
                mal_entries=[(0x000002, 0, 0), (0x000001, 0, 0)],
            )
        )
        assert ouidb.oui_db_init(unsorted, raw_db) == ouidb.OUI_ERR_INVALID_SIZE

        # 9. Out-of-bounds string offset -> OUI_ERR_INVALID_SIZE
        bad_soff = tmp_path / "bad_soff.bin"
        bad_soff.write_bytes(
            _make_soui_blob(
                mal_entries=[(0x000001, 9999, 0)],
            )
        )
        assert ouidb.oui_db_init(bad_soff, raw_db) == ouidb.OUI_ERR_INVALID_SIZE

    def test_closed_db_operations(self) -> None:
        db = ouidb.OuiDb(DB_PATH)
        db.close()
        db.close()  # idempotent second close

        with pytest.raises(ouidb.OuiError):
            db.lookup("00:00:0C:12:34:56")
        with pytest.raises(ouidb.OuiError):
            db.summary()
        with pytest.raises(ouidb.OuiError):
            _ = len(db)

        assert ouidb.oui_db_lookup(db, "00:00:0C:12:34:56") is None
        assert ouidb.oui_db_print_summary(db, io.StringIO()) == ouidb.OUI_ERR_INVALID_ARG
        assert ouidb.oui_db_dump(db, io.StringIO()) == ouidb.OUI_ERR_INVALID_ARG

    def test_iterators_closed_before_and_mid_iteration(self) -> None:
        for method_name in ("iter_mal", "iter_mam", "iter_mas", "iter_entries", "__iter__"):
            db = ouidb.OuiDb(DB_PATH)
            it = getattr(db, method_name)()
            first = next(it)
            assert isinstance(first, ouidb.OuiEntry)
            db.close()
            assert db.path is None
            with pytest.raises(ouidb.OuiError):
                next(it)
            # Calling iterator factory on already-closed db raises immediately
            with pytest.raises(ouidb.OuiError):
                getattr(db, method_name)()

    def test_mutated_oui_db_t_pointers_do_not_crash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for cext_val in (ouidb._cext, None):
            monkeypatch.setattr(ouidb, "_cext", cext_val)
            for field, bad_val in (
                ("hdr", None),
                ("str_pool", None),
                ("mal", None),
                ("mam", None),
                ("mas", None),
                ("size", 10),
            ):
                db = ouidb.OuiDb(DB_PATH)
                orig_base = db._db.base
                orig_size = db._db.size
                try:
                    setattr(db._db, field, bad_val)
                    assert db.closed is True
                    with pytest.raises(ouidb.OuiError):
                        _ = db.header
                    with pytest.raises(ouidb.OuiError):
                        db.lookup("00:00:0C:12:34:56")
                    with pytest.raises(ouidb.OuiError):
                        db.iter_mal()
                    assert ouidb.oui_db_lookup(db._db, "00:00:0C:12:34:56") is None
                    assert ouidb.oui_db_lookup_ex(db._db, "00:00:0C:12:34:56") is None
                    assert ouidb.oui_db_print_summary(db._db, io.StringIO()) == ouidb.OUI_ERR_INVALID_ARG
                    assert ouidb.oui_db_dump(db._db, io.StringIO()) == ouidb.OUI_ERR_INVALID_ARG
                finally:
                    db._db.base = orig_base
                    db._db.size = orig_size
                    db.close()

    def test_null_ctypes_pointers_and_buffer_validation(self) -> None:
        null_db_ptr = ctypes.POINTER(ouidb.oui_db_t)()
        null_u8_ptr = ctypes.POINTER(ctypes.c_uint8)()
        null_char_ptr = ctypes.c_char_p(None)

        assert ouidb.oui_db_init(str(DB_PATH), null_db_ptr) == ouidb.OUI_ERR_INVALID_ARG
        ouidb.oui_db_deinit(null_db_ptr)  # no-op
        assert ouidb.oui_db_lookup(null_db_ptr, "00:00:0C:12:34:56") is None
        assert ouidb.oui_db_lookup_ex(null_db_ptr, "00:00:0C:12:34:56") is None
        assert ouidb.oui_db_print_summary(null_db_ptr, io.StringIO()) == ouidb.OUI_ERR_INVALID_ARG
        assert ouidb.oui_db_dump(null_db_ptr, io.StringIO()) == ouidb.OUI_ERR_INVALID_ARG

        # parse_mac with memoryview, LP_c_ubyte, NULL LP_c_ubyte, c_char_p, and undersized buffers
        assert ouidb.oui_db_parse_mac(memoryview(b"00:00:0C:12:34:56")) == b"\x00\x00\x0c\x12\x34\x56"
        assert ouidb.oui_db_parse_mac(ctypes.c_char_p(b"00:00:0C:12:34:56")) == b"\x00\x00\x0c\x12\x34\x56"
        assert ouidb.oui_db_parse_mac(null_char_ptr) is None
        assert ouidb.oui_db_parse_mac("00:00:0C:12:34:56", null_u8_ptr) is False

        c_arr = (ctypes.c_uint8 * 6)()
        c_ptr = ctypes.cast(c_arr, ctypes.POINTER(ctypes.c_uint8))
        assert ouidb.oui_db_parse_mac("00:00:0C:12:34:56", c_ptr) is True
        assert bytes(c_arr) == b"\x00\x00\x0c\x12\x34\x56"

        for small_buf in (
            bytearray(3),
            memoryview(bytearray(4)),
            (ctypes.c_uint8 * 3)(),
            ctypes.byref((ctypes.c_uint8 * 3)()),
            [1, 2],
        ):
            with pytest.raises(ValueError):
                ouidb.oui_db_parse_mac("00:00:0C:12:34:56", small_buf)
            with pytest.raises(ValueError):
                ouidb.oui_db_parse_mac("invalid-mac", small_buf)

        raw = ouidb.oui_db_t()
        assert ouidb.oui_db_init(DB_PATH, raw) == ouidb.OUI_OK
        try:
            assert ouidb.oui_db_lookup(raw, c_ptr, null_u8_ptr) == "Cisco Systems, Inc"
            assert ouidb.oui_db_lookup_ex(raw, c_ptr, null_u8_ptr, null_u8_ptr) == "Cisco Systems, Inc"
            assert ouidb.oui_db_lookup(raw, null_u8_ptr) is None
            assert ouidb.oui_db_lookup_ex(raw, null_u8_ptr, null_u8_ptr, null_u8_ptr) is None
        finally:
            ouidb.oui_db_deinit(raw)

    def test_multithreaded_concurrent_close_and_access(self) -> None:
        import threading

        db = ouidb.OuiDb(DB_PATH)
        stop = False
        unexpected: list[BaseException] = []

        def reader() -> None:
            while not stop:
                try:
                    _ = db.lookup("00:00:0C:12:34:56")
                    for idx, entry in enumerate(db.iter_mal()):
                        _ = entry.vendor
                        if idx >= 16:
                            break
                except ouidb.OuiError:
                    pass
                except BaseException as exc:
                    unexpected.append(exc)
                    break

        def closer() -> None:
            for _ in range(40):
                db.close()
                db.init(DB_PATH)

        threads = [threading.Thread(target=reader) for _ in range(2)]
        t_close = threading.Thread(target=closer)
        for t in threads:
            t.start()
        t_close.start()
        t_close.join()
        stop = True
        for t in threads:
            t.join()
        db.close()
        assert unexpected == []

    def test_streaming_dump_early_abort_on_broken_pipe(self) -> None:
        class BrokenPipeStream:
            def __init__(self) -> None:
                self.calls = 0

            def write(self, _data: str) -> int:
                self.calls += 1
                raise BrokenPipeError("Simulated broken pipe")

        with ouidb.OuiDb(DB_PATH) as db:
            bps = BrokenPipeStream()
            rc = ouidb.oui_db_dump(db, bps)
            assert rc == ouidb.OUI_ERR_IO
            # Should abort on the very first 8KB chunk rather than after all 58,197 records
            assert bps.calls == 1


class TestCliBindings:
    @pytest.mark.parametrize(
        "args",
        [
            ["--help"],
            ["-h"],
            ["--summary", str(DB_PATH)],
            ["-s", str(DB_PATH)],
            [str(DB_PATH)],
            ["--lookup", "00:00:0C:12:34:56", str(DB_PATH)],
            ["-l", "00-00-0C-12-34-56", str(DB_PATH)],
            ["00000C123456", str(DB_PATH)],
            ["--lookup", "FF:FF:FF:FF:FF:FF", str(DB_PATH)],
            ["--", "00:00:0C:12:34:56", str(DB_PATH)],
            ["--unknown-flag"],
            ["--summary", "--dump"],
            ["--lookup"],
            ["--lookup", "not-a-mac", str(DB_PATH)],
            [str(DB_PATH), "extra-arg"],
            [str(HERE / "nonexistent_oui_db.bin")],
        ],
    )
    def test_cli_parity_with_oui_db_cli(self, args: list[str], cli_path: Path) -> None:
        c_proc = subprocess.run(
            [str(cli_path), *args],
            capture_output=True,
            text=True,
        )
        out_io = io.StringIO()
        err_io = io.StringIO()
        py_rc = ouidb.main(args, stream=out_io, err_stream=err_io, prog=str(cli_path))

        assert py_rc == c_proc.returncode
        assert out_io.getvalue() == c_proc.stdout
        assert err_io.getvalue() == c_proc.stderr

        c_out_io = io.StringIO()
        c_err_io = io.StringIO()
        c_main_rc = ouidb.c_main([str(cli_path), *args], stream=c_out_io, err_stream=c_err_io)
        assert c_main_rc == c_proc.returncode
        assert c_out_io.getvalue() == c_proc.stdout
        assert c_err_io.getvalue() == c_proc.stderr

        run_cli_proc = ouidb.run_cli(*args, cli_path=cli_path)
        assert run_cli_proc.returncode == c_proc.returncode
        assert run_cli_proc.stdout == c_proc.stdout
        assert run_cli_proc.stderr == c_proc.stderr

    def test_c_main_invocation_and_sigpipe_preservation(self, tmp_path: Path) -> None:
        # Both with and without argv[0]
        sio = io.StringIO()
        err_sio = io.StringIO()
        assert ouidb.c_main(["oui_db_cli", "--lookup", "00:00:0C:12:34:56", str(DB_PATH)], stream=sio) == 0
        assert ouidb.c_main(["--lookup", "00:00:0C:12:34:56", str(DB_PATH)], stream=sio) == 0
        assert ouidb.c_main(["--lookup", "FF:FF:FF:FF:FF:FF", str(DB_PATH)], stream=sio) == 1
        assert ouidb.c_main(["--invalid-opt"], err_stream=err_sio) == 2

        # Verify custom database filename without .bin extension works with c_main and main
        custom_soui = tmp_path / "custom_oui_image.soui"
        custom_soui.write_bytes(_make_soui_blob(mal_entries=[(0x00000C, 0, 0)], str_pool=b"Cisco\x00"))
        out_custom = io.StringIO()
        assert ouidb.c_main([custom_soui], stream=out_custom) == 0
        assert out_custom.getvalue().startswith("Magic: b'SOUI' | Ver: 1\n")
        out_main_path = io.StringIO()
        assert ouidb.main([custom_soui], stream=out_main_path) == 0
        assert out_main_path.getvalue() == out_custom.getvalue()

        # Verify SIGPIPE remains ignored in Python after calling c_main()
        r_fd, w_fd = os.pipe()
        os.close(r_fd)
        try:
            with pytest.raises(BrokenPipeError):
                os.write(w_fd, b"test")
        finally:
            os.close(w_fd)

    def test_module_cli_invocation_and_cwd_independence(self, tmp_path: Path) -> None:
        env = {**os.environ, "PYTHONPATH": str(HERE)}
        proc = subprocess.run(
            [sys.executable, "-m", "spectramesh_ouidb", "--lookup", "00:00:0C:12:34:56"],
            cwd=str(tmp_path),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        assert proc.stdout == "00:00:0C:12:34:56\tMA-L\t00:00:0C\t/24\t0x00\tnone\t116\tCisco Systems, Inc\n"

        # Verify 0-arg oui_db_init() and dump_soui() also work when cwd is tmp_path
        orig_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            with ouidb.oui_db_init() as db:
                assert db.total_count == 58197
            sio = io.StringIO()
            ouidb.dump_soui(stream=sio)
            assert sio.getvalue().count("\n") == 58197
        finally:
            os.chdir(orig_cwd)

    def test_module_level_convenience_functions_and_reinit(self) -> None:
        assert ouidb.lookup("00:00:0C:12:34:56", DB_PATH) == "Cisco Systems, Inc"
        assert ouidb.lookup("00:00:0C:12:34:56", os.fsencode(DB_PATH)) == "Cisco Systems, Inc"
        res = ouidb.lookup_ex("00:00:0C:12:34:56", DB_PATH)
        assert res is not None and res.vendor == "Cisco Systems, Inc" and res.prefix_bits == 24
        entry = ouidb.lookup_entry("00:00:0C:12:34:56", DB_PATH)
        assert entry == ouidb.OuiEntry("MA-L", 0x00000C, 24, "00:00:0C", 116, 0, "Cisco Systems, Inc")
        assert ouidb.summary(DB_PATH).startswith("Magic: b'SOUI' | Ver: 1\n")

        sio = io.StringIO()
        assert ouidb.print_summary(DB_PATH, stream=sio) == ouidb.OUI_OK
        assert sio.getvalue().startswith("Magic: b'SOUI' | Ver: 1\n")

        sio_dump = io.StringIO()
        ouidb.dump_soui(DB_PATH, stream=sio_dump)
        assert sio_dump.getvalue().count("\n") == 58197

        # Re-initializing an already-mapped oui_db_t works cleanly, and passing byref(raw_db) works
        raw_db = ouidb.oui_db_t()
        assert ouidb.oui_db_init(DB_PATH, raw_db) == ouidb.OUI_OK
        assert ouidb.oui_db_init(DB_PATH, raw_db) == ouidb.OUI_OK
        assert ouidb.lookup("00:00:0C:12:34:56", ctypes.byref(raw_db)) == "Cisco Systems, Inc"
        assert ouidb.lookup("00:00:0C:12:34:56", ctypes.pointer(raw_db)) == "Cisco Systems, Inc"
        ouidb.oui_db_deinit(raw_db)

        # Sequence with bool/float/str elements rejected by parse_mac
        for bad_seq in (
            [True, 0, 0, 0, 0, 0],
            [1.5, 0, 0, 0, 0, 0],
            ["00", "00", "0C", "12", "34", "56"],
        ):
            with pytest.raises(ValueError):
                ouidb.parse_mac(bad_seq)


class TestReadmeHighLevelLookup:
    def test_readme_high_level_lookup_details(self) -> None:
        with ouidb.OuiDb(DB_PATH) as db:
            res = db.lookup("B0:10:41:12:34:56")
            assert isinstance(res, ouidb.LookupResult)
            assert (
                res.vendor,
                res.manufacturer,
                res.table,
                res.prefix,
                res.prefix_bits,
                res.prefix_str,
                res.oui,
                res.str_off,
                res.flags,
                res.device_type,
                res.category_label,
                res.is_surveillance,
            ) == (
                "Flock Safety",
                "Flock Safety",
                "MA-L",
                0xB01041,
                24,
                "B0:10:41",
                "B0:10:41",
                402565,
                ouidb.OUI_SURV_ALPR,
                "alpr",
                "alpr",
                True,
            )
            assert res.to_dict() == {
                "vendor": "Flock Safety",
                "manufacturer": "Flock Safety",
                "flags": 2,
                "device_type": "alpr",
                "category": "alpr",
                "category_label": "alpr",
                "surv_category": 2,
                "is_surveillance": True,
                "table": "MA-L",
                "prefix": 0xB01041,
                "prefix_bits": 24,
                "prefix_str": "B0:10:41",
                "oui": "B0:10:41",
                "str_off": 402565,
            }
            assert res.format_tsv("B0:10:41:12:34:56") == (
                "B0:10:41:12:34:56\tMA-L\tB0:10:41\t/24\t0x02\talpr\t402565\tFlock Safety"
            )
            assert "B0:10:41:12:34:56" in db
            assert db["3C:5A:37:00:11:22"].vendor == "Samsung Electronics Co.,Ltd"
            assert db.lookup_vendor("B0:10:41:12:34:56") == "Flock Safety"




