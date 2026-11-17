# Linux `amd64` Port (`oui_db.c` / `oui_db.h`) & Comparison

`oui_db.h` and `oui_db.c` have been ported from ESP-IDF (`esp_partition_mmap`) to Linux `amd64` (POSIX `mmap`) and extended with library and CLI capabilities matching `final_oui_db.py` and `dump_ouidb.py`.

## Summary of Port Changes

1. **Header & Types (`oui_db.h`)**
   - Replaced ESP-IDF headers (`esp_err.h`, `esp_partition.h`) with standard C headers (`<stdint.h>`, `<stdbool.h>`, `<stddef.h>`, `<stdio.h>`).
   - Added `oui_err_t` status codes (`OUI_OK`, `OUI_ERR_INVALID_ARG`, `OUI_ERR_NOT_FOUND`, `OUI_ERR_IO`, `OUI_ERR_INVALID_VERSION`, `OUI_ERR_INVALID_SIZE`) along with backwards-compatible `esp_err_t` / `ESP_OK` aliases.
   - Replaced `esp_partition_mmap_handle_t` in `oui_db_t` with `size_t size` for POSIX `munmap`.
   - Added surveillance category constants (`OUI_SURV_NONE` .. `OUI_SURV_BODYCAM`) and `oui_surv_category_label`.
   - Declared `oui_db_lookup_ex`, `oui_db_print_summary`, `oui_db_dump`, and `oui_db_parse_mac`.

2. **Implementation & CLI (`oui_db.c`)**
   - **Memory Mapping & Validation (`oui_db_init`, `oui_db_deinit`):** Uses `open` + `fstat` + `mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0)`. Validates the 40-byte `SOUI` v1 header, section bounds (`MA-L`, `MA-M`, `MA-S`, string pool), trailing NUL termination of the string pool, prefix bit-width bounds (`24`, `28`, `36` bits), `str_off < str_size`, and strict ascending prefix sort order across all three tables. Uses `<endian.h>` (`le32toh`, `le64toh`) for explicit little-endian decoding.
   - **Longest-Prefix Lookup (`oui_db_lookup_ex`, `oui_db_lookup`):** Performs $O(\log N)$ binary search in specificity order (`MA-S /36` -> `MA-M /28` -> `MA-L /24`) using unsigned midpoint arithmetic (`lo + ((hi - lo) >> 1)`).
   - **Summary & Dump (`oui_db_print_summary`, `oui_db_dump`):** Reproduces the exact output of `final_oui_db.py` and `dump_ouidb.py`.
   - **Weak `main` CLI (`main`):** Marked `__attribute__((weak))` so `oui_db.c` can be linked into other binaries as a library or compiled directly into a standalone CLI utility supporting `--summary` (`-s`), `--dump` (`-d`), and `--lookup <MAC>` (`-l <MAC>`).

## Feature Comparison: `oui_db.c` / `oui_db.h` vs `dump_ouidb.py` vs `final_oui_db.py`

| Feature / Aspect | `oui_db.c` & `oui_db.h` (Linux amd64 Port) | `dump_ouidb.py` | `final_oui_db.py` |
| :--- | :--- | :--- | :--- |
| **Primary Role** | Embeddable zero-copy C library + standalone CLI (`--summary`, `--dump`, `--lookup`). | Standalone script that dumps all records across `MA-L`, `MA-M`, and `MA-S` as TSV. | Diagnostic script that inspects the 40-byte header and prints the first 5 raw records per table. |
| **Memory & I/O Model** | Zero-copy read-only POSIX `mmap` (`PROT_READ`, `MAP_PRIVATE`); zero heap allocations. | Reads entire 1.36 MB file into heap (`f.read()`) and allocates strings per entry. | Reads entire 1.36 MB file into heap (`f.read()`) and slices the first 5 records per table. |
| **MAC Longest-Prefix Lookup** | $O(\log N)$ binary search (`MA-S /36` -> `MA-M /28` -> `MA-L /24`) via `oui_db_lookup` & `oui_db_lookup_ex`. | Not supported (linear full-table iteration only). | Not supported. |
| **Header Summary & Sample Hex** | `oui_db_print_summary` (`--summary`): byte-for-byte identical output to `final_oui_db.py`, bounded to `min(cnt, 5)`. | Not supported. | Prints header fields and first 5 raw records per table (assumes `cnt >= 5`). |
| **Full TSV Database Dump** | `oui_db_dump` (`--dump`): byte-for-byte identical output to `dump_ouidb.py` across all 58,197 records. | `dump_soui`: iterates and formats all 58,197 `MA-L`, `MA-M`, and `MA-S` records as TSV. | Not supported. |
| **Format & Bounds Validation** | Validates regular file, size >= 40 B, `SOUI` magic, version & padding, section bounds, string pool NUL termination, `str_off < str_size`, prefix bit-widths, and ascending sort order. | Only checks `magic == b"SOUI"`. | None (blindly unpacks `<4s9I` from hardcoded `"oui_db.bin"`). |

## Build & Usage on Linux `amd64`

```bash
# Compile standalone CLI (or link oui_db.c into another target)
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 oui_db.c -o oui_db_cli

# 1. Header summary + first 5 raw records per table (matches final_oui_db.py)
./oui_db_cli --summary oui_db.bin

# 2. Full TSV dump of all 58,197 prefixes (matches dump_ouidb.py)
./oui_db_cli --dump oui_db.bin

# 3. Longest-prefix MAC lookup (/36 -> /28 -> /24)
./oui_db_cli --lookup B0:10:41:12:34:56 oui_db.bin
```

---

# Python Bindings (`spectramesh_ouidb`)

Python bindings for `oui_db.c` and `oui_db_cli` are provided in `spectramesh_ouidb`.

## Files Created & Updated

1. **`spectramesh_ouidb.py`** — Main Python bindings module providing:
   - **1:1 Low-Level C API Bindings (matching `oui_db.h`)**:
     - `oui_db_init`, `oui_db_deinit`, `oui_db_lookup`, `oui_db_lookup_ex`, `oui_db_lookup_entry`, `oui_surv_category_label`, `oui_db_print_summary`, `oui_db_dump`, and `oui_db_parse_mac`.
     - `ctypes` structure definitions matching the packed C layout: `soui_header_t` (40 B), `soui_entry32_t` (9 B), `soui_entry64_t` (13 B), `oui_db_t`, and `oui_entry_t`.
     - Constants & enums: `OuiErr`, `SurvCategory`, `SOUI_MAGIC`, `SOUI_VERSION`, `OUI_OK`, `OUI_ERR_*`, `ESP_OK`, `ESP_ERR_*`, and `OUI_SURV_*`.
   - **High-Level Pythonic API**:
     - `OuiDb` (with aliases `OUIDB`, `OuiDatabase`, `SOUIDatabase`): context-managed, thread-safe wrapper over `oui_db_t` supporting `.lookup(mac)`, `.lookup_ex(mac)`, `.lookup_entry(mac)`, `.lookup_vendor(mac)`, `db[mac]`, `mac in db`, `len(db)`, `.header`, `.summary()`, `.print_summary()`, `.dump()`, `.iter_mal()`, `.iter_mam()`, `.iter_mas()`, and `.iter_entries()`.
     - Structured types: `LookupResult` (exposing `vendor`/`manufacturer`, `device_type`/`category`/`category_label`, `flags`, `surv_category`, `is_surveillance`, `table`, `prefix`, `prefix_bits`, `prefix_str`/`oui`, `str_off`, `entry`, `to_dict()`, `format_tsv()`), `OuiHeader`, `OuiEntry`, and exception hierarchy `OuiError`.
     - Module-level convenience functions: `lookup`, `lookup_ex`, `lookup_entry`, `parse_mac`, `format_mac`, `summary`, `print_summary`, `dump`, and `dump_soui`.
   - **CLI Bindings for `oui_db_cli`**:
     - `main` (`python3 -m spectramesh_ouidb`), `c_main` (invokes C `main(argc, argv)` in-process), and `run_cli` (runs `oui_db_cli` binary with fallback).

2. **`_spectramesh_ouidb.c`**, **`setup.py`**, **`pyproject.toml`** — CPython C extension (`_spectramesh_ouidb*.so`) and shared library (`liboui_db.so`) build configuration.
3. **`test_spectramesh_ouidb.py`** — 60+ unit and parity tests covering C structs, MAC parsing, longest-prefix lookup (`/36` -> `/28` -> `/24`), full OUI entry metadata, thread safety, error handling, and byte-for-byte parity with `oui_db_cli`, `final_oui_db.py`, and `dump_ouidb.py`.

## Usage Examples

```python
import spectramesh_ouidb as ouidb

# 1. High-level context manager API
with ouidb.OuiDb("oui_db.bin") as db:
    res = db.lookup("B0:10:41:12:34:56")
    print(res.manufacturer, res.table, res.oui, res.prefix_bits, res.device_type, res.str_off, res.is_surveillance)
    # -> Flock Safety MA-L B0:10:41 24 alpr 402565 True

    # Dict-style lookup & membership check
    assert "B0:10:41:12:34:56" in db
    print(db["3C:5A:37:00:11:22"].to_dict())

# 2. Low-level 1:1 C API (matching oui_db.h)
raw_db = ouidb.oui_db_t()
assert ouidb.oui_db_init("oui_db.bin", raw_db) == ouidb.OUI_OK
vendor, flags, bits = ouidb.oui_db_lookup_ex(raw_db, b"\xb0\x10\x41\x12\x34\x56")
ouidb.oui_db_deinit(raw_db)
```

```bash
# CLI usage (matches ./oui_db_cli byte-for-byte)
python3 -m spectramesh_ouidb --summary oui_db.bin
python3 -m spectramesh_ouidb --dump oui_db.bin
python3 -m spectramesh_ouidb --lookup B0:10:41:12:34:56 oui_db.bin
```

