#ifndef OUI_DB_H
#define OUI_DB_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SOUI_MAGIC   0x49554F53u  /* "SOUI" (little-endian) */
#define SOUI_VERSION 1u

/* Error codes (0 = success, negative = error) */
typedef int oui_err_t;

#define OUI_OK                   0
#define OUI_ERR_INVALID_ARG     -1
#define OUI_ERR_NOT_FOUND       -2
#define OUI_ERR_IO              -3
#define OUI_ERR_INVALID_VERSION -4
#define OUI_ERR_INVALID_SIZE    -5

/* Backwards-compatible ESP-IDF status aliases */
#ifndef ESP_OK
typedef int esp_err_t;
#define ESP_OK                  OUI_OK
#define ESP_ERR_INVALID_ARG     OUI_ERR_INVALID_ARG
#define ESP_ERR_NOT_FOUND       OUI_ERR_NOT_FOUND
#define ESP_ERR_INVALID_VERSION OUI_ERR_INVALID_VERSION
#define ESP_ERR_INVALID_SIZE    OUI_ERR_INVALID_SIZE
#endif

/* Surveillance category codes (stored in soui_entry*_t.flags; mirrors oui.py / oui_blob.rs) */
#define OUI_SURV_NONE      0u
#define OUI_SURV_CAMERA    1u  /* Fixed / IP / doorbell cameras */
#define OUI_SURV_ALPR      2u  /* Automated license-plate readers (e.g. Flock) */
#define OUI_SURV_DRONE     3u  /* UAS / drones */
#define OUI_SURV_TRACKER   4u  /* Item trackers (AirTag / Tile / SmartTag) */
#define OUI_SURV_ASSISTANT 5u  /* Smart speakers / voice assistants */
#define OUI_SURV_BODYCAM   6u  /* Police body cameras / conducted-energy (Axon) */

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version; /* LE: byte +4 = version (u8), byte +5 = hdr_flags (u8), +6..+7 = pad */
    uint32_t mal_count;
    uint32_t mam_count;
    uint32_t mas_count;
    uint32_t mal_offset;
    uint32_t mam_offset;
    uint32_t mas_offset;
    uint32_t str_offset;
    uint32_t str_size;
} soui_header_t;

typedef struct __attribute__((packed)) {
    uint32_t prefix;
    uint32_t str_off;
    uint8_t  flags;
} soui_entry32_t; /* 9 bytes */

typedef struct __attribute__((packed)) {
    uint64_t prefix;
    uint32_t str_off;
    uint8_t  flags;
} soui_entry64_t; /* 13 bytes */

typedef struct {
    const uint8_t        *base;
    size_t                size;
    const soui_header_t  *hdr;
    const soui_entry32_t *mal;
    const soui_entry32_t *mam;
    const soui_entry64_t *mas;
    const char           *str_pool;
} oui_db_t;

typedef struct {
    const char *table;          /* Matched IEEE table ("MA-L", "MA-M", or "MA-S") */
    uint64_t    prefix;         /* Matched 24-, 28-, or 36-bit integer prefix */
    uint8_t     prefix_bits;    /* Matched prefix length in bits (24, 28, or 36) */
    char        prefix_str[24]; /* Formatted OUI prefix ("XX:XX:XX", "XX:XX:XX:X0/28", "XX:XX:XX:XX:X0/36") */
    uint32_t    str_off;        /* Byte offset of vendor string in string pool */
    uint8_t     flags;          /* Surveillance / device category code (OUI_SURV_*) */
    const char *category;       /* Human-readable device category label ("none", "camera", "alpr", ...) */
    const char *vendor;         /* Null-terminated manufacturer / vendor string in mapped memory */
} oui_entry_t;

/**
 * @brief Memory-map the OUI database file into the Linux process address space.
 * @param path   Filesystem path to the SOUI binary image (e.g., "oui_db.bin")
 * @param out_db Pointer to caller-allocated oui_db_t context
 * @return OUI_OK (0) on success, or negative error code on failure.
 */
oui_err_t oui_db_init(const char *path, oui_db_t *out_db);

/**
 * @brief Unmap the OUI database file and clear the context.
 */
void oui_db_deinit(oui_db_t *db);

/**
 * @brief Resolve a 6-byte MAC address (longest-prefix match: MA-S /36 -> MA-M /28 -> MA-L /24).
 * @param db        Initialized database context
 * @param mac       6-byte MAC address in network byte order
 * @param out_flags Optional pointer to receive the record's trailing metadata byte
 * @return Pointer to null-terminated vendor string in mapped memory, or NULL if not found.
 */
const char *oui_db_lookup(const oui_db_t *db, const uint8_t mac[6], uint8_t *out_flags);

/**
 * @brief Extended MAC address lookup that also reports the matched prefix length (36, 28, or 24).
 */
const char *oui_db_lookup_ex(const oui_db_t *db, const uint8_t mac[6],
                             uint8_t *out_flags, uint8_t *out_prefix_bits);

/**
 * @brief Full MAC address lookup retrieving all metadata from the matched OUI entry.
 */
const char *oui_db_lookup_entry(const oui_db_t *db, const uint8_t mac[6],
                                oui_entry_t *out_entry);

/**
 * @brief Return the human-readable surveillance category label for a record flags byte.
 */
const char *oui_surv_category_label(uint8_t flags);

/**
 * @brief Print header metadata and first 5 raw records per table (equivalent to final_oui_db.py).
 */
oui_err_t oui_db_print_summary(const oui_db_t *db, FILE *stream);

/**
 * @brief Dump all MA-L, MA-M, and MA-S records in TSV format (equivalent to dump_ouidb.py).
 */
oui_err_t oui_db_dump(const oui_db_t *db, FILE *stream);

/**
 * @brief Parse a MAC string ("AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", or "AABBCCDDEEFF") into 6 bytes.
 */
bool oui_db_parse_mac(const char *mac_str, uint8_t out_mac[6]);

#ifdef __cplusplus
}
#endif

#endif /* OUI_DB_H */
