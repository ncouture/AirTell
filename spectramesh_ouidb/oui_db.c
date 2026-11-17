#define _GNU_SOURCE
#include "oui_db.h"

#if defined(__linux__) || defined(__GLIBC__) || defined(__CYGWIN__)
#include <endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/endian.h>
#else
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define le32toh(x) __builtin_bswap32(x)
#define le64toh(x) __builtin_bswap64(x)
#else
#define le32toh(x) ((uint32_t)(x))
#define le64toh(x) ((uint64_t)(x))
#endif
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(soui_header_t)  == 40, "soui_header_t must be 40 bytes");
_Static_assert(sizeof(soui_entry32_t) == 9,  "soui_entry32_t must be 9 bytes");
_Static_assert(sizeof(soui_entry64_t) == 13, "soui_entry64_t must be 13 bytes");

static bool section_in_bounds(uint32_t offset, uint32_t count, size_t elem_size, size_t file_size)
{
    uint64_t total_bytes = (uint64_t)count * (uint64_t)elem_size;
    if (total_bytes > 0 && offset < sizeof(soui_header_t)) {
        return false;
    }
    return (uint64_t)offset + total_bytes <= (uint64_t)file_size;
}

static bool db_context_valid(const oui_db_t *db)
{
    if (!db || !db->base || !db->hdr || db->size < sizeof(soui_header_t)) {
        return false;
    }
    uintptr_t base_addr = (uintptr_t)db->base;
    if ((uintptr_t)db->hdr != base_addr) {
        return false;
    }
    uint32_t magic    = le32toh(db->hdr->magic);
    uint32_t ver_word = le32toh(db->hdr->version);
    uint8_t  ver_u8   = (uint8_t)(ver_word & 0xFFu);
    uint16_t ver_pad  = (uint16_t)(ver_word >> 16);
    if (magic != SOUI_MAGIC || ver_u8 != SOUI_VERSION || ver_pad != 0u) {
        return false;
    }

    uint32_t mal_count  = le32toh(db->hdr->mal_count);
    uint32_t mam_count  = le32toh(db->hdr->mam_count);
    uint32_t mas_count  = le32toh(db->hdr->mas_count);
    uint32_t mal_offset = le32toh(db->hdr->mal_offset);
    uint32_t mam_offset = le32toh(db->hdr->mam_offset);
    uint32_t mas_offset = le32toh(db->hdr->mas_offset);
    uint32_t str_offset = le32toh(db->hdr->str_offset);
    uint32_t str_size   = le32toh(db->hdr->str_size);

    if (!section_in_bounds(mal_offset, mal_count, sizeof(soui_entry32_t), db->size) ||
        !section_in_bounds(mam_offset, mam_count, sizeof(soui_entry32_t), db->size) ||
        !section_in_bounds(mas_offset, mas_count, sizeof(soui_entry64_t), db->size) ||
        !section_in_bounds(str_offset, str_size,  1u,                     db->size)) {
        return false;
    }
    if ((uintptr_t)db->mal != base_addr + mal_offset ||
        (uintptr_t)db->mam != base_addr + mam_offset ||
        (uintptr_t)db->mas != base_addr + mas_offset ||
        (uintptr_t)db->str_pool != base_addr + str_offset) {
        return false;
    }
    if (str_size > 0 && db->str_pool[str_size - 1] != '\0') {
        return false;
    }
    return true;
}

static bool validate_table32(const soui_entry32_t *table, uint32_t count,
                             uint32_t str_size, uint32_t max_prefix)
{
    uint32_t prev = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t pfx = le32toh(table[i].prefix);
        uint32_t soff = le32toh(table[i].str_off);
        if (pfx > max_prefix || soff >= str_size) {
            return false;
        }
        if (i > 0 && pfx <= prev) {
            return false;
        }
        prev = pfx;
    }
    return true;
}

static bool validate_table64(const soui_entry64_t *table, uint32_t count,
                             uint32_t str_size, uint64_t max_prefix)
{
    uint64_t prev = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t pfx = le64toh(table[i].prefix);
        uint32_t soff = le32toh(table[i].str_off);
        if (pfx > max_prefix || soff >= str_size) {
            return false;
        }
        if (i > 0 && pfx <= prev) {
            return false;
        }
        prev = pfx;
    }
    return true;
}

oui_err_t oui_db_init(const char *path, oui_db_t *out_db)
{
    if (!path || !out_db) {
        return OUI_ERR_INVALID_ARG;
    }
    memset(out_db, 0, sizeof(*out_db));

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "oui_db: failed to open '%s': %s\n", path, strerror(errno));
        return OUI_ERR_NOT_FOUND;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "oui_db: '%s' is not a regular file\n", path);
        close(fd);
        return OUI_ERR_IO;
    }

    if (st.st_size < (off_t)sizeof(soui_header_t)) {
        fprintf(stderr, "oui_db: file too small (%lld bytes, need >= %zu)\n",
                (long long)st.st_size, sizeof(soui_header_t));
        close(fd);
        return OUI_ERR_INVALID_SIZE;
    }

    size_t map_size = (size_t)st.st_size;
    void *mapped_ptr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped_ptr == MAP_FAILED) {
        fprintf(stderr, "oui_db: mmap failed: %s\n", strerror(errno));
        return OUI_ERR_IO;
    }

    const soui_header_t *hdr = (const soui_header_t *)mapped_ptr;
    uint32_t magic    = le32toh(hdr->magic);
    uint32_t ver_word = le32toh(hdr->version);
    uint8_t  ver_u8   = (uint8_t)(ver_word & 0xFFu);
    uint16_t ver_pad  = (uint16_t)(ver_word >> 16);
    if (magic != SOUI_MAGIC || ver_u8 != SOUI_VERSION || ver_pad != 0u) {
        fprintf(stderr, "oui_db: invalid header (magic=0x%08" PRIx32 ", ver=%" PRIu8 ")\n",
                magic, ver_u8);
        munmap(mapped_ptr, map_size);
        return OUI_ERR_INVALID_VERSION;
    }

    uint32_t mal_count  = le32toh(hdr->mal_count);
    uint32_t mam_count  = le32toh(hdr->mam_count);
    uint32_t mas_count  = le32toh(hdr->mas_count);
    uint32_t mal_offset = le32toh(hdr->mal_offset);
    uint32_t mam_offset = le32toh(hdr->mam_offset);
    uint32_t mas_offset = le32toh(hdr->mas_offset);
    uint32_t str_offset = le32toh(hdr->str_offset);
    uint32_t str_size   = le32toh(hdr->str_size);

    if (!section_in_bounds(mal_offset, mal_count, sizeof(soui_entry32_t), map_size) ||
        !section_in_bounds(mam_offset, mam_count, sizeof(soui_entry32_t), map_size) ||
        !section_in_bounds(mas_offset, mas_count, sizeof(soui_entry64_t), map_size) ||
        !section_in_bounds(str_offset, str_size,  1u,                     map_size)) {
        fprintf(stderr, "oui_db: truncated file (have %zu bytes)\n", map_size);
        munmap(mapped_ptr, map_size);
        return OUI_ERR_INVALID_SIZE;
    }

    const uint8_t *base = (const uint8_t *)mapped_ptr;
    const char *str_pool = (const char *)(base + str_offset);
    if (str_size > 0 && str_pool[str_size - 1] != '\0') {
        fprintf(stderr, "oui_db: string pool is missing trailing NUL terminator\n");
        munmap(mapped_ptr, map_size);
        return OUI_ERR_INVALID_SIZE;
    }

    const soui_entry32_t *mal = (const soui_entry32_t *)(base + mal_offset);
    const soui_entry32_t *mam = (const soui_entry32_t *)(base + mam_offset);
    const soui_entry64_t *mas = (const soui_entry64_t *)(base + mas_offset);

    if (!validate_table32(mal, mal_count, str_size, 0xFFFFFFu) ||
        !validate_table32(mam, mam_count, str_size, 0xFFFFFFFu) ||
        !validate_table64(mas, mas_count, str_size, 0xFFFFFFFFFull)) {
        fprintf(stderr, "oui_db: corrupted table entries (unsorted prefixes or invalid string offsets)\n");
        munmap(mapped_ptr, map_size);
        return OUI_ERR_INVALID_SIZE;
    }

    out_db->base     = base;
    out_db->size     = map_size;
    out_db->hdr      = hdr;
    out_db->mal      = mal;
    out_db->mam      = mam;
    out_db->mas      = mas;
    out_db->str_pool = str_pool;

    return OUI_OK;
}

void oui_db_deinit(oui_db_t *db)
{
    if (db) {
        if (db->base && db->size > 0) {
            munmap((void *)db->base, db->size);
        }
        memset(db, 0, sizeof(*db));
    }
}

static inline const char *resolve_str(const oui_db_t *db, uint32_t str_off,
                                      uint8_t flags, uint8_t *out_flags,
                                      uint32_t *out_str_off)
{
    if (!db->str_pool || str_off >= le32toh(db->hdr->str_size)) {
        return NULL;
    }
    if (out_flags) {
        *out_flags = flags;
    }
    if (out_str_off) {
        *out_str_off = str_off;
    }
    return db->str_pool + str_off;
}

static const char *bsearch_32(const oui_db_t *db, const soui_entry32_t *table,
                              uint32_t count, uint32_t target,
                              uint8_t *out_flags, uint32_t *out_str_off)
{
    if (!table) {
        return NULL;
    }
    uint32_t lo = 0;
    uint32_t hi = count;

    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        uint32_t key = le32toh(table[mid].prefix);
        if (key == target) {
            return resolve_str(db, le32toh(table[mid].str_off), table[mid].flags, out_flags, out_str_off);
        } else if (key < target) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return NULL;
}

static const char *bsearch_64(const oui_db_t *db, const soui_entry64_t *table,
                              uint32_t count, uint64_t target,
                              uint8_t *out_flags, uint32_t *out_str_off)
{
    if (!table) {
        return NULL;
    }
    uint32_t lo = 0;
    uint32_t hi = count;

    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        uint64_t key = le64toh(table[mid].prefix);
        if (key == target) {
            return resolve_str(db, le32toh(table[mid].str_off), table[mid].flags, out_flags, out_str_off);
        } else if (key < target) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return NULL;
}

static void format_prefix_str(uint64_t prefix, uint8_t prefix_bits, char out_str[24])
{
    if (!out_str) {
        return;
    }
    if (prefix_bits == 24) {
        snprintf(out_str, 24, "%02X:%02X:%02X",
                 (unsigned)((prefix >> 16) & 0xFFu),
                 (unsigned)((prefix >> 8) & 0xFFu),
                 (unsigned)(prefix & 0xFFu));
    } else if (prefix_bits == 28) {
        uint32_t b = (uint32_t)(prefix << 4);
        snprintf(out_str, 24, "%02X:%02X:%02X:%02X/28",
                 (unsigned)((b >> 24) & 0xFFu),
                 (unsigned)((b >> 16) & 0xFFu),
                 (unsigned)((b >> 8) & 0xFFu),
                 (unsigned)(b & 0xF0u));
    } else if (prefix_bits == 36) {
        uint64_t b = prefix << 4;
        snprintf(out_str, 24, "%02X:%02X:%02X:%02X:%02X/36",
                 (unsigned)((b >> 32) & 0xFFu),
                 (unsigned)((b >> 24) & 0xFFu),
                 (unsigned)((b >> 16) & 0xFFu),
                 (unsigned)((b >> 8) & 0xFFu),
                 (unsigned)(b & 0xF0u));
    } else {
        out_str[0] = '\0';
    }
}

const char *oui_db_lookup_entry(const oui_db_t *db, const uint8_t mac[6], oui_entry_t *out_entry)
{
    if (out_entry) {
        memset(out_entry, 0, sizeof(*out_entry));
    }
    if (!db_context_valid(db) || !mac) {
        return NULL;
    }

    uint64_t mac48 = ((uint64_t)mac[0] << 40) |
                     ((uint64_t)mac[1] << 32) |
                     ((uint64_t)mac[2] << 24) |
                     ((uint64_t)mac[3] << 16) |
                     ((uint64_t)mac[4] << 8)  |
                     ((uint64_t)mac[5]);

    uint8_t flags = 0;
    uint32_t str_off = 0;
    const char *vendor = NULL;
    const char *table_name = NULL;
    uint64_t matched_prefix = 0;
    uint8_t prefix_bits = 0;

    /* 1. Most specific: 36-bit MA-S (OUI-36) */
    uint64_t mas_key = mac48 >> 12;
    vendor = bsearch_64(db, db->mas, le32toh(db->hdr->mas_count), mas_key, &flags, &str_off);
    if (vendor) {
        table_name = "MA-S";
        matched_prefix = mas_key;
        prefix_bits = 36;
    } else {
        /* 2. Medium: 28-bit MA-M */
        uint32_t mam_key = (uint32_t)(mac48 >> 20);
        vendor = bsearch_32(db, db->mam, le32toh(db->hdr->mam_count), mam_key, &flags, &str_off);
        if (vendor) {
            table_name = "MA-M";
            matched_prefix = mam_key;
            prefix_bits = 28;
        } else {
            /* 3. Least specific: 24-bit MA-L (standard OUI) */
            uint32_t mal_key = (uint32_t)(mac48 >> 24);
            vendor = bsearch_32(db, db->mal, le32toh(db->hdr->mal_count), mal_key, &flags, &str_off);
            if (vendor) {
                table_name = "MA-L";
                matched_prefix = mal_key;
                prefix_bits = 24;
            }
        }
    }

    if (!vendor) {
        return NULL;
    }

    if (out_entry) {
        out_entry->table       = table_name;
        out_entry->prefix      = matched_prefix;
        out_entry->prefix_bits = prefix_bits;
        format_prefix_str(matched_prefix, prefix_bits, out_entry->prefix_str);
        out_entry->str_off     = str_off;
        out_entry->flags       = flags;
        out_entry->category    = oui_surv_category_label(flags);
        out_entry->vendor      = vendor;
    }
    return vendor;
}

const char *oui_db_lookup_ex(const oui_db_t *db, const uint8_t mac[6],
                             uint8_t *out_flags, uint8_t *out_prefix_bits)
{
    if (out_flags) {
        *out_flags = 0;
    }
    if (out_prefix_bits) {
        *out_prefix_bits = 0;
    }
    oui_entry_t entry;
    const char *vendor = oui_db_lookup_entry(db, mac, &entry);
    if (!vendor) {
        return NULL;
    }
    if (out_flags) {
        *out_flags = entry.flags;
    }
    if (out_prefix_bits) {
        *out_prefix_bits = entry.prefix_bits;
    }
    return vendor;
}

const char *oui_db_lookup(const oui_db_t *db, const uint8_t mac[6], uint8_t *out_flags)
{
    return oui_db_lookup_ex(db, mac, out_flags, NULL);
}

const char *oui_surv_category_label(uint8_t flags)
{
    switch (flags) {
        case OUI_SURV_NONE:      return "none";
        case OUI_SURV_CAMERA:    return "camera";
        case OUI_SURV_ALPR:      return "alpr";
        case OUI_SURV_DRONE:     return "drone";
        case OUI_SURV_TRACKER:   return "tracker";
        case OUI_SURV_ASSISTANT: return "assistant";
        case OUI_SURV_BODYCAM:   return "bodycam";
        default:                 return "unknown";
    }
}

oui_err_t oui_db_print_summary(const oui_db_t *db, FILE *stream)
{
    if (!db_context_valid(db) || !stream) {
        return OUI_ERR_INVALID_ARG;
    }

    const soui_header_t *h = db->hdr;
    const uint8_t *m = db->base;
    uint32_t ver        = le32toh(h->version);
    uint32_t mal_count  = le32toh(h->mal_count);
    uint32_t mam_count  = le32toh(h->mam_count);
    uint32_t mas_count  = le32toh(h->mas_count);
    uint32_t mal_offset = le32toh(h->mal_offset);
    uint32_t mam_offset = le32toh(h->mam_offset);
    uint32_t mas_offset = le32toh(h->mas_offset);
    uint32_t str_offset = le32toh(h->str_offset);
    uint32_t str_size   = le32toh(h->str_size);

    if (fprintf(stream, "Magic: b'%c%c%c%c' | Ver: %" PRIu32 "\n",
                (char)m[0], (char)m[1], (char)m[2], (char)m[3], ver) < 0 ||
        fprintf(stream, "Counts  -> MA-L: %" PRIu32 ", MA-M: %" PRIu32 ", MA-S: %" PRIu32 "\n",
                mal_count, mam_count, mas_count) < 0 ||
        fprintf(stream, "Offsets -> MA-L: 0x%" PRIx32 ", MA-M: 0x%" PRIx32 ", MA-S: 0x%" PRIx32 "\n",
                mal_offset, mam_offset, mas_offset) < 0 ||
        fprintf(stream, "HDR +0x20: 0x%08" PRIx32 " (%" PRIu32 ") | HDR +0x24: 0x%08" PRIx32 " (%" PRIu32 ")\n\n",
                str_offset, str_offset, str_size, str_size) < 0) {
        return OUI_ERR_IO;
    }

    const struct {
        const char *name;
        uint32_t    off;
        uint32_t    stride;
        uint32_t    cnt;
    } sections[3] = {
        { "MA-L (24b)", mal_offset, (uint32_t)sizeof(soui_entry32_t), mal_count },
        { "MA-M (28b)", mam_offset, (uint32_t)sizeof(soui_entry32_t), mam_count },
        { "MA-S (36b)", mas_offset, (uint32_t)sizeof(soui_entry64_t), mas_count },
    };

    for (size_t s = 0; s < 3; ++s) {
        if (fprintf(stream, "=== %s @ 0x%" PRIx32 " (stride=%" PRIu32 "B) ===\n",
                    sections[s].name, sections[s].off, sections[s].stride) < 0) {
            return OUI_ERR_IO;
        }
        uint32_t limit = sections[s].cnt < 5u ? sections[s].cnt : 5u;
        for (uint32_t i = 0; i < limit; ++i) {
            const uint8_t *rec = db->base + sections[s].off + (size_t)i * sections[s].stride;
            if (fprintf(stream, "  [%" PRIu32 "] raw:", i) < 0) {
                return OUI_ERR_IO;
            }
            for (uint32_t b = 0; b < sections[s].stride; ++b) {
                if (fprintf(stream, " %02x", rec[b]) < 0) {
                    return OUI_ERR_IO;
                }
            }
            if (fputc('\n', stream) == EOF) {
                return OUI_ERR_IO;
            }
        }
    }

    if (fflush(stream) != 0 || ferror(stream)) {
        return OUI_ERR_IO;
    }

    return OUI_OK;
}

oui_err_t oui_db_dump(const oui_db_t *db, FILE *stream)
{
    if (!db_context_valid(db) || !stream) {
        return OUI_ERR_INVALID_ARG;
    }

    char mac_str[24];
    const soui_header_t *h = db->hdr;
    uint32_t mal_count = le32toh(h->mal_count);
    uint32_t mam_count = le32toh(h->mam_count);
    uint32_t mas_count = le32toh(h->mas_count);

    /* 1. MA-L (24-bit OUI, 9 bytes/entry) */
    for (uint32_t i = 0; i < mal_count; ++i) {
        uint32_t pfx = le32toh(db->mal[i].prefix);
        const char *vendor = resolve_str(db, le32toh(db->mal[i].str_off), db->mal[i].flags, NULL, NULL);
        if (!vendor) {
            return OUI_ERR_INVALID_SIZE;
        }
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X",
                 (unsigned)((pfx >> 16) & 0xFFu),
                 (unsigned)((pfx >> 8) & 0xFFu),
                 (unsigned)(pfx & 0xFFu));
        if (fprintf(stream, "MA-L\t%-17s\t0x%02x\t%s\n",
                    mac_str, db->mal[i].flags, vendor) < 0) {
            return OUI_ERR_IO;
        }
    }

    /* 2. MA-M (28-bit prefix, 9 bytes/entry) */
    for (uint32_t i = 0; i < mam_count; ++i) {
        uint32_t b = le32toh(db->mam[i].prefix) << 4;
        const char *vendor = resolve_str(db, le32toh(db->mam[i].str_off), db->mam[i].flags, NULL, NULL);
        if (!vendor) {
            return OUI_ERR_INVALID_SIZE;
        }
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X/28",
                 (unsigned)((b >> 24) & 0xFFu),
                 (unsigned)((b >> 16) & 0xFFu),
                 (unsigned)((b >> 8) & 0xFFu),
                 (unsigned)(b & 0xF0u));
        if (fprintf(stream, "MA-M\t%-17s\t0x%02x\t%s\n",
                    mac_str, db->mam[i].flags, vendor) < 0) {
            return OUI_ERR_IO;
        }
    }

    /* 3. MA-S (36-bit prefix, 13 bytes/entry) */
    for (uint32_t i = 0; i < mas_count; ++i) {
        uint64_t b = le64toh(db->mas[i].prefix) << 4;
        const char *vendor = resolve_str(db, le32toh(db->mas[i].str_off), db->mas[i].flags, NULL, NULL);
        if (!vendor) {
            return OUI_ERR_INVALID_SIZE;
        }
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X/36",
                 (unsigned)((b >> 32) & 0xFFu),
                 (unsigned)((b >> 24) & 0xFFu),
                 (unsigned)((b >> 16) & 0xFFu),
                 (unsigned)((b >> 8) & 0xFFu),
                 (unsigned)(b & 0xF0u));
        if (fprintf(stream, "MA-S\t%-17s\t0x%02x\t%s\n",
                    mac_str, db->mas[i].flags, vendor) < 0) {
            return OUI_ERR_IO;
        }
    }

    if (fflush(stream) != 0 || ferror(stream)) {
        return OUI_ERR_IO;
    }

    return OUI_OK;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool oui_db_parse_mac(const char *mac_str, uint8_t out_mac[6])
{
    if (!mac_str || !out_mac) {
        return false;
    }

    uint8_t tmp[6];
    size_t len = strlen(mac_str);
    if (len == 12) {
        for (size_t i = 0; i < 6; ++i) {
            int hi = hex_nibble(mac_str[i * 2]);
            int lo = hex_nibble(mac_str[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                return false;
            }
            tmp[i] = (uint8_t)((hi << 4) | lo);
        }
        memcpy(out_mac, tmp, sizeof(tmp));
        return true;
    }

    if (len == 17) {
        char sep = mac_str[2];
        if (sep != ':' && sep != '-') {
            return false;
        }
        for (size_t i = 0; i < 6; ++i) {
            if (i > 0 && mac_str[i * 3 - 1] != sep) {
                return false;
            }
            int hi = hex_nibble(mac_str[i * 3]);
            int lo = hex_nibble(mac_str[i * 3 + 1]);
            if (hi < 0 || lo < 0) {
                return false;
            }
            tmp[i] = (uint8_t)((hi << 4) | lo);
        }
        memcpy(out_mac, tmp, sizeof(tmp));
        return true;
    }

    return false;
}

__attribute__((weak))
int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_DFL);

    const char *db_path = "oui_db.bin";
    const char *lookup_mac_str = NULL;
    enum { MODE_NONE, MODE_SUMMARY, MODE_DUMP, MODE_LOOKUP } mode = MODE_NONE;
    bool db_path_set = false;
    bool end_of_opts = false;

    for (int i = 1; i < argc; ++i) {
        if (!end_of_opts && strcmp(argv[i], "--") == 0) {
            end_of_opts = true;
            continue;
        }
        if (!end_of_opts && argv[i][0] == '-') {
            if (strcmp(argv[i], "--dump") == 0 || strcmp(argv[i], "-d") == 0) {
                if (mode != MODE_NONE && mode != MODE_DUMP) {
                    fprintf(stderr, "Usage: %s [--summary|--dump|--lookup <MAC>] [oui_db.bin]\n", argv[0]);
                    return 2;
                }
                mode = MODE_DUMP;
            } else if (strcmp(argv[i], "--summary") == 0 || strcmp(argv[i], "-s") == 0) {
                if (mode != MODE_NONE && mode != MODE_SUMMARY) {
                    fprintf(stderr, "Usage: %s [--summary|--dump|--lookup <MAC>] [oui_db.bin]\n", argv[0]);
                    return 2;
                }
                mode = MODE_SUMMARY;
            } else if (strcmp(argv[i], "--lookup") == 0 || strcmp(argv[i], "-l") == 0) {
                if (i + 1 >= argc || (mode != MODE_NONE && mode != MODE_LOOKUP) || lookup_mac_str) {
                    fprintf(stderr, "Usage: %s [--summary|--dump|--lookup <MAC>] [oui_db.bin]\n", argv[0]);
                    return 2;
                }
                mode = MODE_LOOKUP;
                lookup_mac_str = argv[++i];
            } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                printf("Usage: %s [--summary|--dump|--lookup <MAC>] [oui_db.bin]\n", argv[0]);
                return 0;
            } else {
                fprintf(stderr, "oui_db: unrecognized option '%s'\n", argv[i]);
                fprintf(stderr, "Usage: %s [--summary|--dump|--lookup <MAC>] [oui_db.bin]\n", argv[0]);
                return 2;
            }
        } else {
            uint8_t tmp_mac[6];
            if (mode == MODE_NONE && !lookup_mac_str && oui_db_parse_mac(argv[i], tmp_mac)) {
                mode = MODE_LOOKUP;
                lookup_mac_str = argv[i];
            } else if (!db_path_set) {
                db_path = argv[i];
                db_path_set = true;
            } else {
                fprintf(stderr, "oui_db: unexpected argument '%s'\n", argv[i]);
                fprintf(stderr, "Usage: %s [--summary|--dump|--lookup <MAC>] [oui_db.bin]\n", argv[0]);
                return 2;
            }
        }
    }

    if (mode == MODE_NONE) {
        mode = MODE_SUMMARY;
    }

    uint8_t parsed_mac[6];
    if (mode == MODE_LOOKUP && !oui_db_parse_mac(lookup_mac_str, parsed_mac)) {
        fprintf(stderr, "oui_db: invalid MAC address '%s'\n", lookup_mac_str);
        return 2;
    }

    oui_db_t db;
    if (oui_db_init(db_path, &db) != OUI_OK) {
        return 1;
    }

    int rc = 0;
    if (mode == MODE_DUMP) {
        if (oui_db_dump(&db, stdout) != OUI_OK) {
            rc = 1;
        }
    } else if (mode == MODE_LOOKUP) {
        oui_entry_t entry;
        const char *vendor = oui_db_lookup_entry(&db, parsed_mac, &entry);
        if (vendor) {
            if (printf("%02X:%02X:%02X:%02X:%02X:%02X\t%s\t%s\t/%u\t0x%02x\t%s\t%" PRIu32 "\t%s\n",
                       parsed_mac[0], parsed_mac[1], parsed_mac[2],
                       parsed_mac[3], parsed_mac[4], parsed_mac[5],
                       entry.table, entry.prefix_str, entry.prefix_bits,
                       entry.flags, entry.category, entry.str_off, entry.vendor) < 0 ||
                fflush(stdout) != 0 || ferror(stdout)) {
                rc = 1;
            }
        } else {
            printf("%02X:%02X:%02X:%02X:%02X:%02X\t(not found)\n",
                   parsed_mac[0], parsed_mac[1], parsed_mac[2],
                   parsed_mac[3], parsed_mac[4], parsed_mac[5]);
            fflush(stdout);
            rc = 1;
        }
    } else {
        if (oui_db_print_summary(&db, stdout) != OUI_OK) {
            rc = 1;
        }
    }

    oui_db_deinit(&db);
    return rc;
}
