#define _GNU_SOURCE
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "oui_db.h"

#include <stdlib.h>
#include <string.h>

/*
 * C helper functions exported for both Python C-API and ctypes callers.
 * These wrap FILE*-based oui_db_print_summary / oui_db_dump using POSIX open_memstream
 * so callers can capture the exact C output into memory or redirect to Python streams.
 */
oui_err_t oui_db_summary_to_buf(const oui_db_t *db, char **out_buf, size_t *out_len)
{
    if (!db || !db->base || !out_buf || !out_len) {
        return OUI_ERR_INVALID_ARG;
    }
    *out_buf = NULL;
    *out_len = 0;

    FILE *mem = open_memstream(out_buf, out_len);
    if (!mem) {
        return OUI_ERR_IO;
    }
    oui_err_t err = oui_db_print_summary(db, mem);
    if (fclose(mem) != 0 && err == OUI_OK) {
        err = OUI_ERR_IO;
    }
    if (err != OUI_OK) {
        free(*out_buf);
        *out_buf = NULL;
        *out_len = 0;
    }
    return err;
}

oui_err_t oui_db_dump_to_buf(const oui_db_t *db, char **out_buf, size_t *out_len)
{
    if (!db || !db->base || !out_buf || !out_len) {
        return OUI_ERR_INVALID_ARG;
    }
    *out_buf = NULL;
    *out_len = 0;

    FILE *mem = open_memstream(out_buf, out_len);
    if (!mem) {
        return OUI_ERR_IO;
    }
    oui_err_t err = oui_db_dump(db, mem);
    if (fclose(mem) != 0 && err == OUI_OK) {
        err = OUI_ERR_IO;
    }
    if (err != OUI_OK) {
        free(*out_buf);
        *out_buf = NULL;
        *out_len = 0;
    }
    return err;
}

void oui_db_free_buf(void *buf)
{
    free(buf);
}

/* Python C-API wrapper: parse_mac(mac_str) -> bytes | None */
static PyObject *py_parse_mac(PyObject *Py_UNUSED(self), PyObject *arg)
{
    if (!PyUnicode_Check(arg)) {
        Py_RETURN_NONE;
    }
    Py_ssize_t len = 0;
    const char *s = PyUnicode_AsUTF8AndSize(arg, &len);
    if (!s) {
        return NULL;
    }
    /* Reject strings with embedded NUL bytes */
    if ((Py_ssize_t)strlen(s) != len) {
        Py_RETURN_NONE;
    }
    uint8_t mac[6];
    if (!oui_db_parse_mac(s, mac)) {
        Py_RETURN_NONE;
    }
    return PyBytes_FromStringAndSize((const char *)mac, 6);
}

/* Python C-API wrapper: surv_category_label(flags) -> str */
static PyObject *py_surv_category_label(PyObject *Py_UNUSED(self), PyObject *arg)
{
    long val = PyLong_AsLong(arg);
    if (val == -1 && PyErr_Occurred()) {
        return NULL;
    }
    if (val < 0 || val > 255) {
        return PyUnicode_FromString("unknown");
    }
    const char *label = oui_surv_category_label((uint8_t)val);
    return PyUnicode_FromString(label ? label : "unknown");
}

/* Python C-API wrapper: lookup_raw(db_addr, mac_bytes) -> (vendor, flags, prefix_bits, prefix, str_off) | None */
static PyObject *py_lookup_raw(PyObject *Py_UNUSED(self), PyObject *args)
{
    unsigned long long db_addr = 0;
    Py_buffer mac_buf;
    if (!PyArg_ParseTuple(args, "Ky*", &db_addr, &mac_buf)) {
        return NULL;
    }
    if (mac_buf.len != 6 || db_addr == 0) {
        PyBuffer_Release(&mac_buf);
        Py_RETURN_NONE;
    }
    const oui_db_t *db = (const oui_db_t *)(uintptr_t)db_addr;
    oui_entry_t entry;
    const char *vendor = oui_db_lookup_entry(db, (const uint8_t *)mac_buf.buf, &entry);
    PyBuffer_Release(&mac_buf);

    if (!vendor) {
        Py_RETURN_NONE;
    }
    PyObject *vendor_obj = PyUnicode_DecodeUTF8(vendor, (Py_ssize_t)strlen(vendor), "replace");
    if (!vendor_obj) {
        return NULL;
    }
    PyObject *tuple = Py_BuildValue("(NBBKI)", vendor_obj, entry.flags, entry.prefix_bits,
                                    (unsigned long long)entry.prefix, (unsigned int)entry.str_off);
    return tuple;
}

/* Python C-API wrapper: summary_str(db_addr) -> (err, text) */
static PyObject *py_summary_str(PyObject *Py_UNUSED(self), PyObject *arg)
{
    unsigned long long db_addr = PyLong_AsUnsignedLongLong(arg);
    if (db_addr == (unsigned long long)-1 && PyErr_Occurred()) {
        return NULL;
    }
    const oui_db_t *db = (const oui_db_t *)(uintptr_t)db_addr;
    char *buf = NULL;
    size_t len = 0;
    oui_err_t err = oui_db_summary_to_buf(db, &buf, &len);
    if (err != OUI_OK) {
        return Py_BuildValue("(is)", (int)err, "");
    }
    PyObject *text = PyUnicode_DecodeUTF8(buf, (Py_ssize_t)len, "replace");
    free(buf);
    if (!text) {
        return NULL;
    }
    return Py_BuildValue("(iN)", (int)err, text);
}

/* Python C-API wrapper: dump_str(db_addr) -> (err, text) */
static PyObject *py_dump_str(PyObject *Py_UNUSED(self), PyObject *arg)
{
    unsigned long long db_addr = PyLong_AsUnsignedLongLong(arg);
    if (db_addr == (unsigned long long)-1 && PyErr_Occurred()) {
        return NULL;
    }
    const oui_db_t *db = (const oui_db_t *)(uintptr_t)db_addr;
    char *buf = NULL;
    size_t len = 0;
    oui_err_t err = oui_db_dump_to_buf(db, &buf, &len);
    if (err != OUI_OK) {
        return Py_BuildValue("(is)", (int)err, "");
    }
    PyObject *text = PyUnicode_DecodeUTF8(buf, (Py_ssize_t)len, "replace");
    free(buf);
    if (!text) {
        return NULL;
    }
    return Py_BuildValue("(iN)", (int)err, text);
}

static PyMethodDef module_methods[] = {
    {"parse_mac", py_parse_mac, METH_O, "Parse MAC string into 6-byte bytes object or None."},
    {"surv_category_label", py_surv_category_label, METH_O, "Return surveillance category label for flags byte."},
    {"lookup_raw", py_lookup_raw, METH_VARARGS, "Lookup 6-byte MAC on oui_db_t pointer address."},
    {"summary_str", py_summary_str, METH_O, "Return (err, summary_str) for oui_db_t pointer address."},
    {"dump_str", py_dump_str, METH_O, "Return (err, dump_str) for oui_db_t pointer address."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "_spectramesh_ouidb",
    "Native C extension backend for spectramesh_ouidb (oui_db.c).",
    -1,
    module_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC PyInit__spectramesh_ouidb(void)
{
    PyObject *m = PyModule_Create(&module_def);
    if (!m) {
        return NULL;
    }
    PyModule_AddIntConstant(m, "SOUI_MAGIC", (long)SOUI_MAGIC);
    PyModule_AddIntConstant(m, "SOUI_VERSION", (long)SOUI_VERSION);
    PyModule_AddIntConstant(m, "OUI_OK", OUI_OK);
    PyModule_AddIntConstant(m, "OUI_ERR_INVALID_ARG", OUI_ERR_INVALID_ARG);
    PyModule_AddIntConstant(m, "OUI_ERR_NOT_FOUND", OUI_ERR_NOT_FOUND);
    PyModule_AddIntConstant(m, "OUI_ERR_IO", OUI_ERR_IO);
    PyModule_AddIntConstant(m, "OUI_ERR_INVALID_VERSION", OUI_ERR_INVALID_VERSION);
    PyModule_AddIntConstant(m, "OUI_ERR_INVALID_SIZE", OUI_ERR_INVALID_SIZE);
    PyModule_AddIntConstant(m, "OUI_SURV_NONE", OUI_SURV_NONE);
    PyModule_AddIntConstant(m, "OUI_SURV_CAMERA", OUI_SURV_CAMERA);
    PyModule_AddIntConstant(m, "OUI_SURV_ALPR", OUI_SURV_ALPR);
    PyModule_AddIntConstant(m, "OUI_SURV_DRONE", OUI_SURV_DRONE);
    PyModule_AddIntConstant(m, "OUI_SURV_TRACKER", OUI_SURV_TRACKER);
    PyModule_AddIntConstant(m, "OUI_SURV_ASSISTANT", OUI_SURV_ASSISTANT);
    PyModule_AddIntConstant(m, "OUI_SURV_BODYCAM", OUI_SURV_BODYCAM);
    return m;
}
