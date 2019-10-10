#ifndef Py_HASHOPENSSL_H
#define Py_HASHOPENSSL_H

#include "Python.h"
#include <openssl/crypto.h>
#include <openssl/err.h>

/* LCOV_EXCL_START */
static PyObject *
_setException(PyObject *exc)
{
    unsigned long errcode;
    const char *lib, *func, *reason;

    errcode = ERR_peek_last_error();
    if (!errcode) {
        PyErr_SetString(exc, "unknown reasons");
        return NULL;
    }
    ERR_clear_error();

    lib = ERR_lib_error_string(errcode);
    func = ERR_func_error_string(errcode);
    reason = ERR_reason_error_string(errcode);

    if (lib && func) {
        PyErr_Format(exc, "[%s: %s] %s", lib, func, reason);
    }
    else if (lib) {
        PyErr_Format(exc, "[%s] %s", lib, reason);
    }
    else {
        PyErr_SetString(exc, reason);
    }
    return NULL;
}
/* LCOV_EXCL_STOP */


__attribute__((__unused__))
static int
_Py_hashlib_fips_error(PyObject *exc, char *name) {
    int result = FIPS_mode();
    if (result == 0) {
        // XXX: This function skips error checking.
        // This is only appropriate for RHEL.
        // See _hashlib.get_fips_mode for details.

        return 0;
    }
    PyErr_Format(exc, "%s is not available in FIPS mode", name);
    return 1;
}

#define FAIL_RETURN_IN_FIPS_MODE(exc, name) do { \
    if (_Py_hashlib_fips_error(exc, name)) return NULL; \
} while (0)

#endif  // !Py_HASHOPENSSL_H
