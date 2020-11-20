#ifndef SSLMODULE_H
#define SSLMODULE_H
#ifdef __cplusplus
extern "C" {
#endif

/* OpenSSL header files */
#include "openssl/evp.h"
#include "openssl/x509.h"

enum py_ssl_filetype {
    PY_SSL_FILETYPE_PEM=X509_FILETYPE_PEM,
    PY_SSL_FILETYPE_ASN1=X509_FILETYPE_ASN1,
    PY_SSL_FILETYPE_PEM_AUX=X509_FILETYPE_PEM + 0x100,
};

typedef struct {
    PyObject_HEAD
    EVP_PKEY *pkey;
} PySSLPrivateKey;

typedef struct {
    PyObject_HEAD
    X509 *cert;
    Py_hash_t hash;
} PySSLCertificate;

/* ************************************************************************
 * helpers and utils
 */
static BIO *_PySSL_filebio(PyObject *path);
static BIO *_PySSL_bufferbio(Py_buffer *b);
static PyObject *_PySSL_BytesFromBIO(BIO *bio);
#if 0
static PyObject *_PySSL_UnicodeFromBIO(BIO *bio, const char *error);
#endif

/* ************************************************************************
 * password callback
 */

typedef struct {
    PyThreadState *thread_state;
    PyObject *callable;
    char *password;
    int size;
    int error;
} PySSLPasswordInfo;

#define PYSSL_PWINFO_INIT(pw_info, password, err)             \
    if ((password) && (password) != Py_None) {                \
        if (PyCallable_Check(password)) {                     \
            (pw_info)->callable = (password);                 \
        } else if (!PySSL_pwinfo_set((pw_info), (password),   \
                                "password should be a string or callable")) { \
            return (err);                                     \
        }                                                     \
    }

#define PYSSL_PWINFO_ERROR(pw_info)                    \
    if ((pw_info)->error) {                             \
        /* the password callback has already set the error information */ \
        ERR_clear_error();                              \
    }                                                   \
    else if (errno != 0) {                              \
        ERR_clear_error();                              \
        PyErr_SetFromErrno(PyExc_OSError);              \
    }                                                   \
    else {                                              \
        _setSSLError(NULL, 0, __FILE__, __LINE__);      \
    }

static int
PySSL_pwinfo_set(PySSLPasswordInfo *pw_info, PyObject* password,
                 const char *bad_type_error);
static int
PySSL_password_cb(char *buf, int size, int rwflag, void *userdata);

#ifdef __cplusplus
}
#endif
#endif /* SSLMODULE_H */
