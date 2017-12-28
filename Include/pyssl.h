#ifndef Py_LIMITED_API
#ifndef PYSSL_H
#define PYSSL_H
#ifdef __cplusplus
extern "C" {
#endif

/* OpenSSL header files */
#include "openssl/evp.h"
#include "openssl/x509.h"

typedef struct {
    PyObject_HEAD
    EVP_PKEY *pkey;
} PySSLPrivateKey;

typedef struct {
    PyObject_HEAD
    X509 *cert;
    Py_hash_t hash;
} PySSLCertificate;


typedef struct  {
    PyTypeObject *PySSLContext_Type;
    PyTypeObject *PySSLSocket_Type;
    PyTypeObject *PySSLMemoryBIO_Type;
    PyTypeObject *PySSLSession_Type;
    PyTypeObject *PySSLPrivateKey_Type;
    PyTypeObject *PySSLCertificate_Type;
} PySSL_Types;

typedef struct {
    PyObject *sslerror;
    PyObject *certverificationerror;
    PyObject *zeroreturnerror;
    PyObject *wantreaderror;
    PyObject *wantwriteerror;
    PyObject *syscallerror;
    PyObject *eoferror;
} PySSL_Exceptions;

typedef struct {
} PySSL_Constructors;

typedef struct {
} PySSL_Getters;

/* Define structure for C API. */
typedef struct {
    PySSL_Types *types;
    PySSL_Exceptions *exceptions;
    PySSL_Constructors *constructors;
    PySSL_Getters *getters;
} PySSL_CAPI;

#define PySSL_CAPSULE_NAME "_ssl.pyssl_CAPI"

#ifdef __cplusplus
}
#endif
#endif /* PYSSL_H */
#endif /* !Py_LIMITED_API */
