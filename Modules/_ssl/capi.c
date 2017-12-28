#include "Python.h"
#include "pyssl.h"

static PySSL_Types pyssl_types = {
    &PySSLContext_Type,
    &PySSLSocket_Type,
    &PySSLMemoryBIO_Type,
    &PySSLSession_Type,
    &PySSLPrivateKey_Type,
    &PySSLCertificate_Type
};

static PySSL_Exceptions pyssl_exceptions = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

static PySSL_Constructors pyssl_constructors = {
};

static PySSL_Getters pyssl_getters = {
};

static PySSL_CAPI CAPI = {
    &pyssl_types,
    &pyssl_exceptions,
    &pyssl_constructors,
    &pyssl_getters,
};
