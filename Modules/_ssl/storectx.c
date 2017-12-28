#include "Python.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"

/*[clinic input]
module _ssl
class _ssl.StoreContext "PySSLStoreContext *" "&PySSLStoreContext_Type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=607cd837981c37af]*/

/* #include "clinic/storectx.c.h" */

typedef struct {
    PyThreadState *thread_state;
    PyObject *callable;
    int error;
} PySSL_VerifyCallback_Info;

void
_PySSL_StoreContext_set(PySSLStoreContext *self, X509_STORE_CTX *storectx)
{
    self->storectx = storectx;
}

static PyObject *
_PySSL_StoreContext(PyTypeObject *type, X509_STORE_CTX *storectx)
{
    PySSLStoreContext *self;

    assert(type != NULL && type->tp_alloc != NULL);
    assert(storectx != NULL);

    self = (PySSLStoreContext *) type->tp_alloc(type, 0);
    if (self == NULL) {
        return NULL;
    }
    _PySSL_StoreContext_set(self, storectx);

    return (PyObject *) self;
}

static X509_STORE_CTX *
get_storectx(PySSLStoreContext *self)
{
    if (self->storectx == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "StoreContext is no longer available");
        return NULL;
    }
    return self->storectx;
}

static void
storectx_dealloc(PySSLStoreContext *self)
{
    Py_TYPE(self)->tp_free(self);
}

static PyObject *
get_current_issuer(PySSLStoreContext *self, void *c)
{
    X509_STORE_CTX *storectx;
    X509 *cert;

    storectx = get_storectx(self);
    if (storectx == NULL) {
        return NULL;
    }
    /* borrowed X509 */
    cert = X509_STORE_CTX_get0_current_issuer(storectx);
    return _PySSL_CertificateFromX509(cert, 1);
}

static PyObject *
get_current_subject(PySSLStoreContext *self, void *c)
{
    X509_STORE_CTX *storectx;
    X509 *cert;

    storectx = get_storectx(self);
    if (storectx == NULL) {
        return NULL;
    }
    /* borrowed X509 */
    cert = X509_STORE_CTX_get_current_cert(storectx);
    return _PySSL_CertificateFromX509(cert, 1);
}

static PyObject *
get_error(PySSLStoreContext *self, void *c)
{
    X509_STORE_CTX *storectx;
    storectx = get_storectx(self);
    if (storectx == NULL) {
        return NULL;
    }
    return PyLong_FromLong(X509_STORE_CTX_get_error(storectx));
}

static PyObject *
get_error_depth(PySSLStoreContext *self, void *c)
{
    X509_STORE_CTX *storectx;
    storectx = get_storectx(self);
    if (storectx == NULL) {
        return NULL;
    }
    return PyLong_FromLong(X509_STORE_CTX_get_error_depth(storectx));
}

static PyObject *
get_error_string(PySSLStoreContext *self, void *c)
{
    X509_STORE_CTX *storectx;
    const char *msg;

    storectx = get_storectx(self);
    if (storectx == NULL) {
        return NULL;
    }
    msg = X509_verify_cert_error_string(X509_STORE_CTX_get_error(storectx));
    return PyUnicode_FromString(msg);
}

static PyGetSetDef storectx_getsetlist[] = {
    {"current_issuer", (getter)get_current_issuer, NULL, NULL},
    {"current_subject", (getter)get_current_subject, NULL, NULL},
    {"error", (getter)get_error, NULL, NULL},
    {"error_string", (getter)get_error_string, NULL, NULL},
    {"error_depth", (getter)get_error_depth, NULL, NULL},
    {NULL}             /* sentinel */
};

static PyMethodDef storectx_methods[] = {
    {NULL, NULL}
};

static PyTypeObject PySSLStoreContext_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_ssl.StoreContext",                       /*tp_name*/
    sizeof(PySSLStoreContext),                 /*tp_basicsize*/
    0,                                         /*tp_itemsize*/
    (destructor)storectx_dealloc,              /*tp_dealloc*/
    0,                                         /*tp_print*/
    0,                                         /*tp_getattr*/
    0,                                         /*tp_setattr*/
    0,                                         /*tp_reserved*/
    0,                                         /*tp_repr*/
    0,                                         /*tp_as_number*/
    0,                                         /*tp_as_sequence*/
    0,                                         /*tp_as_mapping*/
    0,                                         /*tp_hash*/
    0,                                         /*tp_call*/
    0,                                         /*tp_str*/
    0,                                         /*tp_getattro*/
    0,                                         /*tp_setattro*/
    0,                                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,                        /*tp_flags*/
    0,                                         /*tp_doc*/
    0,                                         /*tp_traverse*/
    0,                                         /*tp_clear*/
    0,                                         /*tp_richcompare*/
    0,                                         /*tp_weaklistoffset*/
    0,                                         /*tp_iter*/
    0,                                         /*tp_iternext*/
    storectx_methods,                          /*tp_methods*/
    0,                                         /*tp_members*/
    storectx_getsetlist,                       /*tp_getset*/
    0,                                         /*tp_base*/
    0,                                         /*tp_dict*/
    0,                                         /*tp_descr_get*/
    0,                                         /*tp_descr_set*/
    0,                                         /*tp_dictoffset*/
    0,                                         /*tp_init*/
    0,                                         /*tp_alloc*/
    0,                                         /*tp_new*/
};
