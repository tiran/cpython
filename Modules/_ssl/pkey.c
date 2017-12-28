#include "Python.h"
#include "pyssl.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"

/*[clinic input]
module _ssl
class _ssl.PrivateKey "PySSLPrivateKey *" "&PySSLPrivateKey_Type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=9e0c488b63c91428]*/

#include "clinic/pkey.c.h"

static PyObject *
newPrivateKey(PyTypeObject *type, EVP_PKEY *pkey, int upref)
{
    PySSLPrivateKey *self;

    assert(type != NULL && type->tp_alloc != NULL);
    assert(pkey != NULL);

    self = (PySSLPrivateKey *) type->tp_alloc(type, 0);
    if (self == NULL) {
        return NULL;
    }
    if (upref) {
       EVP_PKEY_up_ref(pkey);
    }
    self->pkey = pkey;

    return (PyObject *) self;
}

static EVP_PKEY *
read_pkey_bio(BIO *bio, int format, _PySSLPasswordInfo *pw_info)
{
    EVP_PKEY *pkey = NULL;

    switch(format) {
    case PY_SSL_FILETYPE_PEM:
        PySSL_BEGIN_ALLOW_THREADS_S(pw_info->thread_state);
        pkey = PEM_read_bio_PrivateKey(bio, NULL, _password_callback, &pw_info);
        PySSL_END_ALLOW_THREADS_S(pw_info->thread_state);
        break;
    case PY_SSL_FILETYPE_ASN1:
        PySSL_BEGIN_ALLOW_THREADS_S(pw_info->thread_state);
        pkey = d2i_PKCS8PrivateKey_bio(bio, NULL, _password_callback, &pw_info);
        PySSL_END_ALLOW_THREADS_S(pw_info->thread_state);
        break;
    default:
        PyErr_SetString(PyExc_ValueError, "Invalid format");
        return NULL;
    }

    if (pkey == NULL) {
        _PWINFO_ERROR(pw_info)
        return NULL;
    }
    return pkey;
}

/*[clinic input]
@classmethod
_ssl.PrivateKey.from_file
    path: object(converter="PyUnicode_FSConverter")
    *
    password: object = None
    format: int(c_default="PY_SSL_FILETYPE_PEM") = FILETYPE_PEM

[clinic start generated code]*/

static PyObject *
_ssl_PrivateKey_from_file_impl(PyTypeObject *type, PyObject *path,
                               PyObject *password, int format)
/*[clinic end generated code: output=5dc7bfeda73c8b4b input=1f0112f77dded55b]*/
{
    EVP_PKEY *pkey = NULL;
    BIO *bio;
    _PySSLPasswordInfo pw_info = { NULL, NULL, NULL, 0, 0 };

    _PWINFO_INIT(&pw_info, password, NULL)

    bio = _PySSL_filebio(path);
    if (bio == NULL) {
        return NULL;
    }
    pkey = read_pkey_bio(bio, format, &pw_info);
    BIO_free(bio);
    if (pkey == NULL) {
        return NULL;
    }
    return newPrivateKey(type, pkey, 0);
}

/*[clinic input]
@classmethod
_ssl.PrivateKey.from_buffer
    buffer: Py_buffer
    *
    password: object = None
    format: int(c_default="PY_SSL_FILETYPE_PEM") = FILETYPE_PEM
[clinic start generated code]*/

static PyObject *
_ssl_PrivateKey_from_buffer_impl(PyTypeObject *type, Py_buffer *buffer,
                                 PyObject *password, int format)
/*[clinic end generated code: output=e6acef288f8eff17 input=a76a6549e5381124]*/
{
    EVP_PKEY *pkey = NULL;
    BIO *bio;
    _PySSLPasswordInfo pw_info = { NULL, NULL, NULL, 0, 0 };

    _PWINFO_INIT(&pw_info, password, NULL)

    bio = _PySSL_bufferbio(buffer);
    if (bio == NULL) {
        return NULL;
    }
    pkey = read_pkey_bio(bio, format, &pw_info);
    BIO_free(bio);
    if (pkey == NULL) {
        return NULL;
    }
    return newPrivateKey(type, pkey, 0);
}

static void
pkey_dealloc(PySSLPrivateKey *self)
{
    EVP_PKEY_free(self->pkey);
    Py_TYPE(self)->tp_free(self);
}

static PyGetSetDef pkey_getsetlist[] = {
    {NULL}             /* sentinel */
};

static PyMethodDef pkey_methods[] = {
    _SSL_PRIVATEKEY_FROM_FILE_METHODDEF
    _SSL_PRIVATEKEY_FROM_BUFFER_METHODDEF
    {NULL, NULL}
};

static PyTypeObject PySSLPrivateKey_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_ssl.PrivateKey",                         /*tp_name*/
    sizeof(PySSLPrivateKey),                   /*tp_basicsize*/
    0,                                         /*tp_itemsize*/
    (destructor)pkey_dealloc,                  /*tp_dealloc*/
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
    pkey_methods,                              /*tp_methods*/
    0,                                         /*tp_members*/
    pkey_getsetlist,                           /*tp_getset*/
    0,                                         /*tp_base*/
    0,                                         /*tp_dict*/
    0,                                         /*tp_descr_get*/
    0,                                         /*tp_descr_set*/
    0,                                         /*tp_dictoffset*/
    0,                                         /*tp_init*/
    0,                                         /*tp_alloc*/
    0,                                         /*tp_new*/
};
