#include "Python.h"
#include "openssl/bio.h"
#include "openssl/pem.h"

/*[clinic input]
module _ssl
class _ssl.Certificate "PySSLCertificate *" "&PySSLCertificate_Type"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=0edacfebfc6bac7b]*/

#include "clinic/cert.c.h"

static PyObject *
newCertificate(PyTypeObject *type, X509 *cert, int upref)
{
    PySSLCertificate *self;

    assert(type != NULL && type->tp_alloc != NULL);
    assert(cert != NULL);

    self = (PySSLCertificate *) type->tp_alloc(type, 0);
    if (self == NULL) {
        return NULL;
    }
    if (upref) {
        X509_up_ref(cert);
    }
    self->cert = cert;
    self->hash = -1;

    return (PyObject *) self;
}

static PyObject *
_PySSL_CertificateFromX509(X509 *cert, int upref)
{
    return newCertificate(&PySSLCertificate_Type, cert, upref);
}

static PyObject*
_PySSL_CertificateFromX509Stack(STACK_OF(X509) *stack, int upref)
{
    int len, i;
    PyObject *result = NULL;

    len = sk_X509_num(stack);
    result = PyTuple_New(len);
    if (result == NULL) {
        return NULL;
    }
    for (i = 0; i < len; i++) {
        X509 *cert = sk_X509_value(stack, i);
        PyObject *ocert = _PySSL_CertificateFromX509(cert, upref);
        if (ocert == NULL) {
            Py_DECREF(result);
            return NULL;
        }
        PyTuple_SET_ITEM(result, i, ocert);
    }
    return result;
}

/* ************************************************************************
 * cert from file/buffer
 */

static X509 *
read_cert_bio(BIO *bio, int format, _PySSLPasswordInfo *pw_info)
{
    X509 *cert = NULL;

    switch(format) {
    case PY_SSL_FILETYPE_PEM:
        PySSL_BEGIN_ALLOW_THREADS_S(pw_info->thread_state);
        cert = PEM_read_bio_X509(bio, NULL, _password_callback, &pw_info);
        PySSL_END_ALLOW_THREADS_S(pw_info->thread_state);
        break;
    case PY_SSL_FILETYPE_PEM_AUX:
        PySSL_BEGIN_ALLOW_THREADS_S(pw_info->thread_state);
        cert = PEM_read_bio_X509_AUX(bio, NULL, _password_callback, &pw_info);
        PySSL_END_ALLOW_THREADS_S(pw_info->thread_state);
        break;
    case PY_SSL_FILETYPE_ASN1:
        PySSL_BEGIN_ALLOW_THREADS_S(pw_info->thread_state);
        cert = d2i_X509_bio(bio, NULL);
        PySSL_END_ALLOW_THREADS_S(pw_info->thread_state);
        break;
    default:
        PyErr_SetString(PyExc_ValueError, "Unsupported format");
        return NULL;
    }

    if (cert == NULL) {
        _PWINFO_ERROR(pw_info)
        return NULL;
    }
    return cert;
}

/*[clinic input]
@classmethod
_ssl.Certificate.from_file
    path: object(converter="PyUnicode_FSConverter")
    *
    password: object = None
    format: int(c_default="PY_SSL_FILETYPE_PEM") = FILETYPE_PEM

[clinic start generated code]*/

static PyObject *
_ssl_Certificate_from_file_impl(PyTypeObject *type, PyObject *path,
                                PyObject *password, int format)
/*[clinic end generated code: output=9df64b603c7d0682 input=77eaf44d6c8fc08a]*/
{
    X509 *cert = NULL;
    BIO *bio;
    _PySSLPasswordInfo pw_info = { NULL, NULL, NULL, 0, 0 };

    _PWINFO_INIT(&pw_info, password, NULL)

    bio = _PySSL_filebio(path);
    if (bio == NULL) {
        return NULL;
    }
    cert = read_cert_bio(bio, format, &pw_info);
    BIO_free(bio);
    if (cert == NULL) {
        return NULL;
    }
    return newCertificate(type, cert, 0);
}

/*[clinic input]
@classmethod
_ssl.Certificate.from_buffer
    buffer: Py_buffer
    *
    password: object = None
    format: int(c_default="PY_SSL_FILETYPE_PEM") = FILETYPE_PEM
[clinic start generated code]*/

static PyObject *
_ssl_Certificate_from_buffer_impl(PyTypeObject *type, Py_buffer *buffer,
                                  PyObject *password, int format)
/*[clinic end generated code: output=0d128f7dea77b889 input=db4ff53f29c7cccd]*/
{
    X509 *cert = NULL;
    BIO *bio;
    _PySSLPasswordInfo pw_info = { NULL, NULL, NULL, 0, 0 };

    _PWINFO_INIT(&pw_info, password, NULL)

    bio = _PySSL_bufferbio(buffer);
    if (bio == NULL) {
        return NULL;
    }
    cert = read_cert_bio(bio, format, &pw_info);
    BIO_free(bio);
    if (cert == NULL) {
        return NULL;
    }
    return newCertificate(type, cert, 0);
}

/* ************************************************************************
 * cert chain from file/buffer
 */

static PyObject *
read_certchain_bio(PyTypeObject *type, BIO *bio, _PySSLPasswordInfo *pw_info)
{
    PyObject *lst, *certob;
    X509 *cert;
    int rescode;
    int count = 0;

    lst = PyList_New(0);
    if (lst == NULL) {
        return NULL;
    }

    while (1) {
        PySSL_BEGIN_ALLOW_THREADS_S(pw_info->thread_state);
        if (count == 0)
            /* End-entity cert uses AUX */
            cert = PEM_read_bio_X509_AUX(bio, NULL, _password_callback, &pw_info);
        else
            /* The rest of the chain doesn't use AUX */
            cert = PEM_read_bio_X509(bio, NULL, _password_callback, &pw_info);
        PySSL_END_ALLOW_THREADS_S(pw_info->thread_state);

        if (cert == NULL) {
            if (count == 0) {
                /* First cert must load */
                _PWINFO_ERROR(pw_info)
                goto error;
            }
            else {
                /* Read cert 1..n until EOF is reached. */
                int err = ERR_peek_last_error();
                if (ERR_GET_LIB(err) == ERR_LIB_PEM
                        && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
                    /* EOF, return result as tuple */
                    PyObject *tup;
                    ERR_clear_error();
                    tup = PyList_AsTuple(lst);
                    Py_DECREF(lst);
                    return tup;
                } else {
                    _PWINFO_ERROR(pw_info)
                    goto error;
                }
            }
        }
        certob = newCertificate(type, cert, 0);
        if (certob == NULL) {
            goto error;
        }
        rescode = PyList_Append(lst, certob);
        Py_DECREF(certob);
        if (rescode < 0) {
            goto error;
        }
        count++;
    }
    Py_UNREACHABLE();
  error:
    Py_DECREF(lst);
    return NULL;
}

/*[clinic input]
@classmethod
_ssl.Certificate.chain_from_file
    path: object(converter="PyUnicode_FSConverter")
    *
    password: object = None
[clinic start generated code]*/

static PyObject *
_ssl_Certificate_chain_from_file_impl(PyTypeObject *type, PyObject *path,
                                      PyObject *password)
/*[clinic end generated code: output=4883269e5ed24b7e input=8fe5316e08838397]*/
{
    PyObject *chain;
    BIO *bio;
    _PySSLPasswordInfo pw_info = { NULL, NULL, NULL, 0, 0 };

    _PWINFO_INIT(&pw_info, password, NULL)

    bio = _PySSL_filebio(path);
    if (bio == NULL) {
        return NULL;
    }
    chain = read_certchain_bio(type, bio, &pw_info);
    BIO_free(bio);
    return chain;
}

/*[clinic input]
@classmethod
_ssl.Certificate.chain_from_buffer
    buffer: Py_buffer
    *
    password: object = None
[clinic start generated code]*/

static PyObject *
_ssl_Certificate_chain_from_buffer_impl(PyTypeObject *type,
                                        Py_buffer *buffer,
                                        PyObject *password)
/*[clinic end generated code: output=87aef8e4712fafcd input=efccb0e903a4ae73]*/
{
    PyObject *chain;
    BIO *bio;
    _PySSLPasswordInfo pw_info = { NULL, NULL, NULL, 0, 0 };

    _PWINFO_INIT(&pw_info, password, NULL)

    bio = _PySSL_bufferbio(buffer);
    if (bio == NULL) {
        return NULL;
    }
    chain = read_certchain_bio(type, bio, &pw_info);
    BIO_free(bio);
    return chain;
}

/* ************************************************************************
 * certs from file/buffer, returns List[Certificate]
 */

static PyObject *
read_certs_bio(PyTypeObject *type, BIO *bio, int format, _PySSLPasswordInfo *pw_info)
{
    PyObject *lst, *certob;
    X509 *cert;
    int rescode;
    int count = 0;

    if (format != PY_SSL_FILETYPE_PEM_AUX && format != PY_SSL_FILETYPE_PEM) {
        PyErr_SetString(PyExc_ValueError, "Unsupported format");
        return NULL;
    }

    lst = PyList_New(0);
    if (lst == NULL) {
        return NULL;
    }

    while (1) {
        PySSL_BEGIN_ALLOW_THREADS_S(pw_info->thread_state);
        if (format == PY_SSL_FILETYPE_PEM)
            cert = PEM_read_bio_X509_AUX(bio, NULL, _password_callback, &pw_info);
        else
            cert = PEM_read_bio_X509(bio, NULL, _password_callback, &pw_info);
        PySSL_END_ALLOW_THREADS_S(pw_info->thread_state);

        if (cert == NULL) {
            int err = ERR_peek_last_error();
            if (ERR_GET_LIB(err) == ERR_LIB_PEM
                    && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
                /* EOF, return result as list */
                ERR_clear_error();
                return lst;
            } else {
                _PWINFO_ERROR(pw_info)
                goto error;
            }
        }
        certob = newCertificate(type, cert, 0);
        if (certob == NULL) {
            goto error;
        }
        rescode = PyList_Append(lst, certob);
        Py_DECREF(certob);
        if (rescode < 0) {
            goto error;
        }
        count++;
    }
    Py_UNREACHABLE();
  error:
    Py_DECREF(lst);
    return NULL;
}

/*[clinic input]
@classmethod
_ssl.Certificate.certs_from_file
    path: object(converter="PyUnicode_FSConverter")
    *
    password: object = None
    format: int(c_default="PY_SSL_FILETYPE_PEM") = FILETYPE_PEM
[clinic start generated code]*/

static PyObject *
_ssl_Certificate_certs_from_file_impl(PyTypeObject *type, PyObject *path,
                                      PyObject *password, int format)
/*[clinic end generated code: output=921810181d888f13 input=efc7b1f894be9b08]*/
{
    PyObject *certs;
    BIO *bio;
    _PySSLPasswordInfo pw_info = { NULL, NULL, NULL, 0, 0 };

    _PWINFO_INIT(&pw_info, password, NULL)

    bio = _PySSL_filebio(path);
    if (bio == NULL) {
        return NULL;
    }
    certs = read_certs_bio(type, bio, format, &pw_info);
    BIO_free(bio);
    return certs;
}

/*[clinic input]
@classmethod
_ssl.Certificate.certs_from_buffer
    buffer: Py_buffer
    *
    password: object = None
    format: int(c_default="PY_SSL_FILETYPE_PEM") = FILETYPE_PEM
[clinic start generated code]*/

static PyObject *
_ssl_Certificate_certs_from_buffer_impl(PyTypeObject *type,
                                        Py_buffer *buffer,
                                        PyObject *password, int format)
/*[clinic end generated code: output=eec09ea4dee51fc6 input=a97215f252b3736d]*/
{
    PyObject *certs;
    BIO *bio;
    _PySSLPasswordInfo pw_info = { NULL, NULL, NULL, 0, 0 };

    _PWINFO_INIT(&pw_info, password, NULL)

    bio = _PySSL_bufferbio(buffer);
    if (bio == NULL) {
        return NULL;
    }
    certs = read_certs_bio(type, bio, format, &pw_info);
    BIO_free(bio);
    return certs;
}

/* ************************************************************************
 * misc methods
 */

/*[clinic input]
_ssl.Certificate.check_hostname
    hostname: str(encoding='idna', accept={bytes, bytearray, str})
    *
    flags: unsigned_int(bitwise=True) = 0

[clinic start generated code]*/

static PyObject *
_ssl_Certificate_check_hostname_impl(PySSLCertificate *self, char *hostname,
                                     unsigned int flags)
/*[clinic end generated code: output=ba5a8a01cb6ef23c input=68769dc729509c7b]*/
{
    int retcode;
    char *peername = NULL;
    PyObject *result;

    retcode = X509_check_host(self->cert, hostname, strlen(hostname), flags, &peername);
    if (retcode != 1) {
        if (peername != NULL) {
            OPENSSL_free(peername);
        }
        Py_RETURN_FALSE;
    }
    assert(peername);
    result = PyUnicode_FromString(peername);
    OPENSSL_free(peername);
    return result;
}

/*[clinic input]
_ssl.Certificate.check_ipaddress
    address: str
    *
    flags: unsigned_int(bitwise=True) = 0

[clinic start generated code]*/

static PyObject *
_ssl_Certificate_check_ipaddress_impl(PySSLCertificate *self,
                                      const char *address,
                                      unsigned int flags)
/*[clinic end generated code: output=c85f838ca66238dd input=98eb596458ecbc68]*/
{
    int retcode;
    retcode = X509_check_ip_asc(self->cert, address, flags);
    if (retcode != 1) {
        Py_RETURN_FALSE;
    }
    Py_RETURN_TRUE;
}

/*[clinic input]
_ssl.Certificate.dump
    format: int(c_default="PY_SSL_FILETYPE_PEM") = FILETYPE_PEM

[clinic start generated code]*/

static PyObject *
_ssl_Certificate_dump_impl(PySSLCertificate *self, int format)
/*[clinic end generated code: output=649b76177e62bacd input=656449ea0d5abfc8]*/
{
    BIO *bio;
    int retcode;
    PyObject *result;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        PyErr_SetString(PySSLErrorObject,
                        "failed to allocate BIO");
        return NULL;
    }
    /* release GIL? */
    switch(format) {
    case PY_SSL_FILETYPE_PEM:
        retcode = PEM_write_bio_X509(bio, self->cert);
        break;
    case PY_SSL_FILETYPE_PEM_AUX:
        retcode = PEM_write_bio_X509_AUX(bio, self->cert);
        break;
    case PY_SSL_FILETYPE_ASN1:
        retcode = i2d_X509_bio(bio, self->cert);
        break;
    default:
        PyErr_SetString(PyExc_ValueError, "Unsupported format");
        BIO_free(bio);
        return NULL;
    }
    if (retcode != 1) {
        BIO_free(bio);
        _setSSLError(NULL, 0, __FILE__, __LINE__);
        return NULL;
    }
    result = _PySSL_BytesFromBIO(bio);
    BIO_free(bio);
    return result;
}


/*[clinic input]
_ssl.Certificate.get_info

[clinic start generated code]*/

static PyObject *
_ssl_Certificate_get_info_impl(PySSLCertificate *self)
/*[clinic end generated code: output=0f0deaac54f4408b input=ba2c1694b39d0778]*/
{
    return _decode_certificate(self->cert);
}

static PyObject*
_x509name_oneline(X509_NAME *name)
{
    char *p = NULL;
    PyObject *result = NULL;

    if ((p = X509_NAME_oneline(name, NULL, 0)) == NULL) {
        _setSSLError(NULL, 0, __FILE__, __LINE__);
        return NULL;
    }
    result = PyUnicode_DecodeUTF8(p, strlen(p), "replace");
    OPENSSL_free(p);
    return result;
}

/*[clinic input]
_ssl.Certificate.get_issuer
    oneline: bool = False
    /

[clinic start generated code]*/

static PyObject *
_ssl_Certificate_get_issuer_impl(PySSLCertificate *self, int oneline)
/*[clinic end generated code: output=20a1cae5cfdc7a7e input=5e2f2d91781843ee]*/
{
    X509_NAME *name;

    name = X509_get_issuer_name(self->cert);
    if (oneline) {
        return _x509name_oneline(name);
    } else {
        return _create_tuple_for_X509_NAME(name);
    }
}

/*[clinic input]
_ssl.Certificate.get_subject
    oneline: bool = False
    /

[clinic start generated code]*/

static PyObject *
_ssl_Certificate_get_subject_impl(PySSLCertificate *self, int oneline)
/*[clinic end generated code: output=0103882ff67c00b1 input=048da63de1b38464]*/
{
    X509_NAME *name;

    name = X509_get_subject_name(self->cert);
    if (oneline) {
        return _x509name_oneline(name);
    } else {
        return _create_tuple_for_X509_NAME(name);
    }
}

/*[clinic input]
_ssl.Certificate.get_spki

[clinic start generated code]*/

static PyObject *
_ssl_Certificate_get_spki_impl(PySSLCertificate *self)
/*[clinic end generated code: output=93ca3624873a9c0d input=342685f656a52052]*/
{
    unsigned char *buf;
    int len;
    PyObject *spki;
    X509_PUBKEY *pkey;

    pkey = X509_get_X509_PUBKEY(self->cert);
    assert(pkey != NULL);
    len = i2d_X509_PUBKEY(pkey, NULL);

    spki = PyBytes_FromStringAndSize(NULL, len);
    if (spki == NULL)
        return NULL;

    buf = (unsigned char *)PyBytes_AS_STRING(spki);
    i2d_X509_PUBKEY(pkey, &buf);
    return spki;
}

/* ************************************************************************
 * PySSLCertificate_Type
 */

static PyObject *
certificate_repr(PySSLCertificate *self)
{
    PyObject *osubject, *result;
    char *subject;

    subject = X509_NAME_oneline(X509_get_subject_name(self->cert), NULL, 0);
    osubject = PyUnicode_DecodeUTF8(subject, strlen(subject), "replace");
    OPENSSL_free(subject);
    if (osubject == NULL)
        return NULL;
    result = PyUnicode_FromFormat(
        "<%s '%S'>",
        Py_TYPE(self)->tp_name, osubject
    );
    Py_DECREF(osubject);
    return result;
}

static Py_hash_t
certificate_hash(PySSLCertificate *self)
{
    if (self->hash == (Py_hash_t)-1) {
        unsigned long hash;
        hash = X509_subject_name_hash(self->cert);
        if ((Py_hash_t)hash == (Py_hash_t)-1) {
            self->hash = -2;
        } else {
            self->hash = (Py_hash_t)hash;
        }
    }
    return self->hash;
}

static PyObject *
certificate_richcompare(PySSLCertificate *self, PyObject *other, int op)
{
    int cmp;

    if (Py_TYPE(other) != &PySSLCertificate_Type) {
        Py_RETURN_NOTIMPLEMENTED;
    }
    /* only support == and != */
    if ((op != Py_EQ) && (op != Py_NE)) {
        Py_RETURN_NOTIMPLEMENTED;
    }
    cmp = X509_cmp(self->cert, ((PySSLCertificate*)other)->cert);
    if (((op == Py_EQ) && (cmp == 0)) || ((op == Py_NE) && (cmp != 0))) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static void
certificate_dealloc(PySSLCertificate *self)
{
    X509_free(self->cert);
    Py_TYPE(self)->tp_free(self);
}

static PyGetSetDef certificate_getsetlist[] = {
    {NULL}             /* sentinel */
};

static PyMethodDef certificate_methods[] = {
    /* constructors */
    _SSL_CERTIFICATE_FROM_FILE_METHODDEF
    _SSL_CERTIFICATE_FROM_BUFFER_METHODDEF
    _SSL_CERTIFICATE_CHAIN_FROM_FILE_METHODDEF
    _SSL_CERTIFICATE_CHAIN_FROM_BUFFER_METHODDEF
    _SSL_CERTIFICATE_CERTS_FROM_FILE_METHODDEF
    _SSL_CERTIFICATE_CERTS_FROM_BUFFER_METHODDEF
    /* methods */
    _SSL_CERTIFICATE_CHECK_HOSTNAME_METHODDEF
    _SSL_CERTIFICATE_CHECK_IPADDRESS_METHODDEF
    _SSL_CERTIFICATE_DUMP_METHODDEF
    _SSL_CERTIFICATE_GET_INFO_METHODDEF
    _SSL_CERTIFICATE_GET_ISSUER_METHODDEF
    _SSL_CERTIFICATE_GET_SUBJECT_METHODDEF
    _SSL_CERTIFICATE_GET_SPKI_METHODDEF
    {NULL, NULL}
};

static PyTypeObject PySSLCertificate_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_ssl.Certificate",                        /*tp_name*/
    sizeof(PySSLCertificate),                  /*tp_basicsize*/
    0,                                         /*tp_itemsize*/
    (destructor)certificate_dealloc,           /*tp_dealloc*/
    0,                                         /*tp_print*/
    0,                                         /*tp_getattr*/
    0,                                         /*tp_setattr*/
    0,                                         /*tp_reserved*/
    (reprfunc)certificate_repr,                /*tp_repr*/
    0,                                         /*tp_as_number*/
    0,                                         /*tp_as_sequence*/
    0,                                         /*tp_as_mapping*/
    (hashfunc)certificate_hash,                /*tp_hash*/
    0,                                         /*tp_call*/
    0,                                         /*tp_str*/
    0,                                         /*tp_getattro*/
    0,                                         /*tp_setattro*/
    0,                                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,                        /*tp_flags*/
    0,                                         /*tp_doc*/
    0,                                         /*tp_traverse*/
    0,                                         /*tp_clear*/
    (richcmpfunc)certificate_richcompare,      /*tp_richcompare*/
    0,                                         /*tp_weaklistoffset*/
    0,                                         /*tp_iter*/
    0,                                         /*tp_iternext*/
    certificate_methods,                       /*tp_methods*/
    0,                                         /*tp_members*/
    certificate_getsetlist,                    /*tp_getset*/
    0,                                         /*tp_base*/
    0,                                         /*tp_dict*/
    0,                                         /*tp_descr_get*/
    0,                                         /*tp_descr_set*/
    0,                                         /*tp_dictoffset*/
    0,                                         /*tp_init*/
    0,                                         /*tp_alloc*/
    0,                                         /*tp_new*/
};
