/*[clinic input]
preserve
[clinic start generated code]*/

PyDoc_STRVAR(_ssl_Certificate_from_file__doc__,
"from_file($type, /, path, *, password=None, format=FILETYPE_PEM)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_FROM_FILE_METHODDEF    \
    {"from_file", (PyCFunction)_ssl_Certificate_from_file, METH_FASTCALL|METH_KEYWORDS|METH_CLASS, _ssl_Certificate_from_file__doc__},

static PyObject *
_ssl_Certificate_from_file_impl(PyTypeObject *type, PyObject *path,
                                PyObject *password, int format);

static PyObject *
_ssl_Certificate_from_file(PyTypeObject *type, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"path", "password", "format", NULL};
    static _PyArg_Parser _parser = {"O&|$Oi:from_file", _keywords, 0};
    PyObject *path;
    PyObject *password = Py_None;
    int format = PY_SSL_FILETYPE_PEM;

    if (!_PyArg_ParseStackAndKeywords(args, nargs, kwnames, &_parser,
        PyUnicode_FSConverter, &path, &password, &format)) {
        goto exit;
    }
    return_value = _ssl_Certificate_from_file_impl(type, path, password, format);

exit:
    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_from_buffer__doc__,
"from_buffer($type, /, buffer, *, password=None, format=FILETYPE_PEM)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_FROM_BUFFER_METHODDEF    \
    {"from_buffer", (PyCFunction)_ssl_Certificate_from_buffer, METH_FASTCALL|METH_KEYWORDS|METH_CLASS, _ssl_Certificate_from_buffer__doc__},

static PyObject *
_ssl_Certificate_from_buffer_impl(PyTypeObject *type, Py_buffer *buffer,
                                  PyObject *password, int format);

static PyObject *
_ssl_Certificate_from_buffer(PyTypeObject *type, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"buffer", "password", "format", NULL};
    static _PyArg_Parser _parser = {"y*|$Oi:from_buffer", _keywords, 0};
    Py_buffer buffer = {NULL, NULL};
    PyObject *password = Py_None;
    int format = PY_SSL_FILETYPE_PEM;

    if (!_PyArg_ParseStackAndKeywords(args, nargs, kwnames, &_parser,
        &buffer, &password, &format)) {
        goto exit;
    }
    return_value = _ssl_Certificate_from_buffer_impl(type, &buffer, password, format);

exit:
    /* Cleanup for buffer */
    if (buffer.obj) {
       PyBuffer_Release(&buffer);
    }

    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_chain_from_file__doc__,
"chain_from_file($type, /, path, *, password=None)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_CHAIN_FROM_FILE_METHODDEF    \
    {"chain_from_file", (PyCFunction)_ssl_Certificate_chain_from_file, METH_FASTCALL|METH_KEYWORDS|METH_CLASS, _ssl_Certificate_chain_from_file__doc__},

static PyObject *
_ssl_Certificate_chain_from_file_impl(PyTypeObject *type, PyObject *path,
                                      PyObject *password);

static PyObject *
_ssl_Certificate_chain_from_file(PyTypeObject *type, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"path", "password", NULL};
    static _PyArg_Parser _parser = {"O&|$O:chain_from_file", _keywords, 0};
    PyObject *path;
    PyObject *password = Py_None;

    if (!_PyArg_ParseStackAndKeywords(args, nargs, kwnames, &_parser,
        PyUnicode_FSConverter, &path, &password)) {
        goto exit;
    }
    return_value = _ssl_Certificate_chain_from_file_impl(type, path, password);

exit:
    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_chain_from_buffer__doc__,
"chain_from_buffer($type, /, buffer, *, password=None)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_CHAIN_FROM_BUFFER_METHODDEF    \
    {"chain_from_buffer", (PyCFunction)_ssl_Certificate_chain_from_buffer, METH_FASTCALL|METH_KEYWORDS|METH_CLASS, _ssl_Certificate_chain_from_buffer__doc__},

static PyObject *
_ssl_Certificate_chain_from_buffer_impl(PyTypeObject *type,
                                        Py_buffer *buffer,
                                        PyObject *password);

static PyObject *
_ssl_Certificate_chain_from_buffer(PyTypeObject *type, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"buffer", "password", NULL};
    static _PyArg_Parser _parser = {"y*|$O:chain_from_buffer", _keywords, 0};
    Py_buffer buffer = {NULL, NULL};
    PyObject *password = Py_None;

    if (!_PyArg_ParseStackAndKeywords(args, nargs, kwnames, &_parser,
        &buffer, &password)) {
        goto exit;
    }
    return_value = _ssl_Certificate_chain_from_buffer_impl(type, &buffer, password);

exit:
    /* Cleanup for buffer */
    if (buffer.obj) {
       PyBuffer_Release(&buffer);
    }

    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_certs_from_file__doc__,
"certs_from_file($type, /, path, *, password=None, format=FILETYPE_PEM)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_CERTS_FROM_FILE_METHODDEF    \
    {"certs_from_file", (PyCFunction)_ssl_Certificate_certs_from_file, METH_FASTCALL|METH_KEYWORDS|METH_CLASS, _ssl_Certificate_certs_from_file__doc__},

static PyObject *
_ssl_Certificate_certs_from_file_impl(PyTypeObject *type, PyObject *path,
                                      PyObject *password, int format);

static PyObject *
_ssl_Certificate_certs_from_file(PyTypeObject *type, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"path", "password", "format", NULL};
    static _PyArg_Parser _parser = {"O&|$Oi:certs_from_file", _keywords, 0};
    PyObject *path;
    PyObject *password = Py_None;
    int format = PY_SSL_FILETYPE_PEM;

    if (!_PyArg_ParseStackAndKeywords(args, nargs, kwnames, &_parser,
        PyUnicode_FSConverter, &path, &password, &format)) {
        goto exit;
    }
    return_value = _ssl_Certificate_certs_from_file_impl(type, path, password, format);

exit:
    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_certs_from_buffer__doc__,
"certs_from_buffer($type, /, buffer, *, password=None,\n"
"                  format=FILETYPE_PEM)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_CERTS_FROM_BUFFER_METHODDEF    \
    {"certs_from_buffer", (PyCFunction)_ssl_Certificate_certs_from_buffer, METH_FASTCALL|METH_KEYWORDS|METH_CLASS, _ssl_Certificate_certs_from_buffer__doc__},

static PyObject *
_ssl_Certificate_certs_from_buffer_impl(PyTypeObject *type,
                                        Py_buffer *buffer,
                                        PyObject *password, int format);

static PyObject *
_ssl_Certificate_certs_from_buffer(PyTypeObject *type, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"buffer", "password", "format", NULL};
    static _PyArg_Parser _parser = {"y*|$Oi:certs_from_buffer", _keywords, 0};
    Py_buffer buffer = {NULL, NULL};
    PyObject *password = Py_None;
    int format = PY_SSL_FILETYPE_PEM;

    if (!_PyArg_ParseStackAndKeywords(args, nargs, kwnames, &_parser,
        &buffer, &password, &format)) {
        goto exit;
    }
    return_value = _ssl_Certificate_certs_from_buffer_impl(type, &buffer, password, format);

exit:
    /* Cleanup for buffer */
    if (buffer.obj) {
       PyBuffer_Release(&buffer);
    }

    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_check_hostname__doc__,
"check_hostname($self, /, hostname, *, flags=0)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_CHECK_HOSTNAME_METHODDEF    \
    {"check_hostname", (PyCFunction)_ssl_Certificate_check_hostname, METH_FASTCALL|METH_KEYWORDS, _ssl_Certificate_check_hostname__doc__},

static PyObject *
_ssl_Certificate_check_hostname_impl(PySSLCertificate *self, char *hostname,
                                     unsigned int flags);

static PyObject *
_ssl_Certificate_check_hostname(PySSLCertificate *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"hostname", "flags", NULL};
    static _PyArg_Parser _parser = {"et|$I:check_hostname", _keywords, 0};
    char *hostname = NULL;
    unsigned int flags = 0;

    if (!_PyArg_ParseStackAndKeywords(args, nargs, kwnames, &_parser,
        "idna", &hostname, &flags)) {
        goto exit;
    }
    return_value = _ssl_Certificate_check_hostname_impl(self, hostname, flags);

exit:
    /* Cleanup for hostname */
    if (hostname) {
       PyMem_FREE(hostname);
    }

    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_check_ipaddress__doc__,
"check_ipaddress($self, /, address, *, flags=0)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_CHECK_IPADDRESS_METHODDEF    \
    {"check_ipaddress", (PyCFunction)_ssl_Certificate_check_ipaddress, METH_FASTCALL|METH_KEYWORDS, _ssl_Certificate_check_ipaddress__doc__},

static PyObject *
_ssl_Certificate_check_ipaddress_impl(PySSLCertificate *self,
                                      const char *address,
                                      unsigned int flags);

static PyObject *
_ssl_Certificate_check_ipaddress(PySSLCertificate *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"address", "flags", NULL};
    static _PyArg_Parser _parser = {"s|$I:check_ipaddress", _keywords, 0};
    const char *address;
    unsigned int flags = 0;

    if (!_PyArg_ParseStackAndKeywords(args, nargs, kwnames, &_parser,
        &address, &flags)) {
        goto exit;
    }
    return_value = _ssl_Certificate_check_ipaddress_impl(self, address, flags);

exit:
    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_dump__doc__,
"dump($self, /, format=FILETYPE_PEM)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_DUMP_METHODDEF    \
    {"dump", (PyCFunction)_ssl_Certificate_dump, METH_FASTCALL|METH_KEYWORDS, _ssl_Certificate_dump__doc__},

static PyObject *
_ssl_Certificate_dump_impl(PySSLCertificate *self, int format);

static PyObject *
_ssl_Certificate_dump(PySSLCertificate *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"format", NULL};
    static _PyArg_Parser _parser = {"|i:dump", _keywords, 0};
    int format = PY_SSL_FILETYPE_PEM;

    if (!_PyArg_ParseStackAndKeywords(args, nargs, kwnames, &_parser,
        &format)) {
        goto exit;
    }
    return_value = _ssl_Certificate_dump_impl(self, format);

exit:
    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_get_info__doc__,
"get_info($self, /)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_GET_INFO_METHODDEF    \
    {"get_info", (PyCFunction)_ssl_Certificate_get_info, METH_NOARGS, _ssl_Certificate_get_info__doc__},

static PyObject *
_ssl_Certificate_get_info_impl(PySSLCertificate *self);

static PyObject *
_ssl_Certificate_get_info(PySSLCertificate *self, PyObject *Py_UNUSED(ignored))
{
    return _ssl_Certificate_get_info_impl(self);
}

PyDoc_STRVAR(_ssl_Certificate_get_issuer__doc__,
"get_issuer($self, oneline=False, /)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_GET_ISSUER_METHODDEF    \
    {"get_issuer", (PyCFunction)_ssl_Certificate_get_issuer, METH_FASTCALL, _ssl_Certificate_get_issuer__doc__},

static PyObject *
_ssl_Certificate_get_issuer_impl(PySSLCertificate *self, int oneline);

static PyObject *
_ssl_Certificate_get_issuer(PySSLCertificate *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    int oneline = 0;

    if (!_PyArg_ParseStack(args, nargs, "|p:get_issuer",
        &oneline)) {
        goto exit;
    }
    return_value = _ssl_Certificate_get_issuer_impl(self, oneline);

exit:
    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_get_subject__doc__,
"get_subject($self, oneline=False, /)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_GET_SUBJECT_METHODDEF    \
    {"get_subject", (PyCFunction)_ssl_Certificate_get_subject, METH_FASTCALL, _ssl_Certificate_get_subject__doc__},

static PyObject *
_ssl_Certificate_get_subject_impl(PySSLCertificate *self, int oneline);

static PyObject *
_ssl_Certificate_get_subject(PySSLCertificate *self, PyObject *const *args, Py_ssize_t nargs)
{
    PyObject *return_value = NULL;
    int oneline = 0;

    if (!_PyArg_ParseStack(args, nargs, "|p:get_subject",
        &oneline)) {
        goto exit;
    }
    return_value = _ssl_Certificate_get_subject_impl(self, oneline);

exit:
    return return_value;
}

PyDoc_STRVAR(_ssl_Certificate_get_spki__doc__,
"get_spki($self, /)\n"
"--\n"
"\n");

#define _SSL_CERTIFICATE_GET_SPKI_METHODDEF    \
    {"get_spki", (PyCFunction)_ssl_Certificate_get_spki, METH_NOARGS, _ssl_Certificate_get_spki__doc__},

static PyObject *
_ssl_Certificate_get_spki_impl(PySSLCertificate *self);

static PyObject *
_ssl_Certificate_get_spki(PySSLCertificate *self, PyObject *Py_UNUSED(ignored))
{
    return _ssl_Certificate_get_spki_impl(self);
}
/*[clinic end generated code: output=7f16ba51d9084f88 input=a9049054013a1b77]*/
