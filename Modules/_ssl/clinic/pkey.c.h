/*[clinic input]
preserve
[clinic start generated code]*/

PyDoc_STRVAR(_ssl_PrivateKey_from_file__doc__,
"from_file($type, /, path, *, password=None, format=FILETYPE_PEM)\n"
"--\n"
"\n");

#define _SSL_PRIVATEKEY_FROM_FILE_METHODDEF    \
    {"from_file", (PyCFunction)_ssl_PrivateKey_from_file, METH_FASTCALL|METH_KEYWORDS|METH_CLASS, _ssl_PrivateKey_from_file__doc__},

static PyObject *
_ssl_PrivateKey_from_file_impl(PyTypeObject *type, PyObject *path,
                               PyObject *password, int format);

static PyObject *
_ssl_PrivateKey_from_file(PyTypeObject *type, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
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
    return_value = _ssl_PrivateKey_from_file_impl(type, path, password, format);

exit:
    return return_value;
}

PyDoc_STRVAR(_ssl_PrivateKey_from_buffer__doc__,
"from_buffer($type, /, buffer, *, password=None, format=FILETYPE_PEM)\n"
"--\n"
"\n");

#define _SSL_PRIVATEKEY_FROM_BUFFER_METHODDEF    \
    {"from_buffer", (PyCFunction)_ssl_PrivateKey_from_buffer, METH_FASTCALL|METH_KEYWORDS|METH_CLASS, _ssl_PrivateKey_from_buffer__doc__},

static PyObject *
_ssl_PrivateKey_from_buffer_impl(PyTypeObject *type, Py_buffer *buffer,
                                 PyObject *password, int format);

static PyObject *
_ssl_PrivateKey_from_buffer(PyTypeObject *type, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
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
    return_value = _ssl_PrivateKey_from_buffer_impl(type, &buffer, password, format);

exit:
    /* Cleanup for buffer */
    if (buffer.obj) {
       PyBuffer_Release(&buffer);
    }

    return return_value;
}
/*[clinic end generated code: output=424b5361352fd619 input=a9049054013a1b77]*/
