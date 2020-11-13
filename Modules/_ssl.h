#ifndef Py_SSL_H
#define Py_SSL_H

/*
 * ssl module state
 */

typedef struct {
    /* Types */
    PyTypeObject *PySSLContext_Type;
    PyTypeObject *PySSLSocket_Type;
    PyTypeObject *PySSLMemoryBIO_Type;
    PyTypeObject *PySSLSession_Type;
    /* SSL error object */
    PyObject *PySSLErrorObject;
    PyObject *PySSLCertVerificationErrorObject;
    PyObject *PySSLZeroReturnErrorObject;
    PyObject *PySSLWantReadErrorObject;
    PyObject *PySSLWantWriteErrorObject;
    PyObject *PySSLSyscallErrorObject;
    PyObject *PySSLEOFErrorObject;
    /* Error mappings */
    PyObject *err_codes_to_names;
    PyObject *err_names_to_codes;
    PyObject *lib_codes_to_names;
    /* socket module API */
    PySocketModule_APIObject *PySocketModule;
} _sslmodulestate;

static struct PyModuleDef _sslmodule_def;

Py_LOCAL_INLINE(_sslmodulestate*)
get_ssl_state(PyObject *module)
{
    void *state = PyModule_GetState(module);
    assert(state != NULL);
    return (_sslmodulestate *)state;
}

#define get_ssl_state_by_type(type) \
    (get_ssl_state(_PyType_GetModuleByDef(type, &_sslmodule_def)))

#endif /* Py_SSL_H */
