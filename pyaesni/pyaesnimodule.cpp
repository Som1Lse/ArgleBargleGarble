#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <wmmintrin.h>

// TODO: Faster key scheduling?
#define EXPAND_KEY(k,rcon)                              \
    {                                                   \
        auto ka = _mm_aeskeygenassist_si128(k,rcon);    \
        ka = _mm_shuffle_epi32(ka,255);                 \
        k = _mm_xor_si128(k,_mm_slli_si128(k,4));       \
        k = _mm_xor_si128(k,_mm_slli_si128(k,4));       \
        k = _mm_xor_si128(k,_mm_slli_si128(k,4));       \
        k = _mm_xor_si128(k,ka);                        \
    }                                                   \

void do_aesni1(char* r,const char* k_,const char* m_) noexcept {
    auto k = _mm_loadu_si128(reinterpret_cast<const __m128i*>(k_));
    auto m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_));

    m = _mm_xor_si128(m,k);

    EXPAND_KEY(k,0x01);
    m = _mm_aesenc_si128(m,k);

    EXPAND_KEY(k,0x02);
    m = _mm_aesenc_si128(m,k);

    EXPAND_KEY(k,0x04);
    m = _mm_aesenc_si128(m,k);

    EXPAND_KEY(k,0x08);
    m = _mm_aesenc_si128(m,k);

    EXPAND_KEY(k,0x10);
    m = _mm_aesenc_si128(m,k);

    EXPAND_KEY(k,0x20);
    m = _mm_aesenc_si128(m,k);

    EXPAND_KEY(k,0x40);
    m = _mm_aesenc_si128(m,k);

    EXPAND_KEY(k,0x80);
    m = _mm_aesenc_si128(m,k);

    EXPAND_KEY(k,0x1B);
    m = _mm_aesenc_si128(m,k);

    EXPAND_KEY(k,0x36);
    m = _mm_aesenclast_si128(m,k);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(r),m);
}

void do_aesni2(char* r,const char* k1_,const char* k2_,const char* m_) noexcept {
    auto k1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(k1_));
    auto k2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(k2_));
    auto m1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_));
    auto m2 = m1;

    m1 = _mm_xor_si128(m1,k1);
    m2 = _mm_xor_si128(m2,k2);

    EXPAND_KEY(k1,0x01);
    m1 = _mm_aesenc_si128(m1,k1);
    EXPAND_KEY(k2,0x01);
    m2 = _mm_aesenc_si128(m2,k2);

    EXPAND_KEY(k1,0x02);
    m1 = _mm_aesenc_si128(m1,k1);
    EXPAND_KEY(k2,0x02);
    m2 = _mm_aesenc_si128(m2,k2);

    EXPAND_KEY(k1,0x04);
    m1 = _mm_aesenc_si128(m1,k1);
    EXPAND_KEY(k2,0x04);
    m2 = _mm_aesenc_si128(m2,k2);

    EXPAND_KEY(k1,0x08);
    m1 = _mm_aesenc_si128(m1,k1);
    EXPAND_KEY(k2,0x08);
    m2 = _mm_aesenc_si128(m2,k2);

    EXPAND_KEY(k1,0x10);
    m1 = _mm_aesenc_si128(m1,k1);
    EXPAND_KEY(k2,0x10);
    m2 = _mm_aesenc_si128(m2,k2);

    EXPAND_KEY(k1,0x20);
    m1 = _mm_aesenc_si128(m1,k1);
    EXPAND_KEY(k2,0x20);
    m2 = _mm_aesenc_si128(m2,k2);

    EXPAND_KEY(k1,0x40);
    m1 = _mm_aesenc_si128(m1,k1);
    EXPAND_KEY(k2,0x40);
    m2 = _mm_aesenc_si128(m2,k2);

    EXPAND_KEY(k1,0x80);
    m1 = _mm_aesenc_si128(m1,k1);
    EXPAND_KEY(k2,0x80);
    m2 = _mm_aesenc_si128(m2,k2);

    EXPAND_KEY(k1,0x1B);
    m1 = _mm_aesenc_si128(m1,k1);
    EXPAND_KEY(k2,0x1B);
    m2 = _mm_aesenc_si128(m2,k2);

    EXPAND_KEY(k1,0x36);
    m1 = _mm_aesenclast_si128(m1,k1);
    EXPAND_KEY(k2,0x36);
    m2 = _mm_aesenclast_si128(m2,k2);

    m1 = _mm_xor_si128(m1,m2);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(r),m1);
}

static PyObject* aesni1(PyObject*,PyObject* Args,PyObject *Kwargs) noexcept {
    static char* kw[] = {"key","m",nullptr};

    const char* Key;
    Py_ssize_t KeySize;
    const char* Message;
    Py_ssize_t MessageSize;
    if(!PyArg_ParseTupleAndKeywords(Args,Kwargs,"y#y#",kw,
            &Key,&KeySize,
            &Message,&MessageSize)){
        return nullptr;
    }

    if(KeySize != 16){
        return nullptr;
    }

    if(MessageSize != 16){
        return nullptr;
    }

    auto r = PyBytes_FromStringAndSize(nullptr,16);
    if(!r){
        return PyErr_NoMemory();
    }

    Py_BEGIN_ALLOW_THREADS;

    do_aesni1(PyBytes_AsString(r),Key,Message);

    Py_END_ALLOW_THREADS;

    return r;
}

static PyObject* aesni2(PyObject*,PyObject* Args,PyObject *Kwargs) noexcept {
    static char* kw[] = {"keys","m",nullptr};

    const char* Key1;
    Py_ssize_t Key1Size;
    const char* Key2;
    Py_ssize_t Key2Size;
    const char* Message;
    Py_ssize_t MessageSize;
    if(!PyArg_ParseTupleAndKeywords(Args,Kwargs,"(y#y#)y#",kw,
            &Key1,&Key1Size,
            &Key2,&Key2Size,
            &Message,&MessageSize)){
        return nullptr;
    }

    if(Key1Size != 16){
        return nullptr;
    }

    if(Key2Size != 16){
        return nullptr;
    }

    if(MessageSize != 16){
        return nullptr;
    }

    auto r = PyBytes_FromStringAndSize(nullptr,16);
    if(!r){
        return PyErr_NoMemory();
    }

    Py_BEGIN_ALLOW_THREADS;

    do_aesni2(PyBytes_AsString(r),Key1,Key2,Message);

    Py_END_ALLOW_THREADS;

    return r;
}

static PyMethodDef PylzoMethods[] = {
    {"aesni1",reinterpret_cast<PyCFunction>(aesni1),METH_VARARGS,
     "Encrypt a single block using AES-NI instructions."},
    {"aesni2",reinterpret_cast<PyCFunction>(aesni2),METH_VARARGS,
     "Encrypt a single block using AES-NI instructions twice with two keys."},
    {nullptr,nullptr,0,nullptr},
};

static PyModuleDef PylzoDef = {};

PyMODINIT_FUNC PyInit_pyaesni() noexcept {
    PylzoDef.m_base    = PyModuleDef_HEAD_INIT;
    PylzoDef.m_name    = "pyaesni";
    PylzoDef.m_doc     = "Provides a simple wrapper around the AES-NI instructions.";
    PylzoDef.m_size    = -1;
    PylzoDef.m_methods = PylzoMethods;

    return PyModule_Create(&PylzoDef);
}
