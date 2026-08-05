//go:build cgo && !windows

package pqc

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>

// Minimal, self-contained PKCS#11 3.2 ABI. The repo's vendored headers are
// 2.40 and predate C_GetInterface / C_EncapsulateKey / C_DecapsulateKey, so we
// declare exactly what the KEM round trip needs. Types match the standard
// Cryptoki ABI (natural alignment on Linux/macOS, as real modules use).
typedef unsigned char      CK_BYTE;
typedef unsigned char      CK_BBOOL;
typedef unsigned long int  CK_ULONG;
typedef CK_ULONG           CK_RV;
typedef CK_ULONG           CK_FLAGS;
typedef CK_ULONG           CK_SESSION_HANDLE;
typedef CK_ULONG           CK_OBJECT_HANDLE;
typedef CK_ULONG           CK_OBJECT_CLASS;
typedef CK_ULONG           CK_KEY_TYPE;
typedef CK_ULONG           CK_MECHANISM_TYPE;
typedef CK_ULONG           CK_ATTRIBUTE_TYPE;
typedef CK_BYTE           *CK_BYTE_PTR;
typedef CK_ULONG          *CK_ULONG_PTR;
typedef void              *CK_VOID_PTR;
typedef CK_BYTE           *CK_UTF8CHAR_PTR;
typedef CK_OBJECT_HANDLE  *CK_OBJECT_HANDLE_PTR;

typedef struct CK_VERSION { CK_BYTE major; CK_BYTE minor; } CK_VERSION;
typedef CK_VERSION *CK_VERSION_PTR;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR       pParameter;
    CK_ULONG          ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM *CK_MECHANISM_PTR;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       pValue;
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

typedef struct CK_INTERFACE {
    CK_UTF8CHAR_PTR pInterfaceName;
    CK_VOID_PTR     pFunctionList;
    CK_FLAGS        flags;
} CK_INTERFACE;
typedef CK_INTERFACE  *CK_INTERFACE_PTR;
typedef CK_INTERFACE **CK_INTERFACE_PTR_PTR;

// The 3.2 function list is a version followed by function pointers in the order
// defined by pkcs11f.h. C_EncapsulateKey is the 93rd function (index 92),
// C_DecapsulateKey the 94th (index 93).
typedef struct FL32 { CK_VERSION version; CK_VOID_PTR fns[104]; } FL32;

typedef CK_RV (*CK_C_GetInterface)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS);
typedef CK_RV (*CK_C_EncapsulateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*CK_C_DecapsulateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

#define CKO_SECRET_KEY       0x00000004UL
#define CKK_GENERIC_SECRET   0x00000010UL
#define CKA_CLASS            0x00000000UL
#define CKA_TOKEN            0x00000001UL
#define CKA_KEY_TYPE         0x00000100UL
#define CKA_SENSITIVE        0x00000103UL
#define CKA_EXTRACTABLE      0x00000162UL
#define CKA_VALUE_LEN        0x00000161UL
#define CKR_OK               0x00000000UL

// kem_roundtrip encapsulates to hPub then decapsulates with hPriv on an
// already-open session, returning the two derived secret-key handles.
// Returns 0 on success; -1 when the module has no usable 3.2 KEM interface;
// a positive CK_RV on a call failure.
static long kem_roundtrip(const char *path, CK_ULONG session, CK_ULONG hPub,
                          CK_ULONG hPriv, CK_ULONG mechType,
                          CK_ULONG *out1, CK_ULONG *out2) {
    void *h = dlopen(path, RTLD_NOLOAD | RTLD_NOW);
    if (h == NULL) {
        h = dlopen(path, RTLD_NOW);
    }
    if (h == NULL) {
        return -1;
    }
    CK_C_GetInterface getIface = (CK_C_GetInterface)dlsym(h, "C_GetInterface");
    if (getIface == NULL) {
        dlclose(h);
        return -1;
    }
    CK_INTERFACE_PTR iface = NULL;
    if (getIface(NULL, NULL, &iface, 0) != CKR_OK || iface == NULL ||
        iface->pFunctionList == NULL) {
        dlclose(h);
        return -1;
    }
    FL32 *fl = (FL32 *)iface->pFunctionList;
    if (fl->version.major < 3 || (fl->version.major == 3 && fl->version.minor < 2)) {
        dlclose(h);
        return -1;
    }
    CK_C_EncapsulateKey enc = (CK_C_EncapsulateKey)fl->fns[92];
    CK_C_DecapsulateKey dec = (CK_C_DecapsulateKey)fl->fns[93];
    if (enc == NULL || dec == NULL) {
        dlclose(h);
        return -1;
    }

    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
    CK_BBOOL ctrue = 1, cfalse = 0;
    CK_ULONG vlen = 32; // ML-KEM shared secret is 32 bytes.
    CK_ATTRIBUTE tmpl[6] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_TOKEN, &cfalse, sizeof(cfalse)},
        {CKA_SENSITIVE, &cfalse, sizeof(cfalse)},
        {CKA_EXTRACTABLE, &ctrue, sizeof(ctrue)},
        {CKA_VALUE_LEN, &vlen, sizeof(vlen)},
    };
    CK_MECHANISM mech = {mechType, NULL, 0};

    CK_BYTE ct[4096];
    CK_ULONG ctlen = sizeof(ct);
    CK_OBJECT_HANDLE k1 = 0, k2 = 0;
    CK_RV rv = enc(session, &mech, hPub, tmpl, 6, ct, &ctlen, &k1);
    if (rv != CKR_OK) {
        dlclose(h);
        return (long)rv;
    }
    rv = dec(session, &mech, hPriv, tmpl, 6, ct, ctlen, &k2);
    if (rv != CKR_OK) {
        dlclose(h);
        return (long)rv;
    }
    *out1 = k1;
    *out2 = k2;
    dlclose(h);
    return 0;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// kemRoundTrip performs an ML-KEM encapsulate/decapsulate round trip on an
// already-open session (via the PKCS#11 3.2 interface, which miekg predates)
// and returns the two derived secret-key handles for the caller to compare.
func kemRoundTrip(modulePath string, session, pub, priv uint64, mech uint) (uint64, uint64, error) {
	cpath := C.CString(modulePath)
	defer C.free(unsafe.Pointer(cpath))

	var o1, o2 C.CK_ULONG
	rc := C.kem_roundtrip(cpath, C.CK_ULONG(session), C.CK_ULONG(pub),
		C.CK_ULONG(priv), C.CK_ULONG(mech), &o1, &o2)
	switch rc {
	case 0:
		return uint64(o1), uint64(o2), nil
	case -1:
		return 0, 0, errKEMUnsupported
	default:
		return 0, 0, fmt.Errorf("C_EncapsulateKey/C_DecapsulateKey failed (CKR 0x%x)", uint64(rc))
	}
}
