/* HSM Doctor PKCS#11 Flight Recorder shim.
 *
 * The application loads this library instead of the real PKCS#11 module.
 * Each call is timed, forwarded to the real module (dlopen'd from
 * HSMDOCTOR_TRACE_MODULE), and reported to the Go layer as metadata only —
 * never PINs, key material or plaintext.
 *
 * Only a curated, high-traffic subset of the API is instrumented; every
 * other slot in the function list is filled from the real module's own list
 * so unwrapped calls still work (just untraced). */
#include "shim.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static CK_FUNCTION_LIST_PTR g_real = NULL_PTR;   /* real module's list */
static CK_FUNCTION_LIST g_list;                  /* the list we hand out */
static void *g_handle = NULL;                    /* dlopen handle */

static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* load_real dlopens the real module named by HSMDOCTOR_TRACE_MODULE and
 * fetches its function list. Returns CKR_OK or a CKR_ error. */
static CK_RV load_real(void) {
    if (g_real != NULL_PTR) {
        return CKR_OK;
    }
    const char *path = getenv("HSMDOCTOR_TRACE_MODULE");
    if (path == NULL || path[0] == '\0') {
        return CKR_GENERAL_ERROR;
    }
    g_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (g_handle == NULL) {
        return CKR_GENERAL_ERROR;
    }
    CK_C_GetFunctionList getList =
        (CK_C_GetFunctionList)dlsym(g_handle, "C_GetFunctionList");
    if (getList == NULL) {
        return CKR_GENERAL_ERROR;
    }
    return getList(&g_real);
}

/* mech_of safely extracts the mechanism code from a CK_MECHANISM_PTR. */
static unsigned long mech_of(CK_MECHANISM_PTR m) {
    return m ? (unsigned long)m->mechanism : 0;
}

/* --- Instrumented trampolines --------------------------------------------
 * Pattern: time, forward to g_real->C_Foo, time, emit metadata, return. */

#define BEGIN long long _t0 = now_ns()
#define EMIT(fn, hasSes, ses, hasMech, mech, dlen, olen) \
    goEmit((char *)fn, hasSes, (unsigned long)(ses), hasMech, \
           (unsigned long)(mech), (long)(dlen), (long)(olen), \
           (unsigned long)_rv, now_ns() - _t0)

CK_RV shim_C_Initialize(CK_VOID_PTR p) {
    BEGIN;
    CK_RV _load = load_real();
    if (_load != CKR_OK) return _load;
    CK_RV _rv = g_real->C_Initialize(p);
    EMIT("C_Initialize", 0, 0, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_Finalize(CK_VOID_PTR p) {
    BEGIN;
    CK_RV _rv = g_real->C_Finalize(p);
    EMIT("C_Finalize", 0, 0, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_GetInfo(CK_INFO_PTR p) {
    BEGIN;
    CK_RV _rv = g_real->C_GetInfo(p);
    EMIT("C_GetInfo", 0, 0, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_GetSlotList(CK_BBOOL tok, CK_SLOT_ID_PTR list, CK_ULONG_PTR n) {
    BEGIN;
    CK_RV _rv = g_real->C_GetSlotList(tok, list, n);
    EMIT("C_GetSlotList", 0, 0, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_GetSlotInfo(CK_SLOT_ID slot, CK_SLOT_INFO_PTR p) {
    BEGIN;
    CK_RV _rv = g_real->C_GetSlotInfo(slot, p);
    EMIT("C_GetSlotInfo", 0, 0, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_GetTokenInfo(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR p) {
    BEGIN;
    CK_RV _rv = g_real->C_GetTokenInfo(slot, p);
    EMIT("C_GetTokenInfo", 0, 0, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_GetMechanismList(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR l, CK_ULONG_PTR n) {
    BEGIN;
    CK_RV _rv = g_real->C_GetMechanismList(slot, l, n);
    EMIT("C_GetMechanismList", 0, 0, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_GetMechanismInfo(CK_SLOT_ID slot, CK_MECHANISM_TYPE t, CK_MECHANISM_INFO_PTR p) {
    BEGIN;
    CK_RV _rv = g_real->C_GetMechanismInfo(slot, t, p);
    EMIT("C_GetMechanismInfo", 0, 0, 1, t, -1, -1);
    return _rv;
}

CK_RV shim_C_OpenSession(CK_SLOT_ID slot, CK_FLAGS f, CK_VOID_PTR app,
                         CK_NOTIFY note, CK_SESSION_HANDLE_PTR ph) {
    BEGIN;
    CK_RV _rv = g_real->C_OpenSession(slot, f, app, note, ph);
    CK_SESSION_HANDLE ses = (ph != NULL) ? *ph : 0;
    EMIT("C_OpenSession", 1, ses, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_CloseSession(CK_SESSION_HANDLE s) {
    BEGIN;
    CK_RV _rv = g_real->C_CloseSession(s);
    EMIT("C_CloseSession", 1, s, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_CloseAllSessions(CK_SLOT_ID slot) {
    BEGIN;
    CK_RV _rv = g_real->C_CloseAllSessions(slot);
    EMIT("C_CloseAllSessions", 0, 0, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_GetSessionInfo(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR p) {
    BEGIN;
    CK_RV _rv = g_real->C_GetSessionInfo(s, p);
    EMIT("C_GetSessionInfo", 1, s, 0, 0, -1, -1);
    return _rv;
}

/* C_Login: the PIN pointer/length are deliberately NOT read or emitted. */
CK_RV shim_C_Login(CK_SESSION_HANDLE s, CK_USER_TYPE u, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen) {
    BEGIN;
    (void)pin;
    (void)pinLen;
    CK_RV _rv = g_real->C_Login(s, u, pin, pinLen);
    EMIT("C_Login", 1, s, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_Logout(CK_SESSION_HANDLE s) {
    BEGIN;
    CK_RV _rv = g_real->C_Logout(s);
    EMIT("C_Logout", 1, s, 0, 0, -1, -1);
    return _rv;
}

CK_RV shim_C_FindObjectsInit(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR t, CK_ULONG n) {
    BEGIN;
    CK_RV _rv = g_real->C_FindObjectsInit(s, t, n);
    EMIT("C_FindObjectsInit", 1, s, 0, 0, (long)n, -1);
    return _rv;
}

CK_RV shim_C_FindObjects(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR o, CK_ULONG max, CK_ULONG_PTR n) {
    BEGIN;
    CK_RV _rv = g_real->C_FindObjects(s, o, max, n);
    long found = (n != NULL) ? (long)*n : -1;
    EMIT("C_FindObjects", 1, s, 0, 0, -1, found);
    return _rv;
}

CK_RV shim_C_FindObjectsFinal(CK_SESSION_HANDLE s) {
    BEGIN;
    CK_RV _rv = g_real->C_FindObjectsFinal(s);
    EMIT("C_FindObjectsFinal", 1, s, 0, 0, -1, -1);
    return _rv;
}

/* C_GetAttributeValue: attribute VALUES are never read; only the count. */
CK_RV shim_C_GetAttributeValue(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR t, CK_ULONG n) {
    BEGIN;
    CK_RV _rv = g_real->C_GetAttributeValue(s, o, t, n);
    EMIT("C_GetAttributeValue", 1, s, 0, 0, (long)n, -1);
    return _rv;
}

CK_RV shim_C_GenerateKey(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR t, CK_ULONG n, CK_OBJECT_HANDLE_PTR o) {
    BEGIN;
    CK_RV _rv = g_real->C_GenerateKey(s, m, t, n, o);
    EMIT("C_GenerateKey", 1, s, 1, mech_of(m), -1, -1);
    return _rv;
}

CK_RV shim_C_GenerateKeyPair(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m,
                             CK_ATTRIBUTE_PTR pub, CK_ULONG npub,
                             CK_ATTRIBUTE_PTR priv, CK_ULONG npriv,
                             CK_OBJECT_HANDLE_PTR hpub, CK_OBJECT_HANDLE_PTR hpriv) {
    BEGIN;
    CK_RV _rv = g_real->C_GenerateKeyPair(s, m, pub, npub, priv, npriv, hpub, hpriv);
    EMIT("C_GenerateKeyPair", 1, s, 1, mech_of(m), -1, -1);
    return _rv;
}

CK_RV shim_C_SignInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k) {
    BEGIN;
    CK_RV _rv = g_real->C_SignInit(s, m, k);
    EMIT("C_SignInit", 1, s, 1, mech_of(m), -1, -1);
    return _rv;
}

/* C_Sign: only the input/output LENGTHS are emitted, never the bytes. */
CK_RV shim_C_Sign(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG dlen, CK_BYTE_PTR sig, CK_ULONG_PTR slen) {
    BEGIN;
    CK_RV _rv = g_real->C_Sign(s, data, dlen, sig, slen);
    long olen = (slen != NULL) ? (long)*slen : -1;
    EMIT("C_Sign", 1, s, 0, 0, (long)dlen, olen);
    return _rv;
}

CK_RV shim_C_VerifyInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k) {
    BEGIN;
    CK_RV _rv = g_real->C_VerifyInit(s, m, k);
    EMIT("C_VerifyInit", 1, s, 1, mech_of(m), -1, -1);
    return _rv;
}

CK_RV shim_C_Verify(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG dlen, CK_BYTE_PTR sig, CK_ULONG slen) {
    BEGIN;
    CK_RV _rv = g_real->C_Verify(s, data, dlen, sig, slen);
    EMIT("C_Verify", 1, s, 0, 0, (long)dlen, (long)slen);
    return _rv;
}

CK_RV shim_C_EncryptInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k) {
    BEGIN;
    CK_RV _rv = g_real->C_EncryptInit(s, m, k);
    EMIT("C_EncryptInit", 1, s, 1, mech_of(m), -1, -1);
    return _rv;
}

CK_RV shim_C_Encrypt(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG dlen, CK_BYTE_PTR out, CK_ULONG_PTR olen) {
    BEGIN;
    CK_RV _rv = g_real->C_Encrypt(s, data, dlen, out, olen);
    long ol = (olen != NULL) ? (long)*olen : -1;
    EMIT("C_Encrypt", 1, s, 0, 0, (long)dlen, ol);
    return _rv;
}

CK_RV shim_C_DecryptInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k) {
    BEGIN;
    CK_RV _rv = g_real->C_DecryptInit(s, m, k);
    EMIT("C_DecryptInit", 1, s, 1, mech_of(m), -1, -1);
    return _rv;
}

CK_RV shim_C_Decrypt(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG dlen, CK_BYTE_PTR out, CK_ULONG_PTR olen) {
    BEGIN;
    CK_RV _rv = g_real->C_Decrypt(s, data, dlen, out, olen);
    long ol = (olen != NULL) ? (long)*olen : -1;
    EMIT("C_Decrypt", 1, s, 0, 0, (long)dlen, ol);
    return _rv;
}

CK_RV shim_C_DigestInit(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m) {
    BEGIN;
    CK_RV _rv = g_real->C_DigestInit(s, m);
    EMIT("C_DigestInit", 1, s, 1, mech_of(m), -1, -1);
    return _rv;
}

CK_RV shim_C_GenerateRandom(CK_SESSION_HANDLE s, CK_BYTE_PTR buf, CK_ULONG n) {
    BEGIN;
    CK_RV _rv = g_real->C_GenerateRandom(s, buf, n);
    EMIT("C_GenerateRandom", 1, s, 0, 0, -1, (long)n);
    return _rv;
}

CK_RV shim_C_WrapKey(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE wk,
                     CK_OBJECT_HANDLE k, CK_BYTE_PTR out, CK_ULONG_PTR olen) {
    BEGIN;
    CK_RV _rv = g_real->C_WrapKey(s, m, wk, k, out, olen);
    EMIT("C_WrapKey", 1, s, 1, mech_of(m), -1, -1);
    return _rv;
}

CK_RV shim_C_UnwrapKey(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE uk,
                       CK_BYTE_PTR wrapped, CK_ULONG wlen, CK_ATTRIBUTE_PTR t, CK_ULONG n,
                       CK_OBJECT_HANDLE_PTR o) {
    BEGIN;
    CK_RV _rv = g_real->C_UnwrapKey(s, m, uk, wrapped, wlen, t, n, o);
    EMIT("C_UnwrapKey", 1, s, 1, mech_of(m), (long)wlen, -1);
    return _rv;
}

/* C_GetFunctionList hands out our list, initialized from the real module's
 * list (so uninstrumented functions still work) with the instrumented slots
 * overridden by our trampolines. */
CK_RV shim_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppList) {
    CK_RV rv = load_real();
    if (rv != CKR_OK) return rv;

    g_list = *g_real; /* copy real pointers as the untraced baseline */
    g_list.C_GetFunctionList = shim_C_GetFunctionList;

    g_list.C_Initialize = shim_C_Initialize;
    g_list.C_Finalize = shim_C_Finalize;
    g_list.C_GetInfo = shim_C_GetInfo;
    g_list.C_GetSlotList = shim_C_GetSlotList;
    g_list.C_GetSlotInfo = shim_C_GetSlotInfo;
    g_list.C_GetTokenInfo = shim_C_GetTokenInfo;
    g_list.C_GetMechanismList = shim_C_GetMechanismList;
    g_list.C_GetMechanismInfo = shim_C_GetMechanismInfo;
    g_list.C_OpenSession = shim_C_OpenSession;
    g_list.C_CloseSession = shim_C_CloseSession;
    g_list.C_CloseAllSessions = shim_C_CloseAllSessions;
    g_list.C_GetSessionInfo = shim_C_GetSessionInfo;
    g_list.C_Login = shim_C_Login;
    g_list.C_Logout = shim_C_Logout;
    g_list.C_FindObjectsInit = shim_C_FindObjectsInit;
    g_list.C_FindObjects = shim_C_FindObjects;
    g_list.C_FindObjectsFinal = shim_C_FindObjectsFinal;
    g_list.C_GetAttributeValue = shim_C_GetAttributeValue;
    g_list.C_GenerateKey = shim_C_GenerateKey;
    g_list.C_GenerateKeyPair = shim_C_GenerateKeyPair;
    g_list.C_SignInit = shim_C_SignInit;
    g_list.C_Sign = shim_C_Sign;
    g_list.C_VerifyInit = shim_C_VerifyInit;
    g_list.C_Verify = shim_C_Verify;
    g_list.C_EncryptInit = shim_C_EncryptInit;
    g_list.C_Encrypt = shim_C_Encrypt;
    g_list.C_DecryptInit = shim_C_DecryptInit;
    g_list.C_Decrypt = shim_C_Decrypt;
    g_list.C_DigestInit = shim_C_DigestInit;
    g_list.C_GenerateRandom = shim_C_GenerateRandom;
    g_list.C_WrapKey = shim_C_WrapKey;
    g_list.C_UnwrapKey = shim_C_UnwrapKey;

    *ppList = &g_list;
    return CKR_OK;
}

/* C_GetFunctionList is the public entry point the application looks up by
 * name in the .so; it delegates to the instrumented builder above. */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppList) {
    return shim_C_GetFunctionList(ppList);
}
