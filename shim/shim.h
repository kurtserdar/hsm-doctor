/* Platform macros required by the OASIS pkcs11.h, matching the standard
 * Unix conventions, then the official headers. */
#ifndef HSMDOCTOR_SHIM_H
#define HSMDOCTOR_SHIM_H

#define CK_PTR *
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#include "pkcs11.h"

/* goEmit is implemented in Go (//export goEmit). The C trampolines call it
 * with cheap, non-secret metadata only. hasSession/hasObject/hasMech and
 * dataLen/outLen use 0 / -1 sentinels when not applicable; label/keyID are
 * NULL except on C_FindObjectsInit (CKA_LABEL/CKA_ID search values). */
extern void goEmit(char *fn, int hasSession, unsigned long session,
                   int hasObject, unsigned long object,
                   int hasMech, unsigned long mech,
                   long dataLen, long outLen,
                   char *label, char *keyID,
                   unsigned long rv, long long durNs);

/* Builds and returns the instrumented function list (defined in shim.c). */
CK_RV shim_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppList);

#endif
