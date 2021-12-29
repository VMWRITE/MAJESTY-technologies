#pragma once
#include "Struct.h"



 

typedef NTSTATUS (NTAPI* t_PsGetContextThread)
(
     PETHREAD Thread,
     PCONTEXT ThreadContext,
     KPROCESSOR_MODE Mode
);


typedef NTSTATUS(NTAPI* t_ZwSystemDebugControl)
(
    unsigned long ControlCode,
    void* InputBuffer,
    unsigned long InputBufferLength,
    void* OutputBuffer,
    unsigned long OutputBufferLength,
    unsigned long* pResultLength
    );

 
 



typedef NTSTATUS(NTAPI* t_KdDisableDebugger)();

typedef NTSTATUS(NTAPI* t_KdChangeOption)
(
    KD_OPTION Option,
    ULONG     InBufferBytes,
    PVOID     InBuffer,
    ULONG     OutBufferBytes,
    PVOID     OutBuffer,
    PULONG    OutBufferNeeded
    );


typedef ULONG(NTAPI* t_vDbgPrintExWithPrefix)(
    PCCH    Prefix,
    ULONG   ComponentId,
    ULONG   Level,
    PCCH    Format,
    va_list arglist
    );

typedef  NTSTATUS(NTAPI* t_RtlGetVersion)
(
    PRTL_OSVERSIONINFOW lpVersionInformation
    );


 

typedef  NTSTATUS(NTAPI* t_PsLookupThreadByThreadId)
(
    HANDLE   ThreadId,
    PETHREAD* Thread
    );


 
typedef LONG_PTR(NTAPI* t_ObfReferenceObject)
(
    PVOID Object
    );


typedef NTSTATUS(NTAPI* t_ObOpenObjectByPointer)(
    PVOID           Object,
    ULONG           HandleAttributes,
    PACCESS_STATE   PassedAccessState,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PHANDLE         Handle
    );
 
EXTERN_C NTSTATUS NTAPI ExRaiseHardError
(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters,
    ULONG ValidResponseOptions,
    PULONG Response
);


EXTERN_C NTSTATUS
ObReferenceObjectByName(
    __in PUNICODE_STRING ObjectName,
    __in ULONG Attributes,
    __in_opt PACCESS_STATE AccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __in POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __inout_opt PVOID ParseContext,
    __out PVOID* Object
);
