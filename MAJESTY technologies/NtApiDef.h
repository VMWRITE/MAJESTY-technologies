#pragma once
#include "Struct.h"





typedef BOOLEAN(NTAPI* t_PsIsProcessBeingDebugged)
(
    PEPROCESS Process

    );



typedef NTSTATUS (NTAPI* t_ZwQuerySystemInformation)
(
     SYSTEM_INFORMATION_CLASS SystemInformationClass,
     PVOID                    SystemInformation,
     ULONG                    SystemInformationLength,
     PULONG                   ReturnLength
);

typedef NTSTATUS (NTAPI * t_ZwQueryInformationThread)(
   HANDLE          ThreadHandle,
   THREADINFOCLASS ThreadInformationClass,
   PVOID           ThreadInformation,
   ULONG           ThreadInformationLength,
   PULONG          ReturnLength
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


typedef NTSTATUS (NTAPI * t_PspGetContextThreadInternal)
( 
    PETHREAD thread,
    PCONTEXT context , 
    MODE,
    MODE, 
    MODE
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


typedef void ( NTAPI * t_ExFreePoolWithTag)(
    PVOID P,
    ULONG Tag
);


typedef PVOID (NTAPI* t_ExAllocatePool)(
    POOL_TYPE PoolType,
    SIZE_T  NumberOfBytes
);


typedef  NTSTATUS(NTAPI* t_PsLookupThreadByThreadId)
(
    HANDLE   ThreadId,
    PETHREAD* Thread
    );



typedef NTSTATUS(NTAPI* t_PsLookupProcessByProcessId)(
    HANDLE    ProcessId,
    PEPROCESS* Process
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

typedef NTSTATUS(NTAPI* t_NtClose)(
    HANDLE Handle
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
