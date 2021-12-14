#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <minwindef.h>
#include <intrin.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <cstdint>

#include "XorStr.h"


#define WINDOWS_7 7600
#define WINDOWS_7_SP1 7601
#define WINDOWS_8 9200
#define WINDOWS_8_1 9600
#define WINDOWS_10 10
#define WINDOWS_10_VERSION_THRESHOLD1 10240
#define WINDOWS_10_VERSION_THRESHOLD2 10586
#define WINDOWS_10_VERSION_REDSTONE1 14393
#define WINDOWS_10_VERSION_REDSTONE2 15063
#define WINDOWS_10_VERSION_REDSTONE3 16299
#define WINDOWS_10_VERSION_REDSTONE4 17134
#define WINDOWS_10_VERSION_REDSTONE5 17763
#define WINDOWS_10_VERSION_19H1 18362
#define WINDOWS_10_VERSION_19H2 18363
#define WINDOWS_10_VERSION_20H1 19041
#define WINDOWS_10_VERSION_20H2 19042
#define WINDOWS_10_VERSION_21H1 19043
#define WINDOWS_10_VERSION_21H2 19044
#define WINDOWS_11 22000



#define IA32_P5_MC_ADDR_MSR		0x00000000
#define DEBUGCTL_LBR            0x01
#define DEBUGCTL_BTF            0x02
#define	IA32_TIME_STAMP_COUNTER 0x00000010
#define SMI_COUNT_MSR 0x00000034
#define IA32_MPERF_MSR 0x000000E7
#define IA32_APERF_MSR 0x000000E8
#define	MSR_P6M_LBSTK_TOS	0x1c9
#define	MSR_DEBUGCTL		0x1d9

static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK   0x00000001

#define 	LDR_IS_DATAFILE(handle)   (((ULONG_PTR)(handle)) & (ULONG_PTR)1)

#define 	LDR_DATAFILE_TO_VIEW(x)   ((PVOID)(((ULONG_PTR)(x)) & ~(ULONG_PTR)1))


DWORD64 gl_baseNtoskrnl = 0;

EXTERN_C POBJECT_TYPE* IoDriverObjectType;

#define PAGE_OFFSET_SIZE 12

#define FLS_MAXIMUM_AVAILABLE 128
#define TLS_MINIMUM_AVAILABLE 64
#define TLS_EXPANSION_SLOTS 1024

#define RTL_MAX_DRIVE_LETTERS 32


#define GDI_HANDLE_BUFFER_SIZE32    34
#define GDI_HANDLE_BUFFER_SIZE64    60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];



typedef enum _LDR_DDAG_STATE
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;


typedef enum _SYSDBG_COMMAND {
	SysDbgQueryModuleInformation,
	SysDbgQueryTraceInformation,
	SysDbgSetTracepoint,
	SysDbgSetSpecialCall,
	SysDbgClearSpecialCalls,
	SysDbgQuerySpecialCalls,
	SysDbgBreakPoint,
	SysDbgQueryVersion,
	SysDbgReadVirtual,
	SysDbgWriteVirtual,
	SysDbgReadPhysical,
	SysDbgWritePhysical,
	SysDbgReadControlSpace,
	SysDbgWriteControlSpace,
	SysDbgReadIoSpace,
	SysDbgWriteIoSpace,
	SysDbgReadMsr,
	SysDbgWriteMsr,
	SysDbgReadBusData,
	SysDbgWriteBusData,
	SysDbgCheckLowMemory,
	SysDbgEnableKernelDebugger,
	SysDbgDisableKernelDebugger,
	SysDbgGetAutoKdEnable,
	SysDbgSetAutoKdEnable,
	SysDbgGetPrintBufferSize,
	SysDbgSetPrintBufferSize,
	SysDbgGetKdUmExceptionEnable,
	SysDbgSetKdUmExceptionEnable,
	SysDbgGetTriageDump,
	SysDbgGetKdBlockEnable,
	SysDbgSetKdBlockEnable,
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;

typedef enum _uTypeBoxReason
{
	MB_OK,
	MB_OKCANCEL,
	MB_ABORTRETRYIGNORE,
	MB_YESNOCANCEL,
	MB_YESNO,
	MB_RETRYCANCEL,
	MB_HELP = 0x00004000L
}uTypeBoxReason;




typedef struct _RUNTIME_FUNCTION {
	ULONG BeginAddress;
	ULONG EndAddress;
	ULONG UnwindInfoAddress;
} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;


typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
	ULONG64 ImageBase;
	ULONG64 Gp;
	PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, * PUNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE {
	ULONG Count;
	UCHAR Search;
	ULONG64 LowAddress;
	ULONG64 HighAddress;
	UNWIND_HISTORY_TABLE_ENTRY Entry[12];
} UNWIND_HISTORY_TABLE, * PUNWIND_HISTORY_TABLE;



typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;  // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;  // LDR_*
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	//    PVOID			LoadedImports;
	//    // seems they are exist only on XP !!! PVOID
	//    EntryPointActivationContext;	// -same-
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

union _KSTACK_COUNT
{
	LONG Value;                                                             //0x0
	ULONG State : 3;                                                          //0x0
	ULONG StackCount : 29;                                                    //0x0
};

struct _KAFFINITY_EX
{
	USHORT Count;                                                           //0x0
	USHORT Size;                                                            //0x2
	ULONG Reserved;                                                         //0x4
	ULONGLONG Bitmap[20];                                                   //0x8
};
union _KEXECUTE_OPTIONS
{
	UCHAR ExecuteDisable : 1;                                                 //0x0
	UCHAR ExecuteEnable : 1;                                                  //0x0
	UCHAR DisableThunkEmulation : 1;                                          //0x0
	UCHAR Permanent : 1;                                                      //0x0
	UCHAR ExecuteDispatchEnable : 1;                                          //0x0
	UCHAR ImageDispatchEnable : 1;                                            //0x0
	UCHAR DisableExceptionChainValidation : 1;                                //0x0
	UCHAR Spare : 1;                                                          //0x0
	volatile UCHAR ExecuteOptions;                                          //0x0
	UCHAR ExecuteOptionsNV;                                                 //0x0
};


struct _MMSUPPORT_SHARED
{
	volatile LONG WorkingSetLock;                                           //0x0
	LONG GoodCitizenWaiting;                                                //0x4
	ULONGLONG ReleasedCommitDebt;                                           //0x8
	ULONGLONG ResetPagesRepurposedCount;                                    //0x10
	VOID* WsSwapSupport;                                                    //0x18
	VOID* CommitReleaseContext;                                             //0x20
	VOID* AccessLog;                                                        //0x28
	volatile ULONGLONG ChargedWslePages;                                    //0x30
	ULONGLONG ActualWslePages;                                              //0x38
	ULONGLONG WorkingSetCoreLock;                                           //0x40
	VOID* ShadowMapping;                                                    //0x48
};


struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
};

struct _EX_FAST_REF
{
	union
	{
		VOID* Object;                                                       //0x0
		ULONGLONG RefCnt : 4;                                                 //0x0
		ULONGLONG Value;                                                    //0x0
	};
};



struct _MMSUPPORT_FLAGS
{
	union
	{
		struct
		{
			UCHAR WorkingSetType : 3;                                         //0x0
			UCHAR Reserved0 : 3;                                              //0x0
			UCHAR MaximumWorkingSetHard : 1;                                  //0x0
			UCHAR MinimumWorkingSetHard : 1;                                  //0x0
			UCHAR SessionMaster : 1;                                          //0x1
			UCHAR TrimmerState : 2;                                           //0x1
			UCHAR Reserved : 1;                                               //0x1
			UCHAR PageStealers : 4;                                           //0x1
		};
		USHORT u1;                                                          //0x0
	};
	UCHAR MemoryPriority;                                                   //0x2
	union
	{
		struct
		{
			UCHAR WsleDeleted : 1;                                            //0x3
			UCHAR SvmEnabled : 1;                                             //0x3
			UCHAR ForceAge : 1;                                               //0x3
			UCHAR ForceTrim : 1;                                              //0x3
			UCHAR NewMaximum : 1;                                             //0x3
			UCHAR CommitReleaseState : 2;                                     //0x3
		};
		UCHAR u2;                                                           //0x3
	};
};


struct _MMSUPPORT_INSTANCE
{
	ULONG NextPageColor;                                                    //0x0
	ULONG PageFaultCount;                                                   //0x4
	ULONGLONG TrimmedPageCount;                                             //0x8
	struct _MMWSL_INSTANCE* VmWorkingSetList;                               //0x10
	struct _LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
	ULONGLONG AgeDistribution[8];                                           //0x28
	struct _KGATE* ExitOutswapGate;                                         //0x68
	ULONGLONG MinimumWorkingSetSize;                                        //0x70
	ULONGLONG WorkingSetLeafSize;                                           //0x78
	ULONGLONG WorkingSetLeafPrivateSize;                                    //0x80
	ULONGLONG WorkingSetSize;                                               //0x88
	ULONGLONG WorkingSetPrivateSize;                                        //0x90
	ULONGLONG MaximumWorkingSetSize;                                        //0x98
	ULONGLONG PeakWorkingSetSize;                                           //0xa0
	ULONG HardFaultCount;                                                   //0xa8
	USHORT LastTrimStamp;                                                   //0xac
	USHORT PartitionId;                                                     //0xae
	ULONGLONG SelfmapLock;                                                  //0xb0
	struct _MMSUPPORT_FLAGS Flags;                                          //0xb8
};

struct _MMSUPPORT_FULL
{
	struct _MMSUPPORT_INSTANCE Instance;                                    //0x0
	struct _MMSUPPORT_SHARED Shared;                                        //0xc0
};

struct _RTL_AVL_TREE
{
	struct _RTL_BALANCED_NODE* Root;                                        //0x0
};



struct _SE_AUDIT_PROCESS_CREATION_INFO
{
	struct _OBJECT_NAME_INFORMATION* ImageFileName;                         //0x0
};


struct _JOBOBJECT_WAKE_FILTER
{
	ULONG HighEdgeFilter;                                                   //0x0
	ULONG LowEdgeFilter;                                                    //0x4
};

struct _PS_PROCESS_WAKE_INFORMATION
{
	ULONGLONG NotificationChannel;                                          //0x0
	ULONG WakeCounters[7];                                                  //0x8
	struct _JOBOBJECT_WAKE_FILTER WakeFilter;                               //0x24
	ULONG NoWakeCounter;                                                    //0x2c
};


struct _ALPC_PROCESS_CONTEXT
{
	struct _EX_PUSH_LOCK Lock;                                              //0x0
	struct _LIST_ENTRY ViewListHead;                                        //0x8
	volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
};

union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
	ULONGLONG DelayMs : 30;                                                   //0x0
	ULONGLONG CoalescingWindowMs : 30;                                        //0x0
	ULONGLONG Reserved : 1;                                                   //0x0
	ULONGLONG NewTimerWheel : 1;                                              //0x0
	ULONGLONG Retry : 1;                                                      //0x0
	ULONGLONG Locked : 1;                                                     //0x0
	ULONGLONG All;                                                          //0x0
};



typedef struct _SYSTEM_MODULE
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef union _PS_PROTECTION
{
	UCHAR Level;
	struct
	{
		int Type : 3;
		int Audit : 1;
		int Signer : 4;
	} Flags;
} PS_PROTECTION, * PPS_PROTECTION;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode = 1,
	PsProtectedSignerCodeGen = 2,
	PsProtectedSignerAntimalware = 3,
	PsProtectedSignerLsa = 4,
	PsProtectedSignerWindows = 5,
	PsProtectedSignerWinTcb = 6,
	PsProtectedSignerWinSystem = 7,
	PsProtectedSignerApp = 8,
	PsProtectedSignerMax = 9
} PS_PROTECTED_SIGNER;

typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2,
	PsProtectedTypeMax = 3

} PS_PROTECTED_TYPE;


struct DebugOffset
{
	
	ULONG NoDebugInherit;
	DWORD DebugPort;
	ULONG HideFromDebugger;
	DWORD InstrumentationCallback;
	DWORD InheritedFromUniqueProcessId;
};

struct PprocOffset
{
	uint64_t protection;

};
