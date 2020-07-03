#pragma once
#include <windows.h>

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_FREE_BLOCK
{
	_PEB_FREE_BLOCK* Next;
	ULONG Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;


typedef struct _ACTIVATION_CONTEXT_DATA { void* dummy; } ACTIVATION_CONTEXT_DATA;
typedef struct _ASSEMBLY_STORAGE_MAP { void* dummy; } ASSEMBLY_STORAGE_MAP;
typedef struct _FLS_CALLBACK_INFO { void* dummy; } FLS_CALLBACK_INFO;


typedef void (*PPEBLOCKROUTINE)(
	PVOID PebLock
	);

typedef struct _PEB {
	BYTE InheritedAddressSpace;
	BYTE ReadImageFileExecOptions;
	BYTE BeingDebugged;
	BYTE SpareBool;
	void* Mutant;
	LPVOID lpImageBaseAddress;
	_PEB_LDR_DATA* Ldr;
	_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	void* SubSystemData;
	void* ProcessHeap;
	_RTL_CRITICAL_SECTION* FastPebLock;
	void* FastPebLockRoutine;
	void* FastPebUnlockRoutine;
	DWORD EnvironmentUpdateCount;
	void* KernelCallbackTable;
	DWORD SystemReserved[1];
	DWORD ExecuteOptions : 2;  // bit offset: 34, len=2
	DWORD SpareBits : 30;      // bit offset: 34, len=30
	_PEB_FREE_BLOCK* FreeList;
	DWORD TlsExpansionCounter;
	void* TlsBitmap;
	DWORD TlsBitmapBits[2];
	void* ReadOnlySharedMemoryBase;
	void* ReadOnlySharedMemoryHeap;
	void** ReadOnlyStaticServerData;
	void* AnsiCodePageData;
	void* OemCodePageData;
	void* UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	DWORD NtGlobalFlag;
	_LARGE_INTEGER CriticalSectionTimeout;
	DWORD HeapSegmentReserve;
	DWORD HeapSegmentCommit;
	DWORD HeapDeCommitTotalFreeThreshold;
	DWORD HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	void** ProcessHeaps;
	void* GdiSharedHandleTable;
	void* ProcessStarterHelper;
	DWORD GdiDCAttributeList;
	void* LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	DWORD ImageSubsystemMinorVersion;
	DWORD ImageProcessAffinityMask;
	DWORD GdiHandleBuffer[34];
	void (*PostProcessInitRoutine)();
	void* TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	DWORD SessionId;
	_ULARGE_INTEGER AppCompatFlags;
	_ULARGE_INTEGER AppCompatFlagsUser;
	void* pShimData;
	void* AppCompatInfo;
	_UNICODE_STRING CSDVersion;
	void* ActivationContextData;
	void* ProcessAssemblyStorageMap;
	void* SystemDefaultActivationContextData;
	void* SystemAssemblyStorageMap;
	DWORD MinimumStackCommit;
} PEB, *PPEB;
