#include <windows.h>
#include "stdio.h"



int main()
{

	HANDLE hFile = CreateFileA(
		"C:\\Users\\pip\\Desktop\\HollowProcessInjection3\\HollowProcessInjection3\\yo.exe",
		GENERIC_READ,
		NULL,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Error opening file: %i", GetLastError());
        return -1;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);

    PBYTE pbBuffer = new BYTE[dwFileSize];
    PDWORD pdwNumberOfBytesRead = NULL;

    if (!ReadFile(hFile, pbBuffer, dwFileSize, pdwNumberOfBytesRead, NULL)) 
    {

        printf("Error reading file: %i", GetLastError());
        return -1;

    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pbBuffer;

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Failed: .exe does not have a valid DOS signature %i", GetLastError());
    }

    PIMAGE_NT_HEADERS pNTHeaderResource = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

    LPVOID lpVMem = VirtualAlloc(NULL, pNTHeaderResource->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    PBYTE pHeader = new BYTE[pNTHeaderResource->OptionalHeader.SizeOfHeaders];

    memcpy(pHeader, pDosHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders);

    if (!CopyMemory(lpVMem, pHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders))
    {
        printf("Failed: Unable to write headers: %i", GetLastError());
        return -1;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaderResource);
	DWORD dwRelocAddr = NULL;

    for (int i = 0; i < pNTHeaderResource->FileHeader.NumberOfSections; i++)
    {
        printf("Copying data from: %s\n", pSectionHeader->Name);

		if (i == 8) {
			dwRelocAddr = pSectionHeader->PointerToRawData;
		}

        PBYTE pSectionData = new BYTE[(DWORD)pSectionHeader->SizeOfRawData];

        memcpy(pSectionData, (PVOID)((DWORD)pDosHeader + (DWORD)pSectionHeader->PointerToRawData), (DWORD)pSectionHeader->SizeOfRawData);

        if (!CopyMemory((LPVOID)((DWORD)lpVMem + (DWORD)pSectionHeader->VirtualAddress), pSectionData, (DWORD)pSectionHeader->SizeOfRawData))
        {
            printf("Failed copying data from %s: %i", pSectionHeader->Name, GetLastError());
            return -1;
        }
        pSectionHeader++;
    }

	int delta = 0;;



	IMAGE_DATA_DIRECTORY relocData = pNTHeaderResource->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD dwOffset = 0;
	typedef struct BASE_RELOCATION_BLOCK {
		DWORD PageAddress;
		DWORD BlockSize;
	} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

	typedef struct BASE_RELOCATION_ENTRY {
		USHORT Offset : 12;
		USHORT Type : 4;
	} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

	

	PBASE_RELOCATION_BLOCK pBlockheader;


	DWORD dwEntryCount;
	PBASE_RELOCATION_ENTRY pBlocks;
	delta = (DWORD)lpVMem - (DWORD)pNTHeaderResource->OptionalHeader.ImageBase;
	
	while (dwOffset < relocData.Size)
	{
		pBlockheader = (PBASE_RELOCATION_BLOCK)&pbBuffer[dwRelocAddr + dwOffset];

		dwOffset += sizeof(BASE_RELOCATION_BLOCK);

		dwEntryCount = (pBlockheader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		pBlocks = (PBASE_RELOCATION_ENTRY)&pbBuffer[dwRelocAddr + dwOffset];

		for (DWORD y = 0; y < dwEntryCount; y++)
		{
			dwOffset += sizeof(BASE_RELOCATION_ENTRY);

			if (pBlocks[y].Type == 0)
				continue;

			DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;

			
			DWORD dwBuffer = 0;

			

			memcpy(&dwBuffer, (PVOID)((DWORD)lpVMem + (DWORD)dwFieldAddress), sizeof(dwBuffer));

			printf("Relocating 0x%p -> 0x%p\r\n", dwBuffer, dwBuffer + delta);

			dwBuffer += delta;

			memcpy((PVOID)((DWORD)lpVMem + (DWORD)dwFieldAddress), &dwBuffer, sizeof(dwBuffer));
			
		}


	}
	
	//Relcoation Test End

	// Resolve IAT Begin

	
	pDosHeader = (PIMAGE_DOS_HEADER)lpVMem;

	pNTHeaderResource = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	DWORD origThunkPtr;

	PIMAGE_IMPORT_DESCRIPTOR pImpDecsriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosHeader + (DWORD)pNTHeaderResource->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImpDecsriptor->Name != NULL) {

		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + (DWORD)pImpDecsriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThunkFirst = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + (DWORD)pImpDecsriptor->FirstThunk);
		LPSTR dllName = (LPSTR)((DWORD)lpVMem + (DWORD)pImpDecsriptor->Name);

		printf("%s\n", dllName);
		HMODULE dllHMod = LoadLibraryA(dllName);


		while (pThunk->u1.AddressOfData != NULL) {

			PIMAGE_IMPORT_BY_NAME pImage = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + (DWORD)pThunk->u1.Function);
			HANDLE procAddr = GetProcAddress(dllHMod, pImage->Name);

			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				printf("Ordinal");
			
			
			DWORD oldPrivilege;
			printf("%s -> 0x%p -> 0x%p\n", pImage->Name, pThunkFirst->u1.Function, procAddr);
			pThunkFirst->u1.Function = (DWORD)procAddr;

			printf("%s -> 0x%p -> 0x%p\n", pImage->Name, pThunkFirst->u1.Function, procAddr);
			//VirtualProtect(thunkPtr, sizeof(LPDWORD), oldPrivilege, &oldPrivilege);
			pThunk++;
			pThunkFirst++;
		}

		pImpDecsriptor++;
	}

	// Resolve IAT End
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
		DWORD ExecuteOptions : 2; // bit offset: 34, len=2
		DWORD SpareBits : 30; // bit offset: 34, len=30
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

	PPEB	peb;
	peb = (PPEB)__readfsdword(0x30);
	peb->lpImageBaseAddress = (LPVOID) lpVMem;

	printf("PEB Image Base Address: 0x%08x\n", peb->lpImageBaseAddress);

	DWORD dwOld;
	VirtualProtect((LPVOID)lpVMem, pNTHeaderResource->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &dwOld);

	DWORD dwEP = (DWORD)lpVMem + pNTHeaderResource->OptionalHeader.AddressOfEntryPoint;
	printf("Executing Entry Point: 0x%08x", dwEP);

	
	__asm {
		mov eax, dwEP
		call eax
		int 3
	};
	

    return 0;
}