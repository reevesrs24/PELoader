#include <windows.h>
#include "stdio.h"


int main()
{

	HANDLE hFile = CreateFileA(
		"C:\\Users\\pip\\Desktop\\HollowProcessInjection3\\HollowProcessInjection3\\HelloWorld.exe",
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

    LPVOID lpVMem = VirtualAlloc(NULL, pNTHeaderResource->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PBYTE pHeader = new BYTE[pNTHeaderResource->OptionalHeader.SizeOfHeaders];

    memcpy(pHeader, pDosHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders);

    if (!WriteProcessMemory(GetCurrentProcess(), lpVMem, pHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("Failed: Unable to write headers: %i", GetLastError());
        return -1;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaderResource);
	DWORD dwRelocAddr = NULL;

    for (int i = 0; i < pNTHeaderResource->FileHeader.NumberOfSections; i++)
    {
        printf("Copying data from: %s\n", pSectionHeader->Name);

		if (i == 4) {
			dwRelocAddr = pSectionHeader->PointerToRawData;
		}

        PBYTE pSectionData = new BYTE[(DWORD)pSectionHeader->SizeOfRawData];

        memcpy(pSectionData, (PVOID)((DWORD)pDosHeader + (DWORD)pSectionHeader->PointerToRawData), (DWORD)pSectionHeader->SizeOfRawData);

        if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)((DWORD)lpVMem + (DWORD)pSectionHeader->VirtualAddress), pSectionData, (DWORD)pSectionHeader->SizeOfRawData, NULL))
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
	DWORD dwSize = GetFileSize(hFile, 0);
	PBYTE pBuffer = new BYTE[dwSize];
	DWORD dwBytesRead = 0;
	ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, 0);

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

			printf("%s -> 0x%p -> 0x%p\n", pImage->Name, procAddr, pThunkFirst->u1.Function);
			//LPDWORD thunkPtr = (LPDWORD)&pThunkFirst->u1.AddressOfData;
			pThunkFirst->u1.Function = (DWORD)procAddr;


			pThunk++;
		}

		pImpDecsriptor++;
	}

	// Resolve IAT End
    return 0;
}