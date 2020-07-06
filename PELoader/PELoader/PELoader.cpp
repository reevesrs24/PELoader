#include "PELoader.h"
#include <stdio.h>
#include <unordered_map>

PELoader::PELoader()
{
	hFile = NULL;
	pDosHeader = NULL;
	pNTHeader = NULL;
	dwRelocAddr = NULL;
}


bool PELoader::loadFile(LPCSTR fileName)
{

	hFile = CreateFileA(
		fileName,
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
		return false;
	}

	return true;

}


bool PELoader::loadPE()
{
	DWORD dwFileSize = GetFileSize(hFile, NULL);

	PBYTE pbBuffer = new BYTE[dwFileSize];
	PDWORD pdwNumberOfBytesRead = NULL;

	if (!ReadFile(hFile, pbBuffer, dwFileSize, pdwNumberOfBytesRead, NULL))
	{

		printf("Error reading file: %i", GetLastError());
		return false;

	}

	pDosHeader = (PIMAGE_DOS_HEADER)pbBuffer;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Failed: .exe does not have a valid DOS signature %i", GetLastError());
		return false;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	LPVOID lpImageBaseAddress = VirtualAlloc(NULL, pNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	
	copyPESections(lpImageBaseAddress, pDosHeader, pNTHeader);
	setRelocations(lpImageBaseAddress);
	

	// Resolve IAT Begin
	pDosHeader = (PIMAGE_DOS_HEADER)lpImageBaseAddress;

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	DWORD origThunkPtr;

	PIMAGE_IMPORT_DESCRIPTOR pImpDecsriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosHeader + (DWORD)pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImpDecsriptor->Name != NULL) {

		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + (DWORD)pImpDecsriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThunkFirst = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + (DWORD)pImpDecsriptor->FirstThunk);
		LPSTR dllName = (LPSTR)((DWORD)lpImageBaseAddress + (DWORD)pImpDecsriptor->Name);

		printf("%s\n", dllName);
		HMODULE dllHMod = LoadLibraryA(dllName);


		while (pThunk->u1.AddressOfData != NULL) {

			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				printf("Ordinal");

			PIMAGE_IMPORT_BY_NAME pImage = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + (DWORD)pThunk->u1.Function);
			HANDLE procAddr = GetProcAddress(dllHMod, pImage->Name);

			DWORD oldPrivilege;
			//printf("%s -> 0x%p -> 0x%p\n", pImage->Name, pThunkFirst->u1.Function, procAddr);
			VirtualProtect(&pThunkFirst->u1.Function, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldPrivilege);
			pThunkFirst->u1.Function = (DWORD)procAddr;
			VirtualProtect(&pThunkFirst->u1.Function, sizeof(DWORD), oldPrivilege, &oldPrivilege);

			//printf("%s -> 0x%p -> 0x%p\n", pImage->Name, pThunkFirst->u1.Function, procAddr);
			
			pThunk++;
			pThunkFirst++;
		}

		pImpDecsriptor++;
	}
	// Resolve IAT End


	PPEB peb;
	peb = (PPEB)__readfsdword(0x30);
	peb->lpImageBaseAddress = (LPVOID)lpImageBaseAddress;

	printf("PEB Image Base Address: 0x%08x\n", peb->lpImageBaseAddress);


	DWORD dwEP = (DWORD)lpImageBaseAddress + pNTHeader->OptionalHeader.AddressOfEntryPoint;
	printf("Executing Entry Point: 0x%08x", dwEP);


	__asm {
		push dwEP
		ret
	};

}


bool PELoader::copyPESections(LPVOID lpImageBaseAddress, PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS pNTHeader)
{
	
	DWORD dwOldProtection;

	std::unordered_map<int, int> sectionMemoryProtection;
	sectionMemoryProtection.insert(std::make_pair(0x2, PAGE_EXECUTE));
	sectionMemoryProtection.insert(std::make_pair(0x4, PAGE_READONLY));
	sectionMemoryProtection.insert(std::make_pair(0x6, PAGE_EXECUTE_READ));
	sectionMemoryProtection.insert(std::make_pair(0xC, PAGE_READWRITE));
	sectionMemoryProtection.insert(std::make_pair(0xE, PAGE_EXECUTE_READWRITE));
	
	
	if (!CopyMemory(
		lpImageBaseAddress, 
		pDosHeader, 
		pNTHeader->OptionalHeader.SizeOfHeaders)
	)
	{
		printf("Failed: Unable to write headers: %i", GetLastError());
		return false;
	}

	// Set Header memory protection to PAGE_READONLY
	VirtualProtect(
		(LPVOID)lpImageBaseAddress, 
		pNTHeader->OptionalHeader.SizeOfHeaders, 
		PAGE_READONLY, 
		&dwOldProtection
	);

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);

	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
	{
		printf("Copying data from: %s\n", pSectionHeader->Name);

		if (!CopyMemory(
			(LPVOID)((DWORD)lpImageBaseAddress + (DWORD)pSectionHeader->VirtualAddress), 
			(PVOID)((DWORD)pDosHeader + (DWORD)pSectionHeader->PointerToRawData), 
			(DWORD)pSectionHeader->SizeOfRawData)
		)
		{
			printf("Failed copying data from %s: %i", pSectionHeader->Name, GetLastError());
			return false;
		}

		// Set the section correct memory protection
		VirtualProtect(
			(LPVOID)((DWORD)lpImageBaseAddress + (DWORD)pSectionHeader->VirtualAddress), 
			(DWORD)pSectionHeader->SizeOfRawData, 
			sectionMemoryProtection[(pSectionHeader->Characteristics >> 28)], 
			&dwOldProtection
		);

		pSectionHeader++;
	}

}

bool PELoader::setRelocations(LPVOID lpImageBaseAddress)
{

	DWORD dwOldProtection;
	DWORD dwRelocation;

	// Get Pointer to the relocation data directory
	PIMAGE_DATA_DIRECTORY pBaseReloc = (PIMAGE_DATA_DIRECTORY)&pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
	DWORD imageBaseDifference = (DWORD)lpImageBaseAddress - (DWORD)pNTHeader->OptionalHeader.ImageBase;

	PIMAGE_BASE_RELOCATION pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)lpImageBaseAddress + (DWORD)pBaseReloc->VirtualAddress);

	PBASE_RELOCATION_BLOCK pRelocationBlock = (PBASE_RELOCATION_BLOCK)pImageBaseRelocation;
	
	// Number of relocations needed per block
	DWORD relocationCount = (pImageBaseRelocation->SizeOfBlock - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_FIXUP);

	PBASE_RELOCATION_FIXUP pBaseRelocationFixup = (PBASE_RELOCATION_FIXUP)((DWORD)pRelocationBlock + sizeof(BASE_RELOCATION_BLOCK));

	do {

	
		for (int i = 0; i < relocationCount; i++) {
			
			if (pBaseRelocationFixup->Type == IMAGE_REL_BASED_HIGHLOW) 
			{

				VirtualProtect((PVOID)((DWORD)lpImageBaseAddress + (DWORD)pRelocationBlock->PageRVA + (DWORD)pBaseRelocationFixup->Offset), sizeof(dwRelocation), PAGE_EXECUTE_READWRITE, &dwOldProtection);
				CopyMemory(&dwRelocation, (PVOID)((DWORD)lpImageBaseAddress + (DWORD)pRelocationBlock->PageRVA + (DWORD)pBaseRelocationFixup->Offset), sizeof(dwRelocation));

				printf("0x%p -> 0x%p\n", dwRelocation, dwRelocation + imageBaseDifference);
				dwRelocation += imageBaseDifference;
				CopyMemory((PVOID)((DWORD)lpImageBaseAddress + (DWORD)pRelocationBlock->PageRVA + (DWORD)pBaseRelocationFixup->Offset), &dwRelocation, sizeof(dwRelocation));
				VirtualProtect((PVOID)((DWORD)lpImageBaseAddress + (DWORD)pRelocationBlock->PageRVA + (DWORD)pBaseRelocationFixup->Offset), sizeof(dwRelocation), dwOldProtection, &dwOldProtection);
				
			}
			
			pBaseRelocationFixup += 1;
			
		}

		pRelocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)pRelocationBlock + (DWORD)pRelocationBlock->BlockSize);
		relocationCount = (pRelocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_FIXUP);
		pBaseRelocationFixup = (PBASE_RELOCATION_FIXUP)((DWORD)pRelocationBlock + sizeof(BASE_RELOCATION_BLOCK));

	} while (pRelocationBlock->BlockSize != NULL);


	return true;
}
