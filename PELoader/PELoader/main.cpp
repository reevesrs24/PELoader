#include <windows.h>
#include "stdio.h"


int main()
{

    HANDLE hFile = CreateFileA(
        "C:\\Users\\pip\\Dev\\PELoader\\PELoader\\PELoader\\HelloWorld.exe",
        GENERIC_READ | GENERIC_WRITE,
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

    if (!ReadFile(
        hFile,
        pbBuffer,
        dwFileSize,
        pdwNumberOfBytesRead,
        NULL)) 
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

    /* Allocate virtual memory for the process which is to be injected */
    LPVOID lpVMem = VirtualAllocEx(GetCurrentProcess(), NULL, pNTHeaderResource->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PBYTE pHeader = new BYTE[pNTHeaderResource->OptionalHeader.SizeOfHeaders];

    memcpy(pHeader, pDosHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders);

    /* Copy the headers of the process that is to be injected into the created process */
    if (!WriteProcessMemory(GetCurrentProcess(), lpVMem, pHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("Failed: Unable to write headers: %i", GetLastError());
        return -1;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaderResource);

    /* Copy the sections of the process that is to be injected into the created process */
    for (int i = 0; i < pNTHeaderResource->FileHeader.NumberOfSections; i++)
    {
        printf("Copying data from: %s\n", pSectionHeader->Name);

        PBYTE pSectionData = new BYTE[(DWORD)pSectionHeader->SizeOfRawData];

        memcpy(pSectionData, (PVOID)((DWORD)pDosHeader + (DWORD)pSectionHeader->PointerToRawData), (DWORD)pSectionHeader->SizeOfRawData);

        if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)((DWORD)lpVMem + (DWORD)pSectionHeader->VirtualAddress), pSectionData, (DWORD)pSectionHeader->SizeOfRawData, NULL))
        {
            printf("Failed copying data from %s: %i", pSectionHeader->Name, GetLastError());
            return -1;
        }
        pSectionHeader++;
    }
    return 0;
}