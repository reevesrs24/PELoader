#ifndef PELOADER_H
#define PELOADER_H

#include <unordered_map>
#include "PEHelper.h"


class PELoader
{

public:
	PELoader();
	bool loadPEFromDisk(LPCSTR fileName);
	bool loadPEFromMemory(PBYTE pbBuffer);
	bool copyPESections(LPVOID lpImageBaseAddress);
	bool processReloc(LPVOID lpImageBaseAddress);
	bool processIData(LPVOID lpImageBaseAddress);
	bool processDIData(LPVOID lpImageBaseAddress);

private:
	HANDLE hFile;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeader;

};

#endif 
