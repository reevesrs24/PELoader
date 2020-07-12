#ifndef PELOADER_H
#define PELOADER_H

#include "PEHelper.h"

class PELoader
{

	public:
		PELoader();
		bool loadFile(LPCSTR fileName);
		bool loadPE();
		bool copyPESections(LPVOID lpImageBaseAddress, PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS pNTHeader);
		bool setRelocations(LPVOID lpImageBaseAddress);

    private:
		HANDLE hFile;
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNTHeader; 

};

#endif 
