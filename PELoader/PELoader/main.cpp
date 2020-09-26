#include "PELoader.h"


int main()
{
	
	PELoader p;
	p.loadPEFromDisk("C:\\Windows\\SysWOW64\\explorer.exe");

    return 0;
}