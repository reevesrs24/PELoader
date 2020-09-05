
#include "stdio.h"
#include "PELoader.h"


int main()
{
	
	PELoader p;
	p.loadPEFromDisk("C:\\Windows\\SysWOW64\\write.exe");

    return 0;
}