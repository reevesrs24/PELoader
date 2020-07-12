
#include "stdio.h"
#include "PELoader.h"


int main()
{
	
	PELoader p;

	p.loadFile("C:\\Windows\\SysWOW64\\explorer.exe");
	p.loadPE();

    return 0;
}