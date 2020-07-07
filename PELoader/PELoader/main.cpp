
#include "stdio.h"
#include "PELoader.h"


int main()
{
	
	PELoader p;
	p.loadFile("C:\\Windows\\System32\\calc.exe");

	p.loadPE();

    return 0;
}