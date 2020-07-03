
#include "stdio.h"
#include "PELoader.h"


int main()
{
	
	PELoader p;
	p.loadFile("C:\\Users\\pip\\Desktop\\HollowProcessInjection3\\HollowProcessInjection3\\yo.exe");
	p.loadPE();

    return 0;
}