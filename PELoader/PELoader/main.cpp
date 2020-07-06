
#include "stdio.h"
#include "PELoader.h"


int main()
{
	
	PELoader p;
	//p.loadFile("C:\\Users\\pip\\Desktop\\pestudio\\pestudio\\pestudio.exe");
	p.loadFile("C:\\Users\\pip\\Dev\\PELoader\\PELoader\\PELoader\\yo.exe");

	p.loadPE();

    return 0;
}