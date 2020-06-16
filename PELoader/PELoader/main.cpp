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
        return 0;
    }



    return 0;
}