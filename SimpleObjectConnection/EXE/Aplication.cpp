
#include <Windows.h>
#include <iostream>

/*
    Application to connect with the driver and send the buffer
*/

int main(int argc, const char* argv[])
{

    if (argc < 2) {
        printf("No parameters\n");
        return 0;
    }

    if (argc > 2) {
        printf("Too much parameters\n");
        return 0;
    }

    int data = atoi(argv[1]);

    printf("your number %d\n", data);

    HANDLE hDevice = CreateFile(L"\\\\.\\MyDriver", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("ERROR CREATING HANDLE!\n");
        return 0;
    }

    ULONG number = data;

    DWORD returned;
    BOOL success = WriteFile(hDevice,
        &number, sizeof(number),          // buffer and length
        &returned, nullptr);

    if (!success) {
        CloseHandle(hDevice);
        printf("ERROR SENDING BUFFER!\n");
        return 0;
    }

    printf("Number was changed\n");

    CloseHandle(hDevice);

    return 0;
}