// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include <Windows.h>
#include "pch.h"
#include <stdio.h>
#include <time.h>
#include <winternl.h>
#include "detours.h"

/*
* La primera idea con este DLL es detectar cuando un proceso cargue alguna DLL correspondiente 
* En este caso en conjunto con un driver detectaremos cuando se realice la carga de DLL.
*/

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Advapi32.lib")

/* Donde vamos a poner los logs */
char* LogFilePath = "C:\\SimpleEDR\\log.txt";

/* Lo de siempre sera una suma, incluso puede ser una multiplicacion */
typedef int (WINAPI* anyfun_t)(int, int);

// Configuramos nuestra funcion como Nula
anyfun_t pSum = NULL;

// Added for the Sum
int WINAPI hookSuma(int a, int b) {
    return pSum(a,b) + 100;
}

/* Funcion para escribir logs en un archivo */
void WriteLogFile(CHAR* Data) {
    FILE* fLogFilePath;
    OVERLAPPED overlapped = { 0 };
    DWORD bytesWritten;
    SYSTEMTIME time;
    CHAR eventDataString[1024];

    INT pid = GetProcessId(GetCurrentProcess());
    LPSTR cmd = GetCommandLine();
    GetSystemTime(&time);

    sprintf(eventDataString, "%02d/%02d/%04d  %02d:%02d:%02d\tCommandLine:%s\tProcessId:%d\t%s",
        time.wDay,
        time.wMonth,
        time.wYear,
        time.wHour,
        time.wMinute,
        time.wSecond,
        cmd,
        pid,
        Data);

    HANDLE hFile = CreateFile(LogFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD FileOffset = SetFilePointer(hFile, 0, NULL, FILE_END);
    DWORD LockedBytesOffset = 0;
    while (TRUE) {
        if (!LockFile(hFile, FileOffset + LockedBytesOffset, 0, (DWORD)strlen(eventDataString), 0)) {
            if (GetLastError() != ERROR_LOCK_VIOLATION) {
                CloseHandle(hFile);
                return;
            }
            LockedBytesOffset++;
        }
        else {
            SetFilePointer(hFile, LockedBytesOffset, NULL, FILE_END);
            break;
        }
    }
    WriteFile(hFile, eventDataString, (DWORD)strlen(eventDataString), &bytesWritten, NULL);
    UnlockFile(hFile, FileOffset + LockedBytesOffset, 0, (DWORD)strlen(eventDataString), 0);
    CloseHandle(hFile);
}

/* Funcion para configurar detours */
void ConfigureDetours() {
    DWORD error = NO_ERROR; // Function for errors
    char EventData[512];

    // --- start initializing the detours ------
    
    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        sprintf(EventData, "[!] Fallo el inicio de Detour transaction; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR)
    {
        sprintf(EventData, "[!] Fallo la obtencion de Hilo; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    // Find the specific function from a DLL
    pSum = (anyfun_t) DetourFindFunction("C:\\test\\hola.dll", "suma");

    error = DetourAttach((PVOID*)&pSum, hookSuma);

    if (error != NO_ERROR) {
        sprintf(EventData, "[!] Fallo en DetourAttach; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourTransactionCommit();

    if (error != NO_ERROR) {
        sprintf(EventData, "[!] Fallo en la finalizacion de accion de Detour; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    // On the HTB code here finishes all and didnt use a detach but I'll see whats going on.

    sprintf(EventData, "[+] Detour Adjuntado; Finalizado correctamente\n");
    WriteLogFile(EventData);
}

void detachDetours() 
{
    DWORD error = NO_ERROR;
    char EventData[512];

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        sprintf(EventData, "[!] Fallo en inicio de Operacion en DetourTransaction; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) {
        sprintf(EventData, "[!] Fallo en inicio de actualizacion de Hilo; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourDetach((PVOID*)&pSum, hookSuma);
    if (error != NO_ERROR)
    {
        sprintf(EventData, "[!] Fallo en DetourDetach; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourTransactionCommit();
    if (error != NO_ERROR)
    {
        sprintf(EventData, "[!] Fallo en finalizacion de Operacion en DetourTransactionCommit; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    sprintf(EventData, "[+] Detour Desadjuntdo; Finalizado correctamente");
    WriteLogFile(EventData);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ConfigureDetours();
        break;
    case DLL_THREAD_ATTACH:
        // detachDetours();
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

