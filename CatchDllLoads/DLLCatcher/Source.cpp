#include <Ntifs.h>
#include <ntddk.h>
#include <wdm.h>

/*
    Code to check wich dll where load, so we need to know and filter the exactly dll in a process are loading
*/

#define DRIVER_PREFIX "==========> DRIVER_TEST: " // Prefix for the logs

#define PRINT(fmt, ...) \
    DbgPrint(DRIVER_PREFIX fmt "\n", ##__VA_ARGS__)

/* GLOBAL VARIABLES */

UNICODE_STRING g_ProtectedDll = RTL_CONSTANT_STRING(L"hola.dll");

/* Unload driver routine */
void UnloadDriver(PDRIVER_OBJECT  DriverObject);

/* Routine to detect when a DLL is loaded in a new process */
void LoadDLLNotify(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo);

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    PRINT("Load Driver");

    // Set routine to detect the DLLs
    status = PsSetLoadImageNotifyRoutine(LoadDLLNotify);

    if (!NT_SUCCESS(status))
    {
        PRINT("ERROR CREATING ROUTINE TO DETECT THE DLL (0x%X)", status);
        return status;
    }

    // Set the Unload function for the driver Object
    DriverObject->DriverUnload = UnloadDriver;

    return status;
}

// Routine for Unload the driver
void UnloadDriver(PDRIVER_OBJECT  DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS status = STATUS_SUCCESS;

    status = PsRemoveLoadImageNotifyRoutine(LoadDLLNotify);

    if (!NT_SUCCESS(status)) {
        PRINT("[!] ERROR FATAL REMOVIENDO RUTINA DE CARGA DE DLL");
    }

    PRINT("DRIVER UNLOADED");
}

// Routine to detect when a DLL is loaded
void LoadDLLNotify(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo)
{
    UNREFERENCED_PARAMETER(imageInfo);
    UNREFERENCED_PARAMETER(imageName);

    if (!imageName || !imageName->Buffer)
        return;

    PEPROCESS process = NULL;
    PUNICODE_STRING processName = NULL;
    PsLookupProcessByProcessId(pid, &process);
    SeLocateProcessImageName(process, &processName);

    if (wcsstr(imageName->Buffer, g_ProtectedDll.Buffer)) {
        PRINT("DLL ENCONTRADA EN PROCESO %wZ (%d)", processName, pid);
    }
}
