#include <Ntifs.h>
#include <ntddk.h>
#include <wdm.h>

/*
    Code to check wich dll where load, so we need to know and filter the exactly dll in a process are loading
*/

#define DRIVER_PREFIX "==========> DRIVER_TEST: " // Prefix for the logs

#define PRINT(fmt, ...) \
    DbgPrint(DRIVER_PREFIX fmt, ##__VA_ARGS__)


/* GLOBAL VARIABLES */

// DLL to protect
UNICODE_STRING g_ProtectedDll = RTL_CONSTANT_STRING(L"---.dll");

// Process authorized
HANDLE g_AuthorizedPid = NULL;
BOOLEAN g_IsAuthorizedSet = FALSE;

// Sincronization
FAST_MUTEX g_AuthorizationLock;

/* Unload driver routine */
void UnloadDriver(PDRIVER_OBJECT  DriverObject);

/* Routine to detect when a DLL is loaded in a new process */
void LoadDLLNotify(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo);

/* Routine to detect when a process is created/deleted */
void NotifyForAProcessEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo);

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    PRINT("Load Driver\n");

    ExInitializeFastMutex(&g_AuthorizationLock);

    status = PsSetCreateProcessNotifyRoutineEx(NotifyForAProcessEx, FALSE);

    if (!NT_SUCCESS(status))
    {
        PRINT("ERROR CREATING ROUTINE TO DETECT THE PROCESS (0x%X)\n", status);
        return status;
    }

    status = PsSetLoadImageNotifyRoutine(LoadDLLNotify);

    if (!NT_SUCCESS(status))
    {
        PRINT("ERROR CREATING ROUTINE TO DETECT THE DLL (0x%X)\n", status);
        return status;
    }

    PRINT("Driver Unloaded\n");

    return status;
}

// Routine for Unload the driver
void UnloadDriver(PDRIVER_OBJECT  DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS status = STATUS_SUCCESS;

    status = PsSetCreateProcessNotifyRoutineEx(NotifyForAProcessEx, TRUE);

    if (!NT_SUCCESS(status)) {
        PRINT("[!] ERROR FATAL REMOVIENDO RUTINA DE PROCESOS");
    }

    status = PsRemoveLoadImageNotifyRoutine(LoadDLLNotify);

    if (!NT_SUCCESS(status)) {
        PRINT("[!] ERROR FATAL REMOVIENDO RUTINA DE CARGA DE DLL");
    }

    PRINT("DRIVER UNLOADED\n");
}

// Routine to detect when a DLL is loaded
void LoadDLLNotify(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo)
{
    UNREFERENCED_PARAMETER(imageInfo);

    if (!imageName || !imageName->Buffer)
        return;

    if (wcsstr(imageName->Buffer, g_ProtectedDll.Buffer)) {

        ExAcquireFastMutex(&g_AuthorizationLock);

        if (!g_IsAuthorizedSet) {
            g_AuthorizedPid = pid;
            g_IsAuthorizedSet = TRUE;

            PRINT("DLL loaded by AUTHORIZED process PID %d\n", (ULONG)(ULONG_PTR)pid);
        }
        else if (g_AuthorizedPid != pid) {
            // Proceso no autorizado
            PRINT("BLOCKED DLL load by PID %d (authorized PID %d)\n", (ULONG)(ULONG_PTR)pid, (ULONG)(ULONG_PTR)g_AuthorizedPid);

            // AQUÍ después podrías:
            // - Marcar
            // - Avisar a user-mode
            // - Terminar proceso
        }

        ExReleaseFastMutex(&g_AuthorizationLock);
    }
}

void NotifyForAProcessEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
    UNREFERENCED_PARAMETER(process);

    if (createInfo == NULL) {
        ExAcquireFastMutex(&g_AuthorizationLock);

        if (g_IsAuthorizedSet && g_AuthorizedPid == pid) {
            g_IsAuthorizedSet = FALSE;
            g_AuthorizedPid = NULL;

            PRINT("Authorized process exited\n");
        }

        ExReleaseFastMutex(&g_AuthorizationLock);
        return;
    }

    // Proceso creado
    if (createInfo->ImageFileName) {
        PRINT("Process created: %wZ (PID %d)\n",
            createInfo->ImageFileName,
            (ULONG)(ULONG_PTR)pid);
    }
}