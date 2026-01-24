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

    // Set the Unload function for the driver Object
	DriverObject->DriverUnload = UnloadDriver;

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

    // If the image buffer is empty or nullptr returns
    if (!imageName || !imageName->Buffer)
        return;

    // here we compare the name of the dll
    if (wcsstr(imageName->Buffer, g_ProtectedDll.Buffer)) {

        // Get mutex to avoid crashes
        ExAcquireFastMutex(&g_AuthorizationLock);

        // If the Process is a nullptr, it assigns this process as the main to get the 
        if (!g_IsAuthorizedSet) {
            g_AuthorizedPid = pid;
            g_IsAuthorizedSet = TRUE;

            PRINT("DLL loaded by AUTHORIZED process PID %d\n", pid);
        }
        else if (g_AuthorizedPid != pid) {
            // Proceso no autorizado
            PRINT("BLOCKED DLL load by PID %d (authorized PID %d)\n", pid, g_AuthorizedPid);

            // AQUÍ después podrías:
            // - Marcar
            // - Avisar a user-mode
            // - Terminar proceso
        }

        // Give the mutex
        ExReleaseFastMutex(&g_AuthorizationLock);
    }
}

void NotifyForAProcessEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
    UNREFERENCED_PARAMETER(process);

    // if the process is finishes
    if (createInfo == NULL) {
        // get the mutex to avoid crashes
        ExAcquireFastMutex(&g_AuthorizationLock);

        // If the process is eliminated, throw message
        if (g_IsAuthorizedSet && g_AuthorizedPid == pid) {
            g_IsAuthorizedSet = FALSE;
            g_AuthorizedPid = NULL;

            PRINT("[!] El proceso autorizado se a terminado\n");
        }

        // Give mutex
        ExReleaseFastMutex(&g_AuthorizationLock);
        return;
    }

    // Process Created
    if (createInfo->ImageFileName) {
        PRINT("[+]  Process created: %wZ (PID %d)\n", createInfo->ImageFileName, pid);
    }
}