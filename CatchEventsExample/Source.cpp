#include <ntddk.h>

/*
    Code to detect when a dll is load it
*/

#define DRIVER_PREFIX "==========> DRIVER_TEST: " // Prefix for the logs

#define PRINT(fmt, ...) \
    DbgPrint(DRIVER_PREFIX fmt, ##__VA_ARGS__)

/* Driver Unlaod routine */
void UnloadDriver(PDRIVER_OBJECT  DriverObject);

/* Routine to detect when a DLL is loaded*/
void LoadDLLNotify(PUNICODE_STRING imageName,	HANDLE pid, PIMAGE_INFO imageInfo);

/* Routine to detect when a process is created/deleted */
void NotifyForAProcessCreation(HANDLE ppid, HANDLE pid, BOOLEAN create);

/* Entry Point */
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    PRINT("Load Driver\n");

    /*status = PsSetCreateProcessNotifyRoutine(NotifyForAProcessCreation, FALSE);

    if (!NT_SUCCESS(status))
    {
        PRINT("ERROR CREATING ROUTINE TO DETECT THE PROCESS (0x%X)\n", status);
        return status;
    }*/

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
    PsRemoveLoadImageNotifyRoutine(LoadDLLNotify);
    // PsSetCreateProcessNotifyRoutine(NotifyForAProcessCreation, TRUE);

    PRINT("Unload Driver\n");
}

// Routine to detect when a DLL is loaded
void LoadDLLNotify(PUNICODE_STRING imageName,	HANDLE pid, PIMAGE_INFO imageInfo)
{
	UNREFERENCED_PARAMETER(imageInfo);
	PEPROCESS process = NULL;
	PUNICODE_STRING processName = NULL;
	PsLookupProcessByProcessId(pid, &process);
	SeLocateProcessImageName(process, &processName);

	PRINT("%wZ (%d) loaded %wZ\n", processName, pid, imageName);
}

// Routine to display all process created
void NotifyForAProcessCreation(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
    // Indicates if the process was created
    if (create)
    {

        PRINT(DRIVER_PREFIX "PROCESO CREADO: \n");

        PEPROCESS process = NULL; // Variable to storage the process 
        PUNICODE_STRING parentProcessName = NULL, processName = NULL; // parentProcess and process name

        // Here we look for the parent process by it parent process id
        PsLookupProcessByProcessId(ppid, &process);

        // Get the name of the parent process
        SeLocateProcessImageName(process, &parentProcessName);

        // Locate the Process by it pid 
        PsLookupProcessByProcessId(pid, &process);
        SeLocateProcessImageName(process, &processName);

        // print the process
        PRINT(DRIVER_PREFIX "%d %wZ\n\t\t%d %wZ\n", ppid, parentProcessName, pid, processName);
    }
    else
    {
        PRINT(DRIVER_PREFIX "ELIMINACION DE PROCESO: \n");
        PRINT(DRIVER_PREFIX "Procesexos %d lost child %d\n", ppid, pid);
    }
}