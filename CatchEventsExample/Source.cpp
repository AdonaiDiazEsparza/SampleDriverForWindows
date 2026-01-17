
/*
    My notes (Ignore them):
    These will be a kick of balls cause I dont really understand all the functions, I have one week learning how the drivers work
    Although I need to start creating the code, so here we go and we will start doing this project.

    well, on the example driver that Im basing to program this simple driver could find it on the following link: https://github.com/microsoft/Windows-driver-samples/tree/main/general/event
    Trying to catch events from the kernel. I'll try to get events from process.
*/

#include <Ntifs.h>
#include <ntddk.h>
#include <wdm.h>

/*  DEFINES     */

#define DRIVER_PREFIX "EVENT_CATCHER: "

#define OBJECT_NAME_STRING L"\\Device\\EVENT_CATCHER"
#define SYMBOLIC_NAME_STRING L"\\?\\EVENT_CATCHER"

/*  Routines    */
void DriverUnloadRoutine(PDRIVER_OBJECT DriverObject); // Unload routine
void NotifyForAProcessCreation(HANDLE ppid, HANDLE pid, BOOLEAN create); // Routine to notify when a process starts/finished.

// Entry Point for the Driver
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    PDEVICE_OBJECT      deviceObject; // Pointer to Object
    UNICODE_STRING      ntDeviceName = RTL_CONSTANT_STRING(OBJECT_NAME_STRING); // Name for the Object 
    UNICODE_STRING      symbolicLinkName = RTL_CONSTANT_STRING(SYMBOLIC_NAME_STRING); // The link name for the object 'deviceObject'
    NTSTATUS            status; // The status return 

    KdPrint((DRIVER_PREFIX "======> DRIVER ENTRY POINT\n"));

    /* Create object to use it */
    status = IoCreateDevice(
        DriverObject,               // DriverObject
        0,   // DeviceExtensionSize 
        &ntDeviceName,              // DeviceName
        FILE_DEVICE_UNKNOWN,        // DeviceType
        0 ,// FILE_DEVICE_SECURE_OPEN,    // DeviceCharacteristics
        FALSE,                      // Not Exclusive
        &deviceObject               // DeviceObject
    );

    // Check any error
    if (!NT_SUCCESS(status)) {
        KdPrint((DRIVER_PREFIX " Error Creating object: 0x%x\n", status));
        return status;
    }

    /* Set Entry Points */
    DriverObject->DriverUnload = DriverUnloadRoutine;

    /* Create the link name for the Device Object in the Driver*/
    status = IoCreateSymbolicLink(&symbolicLinkName, &ntDeviceName);

    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        KdPrint((DRIVER_PREFIX "IoCreateSymbolicLink returned 0x%x\n", status));
        return(status);
    }

    // Set the status to obtain all process
    status = PsSetCreateProcessNotifyRoutine(NotifyForAProcessCreation, FALSE);

    if (!NT_SUCCESS(status)) {
        KdPrint((DRIVER_PREFIX "IoCreateSymbolicLink returned 0x%x\n", status));
    }

    return status;
}

// The routine for the driver unload by the moment
void DriverUnloadRoutine(PDRIVER_OBJECT DriverObject)
{
    KdPrint((DRIVER_PREFIX "====>Unloading driver"));

    /* Set the names and objects */
    PDEVICE_OBJECT devObj = DriverObject->DeviceObject;
    UNICODE_STRING symbolicLinkName;

    // Remove routine to detect process
    PsSetCreateProcessNotifyRoutine(NotifyForAProcessCreation, TRUE);

    // Delete symbolic link name for the driver object
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_NAME_STRING);
    IoDeleteSymbolicLink(&symbolicLinkName);

    // Delete at the last the device Object assigned  in the driver object
    IoDeleteDevice(devObj);

    KdPrint((DRIVER_PREFIX "Driver Unloaded"));
}

// Routine to display all process created
void NotifyForAProcessCreation(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
    // Indicates if the process was created
    if (create)
    {
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
        KdPrint((DRIVER_PREFIX "%d %wZ\n\t\t%d %wZ", ppid, parentProcessName, pid, processName));
    }
    else
    {
        KdPrint((DRIVER_PREFIX "Process %d lost child %d", ppid, pid));
    }
}
