
/*
    My notes (Ignore them):
    These will be a kick of balls cause I dont really understand all the functions, I have one week learning how the drivers work
    Although I need to start creating the code, so here we go and we will start doing this project.

    well, on the example driver that Im basing to program this simple driver could find it on the following link: https://github.com/microsoft/Windows-driver-samples/tree/main/general/event
    Trying to catch events from the kernel. I'll try to get events from process.
*/

#include <ntddk.h>

/*  DEFINES     */

#define DRIVER_PREFIX "EVENT_CATCHER: "

#define OBJECT_NAME_STRING L"\\Device\\EVENT_CATCHER"
#define SYMBOLIC_NAME_STRING L"\\?\\EVENT_CATCHER"

/*  STRUCTS     */

// Struct for the extention or data to catch
typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT  Self;   //  the device object
    LIST_ENTRY      EventQueueHead; // where all the user notification requests are queued
    KSPIN_LOCK      QueueLock;  // Lock the queue
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;

/*  Routines    */
void DriverUnloadRoutine(PDRIVER_OBJECT DriverObject); // Unload routine

// Entry Point for the Driver
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    PDEVICE_OBJECT      deviceObject; // Pointer to Object
    PDEVICE_EXTENSION   deviceExtension; // Extesion use for the object device

    // By the moment just for this variable
    UNREFERENCED_PARAMETER(deviceExtension);

    UNICODE_STRING      ntDeviceName = RTL_CONSTANT_STRING(OBJECT_NAME_STRING); // Name for the Object 
    UNICODE_STRING      symbolicLinkName = RTL_CONSTANT_STRING(SYMBOLIC_NAME_STRING); // The link name for the object 'deviceObject'
    NTSTATUS            status; // The status return 

    KdPrint((DRIVER_PREFIX "======> DRIVER ENTRY POINT\n"));

    /* Create object to use it */
    status = IoCreateDevice(DriverObject,               // DriverObject
        sizeof(DEVICE_EXTENSION), // DeviceExtensionSize 
        &ntDeviceName,              // DeviceName
        FILE_DEVICE_UNKNOWN,        // DeviceType
        FILE_DEVICE_SECURE_OPEN,    // DeviceCharacteristics
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

    return status;
}

// The routine for the driver unload by the moment
void DriverUnloadRoutine(PDRIVER_OBJECT DriverObject)
{
    KdPrint((DRIVER_PREFIX "====>Unloading driver"));

    /* Set the names and objects */
    PDEVICE_OBJECT devObj = DriverObject->DeviceObject;
    UNICODE_STRING symbolicLinkName;

    // Delete symbolic link name for the driver object
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_NAME_STRING);
    IoDeleteSymbolicLink(&symbolicLinkName);

    // Delete at the last the device Object assigned  in the driver object
    IoDeleteDevice(devObj);
}
