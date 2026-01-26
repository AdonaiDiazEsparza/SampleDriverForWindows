/*
    This will be the driver to connect with an exe needs to be simple IoCtrl buffer
*/

#include <Ntifs.h>
#include <ntddk.h>
#include <wdm.h>

// Driver prefix
#define DRIVER_PREFIX "==========> DRIVER_TEST: " // Prefix for the logs

// Macro to print on kernel
#define PRINT(fmt, ...) \
    DbgPrint(DRIVER_PREFIX fmt "\n", ##__VA_ARGS__)

/* global variables */
ULONG sampleNumber = 0;

/* Unload driver routine */
void UnloadDriver(PDRIVER_OBJECT  DriverObject);

/* Create Close function */
NTSTATUS MySampleObjectCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* Write Fucntion */
NTSTATUS MySampleObjectWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    DriverObject->MajorFunction[IRP_MJ_CREATE] =
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = MySampleObjectCreateClose;

    DriverObject->MajorFunction[IRP_MJ_WRITE] = MySampleObjectWrite;

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\MyDriver");

    PDEVICE_OBJECT DeviceObject;

    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject
    );

    if (!NT_SUCCESS(status))
    {
        PRINT("Failed Creating device Object (0x%08X)", status);
        return status;
    }

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MyDriver");

    status = IoCreateSymbolicLink(&symLink, &devName);

    if (!NT_SUCCESS(status))
    {
        PRINT("Failed Creating link name (0x%08X)", status);
        IoDeleteDevice(DeviceObject);
        return status;
    }

    PRINT("Loading Driver");

    // Set the Unload function for the driver Object
    DriverObject->DriverUnload = UnloadDriver;

    return status;
}

// Routine for Unload the driver
void UnloadDriver(PDRIVER_OBJECT  DriverObject)
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MyDriver");
    // delete symbolic link
    IoDeleteSymbolicLink(&symLink);

    // delete device object
    IoDeleteDevice(DriverObject->DeviceObject);

    PRINT("DRIVER UNLOADED");
}

// Create close routine
NTSTATUS MySampleObjectCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PRINT("Create/Close file routine called");

    if (IoGetCurrentIrpStackLocation(Irp)->MajorFunction == IRP_MJ_CREATE) {
        PRINT("Create called from process %u", HandleToULong(PsGetCurrentProcessId()));
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Write Routine
NTSTATUS MySampleObjectWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    auto irpSp = IoGetCurrentIrpStackLocation(Irp);

    // do-while-loop just for breake in a point
    do {

        if (irpSp->Parameters.Write.Length < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PULONG data = (PULONG)Irp->UserBuffer;

        if (data == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // A try/except to avoid errors on the pointer
        __try {
            sampleNumber = *data;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }

        PRINT("New number set: %d", sampleNumber);

        information = sizeof(ULONG);

    } while (false);

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}