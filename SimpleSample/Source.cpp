
// this is the import library by standard to connect with the kernel
#include "ntddk.h"

// Sample load for the driver
void SampleUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Unload the driver");
}

// Our entry Point is the following 
// like the main call for as entry point for the program
// IMPORTANT: add a extern C to solve the name entry
extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	UNREFERENCED_PARAMETER(RegistryPath);

	// Add Unload when you stop or uninstall the driver 
	DriverObject->DriverUnload = SampleUnload;

    // Simple print Sample Driver
	DbgPrint("Sample Driver");

	return STATUS_SUCCESS;
}