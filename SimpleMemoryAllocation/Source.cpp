
/*
* The following code is the sample for thea simple memory management
* Allocation and free the memory
* It only copies the path of the registration of the driver
*/

#include "ntddk.h"

#define DRIVER_TAG 'abcd' 

UNICODE_STRING g_RegistryPath;

void SampleUnload(PDRIVER_OBJECT DriverObject);

// Our entry Point is the following 
// like the main call for as entry point for the program
extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	UNREFERENCED_PARAMETER(DriverObject);

	// Set the Unload function for the driver Object
	DriverObject->DriverUnload = SampleUnload;

	/*
	* I supposed in the Driver Object exists callbacks and routines use by the sistem when the Driver is install it and execut it.
	* Thats why we assign a routine when the driver is unload.
	*/

	// Here we allocate or assign the memory size and memory for the Buffer of g_RegistryPath
	g_RegistryPath.Buffer = (WCHAR*)ExAllocatePool2(POOL_FLAG_PAGED | POOL_FLAG_UNINITIALIZED, RegistryPath->Length, DRIVER_TAG);

	if (g_RegistryPath.Buffer == nullptr)
	{
		KdPrint(("failed memory allocation!\n"));

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_RegistryPath.MaximumLength = RegistryPath->Length;

	RtlCopyUnicodeString(&g_RegistryPath,
		(PCUNICODE_STRING)RegistryPath);

	// %wZ is for UNICODE_STRING objects
	KdPrint(("Original registry path: %wZ\n", RegistryPath));
	KdPrint(("Copied registry path: %wZ\n", &g_RegistryPath));
	
	return STATUS_SUCCESS;
}

// Sample load for the driver
void SampleUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	ExFreePool(g_RegistryPath.Buffer); // Free the buffer we allocate
	KdPrint(("Sample driver Unload called\n")); 
}