#pragma once

#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>

#define DRIVER_PREFIX "=> DRIVER_TEST: " // Prefix for the logs

/* Macro for print with line jump */
#define PRINT(fmt, ...) \
    DbgPrint(DRIVER_PREFIX fmt "\n", ##__VA_ARGS__)

// otra manera de imprimir
#define print PRINT

#define STATIC_UNICODE_STRING(name, str) \
    static const UNICODE_STRING name = RTL_CONSTANT_STRING(str)

#define STATIC_OBJECT_ATTRIBUTES(object_attributes, label_name, str_name)\
	STATIC_UNICODE_STRING(label_name, str_name);\
	static OBJECT_ATTRIBUTES object_attributes = { sizeof(object_attributes), 0, const_cast<PUNICODE_STRING>(&label_name), OBJ_CASE_INSENSITIVE }

#define GET_PROCESS(peproc, pid)\
	PEPROCESS peproc = NULL;\
	PsLookupProcessByProcessId(pid, &peproc);

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define NTDLL L"ntdll.dll"
#define EDRDLL L"C:\\test\\edrHook.dll"
