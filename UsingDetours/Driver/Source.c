#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>

#define DRIVER_PREFIX "=> DRIVER_TEST: " // Prefix for the logs

#define PRINT(fmt, ...) \
    DbgPrint(DRIVER_PREFIX fmt "\n", ##__VA_ARGS__)

UNICODE_STRING found_DLL = RTL_CONSTANT_STRING(L"hola.dll");


typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        } struct1;
    } union1;
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    } union2;

    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_DOS_HEADER
{
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG e_lfanew;
}IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
}IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;


typedef struct _IMAGE_FILE_HEADER
{
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
}IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;


typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    ULONG                SizeOfCode;
    ULONG                SizeOfInitializedData;
    ULONG                SizeOfUninitializedData;
    ULONG                AddressOfEntryPoint;
    ULONG                BaseOfCode;
    ULONGLONG            ImageBase;
    ULONG                SectionAlignment;
    ULONG                FileAlignment;
    USHORT                 MajorOperatingSystemVersion;
    USHORT                 MinorOperatingSystemVersion;
    USHORT                 MajorImageVersion;
    USHORT                 MinorImageVersion;
    USHORT                 MajorSubsystemVersion;
    USHORT                 MinorSubsystemVersion;
    ULONG                Win32VersionValue;
    ULONG                SizeOfImage;
    ULONG                SizeOfHeaders;
    ULONG                CheckSum;
    USHORT                 Subsystem;
    USHORT                 DllCharacteristics;
    ULONGLONG            SizeOfStackReserve;
    ULONGLONG            SizeOfStackCommit;
    ULONGLONG            SizeOfHeapReserve;
    ULONGLONG            SizeOfHeapCommit;
    ULONG                LoaderFlags;
    ULONG                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;


typedef struct _IMAGE_NT_HEADERS64 {
    ULONG                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   AddressOfFunctions;
    ULONG   AddressOfNames;
    ULONG   AddressOfNameOrdinals;
}IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;


typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;


typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
}KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID KKERNEL_ROUTINE(PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
typedef KKERNEL_ROUTINE(NTAPI* PKKERNEL_ROUTINE);
typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);

void KeInitializeApc(
    PRKAPC Apc,
    PRKTHREAD Thread,
    KAPC_ENVIRONMENT Environment,
    PKKERNEL_ROUTINE KernelRoutine,
    PKRUNDOWN_ROUTINE RundownRoutine,
    PKNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ProcessorMode,
    PVOID NormalContext
);


BOOLEAN KeInsertQueueApc(
    PRKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment
);

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KmdfEvtDeviceAdd;

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define NTDLL L"ntdll.dll"
#define EDRDLL L"C:\\test\\edrHook.dll"

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);

typedef NTSTATUS(__stdcall* LdrLoadDll_t)(_In_ PWCHAR PathToFile, _In_ ULONG Flags, _In_ PUNICODE_STRING ModuleFileName, _Out_ PHANDLE ModuleHandle);

typedef struct _INJECTION_CONTEXT {
    LdrLoadDll_t pLdrLoadDll;
    UNICODE_STRING DllName;
    WCHAR Buffer[256];
} INJECTION_CONTEXT, * PINJECTION_CONTEXT;


VOID UserApcRoutine(_In_ PVOID NormalContext, _In_ PVOID SystemArgument1, _In_ PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    PINJECTION_CONTEXT ctx = (PINJECTION_CONTEXT)NormalContext;
    HANDLE hModule = NULL;
    ctx->pLdrLoadDll(0, 0, &ctx->DllName, &hModule);
}


VOID UserApcRoutineEnd() {
    // Dummy function
}


SIZE_T UserApcRoutineSize() {
    return (SIZE_T)((ULONG_PTR)(UserApcRoutineEnd)-(ULONG_PTR)(UserApcRoutine));
}


VOID KernelApcRoutine(_In_ PVOID context, _In_ PVOID arg1, _In_ PVOID arg2, _In_ PVOID arg3, _In_ PVOID arg4) {
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);
    UNREFERENCED_PARAMETER(arg3);
    UNREFERENCED_PARAMETER(arg4);
    ExFreePool(context);
}


BOOLEAN UnicodeStringEndswith(PUNICODE_STRING FullString, PUNICODE_STRING SubString) {
    if (FullString && SubString && SubString->Length <= SubString->Length) {
        int offset = FullString->Length - SubString->Length;
        if (RtlCompareMemory((PVOID)((PUCHAR)FullString->Buffer + offset), SubString->Buffer, SubString->Length) == SubString->Length) {
            return TRUE;
        }
    }
    return FALSE;
}


PVOID GetFunctionAddress(PPEB peb, PUNICODE_STRING ModuleName, char* SymbolName) {
    LDR_DATA_TABLE_ENTRY* ModuleListHead = (LDR_DATA_TABLE_ENTRY*)((char*)peb->Ldr->InLoadOrderModuleList.Flink);
    LDR_DATA_TABLE_ENTRY* CurrentEntry = ModuleListHead;
    do {
        if (RtlCompareUnicodeString(&CurrentEntry->BaseDllName, ModuleName, TRUE) == 0) {
            PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)CurrentEntry->DllBase;
            PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)((PCHAR)CurrentEntry->DllBase + dos_header->e_lfanew);
            PIMAGE_OPTIONAL_HEADER64 optional_header = (PIMAGE_OPTIONAL_HEADER64)&nt_header->OptionalHeader;
            PIMAGE_DATA_DIRECTORY data_directory = &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((PCHAR)CurrentEntry->DllBase + data_directory->VirtualAddress);
            ULONG NumberOfFunctions = export_directory->NumberOfFunctions;
            ULONG NumberOfNames = export_directory->NumberOfNames;
            PULONG AddressOfFunctions = (PULONG)((PCHAR)CurrentEntry->DllBase + export_directory->AddressOfFunctions);
            PULONG AddressOfNames = (PULONG)((PCHAR)CurrentEntry->DllBase + export_directory->AddressOfNames);
            PSHORT AddressOfNameOrdinals = (PSHORT)((PCHAR)CurrentEntry->DllBase + export_directory->AddressOfNameOrdinals);

            for (ULONG i = 0; i < NumberOfFunctions; i++) {
                ULONG ordianl = AddressOfNameOrdinals[i];
                if (i >= NumberOfNames || ordianl >= NumberOfFunctions) {
                    return NULL;
                }
                PCHAR FunctionName = (PCHAR)CurrentEntry->DllBase + AddressOfNames[i];
                if (strcmp(FunctionName, SymbolName) == 0) {
                    return (PVOID)((PCHAR)CurrentEntry->DllBase + AddressOfFunctions[ordianl]);
                }
            }
            break;
        }
        CurrentEntry = (LDR_DATA_TABLE_ENTRY*)((char*)CurrentEntry->InLoadOrderLinks.Flink);
    } while (CurrentEntry != ModuleListHead);
    return NULL;
}


void InjectDLL(PEPROCESS Process) {
    PINJECTION_CONTEXT ctx = NULL;
    SIZE_T ctxSize = sizeof(INJECTION_CONTEXT);
    PVOID pUserApcCode = NULL;
    SIZE_T apcRoutineSize = UserApcRoutineSize();
    LdrLoadDll_t pLdrLoadDll;
    UNICODE_STRING ntdll_ustr;
    UNICODE_STRING dllpath_ustr;
    NTSTATUS status = STATUS_SUCCESS;

    PRINT("[.] Ejecutando inyeccion de DLL");

    KAPC_STATE* apc_state = (KAPC_STATE*)ExAllocatePool(NonPagedPool, sizeof(KAPC_STATE));
    KeStackAttachProcess(Process, apc_state);
    PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
    RtlInitUnicodeString(&ntdll_ustr, NTDLL);
    pLdrLoadDll = (LdrLoadDll_t)(GetFunctionAddress(peb, &ntdll_ustr, "LdrLoadDll"));

    PRINT("[+] LdrLoadDll address %p", pLdrLoadDll);

    __try {
        PRINT("[+] Asignando contexto en memoria");
        status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&ctx, 0, &ctxSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            PRINT("[-] Fallo de asignacion de contexto en memoria:0x%x", status);
            __leave;
        }

        PRINT("[+] Inicializando valores en contexto");
        ctx->pLdrLoadDll = pLdrLoadDll;
        RtlInitEmptyUnicodeString(&ctx->DllName, ctx->Buffer, sizeof(ctx->Buffer));
        RtlInitUnicodeString(&dllpath_ustr, EDRDLL);
        RtlCopyUnicodeString(&ctx->DllName, &dllpath_ustr);

        PRINT("[+] Asignando ApcCode");

        status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pUserApcCode, 0, &apcRoutineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!NT_SUCCESS(status)) {
            __leave;
        }
        RtlCopyMemory(pUserApcCode, (PVOID*)&UserApcRoutine, apcRoutineSize);

        PRINT("[+] RtlCopyMemory");
        PKAPC Apc = ExAllocatePool(NonPagedPool, sizeof(KAPC));
        KeInitializeApc(Apc, PsGetCurrentThread(), OriginalApcEnvironment, KernelApcRoutine, NULL, (PKNORMAL_ROUTINE)pUserApcCode, UserMode, ctx);

        PRINT("[+] Succefull KeInitializeApc call");
        if (!KeInsertQueueApc(Apc, NULL, NULL, 0)) {
            ExFreePool(Apc);
        }

        PRINT("[+] Succefull KeInsertQueueApc call");
    }

    __finally {
        KeUnstackDetachProcess(apc_state);
        PRINT("[!] ERROR EN ASIGNACION DE VALORES");
    }
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

    if (wcsstr(imageName->Buffer, found_DLL.Buffer))
    {
        PRINT("DLL ENCONTRADA EN PROCESO %wZ (%d)", processName, pid);
         InjectDLL(process);
    }
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

NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    PRINT("CARGANDO DRIVER");

    // Set routine to detect the DLLs
    status = PsSetLoadImageNotifyRoutine(LoadDLLNotify);

    if (!NT_SUCCESS(status))
    {
        PRINT("ERROR CREANDO RUTINA (0x%X)", status);
        return status;
    }

    // Set the Unload function for the driver Object
    DriverObject->DriverUnload = UnloadDriver;

    PRINT("DRIVER CARGADO");

    return status;
}