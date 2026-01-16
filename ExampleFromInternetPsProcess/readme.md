# Explicacion de código

Toda la documentacion de apoyo para estas funciones podemos encontrarlas detalladamente en la siguiente [página](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/subscribing-to-process-creation-thread-creation-and-image-load-notifications-from-a-kernel-driver). Viene como usar cada una de las funciones que se implementan en el [código](Source.c) que a lo que tengo entendido pueden interactuar con la creación e identificación de procesos de windows. Solamente agrego este readme para que en algun futuro si ocupo tomar documentación, esté este archivo con la información resumida.

- [PsSetCreateProcessNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine)
- [PsSetLoadImageNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine)
- [PsSetCreateThreadNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine)
- [PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)

Cada una de estas funciones pueden generar un callback o rutina cuando se crea algún proceso en específico, depende de el proposito de cada funcion.

## PsSetCreateProcessNotifyRoutine
Notifica al driver sobre un proceso iniciado o terminado. Toma dos parametros:

```c
NTSTATUS PsSetCreateProcessNotifyRoutine(
  // pointer to a function to be called when a process is spawned or terminated
  PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
  // specifies whether to subscribe or unsubscribe from this event
  BOOLEAN                        Remove
);
```

Ejemplo de una rutina integrada para ```PsSetCreateProcessNotifyRoutine```:

```c
// handle incoming notifications about new/terminated processes
void sCreateProcessNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
	if (create)
	{
		PEPROCESS process = NULL;
		PUNICODE_STRING parentProcessName = NULL, processName = NULL;
		
		PsLookupProcessByProcessId(ppid, &process);
		SeLocateProcessImageName(process, &parentProcessName);

		PsLookupProcessByProcessId(pid, &process);
		SeLocateProcessImageName(process, &processName);

		DbgPrint("%d %wZ\n\t\t%d %wZ", ppid, parentProcessName, pid, processName);
	}
	else
	{
		DbgPrint("Process %d lost child %d", ppid, pid);
	}
}

// register sCreateProcessNotifyRoutine function to receive notifications about new/terminated processes
PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, FALSE);
```

## PsSetLoadImageNotifyRoutine
Notifica al driver cuando algún proceso carga una dll. Toma un solo parametro.

``` c
NTSTATUS PsSetLoadImageNotifyRoutine(
  PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);
```

La rutina puede ser implementada de la siguiente manera 

```c
// handle incoming notifications about module loads
void sLoadImageNotifyRoutine(PUNICODE_STRING imageName,	HANDLE pid, PIMAGE_INFO imageInfo)
{
	UNREFERENCED_PARAMETER(imageInfo);
	PEPROCESS process = NULL;
	PUNICODE_STRING processName = NULL;
	PsLookupProcessByProcessId(pid, &process);
	SeLocateProcessImageName(process, &processName);

	DbgPrint("%wZ (%d) loaded %wZ", processName, pid, imageName);
}

// register sLoadImageNotifyRoutinefunction to receive notifications new DLLs being loaded to processes
PsSetLoadImageNotifyRoutine(sLoadImageNotifyRoutine);
```

## PsSetCreateThreadNotifyRoutine
Notifica al driver de el arranque y terminacion de hilos. Usa toma un solo parametro.

```c
NTSTATUS PsSetCreateThreadNotifyRoutine(
  PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
);
```
Puede ser implementado de la siguiente manera.

```c
// handle incoming notifications about new/terminated processes
void sCreateThreadNotifyRoutine(HANDLE pid, HANDLE tid, BOOLEAN create)
{
	if (create)
	{
		DbgPrint("%d created thread %d", pid, tid);
	}
	else
	{
		DbgPrint("Thread %d of process %d exited", tid, pid);
	}
}

// register sCreateThreadNotifyRoutine to receive notifications about thread creation / termination
PsSetCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine);
```

## PsSetCreateProcessNotifyRoutineEx

Notifica al driver de algún proceso nuevo creado, nos permite terminalos después de que se hayan ejecutado. Toma dos parametros

```c
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  // pointer to a function to be called when a process is spawned 
  PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
  // specifies whether to subscribe or unsubscribe from this event
  BOOLEAN                           Remove
);
```
Ejemplo de una rutina integrada a ```PsSetCreateProcessNotifyRoutineEx```

```c
// handle incoming notifications about new/terminated processes and kill
// processes that have "notepad" in their commandline arguments
void sCreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
	UNREFERENCED_PARAMETER(process);
	UNREFERENCED_PARAMETER(pid);
	
	if (createInfo != NULL)
	{
		if (wcsstr(createInfo->CommandLine->Buffer, L"notepad") != NULL)
		{
			DbgPrint("[!] Access to launch notepad.exe was denied!");
			createInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}
	}
}

// subscribe sCreateProcessNotifyRoutineEx to new / terminated process notifications
PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, FALSE);

```