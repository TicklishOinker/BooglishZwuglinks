#include <ntifs.h>
#include <stdarg.h>

#define log_success(fmt, ...) vDbgPrintExWithPrefix("[+] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, __VA_ARGS__)
#define log_failure(fmt, ...) vDbgPrintExWithPrefix("[-] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, __VA_ARGS__)
#define log_neutral(fmt, ...) vDbgPrintExWithPrefix("[.] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, __VA_ARGS__)

#pragma pack(push,1)

typedef struct get_eprocess
{
	ULONG64 process_id;
	ULONG64 eprocess;

	NTSTATUS status;
};

#pragma pack(pop)

__forceinline void get_eprocess(struct get_eprocess* parameters)
{
	parameters->status = PsLookupProcessByProcessId((HANDLE)parameters->process_id, &parameters->eprocess);
	log_neutral("parameters->status = PsLookupProcessByProcessId(%llx, %llx);\n", parameters->process_id, &parameters->eprocess);
}

#pragma pack(push,1)

typedef struct get_process_base
{
	ULONG64 eprocess;
	ULONG64 base_address;
};

#pragma pack(pop)

NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(
	__in PEPROCESS Process
);

#pragma pack(push,1)

__forceinline void get_process_base(struct get_process_base* parameters)
{
	parameters->base_address = PsGetProcessSectionBaseAddress(parameters->eprocess);
	log_neutral("parameters->base_address = PsGetProcessSectionBaseAddress(%llx);\n", parameters->eprocess);
}

typedef struct copy_memory
{
	ULONG64 source_eprocess;
	ULONG64 source_address;
	ULONG64 target_eprocess;
	ULONG64 target_address;

	ULONG64 bytes_to_copy;
	ULONG64 bytes_copied;

	ULONG64 copy_method;

	NTSTATUS error;
};

#pragma pack(pop)

#define MMCOPYVIRTUALMEMORY 0
#define PHYSICAL_MEMORY 1

NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
	IN  PEPROCESS FromProcess,
	IN  CONST VOID* FromAddress,
	IN  PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN  SIZE_T BufferSize,
	IN  KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

__forceinline void copy_memory(struct copy_memory* parameters)
{
	switch (parameters->copy_method)
	{
	case MMCOPYVIRTUALMEMORY:
	{
		parameters->error = MmCopyVirtualMemory
		(
			parameters->source_eprocess
			, parameters->source_address
			, parameters->target_eprocess
			, parameters->target_address
			, parameters->bytes_to_copy
			, KernelMode
			, &parameters->bytes_copied
		);
		break;
	}
	case PHYSICAL_MEMORY:
	{
		log_failure("Physical memory copy method %llx not implemented.\n", parameters->copy_method);
		parameters->error = STATUS_NOT_IMPLEMENTED;
		break;
	}
	default:
	{
		log_failure("Memory copy method %llx not implemented.\n", parameters->copy_method);
		parameters->error = STATUS_NOT_IMPLEMENTED;
	}
	}
}

#define FILE_DEVICE_QOINKYDOINK 0x00009999

#define IOCTL_INDEX 0x2022

#define IOCTL_COPY_MEMORY     CTL_CODE(FILE_DEVICE_QOINKYDOINK,  \
	IOCTL_INDEX,      \
	METHOD_BUFFERED,        \
	FILE_ANY_ACCESS)

#define IOCTL_GET_EPROCESS    CTL_CODE(FILE_DEVICE_QOINKYDOINK,  \
	IOCTL_INDEX + 1,  \
	METHOD_BUFFERED,        \
	FILE_ANY_ACCESS)

#define IOCTL_GET_PROCESS_BASE		 CTL_CODE(FILE_DEVICE_QOINKYDOINK,  \
	IOCTL_INDEX + 2,   \
	METHOD_BUFFERED,         \
	FILE_ANY_ACCESS)

NTSTATUS device_dispatch(DEVICE_OBJECT* device_object, IRP* irp)
{
	PIO_STACK_LOCATION io_stack_location = IoGetCurrentIrpStackLocation(irp);

	switch (io_stack_location->MajorFunction)
	{
	case IRP_MJ_CREATE:
	{
		break;
	}

	case IRP_MJ_CLOSE:
	{
		break;
	}

	case IRP_MJ_DEVICE_CONTROL:
	{
		switch (io_stack_location->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_COPY_MEMORY:
		{
			copy_memory(irp->AssociatedIrp.SystemBuffer);
		}

		case IOCTL_GET_EPROCESS:
		{
			get_eprocess(irp->AssociatedIrp.SystemBuffer);
		}

		
		case IOCTL_GET_PROCESS_BASE:
		{
			get_process_base(irp->AssociatedIrp.SystemBuffer);
		}
		default:
		{
			char io_control_code_unimplemented_log[] = { 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x49, 0x6F, 0x43, 0x6F, 0x6E, 0x74, 0x72, 0x6F, 0x6C, 0x20, 0x49, 0x6F, 0x43, 0x6F, 0x6E, 0x74, 0x72, 0x6F, 0x6C, 0x43, 0x6F, 0x64, 0x65, 0x20, 0x25, 0x78, 0x20, 0x75, 0x6E, 0x69, 0x6D, 0x70, 0x6C, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x65, 0x64, 0x2E, 0x5C, 0x6E, 0x00 };
			log_failure(&io_control_code_unimplemented_log, io_stack_location->Parameters.DeviceIoControl.IoControlCode);
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}

		}

		break;
	}

	default:
	{
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		break;
	}
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void device_unload(DRIVER_OBJECT* driver_object)
{
	UNICODE_STRING symbolic_link;

	wchar_t symbolic_link_unicode[] = { 0x5c , 0x44 , 0x6f , 0x73 , 0x44 , 0x65 , 0x76 , 0x69 , 0x63 , 0x65 , 0x73 , 0x5c , 0x51 , 0x6f , 0x69 , 0x6e , 0x6b , 0x79 , 0x44 , 0x6f , 0x69 , 0x6e , 0x6b, 0x00 };
	RtlInitUnicodeString(&symbolic_link, &symbolic_link_unicode);

	if (!NT_SUCCESS(IoDeleteSymbolicLink(&symbolic_link)))
	{
		char failure_delete_symbolic_link_log[] = { 0x46, 0x61, 0x69, 0x6C, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x64, 0x65, 0x6C, 0x65, 0x74, 0x65, 0x20, 0x73, 0x79, 0x6D, 0x62, 0x6F, 0x6C, 0x69, 0x63, 0x20, 0x6C, 0x69, 0x6E, 0x6B, 0x20, 0x5C, 0x22, 0x25, 0x77, 0x5A, 0x5C, 0x22, 0x2E, 0x5C, 0x6E, 0x00 };
		log_failure(&failure_delete_symbolic_link_log, &symbolic_link);
	}

	char deleted_device_log[] = { 0x44, 0x65, 0x6C, 0x65, 0x74, 0x65, 0x64, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x73, 0x79, 0x6D, 0x62, 0x6F, 0x6C, 0x69, 0x63, 0x20, 0x6C, 0x69, 0x6E, 0x6B, 0x20, 0x5C, 0x22, 0x25, 0x77, 0x5A, 0x5C, 0x22, 0x2E, 0x5C, 0x6E, 0x00 };
	IoDeleteDevice(driver_object->DeviceObject);
	log_success(&deleted_device_log, &symbolic_link);
}

NTSTATUS DriverEntry(DRIVER_OBJECT* driver_object, UNICODE_STRING* registry_path)
{
	UNICODE_STRING device_name;
	UNICODE_STRING symbolic_link;
	PDEVICE_OBJECT device_obect = NULL;
	
	NTSTATUS status;

	char driver_loaded_log[] = { 0x51, 0x6F, 0x69, 0x6E, 0x6B, 0x79, 0x44, 0x6F, 0x69, 0x6E, 0x6B, 0x20, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x20, 0x6C, 0x6F, 0x61, 0x64, 0x65, 0x64, 0x2E, 0x20, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x5F, 0x70, 0x61, 0x74, 0x68, 0x2E, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x20, 0x3D, 0x20, 0x5C, 0x22, 0x25, 0x77, 0x5A, 0x5C, 0x22, 0x2E, 0x5C, 0x6E, 0x00 };
	log_neutral(&driver_loaded_log, registry_path);

	wchar_t device_name_unicode[] = { 0x5c , 0x44 , 0x65 , 0x76 , 0x69 , 0x63 , 0x65 , 0x5c , 0x51 , 0x6f , 0x69 , 0x6e , 0x6b , 0x79 , 0x44 , 0x6f , 0x69 , 0x6e , 0x6b, 0x00 };
	RtlInitUnicodeString(&device_name, &device_name_unicode);

	status = IoCreateDevice
	(
		driver_object
		, 0
		, &device_name
		, FILE_DEVICE_QOINKYDOINK
		, 0
		, FALSE
		, &device_obect
	);

	if (!NT_SUCCESS(status))
	{
		char failure_create_device_log[] = { 0x46, 0x61, 0x69, 0x6C, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x5C, 0x22, 0x25, 0x77, 0x5A, 0x5C, 0x22, 0x2E, 0x5C, 0x6E, 0x00 };
		log_failure(&failure_create_device_log, &device_name);
		return STATUS_UNSUCCESSFUL;
	}

	driver_object->MajorFunction[IRP_MJ_CREATE] =
		driver_object->MajorFunction[IRP_MJ_CLOSE] =
		driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = device_dispatch;
	driver_object->DriverUnload = device_unload;


	wchar_t symbolic_link_unicode[] = { 0x5c , 0x44 , 0x6f , 0x73 , 0x44 , 0x65 , 0x76 , 0x69 , 0x63 , 0x65 , 0x73 , 0x5c , 0x51 , 0x6f , 0x69 , 0x6e , 0x6b , 0x79 , 0x44 , 0x6f , 0x69 , 0x6e , 0x6b, 0x00 };
	RtlInitUnicodeString(&symbolic_link, &symbolic_link_unicode);

	if (!NT_SUCCESS(IoCreateSymbolicLink(&symbolic_link, &device_name)))
	{
		char failure_symbolic_link_log[] = { 0x46, 0x61, 0x69, 0x6C, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x20, 0x73, 0x79, 0x6D, 0x62, 0x6F, 0x6C, 0x69, 0x63, 0x20, 0x6C, 0x69, 0x6E, 0x6B, 0x20, 0x5C, 0x22, 0x25, 0x77, 0x5A, 0x5C, 0x22, 0x2E, 0x5C, 0x6E, 0x00 };
		log_failure(&failure_symbolic_link_log, &symbolic_link);
		return STATUS_UNSUCCESSFUL;
	}

	char successfully_initialized_log[] = { 0x51, 0x6F, 0x69, 0x6E, 0x6B, 0x79, 0x44, 0x6F, 0x69, 0x6E, 0x6B, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x73, 0x79, 0x6D, 0x62, 0x6F, 0x6C, 0x69, 0x63, 0x20, 0x6C, 0x69, 0x6E, 0x6B, 0x20, 0x5C, 0x22, 0x25, 0x77, 0x5A, 0x5C, 0x22, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x66, 0x75, 0x6C, 0x6C, 0x79, 0x20, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x6C, 0x69, 0x7A, 0x65, 0x64, 0x2E, 0x5C, 0x6E, 0x00 };
	log_success(&successfully_initialized_log, &symbolic_link);
	return STATUS_SUCCESS;
}
