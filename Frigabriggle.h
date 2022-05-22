#include <Windows.h>
#include <winternl.h>

#pragma pack(push,1)

typedef struct get_eprocess
{
	ULONG64 process_id;
	ULONG64 eprocess;

	NTSTATUS status;
};

typedef struct get_process_base
{
	ULONG64 eprocess;
	ULONG64 base_address;
};

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

HANDLE driver_handle = NULL;

ULONG64 source_eprocess = NULL;
ULONG64 target_eprocess = NULL;

struct copy_memory copy_memory_struct = { 0 };
struct get_process_base get_process_base_struct = { 0 };
struct get_eprocess get_eprocess_struct = { 0 };

BOOLEAN get_driver_handle()
{
	driver_handle = CreateFileW
	(
		L"\\\\.\\QoinkyDoink"
		, GENERIC_READ | GENERIC_WRITE
		, FILE_SHARE_READ | FILE_SHARE_WRITE
		, NULL
		, OPEN_EXISTING
		, 0
		, NULL
	);

	return (driver_handle != INVALID_HANDLE_VALUE) ? TRUE : FALSE;
}

ULONG64 get_eprocess(ULONG64 process_id)
{
	get_eprocess_struct.process_id = process_id;

	DeviceIoControl(driver_handle, IOCTL_GET_EPROCESS, &get_eprocess_struct, sizeof(struct get_eprocess), NULL, NULL, NULL, NULL);

	return get_eprocess_struct.eprocess;
}

BOOLEAN read_memory(ULONG64 source_address, ULONG64 target_address, ULONG64 bytes_to_copy)
{
	copy_memory_struct.source_address = source_address;
	copy_memory_struct.source_eprocess = source_eprocess;
	copy_memory_struct.bytes_to_copy = bytes_to_copy;
	copy_memory_struct.target_address = target_address;
	copy_memory_struct.target_eprocess = target_eprocess;
	copy_memory_struct.copy_method = MMCOPYVIRTUALMEMORY;

	DeviceIoControl(driver_handle, IOCTL_COPY_MEMORY, &copy_memory_struct, sizeof(struct copy_memory), NULL, NULL, NULL, NULL);

	return (BOOLEAN)NT_SUCCESS(copy_memory_struct.error);
}

BOOLEAN write_memory(ULONG64 source_address, ULONG64 target_address, ULONG64 bytes_to_copy)
{
	copy_memory_struct.source_address = target_address;
	copy_memory_struct.source_eprocess = target_eprocess;
	copy_memory_struct.bytes_to_copy = bytes_to_copy;
	copy_memory_struct.target_address = source_address;
	copy_memory_struct.target_eprocess = source_eprocess;
	copy_memory_struct.copy_method = MMCOPYVIRTUALMEMORY;

	DeviceIoControl(driver_handle, IOCTL_COPY_MEMORY, &copy_memory_struct, sizeof(struct copy_memory), NULL, NULL, NULL, NULL);

	return (BOOLEAN)NT_SUCCESS(copy_memory_struct.error);
}

ULONG64 get_process_base(ULONG64 eprocess)
{
	get_process_base_struct.eprocess = eprocess;

	DeviceIoControl(driver_handle, IOCTL_GET_PROCESS_BASE, &get_process_base_struct, sizeof(struct get_process_base), NULL, NULL, NULL, NULL);

	return get_process_base_struct.base_address;
}
