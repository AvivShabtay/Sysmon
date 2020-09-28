#include "pch.h"
#include "SysMon.h"
#include "SysMonCommon.h"
#include "AutoLock.h"

// Define prototypes:
DRIVER_UNLOAD SysmonUnload;
DRIVER_DISPATCH SysmonCreateClose;
DRIVER_DISPATCH SysmonRead;
void PushItem(LIST_ENTRY* entry);
void OnProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
void OnImageLoadNotify(_Inout_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
Globals g_Globals;

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	auto status = STATUS_SUCCESS;

	// Initialize linked list for the events:
	InitializeListHead(&g_Globals.ItemsHead);
	g_Globals.Mutex.Init();

	// Define the device symbolic link:
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\sysmon");
	bool symLinkCreated = false;
	bool processCallbackRegistered = false;
	bool threadCallbackRegistered = false;
	bool imageLoadCallbackRegistered = false;

	do {
		// Create device object for user-mode communication:
		UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\sysmon");
		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create device (0x%08X)\n", status));
			break;
		}

		// Choose the IO communication method:
		DeviceObject->Flags |= DO_DIRECT_IO;

		// Create symbolic link to the device object:
		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create symbolic link (0x%08X)\n", status));
			break;
		}

		symLinkCreated = true;

		// Register callback function for process creation:
		status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register process callback (0x%08X)\n", status));
			break;
		}

		processCallbackRegistered = true;

		// Register callback function for thread creation and exit:
		status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register thread callback (0x%08X)\n", status));
			break;
		}

		threadCallbackRegistered = true;

		// Register callback function for image load:
		status = PsSetLoadImageNotifyRoutine(OnImageLoadNotify);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to register image load callback (0x%08X)\n", status));
			break;
		}

		imageLoadCallbackRegistered = true;

	} while (false);

	// In case of failure:
	if (!NT_SUCCESS(status)) {
		if (symLinkCreated)
			IoDeleteSymbolicLink(&symLink);
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
		if (processCallbackRegistered)
			PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
		if (threadCallbackRegistered)
			PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
		if (imageLoadCallbackRegistered)
			PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);
	}

	// Define driver prototypes:
	DriverObject->DriverUnload = SysmonUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = SysmonCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SysmonCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = SysmonRead;

	return status;
}

/*
*
*/
NTSTATUS SysmonCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, 0);
	return STATUS_SUCCESS;
}


/*
*
*/
void SysmonUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	// Remove the callback to the notification:
	PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
	PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
	PsRemoveLoadImageNotifyRoutine(OnImageLoadNotify);

	// Remove the symbolic link:
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\sysmon");
	IoDeleteSymbolicLink(&symLink);

	// Remove the device driver:
	IoDeleteDevice(DriverObject->DeviceObject);

	// Free allocated memory:
	while (!IsListEmpty(&g_Globals.ItemsHead)) {
		auto entry = RemoveHeadList(&g_Globals.ItemsHead);
		ExFreePool(CONTAINING_RECORD(entry, FullItem<ItemHeader>, Entry));
	}
}


/*
*
*/
NTSTATUS SysmonRead(PDEVICE_OBJECT, PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto len = stack->Parameters.Read.Length;
	auto status = STATUS_SUCCESS;
	auto count = 0;

	// Test if the driver get address:
	NT_ASSERT(Irp->MdlAddress);

	// Returns the address of the user mode buffer mapped to kernel mode:
	auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	if (!buffer) {
		status = STATUS_INSUFFICIENT_RESOURCES;
	}
	else {
		AutoLock lock(g_Globals.Mutex); // require C++ 17
		while (true) {
			if (g_Globals.ItemCount == 0)
				break;

			auto entry = RemoveHeadList(&g_Globals.ItemsHead);
			// Get the address of Entry filed in the linked list item:
			auto info = CONTAINING_RECORD(entry, FullItem<ItemHeader>, Entry);
			auto size = info->Data.Size;

			// Check if there is enough space in supplied buffer:
			if (len < size) {
				// Not enough space, return the item to the linked list:
				InsertHeadList(&g_Globals.ItemsHead, entry);
				break;
			}

			// Copy the data to user mode buffer:
			::memcpy(buffer, &info->Data, size);

			// Updates count and offsets:
			g_Globals.ItemCount--;
			len -= size;
			buffer += size;
			count += size;

			// Free allocated memory:
			ExFreePool(info);
		}
	}

	// Finish the request:
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = count;
	IoCompleteRequest(Irp, 0);
	return status;
}


/*
* Callback function that will be fired whenever Process creation will occur.
*/
void OnProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);

	// process create:
	if (CreateInfo) {

		// Calculating the allocation size:
		USHORT allocSize = sizeof(FullItem<ProcessCreateInfo>);
		USHORT commandLineSize = 0;
		if (CreateInfo->CommandLine) {
			commandLineSize = CreateInfo->CommandLine->Length;
			allocSize += commandLineSize;
		}

		// Allocating continuous memory for ProcessCreateInfo + command line:
		auto info = (FullItem<ProcessCreateInfo>*)ExAllocatePoolWithTag(PagedPool,
			allocSize, DRIVER_TAG);
		if (info == nullptr) {
			KdPrint((DRIVER_PREFIX "failed allocation\n"));
			return;
		}

		// Adding data to the ProcessCreateInfo notification:
		auto& item = info->Data;
		KeQuerySystemTimePrecise(&item.Time);
		item.Type = ItemType::ProcessCreate;
		item.Size = sizeof(ProcessCreateInfo) + commandLineSize;	// base structure + command line
		item.ProcessId = HandleToULong(ProcessId);
		item.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

		// Coping the commend line to the continuous memory allocation,
		// after the ProcessCreateInfo structure:
		if (commandLineSize > 0) {
			::memcpy((UCHAR*)&item + sizeof(item), CreateInfo->CommandLine->Buffer,
				commandLineSize);
			item.CommandLineLength = commandLineSize / sizeof(WCHAR); // length in WCHARs
			item.CommandLineOffset = sizeof(item);
		}
		else {
			item.CommandLineLength = 0;
		}

		// Adding the notification to the linked-list:
		PushItem(&info->Entry);
	}
	// process exit:
	else {

		// Allocating memory for notification:
		auto info = (FullItem<ProcessExitInfo>*)ExAllocatePoolWithTag(PagedPool,
			sizeof(FullItem<ProcessExitInfo>), DRIVER_TAG);
		if (info == nullptr) {
			KdPrint((DRIVER_PREFIX "failed allocation\n"));
			return;
		}

		// Adding data to the ProcessExitInfo notification:
		auto& item = info->Data;
		KeQuerySystemTimePrecise(&item.Time);
		item.Type = ItemType::ProcessExit;
		item.ProcessId = HandleToULong(ProcessId);
		item.Size = sizeof(ProcessExitInfo);

		// Adding the notification to the linked-list:
		PushItem(&info->Entry);
	}
}

/*
* Callback function that will be fired whenever Thread creation or exit will occur.
*/
void OnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create) {
	auto size = sizeof(FullItem<ThreadCreateExitInfo>);
	auto info = (FullItem<ThreadCreateExitInfo>*)ExAllocatePoolWithTag(PagedPool, size,
		DRIVER_TAG);

	if (info == nullptr) {
		KdPrint((DRIVER_PREFIX "Failed to allocate memory\n"));
		return;
	}

	auto& item = info->Data;

	// Add generic data to the notification:
	KeQuerySystemTimePrecise(&item.Time);
	item.Size = sizeof(item);

	// Add specific data for thread notification:
	item.Type = Create ? ItemType::ThreadCreate : ItemType::ThreadExit;
	item.ProcessId = HandleToUlong(ProcessId);
	item.ThreadId = HandleToUlong(ThreadId);

	// Add notification to the linked-list:
	PushItem(&info->Entry);
}

/*  */
void OnImageLoadNotify(_Inout_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo) {

	// Check if the notification is for system images:
	if (ProcessId == nullptr)
		return;

	// Calculating the allocation size:
	USHORT allocSize = sizeof(FullItem<ImageLoadInfo>);
	USHORT imagePathLength = 0;
	if (FullImageName) {
		imagePathLength = FullImageName->Length;
		allocSize += imagePathLength;
	}

	// Allocating memory + memory for the image path:
	auto info = (FullItem<ImageLoadInfo>*)ExAllocatePoolWithTag(PagedPool, allocSize,
		DRIVER_TAG);

	if (info == nullptr) {
		KdPrint((DRIVER_PREFIX "Failed to allocate memory\n"));
		return;
	}

	// Adding data to the notification:
	auto& item = info->Data;
	KeQuerySystemTimePrecise(&item.Time);
	item.Type = ItemType::ImageLoad;

	item.Size = sizeof(item) + imagePathLength;
	item.ProcessId = HandleToULong(ProcessId);
	item.ImageBage = ImageInfo->ImageBase;
	item.ImageSize = ImageInfo->ImageSize;

	// Coping the image path to the continuous memory allocation,
	// after the ImageLoadInfo structure:
	if (imagePathLength > 0) {
		::memcpy((UCHAR*)&item + sizeof(item), FullImageName->Buffer, imagePathLength);
		item.ImagePathLength = imagePathLength / sizeof(WCHAR); // length in WCHARs
		item.ImagePathOffset = sizeof(item);
	}
	else {
		item.ImagePathLength = 0;
	}

	// Adding the notification to the linked-list:
	PushItem(&info->Entry);
}

/*
* Adding notification item to the list.
*/
void PushItem(LIST_ENTRY* entry) {
	AutoLock<FastMutex> lock(g_Globals.Mutex);

	// In case of too many items, we will remove the oldest item:
	if (g_Globals.ItemCount > 1024) {
		auto head = RemoveHeadList(&g_Globals.ItemsHead);
		g_Globals.ItemCount--;
		auto item = CONTAINING_RECORD(head, FullItem<ItemHeader>, Entry);
		ExFreePool(item);
	}

	// Push item to the end of the list:
	InsertTailList(&g_Globals.ItemsHead, entry);
	g_Globals.ItemCount++;
}