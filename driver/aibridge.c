/*
 * aibridge.c — KMDF Kernel Driver for Roxy Kernel Bridge
 *
 * Creates \Device\AIAgent → \\.\AIAgent and dispatches IOCTLs for
 * system introspection: process memory, registry, files, networking.
 *
 * Build: WDK / Visual Studio with KMDF 1.31+
 */

#include <ntifs.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "aibridge.h"

#define AI_SYSTEM_PROCESS_INFORMATION_CLASS 5
#define AI_PROCESS_TERMINATE 0x0001

typedef struct _AI_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
} AI_SYSTEM_PROCESS_INFORMATION, *PAI_SYSTEM_PROCESS_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

// Dispatch helpers
static NTSTATUS HandleReadProcessMemory(WDFREQUEST Request, size_t InputBufferLength, size_t OutputBufferLength);
static NTSTATUS HandleListProcesses(WDFREQUEST Request, size_t OutputBufferLength);
static NTSTATUS HandleKillProcess(WDFREQUEST Request, size_t InputBufferLength);
static NTSTATUS HandleReadRegistry(WDFREQUEST Request, size_t InputBufferLength, size_t OutputBufferLength);
static NTSTATUS HandleWriteRegistry(WDFREQUEST Request, size_t InputBufferLength);
static NTSTATUS HandleListFiles(WDFREQUEST Request, size_t InputBufferLength, size_t OutputBufferLength);
static NTSTATUS HandleReadFile(WDFREQUEST Request, size_t InputBufferLength, size_t OutputBufferLength);
static NTSTATUS HandleWriteFile(WDFREQUEST Request, size_t InputBufferLength);

static NTSTATUS
InitFixedUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_reads_(Capacity) PWCHAR Buffer,
    _In_ size_t Capacity,
    _In_ BOOLEAN AllowEmpty
)
{
    size_t length = 0;

    while (length < Capacity && Buffer[length] != L'\0') {
        length++;
    }

    if (length == Capacity || (!AllowEmpty && length == 0) ||
        length > (MAXUSHORT / sizeof(WCHAR)) - 1) {
        return STATUS_INVALID_PARAMETER;
    }

    Destination->Buffer = Buffer;
    Destination->Length = (USHORT)(length * sizeof(WCHAR));
    Destination->MaximumLength = (USHORT)((length + 1) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    NTSTATUS status;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = EvtDriverUnload;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &driver
    );
    if (!NT_SUCCESS(status)) {
        KdPrint(("AIBridge: WdfDriverCreate failed: 0x%08X\n", status));
        return status;
    }

    // The bridge performs privileged operations, so only SYSTEM and local
    // administrators may open the control device.
    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    deviceInit = WdfControlDeviceInitAllocate(driver, &sddl);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DECLARE_CONST_UNICODE_STRING(deviceName, AIBRIDGE_DEVICE_NAME);
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WdfDeviceInitSetExclusive(deviceInit, TRUE);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);
    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_AIBRIDGE);
    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    deviceAttributes.ExecutionLevel = WdfExecutionLevelPassive;

    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    DECLARE_CONST_UNICODE_STRING(dosName, AIBRIDGE_DOS_NAME);
    status = WdfDeviceCreateSymbolicLink(device, &dosName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WdfControlFinishInitializing(device);
    KdPrint(("AIBridge: control device created successfully\n"));
    return STATUS_SUCCESS;
}

VOID
EvtDriverUnload(
    _In_ WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);
}

// ---------------------------------------------------------------------------
// EvtIoDeviceControl — main IOCTL dispatch
// ---------------------------------------------------------------------------
VOID
EvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
)
{
    UNREFERENCED_PARAMETER(Queue);

    NTSTATUS status = STATUS_NOT_SUPPORTED;

    switch (IoControlCode) {
    case IOCTL_AI_READ_PROCESS_MEMORY:
        status = HandleReadProcessMemory(Request, InputBufferLength, OutputBufferLength);
        break;
    case IOCTL_AI_LIST_PROCESSES:
        status = HandleListProcesses(Request, OutputBufferLength);
        break;
    case IOCTL_AI_KILL_PROCESS:
        status = HandleKillProcess(Request, InputBufferLength);
        break;
    case IOCTL_AI_READ_REGISTRY:
        status = HandleReadRegistry(Request, InputBufferLength, OutputBufferLength);
        break;
    case IOCTL_AI_WRITE_REGISTRY:
        status = HandleWriteRegistry(Request, InputBufferLength);
        break;
    case IOCTL_AI_LIST_FILES:
        status = HandleListFiles(Request, InputBufferLength, OutputBufferLength);
        break;
    case IOCTL_AI_READ_FILE:
        status = HandleReadFile(Request, InputBufferLength, OutputBufferLength);
        break;
    case IOCTL_AI_WRITE_FILE:
        status = HandleWriteFile(Request, InputBufferLength);
        break;
    default:
        KdPrint(("AIBridge: Unknown IOCTL: 0x%08X\n", IoControlCode));
        break;
    }

    WdfRequestComplete(Request, status);
}

// ---------------------------------------------------------------------------
// Safe cross-process memory read
// ---------------------------------------------------------------------------
static NTSTATUS
ReadProcessMemorySafe(
    _In_  HANDLE  ProcessId,
    _In_  PVOID   Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_  SIZE_T  Size,
    _Out_ SIZE_T* BytesRead
)
{
    NTSTATUS status;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;
    SIZE_T actualRead = 0;

    *BytesRead = 0;

    if (Size == 0 || Size > AI_MAX_READ_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AIBridge: PsLookupProcessByProcessId failed: 0x%08X\n", status));
        return status;
    }

    KeStackAttachProcess(targetProcess, &apcState);

    __try {
        ProbeForRead((PVOID)Address, (ULONG)Size, 1);
        RtlCopyMemory(Buffer, (PVOID)Address, Size);
        actualRead = Size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        KdPrint(("AIBridge: Exception reading memory: 0x%08X\n", status));
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    *BytesRead = actualRead;
    return (actualRead == Size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

// ---------------------------------------------------------------------------
// HandleReadProcessMemory
// ---------------------------------------------------------------------------
static NTSTATUS
HandleReadProcessMemory(
    WDFREQUEST Request,
    size_t     InputBufferLength,
    size_t     OutputBufferLength
)
{
    NTSTATUS status;
    PVOID inBuffer = NULL;
    PVOID outBuffer = NULL;
    size_t bytesReturned = 0;

    if (InputBufferLength < sizeof(AI_READ_PROCESS_MEMORY_IN)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(AI_READ_PROCESS_MEMORY_IN), &inBuffer, NULL);
    if (!NT_SUCCESS(status)) return status;

    PAI_READ_PROCESS_MEMORY_IN input = (PAI_READ_PROCESS_MEMORY_IN)inBuffer;

    if (input->Size > AI_MAX_READ_SIZE || input->Size > OutputBufferLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, (size_t)input->Size, &outBuffer, NULL);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T bytesRead = 0;
    status = ReadProcessMemorySafe(
        (HANDLE)(ULONG_PTR)input->ProcessId,
        (PVOID)(ULONG_PTR)input->Address,
        outBuffer,
        (SIZE_T)input->Size,
        &bytesRead
    );

    bytesReturned = bytesRead;
    WdfRequestSetInformation(Request, bytesReturned);
    return status;
}

// ---------------------------------------------------------------------------
// HandleListProcesses
// ---------------------------------------------------------------------------
static NTSTATUS
HandleListProcesses(
    WDFREQUEST Request,
    size_t     OutputBufferLength
)
{
    NTSTATUS status;
    PVOID outBuffer = NULL;
    ULONG maxEntries;

    if (OutputBufferLength < sizeof(ULONG) + sizeof(AI_PROCESS_ENTRY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maxEntries = (ULONG)((OutputBufferLength - sizeof(ULONG)) / sizeof(AI_PROCESS_ENTRY));

    status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outBuffer, NULL);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(outBuffer, OutputBufferLength);
    ULONG* pCount = (ULONG*)outBuffer;
    PAI_PROCESS_ENTRY entries = (PAI_PROCESS_ENTRY)(pCount + 1);

    // Get system process information
    ULONG bufferSize = 0;
    status = ZwQuerySystemInformation(AI_SYSTEM_PROCESS_INFORMATION_CLASS, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return STATUS_UNSUCCESSFUL;
    }

    bufferSize += 8192;
    PVOID procInfo = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'prcA');
    if (procInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(AI_SYSTEM_PROCESS_INFORMATION_CLASS, procInfo, bufferSize, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePool(procInfo);
        return status;
    }

    PAI_SYSTEM_PROCESS_INFORMATION spi = (PAI_SYSTEM_PROCESS_INFORMATION)procInfo;
    ULONG written = 0;

    while (written < maxEntries) {
        PAI_PROCESS_ENTRY entry = &entries[written];

        entry->ProcessId = (ULONG64)(ULONG_PTR)spi->UniqueProcessId;
        entry->ParentProcessId = (ULONG64)(ULONG_PTR)spi->InheritedFromUniqueProcessId;
        entry->SessionId = spi->SessionId;
        entry->ThreadCount = spi->NumberOfThreads;
        entry->HandleCount = spi->HandleCount;
        entry->CreateTime = spi->CreateTime.QuadPart;

        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            USHORT len = spi->ImageName.Length;
            if (len > (AI_MAX_PROCESS_NAME - 1) * sizeof(WCHAR)) {
                len = (AI_MAX_PROCESS_NAME - 1) * sizeof(WCHAR);
            }
            RtlCopyMemory(entry->ImageName, spi->ImageName.Buffer, len);
            entry->ImageName[len / sizeof(WCHAR)] = L'\0';
        } else {
            RtlStringCbCopyW(entry->ImageName, sizeof(entry->ImageName), L"System");
        }

        written++;

        if (spi->NextEntryOffset == 0) break;
        spi = (PAI_SYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }

    *pCount = written;
    ExFreePool(procInfo);

    size_t bytesReturned = sizeof(ULONG) + written * sizeof(AI_PROCESS_ENTRY);
    WdfRequestSetInformation(Request, bytesReturned);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HandleKillProcess
// ---------------------------------------------------------------------------
static NTSTATUS
HandleKillProcess(
    WDFREQUEST Request,
    size_t     InputBufferLength
)
{
    if (InputBufferLength < sizeof(AI_KILL_PROCESS_IN)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PVOID inBuffer = NULL;
    NTSTATUS status = WdfRequestRetrieveInputBuffer(Request, sizeof(AI_KILL_PROCESS_IN), &inBuffer, NULL);
    if (!NT_SUCCESS(status)) return status;

    PAI_KILL_PROCESS_IN input = (PAI_KILL_PROCESS_IN)inBuffer;

    PEPROCESS targetProcess = NULL;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)input->ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AIBridge: KillProcess: PID not found\n"));
        return status;
    }

    HANDLE hProcess = NULL;
    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)input->ProcessId;
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&hProcess, AI_PROCESS_TERMINATE, &oa, &clientId);
    ObDereferenceObject(targetProcess);

    if (NT_SUCCESS(status)) {
        status = ZwTerminateProcess(hProcess, 0);
        ZwClose(hProcess);
    }

    // Write status to output
    PVOID outBuffer = NULL;
    NTSTATUS outStatus = WdfRequestRetrieveOutputBuffer(Request, sizeof(AI_STATUS), &outBuffer, NULL);
    if (NT_SUCCESS(outStatus)) {
        PAI_STATUS pStatus = (PAI_STATUS)outBuffer;
        pStatus->Status = status;
        WdfRequestSetInformation(Request, sizeof(AI_STATUS));
    }

    return status;
}

// ---------------------------------------------------------------------------
// HandleReadRegistry
// ---------------------------------------------------------------------------
static NTSTATUS
HandleReadRegistry(
    WDFREQUEST Request,
    size_t     InputBufferLength,
    size_t     OutputBufferLength
)
{
    if (InputBufferLength < sizeof(AI_REGISTRY_IN)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PVOID inBuffer = NULL;
    NTSTATUS status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inBuffer, NULL);
    if (!NT_SUCCESS(status)) return status;

    PAI_REGISTRY_IN input = (PAI_REGISTRY_IN)inBuffer;

    UNICODE_STRING keyName;
    status = InitFixedUnicodeString(&keyName, input->KeyPath, AI_MAX_KEY_NAME, FALSE);
    if (!NT_SUCCESS(status)) return status;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey = NULL;
    status = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AIBridge: ZwOpenKey failed: 0x%08X\n", status));
        return status;
    }

    UNICODE_STRING valueName;
    status = InitFixedUnicodeString(&valueName, input->ValueName, AI_MAX_VALUE_NAME, TRUE);
    if (!NT_SUCCESS(status)) {
        ZwClose(hKey);
        return status;
    }

    ULONG resultLength = 0;
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, NULL, 0, &resultLength);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        ZwClose(hKey);
        return (status == STATUS_SUCCESS) ? STATUS_OBJECT_NAME_NOT_FOUND : status;
    }

    ULONG infoSize = resultLength + sizeof(KEY_VALUE_PARTIAL_INFORMATION);
    if (infoSize > OutputBufferLength) {
        infoSize = (ULONG)OutputBufferLength;
    }

    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)
        ExAllocatePool2(POOL_FLAG_PAGED, infoSize, 'vrA');
    if (kvpi == NULL) {
        ZwClose(hKey);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, kvpi, infoSize, &resultLength);
    ZwClose(hKey);

    if (!NT_SUCCESS(status)) {
        ExFreePool(kvpi);
        return status;
    }

    PVOID outBuffer = NULL;
    status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outBuffer, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePool(kvpi);
        return status;
    }

    ULONG dataSize = kvpi->DataLength;
    ULONG outHeaderSize = sizeof(AI_REGISTRY_OUT);
    if (outHeaderSize + dataSize > OutputBufferLength) {
        dataSize = (ULONG)(OutputBufferLength - outHeaderSize);
    }

    PAI_REGISTRY_OUT output = (PAI_REGISTRY_OUT)outBuffer;
    output->ValueType = kvpi->Type;
    output->DataSize = dataSize;
    RtlCopyMemory((PUCHAR)outBuffer + outHeaderSize, kvpi->Data, dataSize);

    ExFreePool(kvpi);

    size_t bytesReturned = outHeaderSize + dataSize;
    WdfRequestSetInformation(Request, bytesReturned);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HandleWriteRegistry
// ---------------------------------------------------------------------------
static NTSTATUS
HandleWriteRegistry(
    WDFREQUEST Request,
    size_t     InputBufferLength
)
{
    if (InputBufferLength < sizeof(AI_REGISTRY_IN)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PVOID inBuffer = NULL;
    NTSTATUS status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inBuffer, NULL);
    if (!NT_SUCCESS(status)) return status;

    PAI_REGISTRY_IN input = (PAI_REGISTRY_IN)inBuffer;

    if (input->DataSize > AI_MAX_VALUE_DATA ||
        sizeof(AI_REGISTRY_IN) + input->DataSize > InputBufferLength) {
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR data = (PUCHAR)inBuffer + sizeof(AI_REGISTRY_IN);

    UNICODE_STRING keyName;
    status = InitFixedUnicodeString(&keyName, input->KeyPath, AI_MAX_KEY_NAME, FALSE);
    if (!NT_SUCCESS(status)) return status;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey = NULL;
    status = ZwOpenKey(&hKey, KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(status)) {
        status = ZwCreateKey(
            &hKey,
            KEY_SET_VALUE,
            &oa,
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            NULL
        );
    }

    if (!NT_SUCCESS(status)) {
        KdPrint(("AIBridge: Open/Create key failed: 0x%08X\n", status));
        return status;
    }

    UNICODE_STRING valueName;
    status = InitFixedUnicodeString(&valueName, input->ValueName, AI_MAX_VALUE_NAME, TRUE);
    if (!NT_SUCCESS(status)) {
        ZwClose(hKey);
        return status;
    }

    status = ZwSetValueKey(hKey, &valueName, 0, input->ValueType, data, input->DataSize);
    ZwClose(hKey);

    PVOID outBuffer = NULL;
    NTSTATUS outStatus = WdfRequestRetrieveOutputBuffer(Request, sizeof(AI_STATUS), &outBuffer, NULL);
    if (NT_SUCCESS(outStatus)) {
        PAI_STATUS pStatus = (PAI_STATUS)outBuffer;
        pStatus->Status = status;
        WdfRequestSetInformation(Request, sizeof(AI_STATUS));
    }

    return status;
}

// ---------------------------------------------------------------------------
// HandleListFiles
// ---------------------------------------------------------------------------
static NTSTATUS
HandleListFiles(
    WDFREQUEST Request,
    size_t     InputBufferLength,
    size_t     OutputBufferLength
)
{
    if (InputBufferLength < sizeof(AI_LIST_FILES_IN)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PVOID inBuffer = NULL;
    NTSTATUS status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inBuffer, NULL);
    if (!NT_SUCCESS(status)) return status;

    PAI_LIST_FILES_IN input = (PAI_LIST_FILES_IN)inBuffer;

    UNICODE_STRING usSearchPath;
    status = InitFixedUnicodeString(&usSearchPath, input->DirectoryPath, AI_MAX_PATH, FALSE);
    if (!NT_SUCCESS(status)) return status;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &usSearchPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    IO_STATUS_BLOCK iosb;

    status = ZwOpenFile(
        &hDir,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("AIBridge: ZwOpenFile for list files failed: 0x%08X\n", status));
        return status;
    }

    if (OutputBufferLength < sizeof(AI_LIST_FILES_OUT) + sizeof(AI_FILE_ENTRY)) {
        ZwClose(hDir);
        return STATUS_BUFFER_TOO_SMALL;
    }

    PVOID outBuffer = NULL;
    status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outBuffer, NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(hDir);
        return status;
    }

    PAI_LIST_FILES_OUT output = (PAI_LIST_FILES_OUT)outBuffer;
    PUCHAR entries = (PUCHAR)(output + 1);
    ULONG maxEntries = (ULONG)((OutputBufferLength - sizeof(AI_LIST_FILES_OUT)) / sizeof(AI_FILE_ENTRY));
    if (maxEntries > AI_MAX_FILE_ENTRIES) {
        maxEntries = AI_MAX_FILE_ENTRIES;
    }

    RtlZeroMemory(outBuffer, OutputBufferLength);

    ULONG dirInfoSize = AI_MAX_READ_SIZE;
    PFILE_DIRECTORY_INFORMATION dirInfo = (PFILE_DIRECTORY_INFORMATION)
        ExAllocatePool2(POOL_FLAG_PAGED, dirInfoSize, 'fdA');
    if (dirInfo == NULL) {
        ZwClose(hDir);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG entryCount = 0;
    BOOLEAN restartScan = TRUE;

    while (entryCount < maxEntries) {
        RtlZeroMemory(dirInfo, dirInfoSize);
        RtlZeroMemory(&iosb, sizeof(iosb));

        status = ZwQueryDirectoryFile(
            hDir,
            NULL, NULL, NULL,
            &iosb,
            dirInfo,
            dirInfoSize,
            FileDirectoryInformation,
            FALSE,
            NULL,
            restartScan
        );
        restartScan = FALSE;

        if (status == STATUS_NO_MORE_FILES) {
            status = STATUS_SUCCESS;
            break;
        }
        if (NT_SUCCESS(status) && iosb.Information == 0) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }
        if (!NT_SUCCESS(status) ||
            iosb.Information > dirInfoSize ||
            iosb.Information < FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName)) {
            if (NT_SUCCESS(status)) status = STATUS_DATA_ERROR;
            break;
        }

        ULONG currentOffset = 0;
        ULONG directoryBytes = (ULONG)iosb.Information;

        while (entryCount < maxEntries) {
            ULONG fixedSize = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
            ULONG remaining = directoryBytes - currentOffset;
            PFILE_DIRECTORY_INFORMATION current =
                (PFILE_DIRECTORY_INFORMATION)((PUCHAR)dirInfo + currentOffset);

            if (remaining < fixedSize ||
                current->FileNameLength > remaining - fixedSize ||
                (current->FileNameLength % sizeof(WCHAR)) != 0) {
                status = STATUS_DATA_ERROR;
                break;
            }

            AI_FILE_ENTRY entry;
            RtlZeroMemory(&entry, sizeof(entry));

            ULONG nameLen = current->FileNameLength / sizeof(WCHAR);
            if (nameLen >= AI_MAX_PATH) nameLen = AI_MAX_PATH - 1;
            RtlCopyMemory(entry.FileName, current->FileName, nameLen * sizeof(WCHAR));
            entry.FileName[nameLen] = L'\0';
            entry.FileSize.QuadPart = current->EndOfFile.QuadPart;
            entry.CreationTime.QuadPart = current->CreationTime.QuadPart;
            entry.LastAccessTime.QuadPart = current->LastAccessTime.QuadPart;
            entry.LastWriteTime.QuadPart = current->LastWriteTime.QuadPart;
            entry.FileAttributes = current->FileAttributes;
            entry.IsDirectory = (current->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

            RtlCopyMemory(entries + entryCount * sizeof(AI_FILE_ENTRY), &entry, sizeof(entry));
            entryCount++;

            if (current->NextEntryOffset == 0) break;
            if (current->NextEntryOffset < fixedSize ||
                current->NextEntryOffset < fixedSize + current->FileNameLength ||
                current->NextEntryOffset > remaining ||
                (current->NextEntryOffset % sizeof(ULONGLONG)) != 0) {
                status = STATUS_DATA_ERROR;
                break;
            }
            currentOffset += current->NextEntryOffset;
        }

        if (!NT_SUCCESS(status)) break;
    }

    output->EntryCount = entryCount;

    ExFreePool(dirInfo);
    ZwClose(hDir);

    if (!NT_SUCCESS(status)) return status;

    WdfRequestSetInformation(
        Request,
        sizeof(AI_LIST_FILES_OUT) + entryCount * sizeof(AI_FILE_ENTRY)
    );
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HandleReadFile
// ---------------------------------------------------------------------------
static NTSTATUS
HandleReadFile(
    WDFREQUEST Request,
    size_t     InputBufferLength,
    size_t     OutputBufferLength
)
{
    if (InputBufferLength < sizeof(AI_FILE_IO_IN)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PVOID inBuffer = NULL;
    NTSTATUS status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inBuffer, NULL);
    if (!NT_SUCCESS(status)) return status;

    PAI_FILE_IO_IN input = (PAI_FILE_IO_IN)inBuffer;

    if (input->Length > AI_MAX_READ_SIZE || input->Length > OutputBufferLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    UNICODE_STRING fileName;
    status = InitFixedUnicodeString(&fileName, input->FilePath, AI_MAX_PATH, FALSE);
    if (!NT_SUCCESS(status)) return status;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb;

    status = ZwOpenFile(
        &hFile,
        FILE_READ_DATA | SYNCHRONIZE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("AIBridge: ReadFile - ZwOpenFile failed: 0x%08X\n", status));
        return status;
    }

    PVOID outBuffer = NULL;
    status = WdfRequestRetrieveOutputBuffer(Request, (size_t)input->Length, &outBuffer, NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(hFile);
        return status;
    }

    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = input->ByteOffset.QuadPart;

    status = ZwReadFile(
        hFile,
        NULL, NULL, NULL,
        &iosb,
        outBuffer,
        input->Length,
        &byteOffset,
        NULL
    );

    ZwClose(hFile);

    if (NT_SUCCESS(status) || status == STATUS_END_OF_FILE) {
        WdfRequestSetInformation(Request, (size_t)iosb.Information);
        return STATUS_SUCCESS;
    }

    return status;
}

// ---------------------------------------------------------------------------
// HandleWriteFile
// ---------------------------------------------------------------------------
static NTSTATUS
HandleWriteFile(
    WDFREQUEST Request,
    size_t     InputBufferLength
)
{
    if (InputBufferLength < sizeof(AI_FILE_IO_IN)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PVOID inBuffer = NULL;
    NTSTATUS status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inBuffer, NULL);
    if (!NT_SUCCESS(status)) return status;

    PAI_FILE_IO_IN input = (PAI_FILE_IO_IN)inBuffer;

    if (input->Length > AI_MAX_READ_SIZE ||
        sizeof(AI_FILE_IO_IN) + input->Length > InputBufferLength) {
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR data = (PUCHAR)inBuffer + sizeof(AI_FILE_IO_IN);

    UNICODE_STRING fileName;
    status = InitFixedUnicodeString(&fileName, input->FilePath, AI_MAX_PATH, FALSE);
    if (!NT_SUCCESS(status)) return status;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb;

    status = ZwCreateFile(
        &hFile,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("AIBridge: WriteFile - ZwCreateFile failed: 0x%08X\n", status));
        return status;
    }

    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = input->ByteOffset.QuadPart;

    status = ZwWriteFile(
        hFile,
        NULL, NULL, NULL,
        &iosb,
        data,
        input->Length,
        &byteOffset,
        NULL
    );

    ZwClose(hFile);

    PVOID outBuffer = NULL;
    NTSTATUS outStatus = WdfRequestRetrieveOutputBuffer(Request, sizeof(AI_STATUS), &outBuffer, NULL);
    if (NT_SUCCESS(outStatus)) {
        PAI_STATUS pStatus = (PAI_STATUS)outBuffer;
        pStatus->Status = status;
        WdfRequestSetInformation(Request, sizeof(AI_STATUS));
    }

    return status;
}
