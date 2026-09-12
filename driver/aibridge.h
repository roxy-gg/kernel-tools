#ifndef AIBRIDGE_H
#define AIBRIDGE_H

#include <winioctl.h>

// ---------------------------------------------------------------------------
// Device names
// ---------------------------------------------------------------------------
#define AIBRIDGE_DEVICE_NAME L"\\Device\\AIAgent"
#define AIBRIDGE_DOS_NAME    L"\\DosDevices\\AIAgent"
#define AIBRIDGE_SYMLINK     L"\\\\.\\AIAgent"

// ---------------------------------------------------------------------------
// IOCTL type
// ---------------------------------------------------------------------------
#define FILE_DEVICE_AIBRIDGE 0x8000

// ---------------------------------------------------------------------------
// IOCTL codes — METHOD_BUFFERED for simplicity
// ---------------------------------------------------------------------------
#define IOCTL_AI_READ_PROCESS_MEMORY  CTL_CODE(FILE_DEVICE_AIBRIDGE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AI_LIST_PROCESSES       CTL_CODE(FILE_DEVICE_AIBRIDGE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AI_KILL_PROCESS         CTL_CODE(FILE_DEVICE_AIBRIDGE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AI_READ_REGISTRY        CTL_CODE(FILE_DEVICE_AIBRIDGE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AI_WRITE_REGISTRY       CTL_CODE(FILE_DEVICE_AIBRIDGE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AI_LIST_FILES           CTL_CODE(FILE_DEVICE_AIBRIDGE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AI_READ_FILE            CTL_CODE(FILE_DEVICE_AIBRIDGE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AI_WRITE_FILE           CTL_CODE(FILE_DEVICE_AIBRIDGE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AI_LIST_CONNECTIONS     CTL_CODE(FILE_DEVICE_AIBRIDGE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Maximum sizes for embedded strings in request/response structures
// ---------------------------------------------------------------------------
#define AI_MAX_PATH          520   // wchar_t count
#define AI_MAX_KEY_NAME      256   // wchar_t count
#define AI_MAX_VALUE_NAME    256   // wchar_t count
#define AI_MAX_VALUE_DATA    4096  // bytes
#define AI_MAX_PROCESS_NAME  64    // wchar_t count

// ---------------------------------------------------------------------------
// ReadProcessMemory — input
// ---------------------------------------------------------------------------
typedef struct _AI_READ_PROCESS_MEMORY_IN {
    ULONG64 ProcessId;       // PID of the target process
    ULONG64 Address;         // Base virtual address to read from
    ULONG   Size;            // Number of bytes to read (max 65536)
} AI_READ_PROCESS_MEMORY_IN, *PAI_READ_PROCESS_MEMORY_IN;

// ---------------------------------------------------------------------------
// ListProcesses — no input; output is an array of these
// ---------------------------------------------------------------------------
typedef struct _AI_PROCESS_ENTRY {
    ULONG64  ProcessId;
    ULONG64  ParentProcessId;
    ULONG    SessionId;
    ULONG    ThreadCount;
    ULONG    HandleCount;
    LONG64   CreateTime;          // FILETIME as nanosecond offset (1601 epoch)
    WCHAR    ImageName[AI_MAX_PROCESS_NAME];
} AI_PROCESS_ENTRY, *PAI_PROCESS_ENTRY;

// ---------------------------------------------------------------------------
// KillProcess — input
// ---------------------------------------------------------------------------
typedef struct _AI_KILL_PROCESS_IN {
    ULONG64 ProcessId;
} AI_KILL_PROCESS_IN, *PAI_KILL_PROCESS_IN;

// ---------------------------------------------------------------------------
// ReadRegistry / WriteRegistry — input
// ---------------------------------------------------------------------------
typedef struct _AI_REGISTRY_IN {
    WCHAR KeyPath[AI_MAX_KEY_NAME];      // e.g. L"\\Registry\\Machine\\Software\\..."
    WCHAR ValueName[AI_MAX_VALUE_NAME];  // empty string = default value
    ULONG ValueType;                     // REG_SZ, REG_DWORD, etc. (write only)
    ULONG DataSize;                      // size of the following data (write only)
    // UCHAR Data[AI_MAX_VALUE_DATA] follows inline after this header
} AI_REGISTRY_IN, *PAI_REGISTRY_IN;

// Maximum total size of registry input: header + data payload
#define AI_REGISTRY_IN_MAX  (sizeof(AI_REGISTRY_IN) + AI_MAX_VALUE_DATA)

// ---------------------------------------------------------------------------
// ReadRegistry — output
// ---------------------------------------------------------------------------
typedef struct _AI_REGISTRY_OUT {
    ULONG ValueType;
    ULONG DataSize;
    // UCHAR Data[DataSize] follows inline
} AI_REGISTRY_OUT, *PAI_REGISTRY_OUT;

#define AI_REGISTRY_OUT_MAX (sizeof(AI_REGISTRY_OUT) + AI_MAX_VALUE_DATA)

// ---------------------------------------------------------------------------
// ListFiles — input (directory path)
// ---------------------------------------------------------------------------
typedef struct _AI_LIST_FILES_IN {
    WCHAR DirectoryPath[AI_MAX_PATH];
} AI_LIST_FILES_IN, *PAI_LIST_FILES_IN;

// ---------------------------------------------------------------------------
// ListFiles — output: count + array of entries
// ---------------------------------------------------------------------------
typedef struct _AI_FILE_ENTRY {
    WCHAR FileName[AI_MAX_PATH];
    LARGE_INTEGER FileSize;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    ULONG  FileAttributes;
    BOOLEAN IsDirectory;
} AI_FILE_ENTRY, *PAI_FILE_ENTRY;

typedef struct _AI_LIST_FILES_OUT {
    ULONG EntryCount;
    // AI_FILE_ENTRY Entries[EntryCount] follows inline
} AI_LIST_FILES_OUT, *PAI_LIST_FILES_OUT;

// Max entries in one call (prevents buffer blowup)
#define AI_MAX_FILE_ENTRIES 512

// ---------------------------------------------------------------------------
// ReadFile / WriteFile — input (path + offset + length)
// ---------------------------------------------------------------------------
typedef struct _AI_FILE_IO_IN {
    WCHAR FilePath[AI_MAX_PATH];
    LARGE_INTEGER ByteOffset;   // offset from start of file
    ULONG Length;               // bytes to read/write
    // For WriteFile: UCHAR Data[Length] follows inline
} AI_FILE_IO_IN, *PAI_FILE_IO_IN;

#define AI_FILE_IO_IN_MAX (sizeof(AI_FILE_IO_IN) + 65536)

// Max read size
#define AI_MAX_READ_SIZE 65536

// ---------------------------------------------------------------------------
// ListConnections — output: array of TCP/UDP connection entries
// ---------------------------------------------------------------------------
typedef struct _AI_CONNECTION_ENTRY {
    ULONG64 LocalAddr;      // IPv4 in lower 32 bits (network byte order)
    ULONG64 RemoteAddr;
    USHORT  LocalPort;      // network byte order
    USHORT  RemotePort;
    ULONG   State;           // MIB_TCP_STATE
    ULONG   OwningPid;
    BOOLEAN IsIPv6;
    BOOLEAN IsUdp;
} AI_CONNECTION_ENTRY, *PAI_CONNECTION_ENTRY;

typedef struct _AI_LIST_CONNECTIONS_OUT {
    ULONG EntryCount;
    // AI_CONNECTION_ENTRY Entries[EntryCount] follows inline
} AI_LIST_CONNECTIONS_OUT, *PAI_LIST_CONNECTIONS_OUT;

// ---------------------------------------------------------------------------
// Generic IOCTL result code
// ---------------------------------------------------------------------------
typedef struct _AI_STATUS {
    LONG Status;  // NTSTATUS
} AI_STATUS, *PAI_STATUS;

#endif // AIBRIDGE_H
