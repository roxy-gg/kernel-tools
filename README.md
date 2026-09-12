# kernel-tools

Roxy Kernel Bridge — a Windows kernel driver + userspace MCP bridge that exposes
system-level operations (process memory, registry, files, networking) as MCP
JSON-RPC tools over stdin/stdout.

## Architecture

```
┌─────────────┐     MCP/JSON-RPC      ┌──────────────────┐     IOCTL       ┌──────────────┐
│  Roxy       │ ◄── stdin/stdout ───► │ roxy-kernel-     │ ◄────────────► │ aibridge.sys │
│  harness    │                       │ bridge.exe       │  DeviceIoControl│ (KMDF)       │
└─────────────┘                       └──────────────────┘                 └──────────────┘
                                                                               │
                                                                        ┌──────┴──────┐
                                                                        │  Windows    │
                                                                        │  Kernel     │
                                                                        └─────────────┘
```

| Component | Description |
|-----------|-------------|
| `driver/aibridge.sys` | KMDF kernel driver exposing `\Device\AIAgent` → `\\\\.\AIAgent` |
| `bridge/roxy-kernel-bridge.exe` | Rust MCP server wrapping DeviceIoControl calls into JSON-RPC tools |
| `install.ps1` | One-liner to create and start the kernel service |

## IOCTLs Exposed

| IOCTL | Purpose |
|-------|---------|
| `IOCTL_AI_READ_PROCESS_MEMORY` | Read virtual memory from a target process |
| `IOCTL_AI_LIST_PROCESSES` | Enumerate running processes with PID, name, session |
| `IOCTL_AI_KILL_PROCESS` | Terminate a process by PID |
| `IOCTL_AI_READ_REGISTRY` | Read a registry key value |
| `IOCTL_AI_WRITE_REGISTRY` | Write a registry key value |
| `IOCTL_AI_LIST_FILES` | Enumerate files in a directory |
| `IOCTL_AI_READ_FILE` | Read a file using kernel APIs (bypasses user-mode ACLs) |
| `IOCTL_AI_WRITE_FILE` | Write a file using kernel APIs |

## MCP Tools (exposed by the bridge)

- `read_process_memory`
- `list_processes`
- `kill_process`
- `read_registry`
- `write_registry`
- `list_files`
- `read_file`
- `write_file`

## Prerequisites

- **Windows 10/11** (x64) with Test Signing enabled: `bcdedit /set testsigning on`
- **WDK** (Windows Driver Kit) — for building `aibridge.sys`
- **Rust** (stable MSVC toolchain) — for building `roxy-kernel-bridge.exe`
- **Administrator** privileges to install the driver

## Quick Start

```powershell
# 1. Build everything
.\driver\build.ps1
.\bridge\build.ps1

# 2. Install the driver
.\install.ps1

# 3. Test the bridge
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | .\out\roxy-kernel-bridge.exe
```

## Security Warning

This driver grants ring-0-backed operations to SYSTEM and elevated administrator
processes that open `\\\\.\AIAgent`. It is intended for **local development and
debugging only**. Do not deploy on production or internet-facing machines.
