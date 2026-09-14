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

## Installable builds

Each version tag publishes `kernel-tools-windows-x64.zip` on GitHub Releases. The
archive contains the test-signed `aibridge.sys` driver, its public test
certificate, and `roxy-kernel-bridge.exe`. Roxy downloads a pinned
release, verifies its SHA-256 digest, and installs it only after explicit user
confirmation and a UAC prompt.

The release workflow creates a one-build, non-exportable private key, embeds a
SHA-256 signature in the driver, verifies it with SignTool's Authenticode
policy, matches the embedded signer to the generated certificate, and deletes
the private key before uploading artifacts. CI temporarily trusts the public
certificate in the runner's machine stores so SignTool must report success, then
removes that trust. A final workflow guard fails if the certificate or private
key remains on the runner. Non-elevated local builds accept only SignTool's
expected self-signed-root error; any other verification failure stops the build.
Only the public certificate is published. During installation, Roxy adds that
certificate to the target machine's Trusted Root and Trusted Publishers stores and removes
only trust entries that Roxy added when Kernel Tools is uninstalled.

These development releases require Windows test-signing mode and trusting the
included public certificate. Normal Secure Boot production deployment requires
Microsoft attestation or WHQL signing; a GitHub-built test certificate is not a
production driver signature.

## Build prerequisites

- **Windows 10/11** (x64) with Test Signing enabled: `bcdedit /set testsigning on`
- **Visual Studio 2022** with Desktop development with C++
- **WDK** with the Windows Driver Kit Visual Studio component
- A matching Windows SDK and WDK version
- **Rust** (stable MSVC toolchain) — for building `roxy-kernel-bridge.exe`
- **Administrator** privileges to install the driver

## Quick Start

```powershell
# 1. Build, test, and package everything
.\build.ps1 -TestSign

# 2. Install the driver
.\install.ps1

# 3. Test the bridge
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | .\out\roxy-kernel-bridge.exe
```

## Security Warning

This driver grants ring-0-backed operations to SYSTEM and elevated administrator
processes that open `\\\\.\AIAgent`. It is intended for **local development and
debugging only**. Do not deploy on production or internet-facing machines.
