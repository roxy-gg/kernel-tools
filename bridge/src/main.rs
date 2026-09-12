//! roxy-kernel-bridge — MCP server over stdin/stdout
//!
//! Wraps \\.\AIAgent kernel driver IOCTLs as MCP JSON-RPC tools.
//! Roxy's harness spawns this process and talks MCP protocol.
//!
//! Protocol: https://spec.modelcontextprotocol.io/specification/2024-11-05/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::ffi::OsStr;
use std::io::{self, BufRead, Write};
use std::os::windows::ffi::OsStrExt;
use windows::core::GUID;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    CTL_CODE, FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED,
};

// ---------------------------------------------------------------------------
// IOCTL definitions (must match aibridge.h)
// ---------------------------------------------------------------------------
const FILE_DEVICE_AIBRIDGE: u32 = 0x8000;

macro_rules! aibridge_ioctl {
    ($func:expr) => {
        CTL_CODE(FILE_DEVICE_AIBRIDGE, $func, METHOD_BUFFERED, FILE_ANY_ACCESS)
    };
}

const IOCTL_AI_READ_PROCESS_MEMORY: u32 = aibridge_ioctl!(0x800);
const IOCTL_AI_LIST_PROCESSES: u32 = aibridge_ioctl!(0x801);
const IOCTL_AI_KILL_PROCESS: u32 = aibridge_ioctl!(0x802);
const IOCTL_AI_READ_REGISTRY: u32 = aibridge_ioctl!(0x803);
const IOCTL_AI_WRITE_REGISTRY: u32 = aibridge_ioctl!(0x804);
const IOCTL_AI_LIST_FILES: u32 = aibridge_ioctl!(0x805);
const IOCTL_AI_READ_FILE: u32 = aibridge_ioctl!(0x806);
const IOCTL_AI_WRITE_FILE: u32 = aibridge_ioctl!(0x807);
const IOCTL_AI_LIST_CONNECTIONS: u32 = aibridge_ioctl!(0x808);

// ---------------------------------------------------------------------------
// Struct definitions matching aibridge.h (packed C layouts)
// ---------------------------------------------------------------------------
const AI_MAX_PATH: usize = 520;
const AI_MAX_KEY_NAME: usize = 256;
const AI_MAX_VALUE_NAME: usize = 256;
const AI_MAX_PROCESS_NAME: usize = 64;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AiReadProcessMemoryIn {
    process_id: u64,
    address: u64,
    size: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
struct AiProcessEntry {
    process_id: u64,
    parent_process_id: u64,
    session_id: u32,
    thread_count: u32,
    handle_count: u32,
    create_time: i64,
    image_name: [u16; 64],
}

#[repr(C)]
struct AiKillProcessIn {
    process_id: u64,
}

#[repr(C)]
struct AiRegistryIn {
    key_path: [u16; 256],
    value_name: [u16; 256],
    value_type: u32,
    data_size: u32,
    // Data follows inline
}

#[repr(C)]
struct AiRegistryOut {
    value_type: u32,
    data_size: u32,
    // Data follows inline
}

#[repr(C)]
struct AiListFilesIn {
    directory_path: [u16; 520],
}

#[repr(C)]
#[derive(Debug)]
struct AiFileEntry {
    file_name: [u16; 520],
    file_size: i64,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    file_attributes: u32,
    is_directory: u32, // BOOLEAN
}

#[repr(C)]
struct AiListFilesOut {
    entry_count: u32,
    // Entries follow inline
}

#[repr(C)]
struct AiFileIoIn {
    file_path: [u16; 520],
    byte_offset: i64,
    length: u32,
    // Data follows inline for writes
}

#[repr(C)]
struct AiConnectionEntry {
    local_addr: u64,
    remote_addr: u64,
    local_port: u16,
    remote_port: u16,
    state: u32,
    owning_pid: u32,
    is_ipv6: u32, // BOOLEAN
    is_udp: u32,  // BOOLEAN
}

#[repr(C)]
struct AiListConnectionsOut {
    entry_count: u32,
    // Entries follow inline
}

#[repr(C)]
struct AiStatus {
    status: i32, // NTSTATUS
}

// ---------------------------------------------------------------------------
// MCP JSON-RPC types
// ---------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

// ---------------------------------------------------------------------------
// Tool definitions for tools/list
// ---------------------------------------------------------------------------
fn tool_definitions() -> Value {
    json!([
        {
            "name": "read_process_memory",
            "description": "Read virtual memory from a target process by PID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "Target process ID" },
                    "address": { "type": "integer", "description": "Virtual address (hex)" },
                    "size": { "type": "integer", "description": "Bytes to read (max 65536)" }
                },
                "required": ["pid", "address", "size"]
            }
        },
        {
            "name": "list_processes",
            "description": "Enumerate all running processes.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "kill_process",
            "description": "Terminate a process by PID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "Process ID to kill" }
                },
                "required": ["pid"]
            }
        },
        {
            "name": "read_registry",
            "description": "Read a registry key value.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key_path": { "type": "string", "description": "Registry path, e.g. \\\\Registry\\\\Machine\\\\Software\\\\..." },
                    "value_name": { "type": "string", "description": "Value name (empty for default)" }
                },
                "required": ["key_path", "value_name"]
            }
        },
        {
            "name": "write_registry",
            "description": "Write a registry key value.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key_path": { "type": "string", "description": "Registry path" },
                    "value_name": { "type": "string", "description": "Value name" },
                    "value_type": { "type": "integer", "description": "REG value type (1=REG_SZ, 4=REG_DWORD, etc.)" },
                    "data": { "type": "string", "description": "Base64-encoded value data" }
                },
                "required": ["key_path", "value_name", "value_type", "data"]
            }
        },
        {
            "name": "list_files",
            "description": "Enumerate files in a directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Directory path" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "read_file",
            "description": "Read a file using kernel APIs (bypasses user-mode ACLs).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File path" },
                    "offset": { "type": "integer", "description": "Byte offset from start (default 0)" },
                    "length": { "type": "integer", "description": "Bytes to read (max 65536, default 65536)" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "write_file",
            "description": "Write a file using kernel APIs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File path" },
                    "offset": { "type": "integer", "description": "Byte offset from start (default 0)" },
                    "data": { "type": "string", "description": "Base64-encoded data to write" }
                },
                "required": ["path", "data"]
            }
        },
        {
            "name": "list_connections",
            "description": "Enumerate active TCP/UDP network connections.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// Device handle management
// ---------------------------------------------------------------------------
struct DeviceHandle(HANDLE);

impl DeviceHandle {
    fn open() -> Result<Self> {
        let path: Vec<u16> = OsStr::new("\\\\.\\AIAgent")
            .encode_wide()
            .chain(Some(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(path.as_ptr()),
                0xC0000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };

        let handle = handle.context("Failed to open \\\\.\\AIAgent. Is the driver installed and running?")?;
        Ok(DeviceHandle(handle))
    }

    fn ioctl(
        &self,
        code: u32,
        input: &[u8],
        output_buffer_size: usize,
    ) -> Result<Vec<u8>> {
        let mut output = vec![0u8; output_buffer_size];
        let mut bytes_returned: u32 = 0;

        let result = unsafe {
            DeviceIoControl(
                self.0,
                code,
                if input.is_empty() {
                    None
                } else {
                    Some(input.as_ptr() as *const _)
                },
                input.len() as u32,
                if output_buffer_size > 0 {
                    Some(output.as_mut_ptr() as *mut _)
                } else {
                    None
                },
                output_buffer_size as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        result.context(format!(
            "DeviceIoControl failed for IOCTL 0x{:08X}",
            code
        ))?;

        output.truncate(bytes_returned as usize);
        Ok(output)
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: wide string conversion
// ---------------------------------------------------------------------------
fn to_wide_fixed<const N: usize>(s: &str) -> [u16; N] {
    let mut buf = [0u16; N];
    let encoded: Vec<u16> = OsStr::new(s).encode_wide().collect();
    let len = encoded.len().min(N - 1);
    buf[..len].copy_from_slice(&encoded[..len]);
    buf
}

fn wide_to_string(data: &[u16]) -> String {
    let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    String::from_utf16_lossy(&data[..end])
}

fn wide_to_string_range(data: &[u16], max: usize) -> String {
    let actual = max.min(data.len());
    let end = data[..actual].iter().position(|&c| c == 0).unwrap_or(actual);
    String::from_utf16_lossy(&data[..end])
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

fn tool_read_process_memory(device: &DeviceHandle, params: &Value) -> Result<Value> {
    let pid: u64 = params["pid"].as_u64().context("pid must be an integer")?;
    let address: u64 = params["address"].as_u64().context("address must be an integer")?;
    let size: u32 = params["size"].as_u64().map(|v| v as u32).unwrap_or(4096);

    if size > 65536 {
        anyhow::bail!("size must not exceed 65536");
    }

    let input = AiReadProcessMemoryIn {
        process_id: pid,
        address,
        size,
    };

    let input_bytes = unsafe {
        std::slice::from_raw_parts(
            &input as *const _ as *const u8,
            std::mem::size_of::<AiReadProcessMemoryIn>(),
        )
    };

    let output = device.ioctl(IOCTL_AI_READ_PROCESS_MEMORY, input_bytes, size as usize)?;

    Ok(json!({
        "pid": pid,
        "address": format!("0x{:X}", address),
        "bytes_read": output.len(),
        "data_hex": hex::encode(&output),
        "data_base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &output)
    }))
}

fn tool_list_processes(device: &DeviceHandle, _params: &Value) -> Result<Value> {
    // Max ~4096 processes of ~304 bytes each ≈ 1.2 MB buffer
    let buf_size = 4096 * std::mem::size_of::<AiProcessEntry>() + 4;
    let output = device.ioctl(IOCTL_AI_LIST_PROCESSES, &[], buf_size)?;

    if output.len() < 4 {
        anyhow::bail!("Invalid response from driver");
    }

    let count = u32::from_le_bytes(output[..4].try_into().unwrap()) as usize;
    let entry_size = std::mem::size_of::<AiProcessEntry>();

    let mut processes = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 4 + i * entry_size;
        if offset + entry_size > output.len() {
            break;
        }

        let entry: &AiProcessEntry = unsafe {
            &*(output[offset..offset + entry_size].as_ptr() as *const AiProcessEntry)
        };

        processes.push(json!({
            "pid": entry.process_id,
            "parent_pid": entry.parent_process_id,
            "session_id": entry.session_id,
            "thread_count": entry.thread_count,
            "handle_count": entry.handle_count,
            "create_time": entry.create_time,
            "image_name": wide_to_string(&entry.image_name)
        }));
    }

    Ok(json!({
        "count": processes.len(),
        "processes": processes
    }))
}

fn tool_kill_process(device: &DeviceHandle, params: &Value) -> Result<Value> {
    let pid: u64 = params["pid"].as_u64().context("pid must be an integer")?;

    let input = AiKillProcessIn { process_id: pid };
    let input_bytes = unsafe {
        std::slice::from_raw_parts(
            &input as *const _ as *const u8,
            std::mem::size_of::<AiKillProcessIn>(),
        )
    };

    let output = device.ioctl(IOCTL_AI_KILL_PROCESS, input_bytes, std::mem::size_of::<AiStatus>())?;

    let status: &AiStatus = unsafe {
        &*(output.as_ptr() as *const AiStatus)
    };

    let success = status.status >= 0; // NT_SUCCESS
    Ok(json!({
        "pid": pid,
        "success": success,
        "ntstatus": format!("0x{:08X}", status.status as u32)
    }))
}

fn tool_read_registry(device: &DeviceHandle, params: &Value) -> Result<Value> {
    let key_path = params["key_path"].as_str().context("key_path must be a string")?;
    let value_name = params["value_name"].as_str().unwrap_or("");

    #[repr(C)]
    struct RegistryInPacked {
        header: AiRegistryIn,
        _pad: [u8; 0],
    }

    let header = AiRegistryIn {
        key_path: to_wide_fixed::<256>(key_path),
        value_name: to_wide_fixed::<256>(value_name),
        value_type: 0,
        data_size: 0,
    };

    let input_bytes = unsafe {
        std::slice::from_raw_parts(
            &header as *const _ as *const u8,
            std::mem::size_of::<AiRegistryIn>(),
        )
    };

    // Output: header + up to 4096 bytes of data
    let out_size = std::mem::size_of::<AiRegistryOut>() + 4096;
    let output = device.ioctl(IOCTL_AI_READ_REGISTRY, input_bytes, out_size)?;

    if output.len() < std::mem::size_of::<AiRegistryOut>() {
        anyhow::bail!("Invalid response from driver");
    }

    let out_header: &AiRegistryOut =
        unsafe { &*(output.as_ptr() as *const AiRegistryOut) };

    let data_offset = std::mem::size_of::<AiRegistryOut>();
    let data_size = out_header.data_size as usize;
    let data = if data_offset + data_size <= output.len() {
        &output[data_offset..data_offset + data_size]
    } else {
        &[]
    };

    // Interpret value based on type
    let value_str = match out_header.value_type {
        1 => {
            // REG_SZ
            let wide_data = unsafe {
                std::slice::from_raw_parts(data.as_ptr() as *const u16, data.len() / 2)
            };
            wide_to_string(wide_data)
        }
        4 => {
            // REG_DWORD
            if data.len() >= 4 {
                format!("{}", u32::from_le_bytes(data[..4].try_into().unwrap()))
            } else {
                format!("0x{}", hex::encode(data))
            }
        }
        11 => {
            // REG_QWORD
            if data.len() >= 8 {
                format!("{}", u64::from_le_bytes(data[..8].try_into().unwrap()))
            } else {
                format!("0x{}", hex::encode(data))
            }
        }
        _ => {
            format!("0x{}", hex::encode(data))
        }
    };

    Ok(json!({
        "key_path": key_path,
        "value_name": value_name,
        "value_type": out_header.value_type,
        "value": value_str,
        "data_hex": hex::encode(data),
        "data_base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
    }))
}

fn tool_write_registry(device: &DeviceHandle, params: &Value) -> Result<Value> {
    let key_path = params["key_path"].as_str().context("key_path must be a string")?;
    let value_name = params["value_name"].as_str().unwrap_or("");
    let value_type: u32 = params["value_type"].as_u64().map(|v| v as u32).unwrap_or(1);
    let data_b64 = params["data"].as_str().context("data must be a base64 string")?;

    let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data_b64)
        .context("Failed to decode base64 data")?;

    if data.len() > 4096 {
        anyhow::bail!("data must not exceed 4096 bytes");
    }

    let header = AiRegistryIn {
        key_path: to_wide_fixed::<256>(key_path),
        value_name: to_wide_fixed::<256>(value_name),
        value_type,
        data_size: data.len() as u32,
    };

    let header_size = std::mem::size_of::<AiRegistryIn>();
    let mut input_bytes = vec![0u8; header_size + data.len()];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &header as *const _ as *const u8,
            input_bytes.as_mut_ptr(),
            header_size,
        );
    }
    input_bytes[header_size..].copy_from_slice(&data);

    let output = device.ioctl(
        IOCTL_AI_WRITE_REGISTRY,
        &input_bytes,
        std::mem::size_of::<AiStatus>(),
    )?;

    let status: &AiStatus = unsafe {
        &*(output.as_ptr() as *const AiStatus)
    };

    let success = status.status >= 0;
    Ok(json!({
        "key_path": key_path,
        "value_name": value_name,
        "success": success,
        "ntstatus": format!("0x{:08X}", status.status as u32)
    }))
}

fn tool_list_files(device: &DeviceHandle, params: &Value) -> Result<Value> {
    let path = params["path"].as_str().context("path must be a string")?;

    let input = AiListFilesIn {
        directory_path: to_wide_fixed::<520>(path),
    };

    let input_bytes = unsafe {
        std::slice::from_raw_parts(
            &input as *const _ as *const u8,
            std::mem::size_of::<AiListFilesIn>(),
        )
    };

    let max_entries = 512usize;
    let out_size = std::mem::size_of::<AiListFilesOut>()
        + max_entries * std::mem::size_of::<AiFileEntry>();
    let output = device.ioctl(IOCTL_AI_LIST_FILES, input_bytes, out_size)?;

    if output.len() < std::mem::size_of::<AiListFilesOut>() {
        anyhow::bail!("Invalid response from driver");
    }

    let out_header: &AiListFilesOut =
        unsafe { &*(output.as_ptr() as *const AiListFilesOut) };
    let entry_size = std::mem::size_of::<AiFileEntry>();
    let entry_count = out_header.entry_count as usize;

    let mut files = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let offset = std::mem::size_of::<AiListFilesOut>() + i * entry_size;
        if offset + entry_size > output.len() {
            break;
        }

        let entry: &AiFileEntry =
            unsafe { &*(output[offset..offset + entry_size].as_ptr() as *const AiFileEntry) };

        fn filetime_to_iso(ft: i64) -> String {
            if ft <= 0 {
                return "N/A".to_string();
            }
            // FILETIME is 100ns intervals since 1601-01-01
            let unix_epoch_diff = 116444736000000000i64;
            let ns_since_epoch = ft - unix_epoch_diff;
            if ns_since_epoch < 0 {
                return "N/A".to_string();
            }
            let secs = ns_since_epoch / 10_000_000;
            let nanos = ((ns_since_epoch % 10_000_000) * 100) as u32;
            // Simplified: just return seconds since epoch
            format!("{}", secs)
        }

        files.push(json!({
            "name": wide_to_string(&entry.file_name),
            "size": entry.file_size,
            "is_directory": entry.is_directory != 0,
            "attributes": entry.file_attributes,
            "creation_time": filetime_to_iso(entry.creation_time),
            "last_access_time": filetime_to_iso(entry.last_access_time),
            "last_write_time": filetime_to_iso(entry.last_write_time)
        }));
    }

    Ok(json!({
        "path": path,
        "count": files.len(),
        "files": files
    }))
}

fn tool_read_file(device: &DeviceHandle, params: &Value) -> Result<Value> {
    let path = params["path"].as_str().context("path must be a string")?;
    let offset: i64 = params["offset"].as_i64().unwrap_or(0);
    let length: u32 = params["length"]
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(65536);

    if length > 65536 {
        anyhow::bail!("length must not exceed 65536");
    }

    let input = AiFileIoIn {
        file_path: to_wide_fixed::<520>(path),
        byte_offset: offset,
        length,
    };

    let input_bytes = unsafe {
        std::slice::from_raw_parts(
            &input as *const _ as *const u8,
            std::mem::size_of::<AiFileIoIn>(),
        )
    };

    let output = device.ioctl(IOCTL_AI_READ_FILE, input_bytes, length as usize)?;

    // Try to interpret as UTF-8 text for display, fallback to hex
    let text_preview = String::from_utf8_lossy(&output);
    let is_text = text_preview.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
        && !output.is_empty();

    Ok(json!({
        "path": path,
        "offset": offset,
        "bytes_read": output.len(),
        "data_hex": hex::encode(&output),
        "data_base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &output),
        "text_preview": if is_text { &text_preview[..text_preview.len().min(4096)] } else { "[binary data]" }
    }))
}

fn tool_write_file(device: &DeviceHandle, params: &Value) -> Result<Value> {
    let path = params["path"].as_str().context("path must be a string")?;
    let offset: i64 = params["offset"].as_i64().unwrap_or(0);
    let data_b64 = params["data"].as_str().context("data must be a base64 string")?;

    let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data_b64)
        .context("Failed to decode base64 data")?;

    if data.len() > 65536 {
        anyhow::bail!("data must not exceed 65536 bytes");
    }

    let header = AiFileIoIn {
        file_path: to_wide_fixed::<520>(path),
        byte_offset: offset,
        length: data.len() as u32,
    };

    let header_size = std::mem::size_of::<AiFileIoIn>();
    let mut input_bytes = vec![0u8; header_size + data.len()];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &header as *const _ as *const u8,
            input_bytes.as_mut_ptr(),
            header_size,
        );
    }
    input_bytes[header_size..].copy_from_slice(&data);

    let output = device.ioctl(
        IOCTL_AI_WRITE_FILE,
        &input_bytes,
        std::mem::size_of::<AiStatus>(),
    )?;

    let status: &AiStatus = unsafe {
        &*(output.as_ptr() as *const AiStatus)
    };

    let success = status.status >= 0;
    Ok(json!({
        "path": path,
        "offset": offset,
        "bytes_written": data.len(),
        "success": success,
        "ntstatus": format!("0x{:08X}", status.status as u32)
    }))
}

fn tool_list_connections(device: &DeviceHandle, _params: &Value) -> Result<Value> {
    let max_entries = 2048usize;
    let out_size = std::mem::size_of::<AiListConnectionsOut>()
        + max_entries * std::mem::size_of::<AiConnectionEntry>();
    let output = device.ioctl(IOCTL_AI_LIST_CONNECTIONS, &[], out_size)?;

    if output.len() < std::mem::size_of::<AiListConnectionsOut>() {
        anyhow::bail!("Invalid response from driver");
    }

    let out_header: &AiListConnectionsOut =
        unsafe { &*(output.as_ptr() as *const AiListConnectionsOut) };
    let entry_size = std::mem::size_of::<AiConnectionEntry>();
    let entry_count = out_header.entry_count as usize;

    fn ip_to_string(addr: u64) -> String {
        let b1 = (addr & 0xFF) as u8;
        let b2 = ((addr >> 8) & 0xFF) as u8;
        let b3 = ((addr >> 16) & 0xFF) as u8;
        let b4 = ((addr >> 24) & 0xFF) as u8;
        format!("{}.{}.{}.{}", b1, b2, b3, b4)
    }

    fn ntohs(port: u16) -> u16 {
        ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    }

    let mut connections = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let offset = std::mem::size_of::<AiListConnectionsOut>() + i * entry_size;
        if offset + entry_size > output.len() {
            break;
        }

        let entry: &AiConnectionEntry =
            unsafe { &*(output[offset..offset + entry_size].as_ptr() as *const AiConnectionEntry) };

        let proto = if entry.is_udp != 0 { "UDP" } else { "TCP" };

        connections.push(json!({
            "protocol": proto,
            "local_address": ip_to_string(entry.local_addr),
            "local_port": ntohs(entry.local_port),
            "remote_address": ip_to_string(entry.remote_addr),
            "remote_port": ntohs(entry.remote_port),
            "state": entry.state,
            "owning_pid": entry.owning_pid
        }));
    }

    Ok(json!({
        "count": connections.len(),
        "connections": connections
    }))
}

// ---------------------------------------------------------------------------
// MCP server main loop
// ---------------------------------------------------------------------------
fn handle_request(device: &DeviceHandle, request: &JsonRpcRequest) -> JsonRpcResponse {
    let id = request.id.clone();

    match request.method.as_str() {
        "initialize" => {
            JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "roxy-kernel-bridge",
                        "version": "1.0.0"
                    }
                })),
                error: None,
            }
        }
        "tools/list" => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({
                "tools": tool_definitions()
            })),
            error: None,
        },
        "tools/call" => {
            let params = match &request.params {
                Some(p) => p,
                None => {
                    return JsonRpcResponse {
                        jsonrpc: "2.0",
                        id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32602,
                            message: "Missing params".into(),
                            data: None,
                        }),
                    }
                }
            };

            let tool_name = params["name"].as_str().unwrap_or("");
            let tool_args = params.get("arguments").cloned().unwrap_or(Value::Null);

            let result = match tool_name {
                "read_process_memory" => tool_read_process_memory(device, &tool_args),
                "list_processes" => tool_list_processes(device, &tool_args),
                "kill_process" => tool_kill_process(device, &tool_args),
                "read_registry" => tool_read_registry(device, &tool_args),
                "write_registry" => tool_write_registry(device, &tool_args),
                "list_files" => tool_list_files(device, &tool_args),
                "read_file" => tool_read_file(device, &tool_args),
                "write_file" => tool_write_file(device, &tool_args),
                "list_connections" => tool_list_connections(device, &tool_args),
                _ => Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
            };

            match result {
                Ok(value) => JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(json!({
                        "content": [
                            {
                                "type": "text",
                                "text": serde_json::to_string_pretty(&value).unwrap_or_else(|e| format!("JSON error: {}", e))
                            }
                        ]
                    })),
                    error: None,
                },
                Err(e) => JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32000,
                        message: format!("{}", e),
                        data: None,
                    }),
                },
            }
        }
        "ping" => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({})),
            error: None,
        },
        "notifications/initialized" => {
            // No response for notifications
            JsonRpcResponse {
                jsonrpc: "2.0",
                id: None,
                result: Some(json!({})),
                error: None,
            }
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", request.method),
                data: None,
            }),
        },
    }
}

fn main() -> Result<()> {
    // Disable buffering on stderr for debug logging
    eprintln!("roxy-kernel-bridge starting...");

    // Open the device
    let device = DeviceHandle::open()
        .context("Cannot open \\\\.\\AIAgent. Make sure the driver is installed and running (run install.ps1 as Administrator first).")?;

    eprintln!("Connected to \\\\.\\AIAgent");

    // MCP protocol over stdin/stdout
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF
                eprintln!("stdin closed, exiting");
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
                    Ok(r) => r,
                    Err(e) => {
                        let err_response = JsonRpcResponse {
                            jsonrpc: "2.0",
                            id: None,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32700,
                                message: format!("Parse error: {}", e),
                                data: None,
                            }),
                        };
                        let mut out = stdout.lock();
                        let _ = writeln!(out, "{}", serde_json::to_string(&err_response).unwrap());
                        let _ = out.flush();
                        continue;
                    }
                };

                let method = request.method.clone();
                let has_id = request.id.is_some();

                let response = handle_request(&device, &request);

                // Don't write response for notifications (no id)
                if response.id.is_some() || method == "notifications/initialized" {
                    let mut out = stdout.lock();
                    if let Ok(json_str) = serde_json::to_string(&response) {
                        let _ = writeln!(out, "{}", json_str);
                        let _ = out.flush();
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading stdin: {}", e);
                break;
            }
        }
    }

    Ok(())
}