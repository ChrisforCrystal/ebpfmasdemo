# Data Model: Core Observability

## Events (eBPF -> User)

All events are transmitted via `BPF_MAP_TYPE_PERF_EVENT_ARRAY`. Structs must be `#[repr(C)]`.

### ProcessEvent

Triggered on `sched_process_exec`.

| Field | Type | Size (bytes) | Description |
|-------|------|--------------|-------------|
| pid   | u32  | 4 | Process ID |
| cgroup_id | u64 | 8 | Cgroup ID (for Pod correlation) |
| comm  | [u8; 16] | 16 | Command name (truncated to 16 chars) |

**Total Size**: 28 bytes

### TcpEvent

Triggered on `tcp_connect` (outbound), `inet_csk_accept` (inbound), and data transmission.

| Field | Type | Size (bytes) | Description |
|-------|------|--------------|-------------|
| cgroup_id | u64 | 8 | Cgroup ID (for Pod correlation) |
| saddr | u32  | 4 | Source IPv4 Address |
| daddr | u32  | 4 | Destination IPv4 Address |
| sport | u16  | 2 | Source Port |
| dport | u16  | 2 | Destination Port |
| family| u16  | 2 | Address Family (Always 2 for AF_INET) |
| direction | u8 | 1 | 0: Connect (Out), 1: Accept (In) |
| data_len | u32 | 4 | Bytes transferred (0 for connect/accept events) |
| _padding | [u8; 1] | 1 | Alignment padding (implicit or explicit) |

**Total Size**: ~20 bytes (depending on alignment)

## Userspace Enriched Model (Log Output)

The agent enriches raw events with timestamps before outputting to stdout.

```json
{
  "timestamp": "ISO8601",
  "type": "PROCESS | TCP_CONNECT | TCP_ACCEPT | TCP_DATA",
  "pid": 1234,
  "data": { ... }
}
```
