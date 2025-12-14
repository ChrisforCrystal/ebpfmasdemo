# Quickstart Verification: Core Observability

**Prerequisites**:
- `cargo` (Rust 1.75+)
- `docker` or `limactl` (for isolation)
- `sudo` access (for loading eBPF)

## 1. Build

Compiles both kernel (eBPF) and userspace components.

```bash
cargo xtask build-ebpf
cargo build --release
```

## 2. Run

Run the agent. Requires `sudo` to load eBPF programs.

```bash
RUST_LOG=info sudo -E ./target/release/masdeepflow
```

*Expected Output*:
```text
INFO masdeepflow: Loggin initialized
INFO masdeepflow: Waiting for events...
```

## 3. Verify

### Test 1: Process Execution
Open a new terminal window:
```bash
ls -la /tmp
```

*Agent Output*:
```text
[PROCESS] PID: <num> Comm: ls
```

### Test 2: Outbound Connection
```bash
curl -I http://1.1.1.1
```

*Agent Output*:
```text
[TCP] Connect PID: <num> <local-ip>:<port> -> 1.1.1.1:80
```

### Test 3: Inbound Connection & Traffic
Terminal A (Server):
```bash
nc -k -l 8080
```

Terminal B (Client):
```bash
echo "Hello" | nc localhost 8080
```

*Agent Output*:
```text
[TCP] Accept PID: <server-pid> ...
[TCP] Data ... Bytes: 6
```
