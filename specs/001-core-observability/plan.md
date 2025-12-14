# Implementation Plan: Core Observability Baseline

**Branch**: `001-core-observability` | **Date**: 2025-12-09 | **Spec**: [Link](../spec.md)
**Input**: Feature specification from `/specs/001-core-observability/spec.md`

## Summary

## Summary

Implement core observability features (Process Exec, TCP Connect/Accept, Traffic Volume) **plus Kubernetes Context (Pod awareness) and Basic HTTP/1.x Observability (URL/Latency)** using Rust and eBPF (aya-rs). The solution will be a lightweight agent that outputs structured events to stdout.

## Technical Context

**Language/Version**: Rust 1.75+ (Stable)
**Primary Dependencies**: `aya`, `aya-ebpf`, `aya-log`, **`kube` (or simple /proc parsing if lightweight)**, **HTTP Parser (httparse)**
**Storage**: N/A (stdout for this baseline)
**Testing**: `cargo xtask` (build), Shell script verification (container/VM)
**Target Platform**: Linux 5.x+ (x86_64/aarch64) - Lima/Docker compatible
**Project Type**: System Agent (Rust Workspace)
**Performance Goals**: Low CPU usage (<1% on idle system), negligible impact on network throughput.
**Constraints**: Must run as single binary (or loader + ebpf payload).
**Scale/Scope**: Single host scope.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] **I. Observability First**: Agent outputs clear logs/metrics (events).
- [x] **II. Rust & eBPF Native**: Uses `aya-rs`, pure Rust implementation.
- [x] **III. Lightweight & Portable**: Minimal dependencies, static linking focus.
- [x] **IV. Verification Driven**: Verification plan uses simple standard tools (`ls`, `curl`).
- [x] **V. Safe Complexity**: Using standard `tracepoint/kprobe` hooks managed by `aya`.

## Project Structure

### Documentation (this feature)

```text
specs/001-core-observability/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
└── checklist.md         # Phase 2 output
```

### Source Code (repository root)

```text
masdeepflow/
├── Cargo.toml                  # Workspace root
├── masdeepflow/                # Userspace Agent
│   ├── src/
│   │   ├── main.rs            # Entry point, log output
│   │   └── process.rs         # Event decoding (future)
│   └── Cargo.toml
├── masdeepflow-ebpf/           # Kernel Space (eBPF)
│   ├── src/
│   │   ├── main.rs            # eBPF Hooks (kprobes/tracepoints)
│   └── Cargo.toml
└── masdeepflow-common/         # Shared Types
    ├── src/
    │   └── lib.rs             # ProcessEvent, TcpEvent structs
    └── Cargo.toml
```

**Structure Decision**: Adhere to existing `aya` scaffold structure which separates `common`, `ebpf`, and `user` (host) crates.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Kernel Probes (kprobe) | Needed for valid socket info causing reliance on kernel internals | Tracepoints alone insufficient for IP extraction on connect |

## Future Roadmap

This baseline sets the stage for advanced features:

1.  **MySQL Protocol Observability** (Phase 7)
    *   Parse binary MySQL packets (COM_QUERY) in userspace.
    *   Calculate SQL execution latency.
2.  **High Performance Gateway** (Phase 8)
    *   Utilize `SK_MSG` / `SOCK_OPS` for L4 transparent proxying.
    *   Implement traffic redirection and load balancing.
