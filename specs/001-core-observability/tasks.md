# Tasks: Core Observability Baseline

**Input**: Design documents from `/specs/001-core-observability/`
**Prerequisites**: plan.md, spec.md, data-model.md

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Verify environment and project dependencies.

- [x] T001 Verify Rust toolchain and components (rust-src, bpf-linker)
- [x] T002 Verify project compiles with existing scaffold (`cargo xtask build-ebpf && cargo build`)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core data structures required by all user stories.

**⚠️ CRITICAL**: Must complete before eBPF work starts.

- [x] T003 Define `ProcessEvent` struct in `masdeepflow-common/src/lib.rs` (C-compatible)
- [x] T004 Define `TcpEvent` struct in `masdeepflow-common/src/lib.rs` (C-compatible)
- [x] T005 [P] Setup basic logger and PerfEventArray polling loop in `masdeepflow/src/main.rs`

**Checkpoint**: Structs defined, userspace scaffhold ready to receive events.

---

## Phase 3: User Story 1 - Process Execution Monitoring (Priority: P1)

**Goal**: Capture `exec` events to identify processes.

**Independent Test**: Run `ls` and see log output.

- [x] T006 [US1] Implement `tracepoint:sched/sched_process_exec` in `masdeepflow-ebpf/src/main.rs`
- [x] T007 [US1] Capture PID and comm in the tracepoint and submit to PerfEventArray
- [x] T008 [US1] Implement userspace handler for `ProcessEvent` in `masdeepflow/src/main.rs`
- [x] T009 [US1] Verify locally with `ls` command

**Checkpoint**: Process monitoring working independently.

---

## Phase 4: User Story 2 - Outgoing TCP Connection Tracking (Priority: P1)

**Goal**: Capture outbound connection attempts.

**Independent Test**: Run `curl` and see log output.

- [x] T010 [US2] Implement `kprobe/tcp_v4_connect` in `masdeepflow-ebpf/src/main.rs`
- [x] T011 [US2] Extract socket details (dest IP/port) or context (PID) and submit `TcpEvent` (Connect)
- [x] T012 [US2] Implement userspace handler for `TcpEvent` (Connect type) in `masdeepflow/src/main.rs`
- [x] T013 [US2] Verify locally with `curl`

**Checkpoint**: Outbound connections visible.

---

## Phase 5: User Story 3 - Incoming TCP & Traffic Volume (Priority: P2)

**Goal**: Capture inbound connections and data volume.

**Independent Test**: Run `nc` server/client loop.

- [x] T014 [US3] Implement `kretprobe/inet_csk_accept` for inbound connections in `masdeepflow-ebpf/src/main.rs`
- [x] T015 [US3] Implement `kprobe/tcp_sendmsg` (or similar) for traffic volume in `masdeepflow-ebpf/src/main.rs`
- [x] T016 [US3] Update userspace handler to process Accept and Data events in `masdeepflow/src/main.rs`

**Checkpoint**: Full visibility (Process + In/Out Net).

---

## Phase 6: User Story 4 - K8s & HTTP Observability (Priority: P2)

**Goal**: Context (Pod) and L7 (URL/Latency).

**Independent Test**: Mock K8s env (or use `kind`) + HTTP Client.

- [x] T017 [US4] Update `ProcessEvent` and `TcpEvent` to include `cgroup_id` (requires eBPF update) in `masdeepflow-common` & `masdeepflow-ebpf`
- [x] T018 [US4] Implement "Metadata Store" in userspace to map `cgroup_id` -> Pod Name (mock/static first, then K8s API/Proc)
- [x] T019 [US4] Implement basic HTTP Header parser in userspace (Parse `TcpEvent` data payload)
- [x] T020 [US4] Implement Request-Response Latency calculation in userspace (Hashmap by socket 5-tuple)
- [x] T021 [US4] Verify in K8s (Kind) or simulated cgroup env

**Checkpoint**: Events show "Pod: frontend" and "URL: /index.html (20ms)".

---

## Dependencies & Execution Order

1. **Setup & Foundational**: T001-T005 (Blocks everything)
2. **User Story 1 (Process)**: T006-T009
3. **User Story 2 (Connect)**: T010-T013
4. **User Story 3 (Traffic)**: T014-T016
5. **User Story 4 (K8s/HTTP)**: T017 (Touches structs again), T018-T021 (Userspace logic)

## Implementation Strategy

1. **MVP**: US1 + US2.
2. **Beta**: US3.
3. **Release**: US4 (Adds the "Wow" factor).

## Phase 7: MySQL Protocol Support (Future)

**Goal**: Extend observability to database layer (MySQL).

- [ ] T022 [MySQL] Implement binary protocol parser (COM_QUERY) in userspace
- [ ] T023 [MySQL] Implement MySQL-specific latency calculation
- [ ] T024 [MySQL] Verify with `traffic_gen` simulating MySQL packets

## Phase 8: High Performance Gateway (Future)

**Goal**: Evolve from Observer to Controller (Traffic Gateway).

- [ ] T025 [Gateway] Research eBPF `SK_MSG` / `SOCK_OPS` for redirection
- [ ] T026 [Gateway] Implement L4 Load Balancing / Proxy prototype

