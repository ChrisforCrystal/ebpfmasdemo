# Feature Specification: Core Observability Baseline

**Feature Branch**: `001-core-observability`
**Created**: 2025-12-09
**Status**: Draft
**Input**: User description: "Implement core observability features including process execution monitoring and TCP connection tracking for MasDeepFlow."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Process Execution Monitoring (Priority: P1)

A DevOps engineer wants to real-time visibility into process execution events on the host to audit system activity and detect suspicious binaries.

**Why this priority**: Fundamental building block for associating network traffic with specific processes. High security value.

**Independent Test**: Can be fully tested by spawning a process (e.g., `ls`) and verifying the agent outputs a corresponding log event.

**Acceptance Scenarios**:

1. **Given** the agent is running with root privileges, **When** a command `ls -la` is executed in a terminal, **Then** the agent logs a "PROCESS" event containing the PID and command name (`ls`).
2. **Given** the agent is running, **When** a short-lived process executes and exits immediately, **Then** the event is captured without loss.

---

### User Story 2 - Outgoing TCP Connection Tracking (Priority: P1)

A Network Admin wants to observe which processes are initiating external TCP connections to understand application dependencies and unauthorized access.

**Why this priority**: Core networking observability requirement. Essential for service maps.

**Independent Test**: Can be tested by running `curl <external-ip>` and verifying the agent outputs a "TCP Connect" event.

**Acceptance Scenarios**:

1.  **Given** the agent is running, **When** a process initiates a TCP connection (e.g., `curl 1.1.1.1`), **Then** the agent logs a "TCP Connect" event with Source IP, Dest IP, Source Port, Dest Port, and PID.
2.  **Given** the agent is running, **When** a connection fails or is blocked (optional stretch), **Then** (Stretch) failed attempts are logged or at least do not crash the agent.

---

### User Story 3 - Incoming TCP Connection & Traffic Volume (Priority: P2)

An SRE wants to measure the traffic volume (bytes sent/received) and identify incoming connections to monitor service load.

**Why this priority**: Completes the visibility loop (ingress + sizing).

**Independent Test**: Can be tested using `nc -l 8080` (server) and `nc localhost 8080` (client) to generate traffic.

**Acceptance Scenarios**:

1.  **Given** an established connection, **When** data is transmitted (e.g., 1KB), **Then** the agent logs "TCP Data" events indicating the number of bytes transferred.

---

### User Story 4 - Kubernetes & HTTP Observability (Priority: P2)

A Platform Engineer wants to see network traffic in the context of Kubernetes (Pod Name) and Layer 7 details (URL, Latency) to troubleshoot microservice performance.

**Why this priority**: elevating data from "IP:Port" to "Service:URL" makes it actionable for developers.

**Independent Test**: Run a Pod in `kind` or `minikube` that makes an HTTP request, and verify log contains Pod Name and URL.

**Acceptance Scenarios**:

1. **Given** the agent is running on a K8s node, **When** a Pod makes an HTTP GET request to `http://example.com/foo`, **Then** the log includes the **Pod Name** (e.g., `frontend-distroless`), the **URL** (`/foo`), and the **Latency** (ms).
2. **Given** non-HTTP traffic, **Then** the agent falls back to TCP stats (graceful degradation).



## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The System MUST use eBPF to capture process creation events.
- **FR-002**: The System MUST use eBPF to capture connection lifecycle events for IPv4.
- **FR-003**: The System MUST use eBPF to measure traffic volume (bytes sent/received).
- **FR-004**: The System MUST correlate Host PIDs/Namespace IDs to Kubernetes Pods (via local metadata or API).
- **FR-005**: The System MUST parse basic HTTP/1.x headers (Method, URL) from TCP payloads (initially plaintext).
- **FR-006**: The System MUST calculate Request-Response latency for HTTP transactions.
- **FR-007**: The System MUST run as a single Rust binary on standard Linux kernels (focus on 5.x+ typical in Lima/Docker).
- **FR-008**: The System MUST output events to stdout in a human-readable format for immediate verification.
- **FR-009**: The System MUST NOT impact system stability (e.g., must undergo verification for memory safety).

### Key Entities

- **ProcessEvent**: { Timestamp, PID, Comm/Name }
- **TcpEvent**: { Timestamp, PID, SrcIP, DstIP, SrcPort, DstPort, Type (Connect/Accept/Data), Bytes }

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Agent starts and attaches probes in under 5 seconds.
- **SC-002**: 100% of manually triggered test events (`curl`, `ls`) are detected and logged during verification.
- **SC-003**: Agent binary size remains under 20MB (consistent with "Lightweight" goal).
- **SC-004**: Can be successfully verified in a standard `limactl` instance or `docker run --privileged` container.
