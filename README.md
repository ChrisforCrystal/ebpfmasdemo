# masDeepFlow: eBPF 云原生可观测性 Agent

> **"上帝视角" 看透你的微服务流量。**

**masDeepFlow** 是一个基于 eBPF (Extended Berkeley Packet Filter) 技术构建的高性能、无侵入式可观测性 Agent。它能够深入 Linux 内核，自动捕获应用层的黄金指标（请求、响应、耗时），并关联 Kubernetes 元数据，为您提供从内核到应用的全链路视角。

## 🚀 核心特性 (Key Features)

### 1. 零侵入 (Zero-Code Instrumentation)
无需修改一行业务代码，无需重启应用。只需在节点上运行一个 Agent，即可自动通过 kprobe/tracepoint 探针捕获流量。

### 2. 多协议深度解析 (L7 Protocol Parsing)
不仅监控 TCP 连接，更能深入应用层协议，提取关键业务信息：
- **HTTP/1.x**: 自动识别 Method (GET/POST), URL, Status Code, Latency。
- **MySQL (New!)**: 解析二进制协议，提取 SQL 查询语句 (`COM_QUERY`) 和执行耗时。

### 3. 全景上下文关联 (Context Propagation)
拒绝枯燥的 IP 地址。Agent 自动将内核网络事件映射到 Kubernetes 实体：
- **Process**: PID, Comm (进程名)
- **K8s**: Pod Name, Container ID, Cgroup 上下文

### 4. 高性能设计 (High Performance)
- **Rust + Aya**: 使用 Rust 编写，兼顾内存安全与高性能。
- **Per-CPU Maps**: 利用 eBPF Map 高效聚合数据。
- **Zero-Copy**: 尽可能减少内核态到用户态的数据拷贝。

---

## 🛠️ 快速开始 (Quick Start)

我们提供了一键 Docker 运行脚本，集成了所有编译环境。

### 前置要求
- Docker (运行在 Linux 或支持特权模式的环境)
- Linux Kernel 5.8+ (推荐)

### 运行 Agent
```bash
# 1. 构建并启动容器 (自动处理编译)
./run-in-docker.sh

# 2. 查看实时日志
docker logs -f masdeepflow-demo
```

---

## 🧪 验证与测试 (Verification)

本项目内置了强大的自测工具 `traffic_gen`，用于验证 eBPF 探针的有效性。

### 验证 MySQL 协议 (全链路闭环)
为了验证数据库监控能力，我们可以在容器内模拟一个完整的 MySQL 客户端-服务端交互：

```bash
# 1. 启动 Mock MySQL Server (监听 3306，自动回复 OK 包)
docker exec -d masdeepflow-demo traffic_gen mysql-server

# 2. 启动 Client 发送查询 (SELECT 1;)
docker exec masdeepflow-demo traffic_gen mysql-client

# 3. 检查 Agent 日志
docker logs masdeepflow-demo 2>&1 | grep "MySQL"
```

**预期输出**:
```text
[INFO] ... MySQL Query: SELECT 1;, , 
[INFO] ... MySQL Response: OK, , Latency: 53ms
```
*(注: Latency 53ms 是 Mock Server 故意注入的 50ms 延迟，证明耗时计算准确无误。)*

---

## 📂 项目结构 (Structure)

```text
ebpmasdemo/
├── masdeepflow/           # Rust 项目源码
│   ├── masdeepflow/       # Userspace Agent (加载器 & 协议解析)
│   ├── masdeepflow-ebpf/  # Kernel Space eBPF Code (探针逻辑)
│   └── masdeepflow-common/# 共享类型定义 (Events)
├── specs/                 # 设计文档 & 任务清单
└── run-in-docker.sh       # 一键启动脚本
```

---

## 📅 对未来的规划 (Roadmap)

- [x] Phase 1-6: 基础 TCP/HTTP 观测, K8s 关联
- [x] **Phase 7: MySQL 协议支持** (已完成)
- [ ] **Phase 8: High Performance Gateway** (流量控制/负载均衡)
- [ ] Phase 9: PostgreSQL / Redis 协议支持

---
*Built with ❤️ by masAllSome Team using Rust & eBPF.*
