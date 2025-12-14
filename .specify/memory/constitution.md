<!--
SYNC IMPACT REPORT
Version Change: 0.0.0 -> 1.0.0
Ratified: 2025-12-09
Modified Principles:
- Added I. Observability First
- Added II. Rust & eBPF Native
- Added III. Lightweight & Portable
- Added IV. Verification Driven
- Added V. Safe Complexity
Templates requiring updates:
- .specify/templates/plan-template.md (✅ Compatible)
- .specify/templates/spec-template.md (✅ Compatible)
- .specify/templates/tasks-template.md (✅ Compatible)
-->
# masDeepFlow 章程

## 核心原则

### I. 可观测性优先
首要目标是可观测性。系统不仅必须观测目标流量，还必须观测自身的健康状况。指标（Metrics）和日志（Logs）对于所有组件都是强制性的。生产环境中的可调试性是关键。

### II. Rust & eBPF 原生
核心逻辑采用 Rust 编写。数据平面使用 eBPF 以实现高性能和安全性。核心代理（Agent）应避免引入重量级的外部运行时依赖（如 JVM/Python），以确保轻量级部署和低开销。

### III. 轻量级与可移植性
组件必须能够在最小环境中运行，包括容器（Docker）和本地虚拟机（Lima）。在适用的情况下首选静态链接（musl）。目标是极小的资源占用，适合作为 Sidecar 或 Daemonset 运行。

### IV. 验证驱动
所有实现必须能够在本地闭环（Lima/Docker）中进行验证。如果在开发过程中无法在本地验证某个功能，则视为风险。必须自动化验证环境的搭建（例如通过脚本或 Makefiles）。

### V. 安全的复杂性
默认使用 Safe Rust。不安全（Unsafe）代码和复杂的 eBPF 逻辑必须被隔离、文档化并经过充分论证。eBPF 程序必须通过验证器检查，除非严格必要且被充分理解，否则不得使用 `unsafe` hack。

## 技术栈约束

- **语言**: Rust 1.75+ (稳定版; eBPF 编译时允许使用 Nightly)。
- **内核框架**: aya-rs (首选) 。
- **目标平台**: Linux (x86_64, aarch64)。
- **验证环境**: Lima VM (macOS), kind k8s。
- **构建系统**: Cargo (Rust); Docker (打包)。

## 开发工作流

1. **设计**: 定义需要哪些 eBPF 挂载点（hooks）以及需要哪些用户空间数据。
2. **eBPF 实现**: 实现内核探针/程序。确保其通过验证器。
3. **用户空间实现**: 实现代理以加载 eBPF，读取 maps/perf buffers，并处理数据。
4. **本地验证**: 运行 `./run.sh` 或类似命令部署到 Lima/Docker 并验证输出。
5. **迭代**: 优化数据收集和性能。

## 治理

- 本章程优先于所有其他实践。
- 修订需要用户批准。
- 项目整体遵守语义化版本控制（Semantic Versioning）。

**版本**: 1.0.0 | **批准日期**: 2025-12-09 | **最后修订**: 2025-12-09
