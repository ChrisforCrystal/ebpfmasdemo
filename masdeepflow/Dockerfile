# === 第 1 阶段：构建环境 (Builder) ===
# 使用 Debian Bookworm 基础的 Rust 镜像
FROM rust:latest AS builder

# 1. 安装编译 eBPF 必须的系统库
# clang/llvm: eBPF 只有 Clang 后端能编译，Rust 也是调用的 LLVM
# libelf-dev: 处理 ELF 格式（内核模块格式）需要
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# 2. 安装 Rust Nightly 工具链
# 为什么？因为 eBPF 编译依赖 unstable 的 `-Z build-std` 特性
# 这个特性允许重新编译 Rust 标准库的核心部分 (core)，使其能在内核这种无标准库环境运行
RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly

# 3. 安装 bpf-linker
# 这是一个特殊的链接器，它能把 Rust 编译出的 .o 文件链接成 eBPF 字节码
RUN cargo install bpf-linker

# 4. 复制代码
WORKDIR /usr/src/masdeepflow
COPY . .

# 5. 执行构建
# 这里虽然写的是 build masdeepflow (用户态)，但里面的 build.rs 会自动触发 eBPF 的编译
WORKDIR /usr/src/masdeepflow/masdeepflow
RUN cargo build --release

# === 第 2 阶段：运行环境 (Runner) ===
# 为了镜像尽可能小，我们只用一个瘦身版的 Debian
FROM debian:bookworm-slim

# 6. 安装验证工具
# curl: 测 HTTP
# netcat: 测 TCP 连接
# iproute2: ip 命令
# procps: ps 命令看进程
RUN apt-get update && apt-get install -y \
    curl \
    netcat-openbsd \
    iproute2 \
    procps \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# 7. 从第一阶段拷贝编译好的二进制文件
# 我们只需要这一个文件，其他的构建垃圾全丢掉
COPY --from=builder /usr/src/masdeepflow/target/release/masdeepflow /usr/local/bin/masdeepflow
COPY --from=builder /usr/src/masdeepflow/target/release/verify_traffic /usr/local/bin/verify_traffic
COPY --from=builder /usr/src/masdeepflow/target/release/traffic_gen /usr/local/bin/traffic_gen

# 8. 设置启动命令
# 注意：运行时必须在 docker run 加 --privileged，否则无法加载 eBPF
CMD ["/usr/local/bin/masdeepflow"]
