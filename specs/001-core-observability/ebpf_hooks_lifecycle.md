# eBPF 挂载点与生命周期梳理 (Hook Lifecycle)

本文档详细梳理了 `masdeepflow` 各个 eBPF 挂载点的触发顺序、核心功能以及它们是如何协作完成完整可观测性闭环的。

---

## 📅 全流程时序图

一个标准的 HTTP 请求生命周期如下：

## 🔑 核心本质 (The Core Essence)

您总结得非常精辟！整个系统虽然挂载点多，但本质上只在维护 **两组关系**，而 **FD (文件描述符)** 是唯一的纽带：

1.  **身份绑定 (Who)**: `FD <-> 五元组 (SIP, DIP, SPort, DPort)`
    *   **建立**: 在 `Connect` / `Accept` 阶段。
    *   **作用**: 给每个 FD 贴上“姓名牌”。
2.  **数据关联 (What)**: `FD <-> Buffer (数据内容)`
    *   **建立**: 在 `Write` / `Read` 阶段。
    *   **作用**: 此时只知道 FD，通过关系 1 查出是谁发的，然后把 Buffer 内容记录下来。
3.  **瞬时桥接 (How)**: `PID (当前线程) <-> 临时状态`
    *   **建立**: 在 Tracepoint Enter 或 Kprobe 阶段暂存。
    *   **作用**: 解决 **“同一个系统调用内部”** 上下文传递的问题。
        *   例1: `Connect Enter (有FD)` -> `Connect Kprobe (有IP)`。靠 PID 传 FD。
        *   例2: `Read Enter (有地址)` -> `Read Exit (有数据)`。靠 PID 传 Buffer 地址。
4.  **云原生身份 (Identity)**: `CGroup ID <-> Pod Name`
    *   **来源**: 每个事件都会带上 `bpf_get_current_cgroup_id()`。
    *   **作用**: 在用户态将枯燥的数字映射为 **"Pod Name / Container Name"**。没有任何一个 syscall 参数直接告诉我们“我是哪个 Pod”，只有 CGroup ID 能做到。

---

## 📅 全流程时序图

### 1.1 `tracepoint:syscalls/sys_enter_connect`
*   **顺序**: **第 1 步** (应用层发起握手请求)
*   **底层签名**: `int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`
*   **关键参数 & 偏移量 (x86_64/arm64)**:
    *   `fd` (Offset 16): **[关键]** 文件描述符，后续所有操作的唯一索引。
    *   `addr` (Offset 24): `struct sockaddr_in*` 指针。
        *   `sin_family` (+0): 协议族 (AF_INET=2)。
        *   `sin_port` (+2): **[关键]** 目标端口 (Big Endian)。
        *   `sin_addr` (+4): **[关键]** 目标 IP (Big Endian)。
    *   `addrlen` (Offset 32): 地址长度 (IPv4 至少 16)。
*   **功能**: 索引建立。关联 `FD -> (DstIP, DstPort)`。
*   **用户态动作**: 查 `pending_connects`，补全 `connections` 表中的源 IP 信息。

---

## 1.5 服务端接收阶段 (Server Accept)

客户端是 `Connect`，服务端则是 `Accept`。

### `kretprobe:inet_csk_accept`
*   **触发时机**: 服务端成功建立一个新连接 (Three-way Handshake 完成) 并返回新的 Socket 对象时。
*   **底层签名**: `struct sock *inet_csk_accept(struct sock *sk, int flags, int *err)`
*   **返回值**: `struct sock *newsk` (新建立连接的 Socket 结构体)。
*   **关键参数 (x86_64)**:
    *   `ret` (Register `rax`): **[关键]** 新 Socket 的指针。
    *   `newsk` 内部布局同 `tcp_connect` 的 `sk`。
*   **功能**:
    *   不需要像客户端那样搞两步 (sys_enter + kprobe)，因为 `accept` 返回时连接已经完全建立好了。
    *   直接从 `newsk` 里读出完整的 **SIP, DIP, SPort, DPort**。
*   **用户态动作**: 直接在 `connections` 表里插入一条记录 (无需关联 FD，或者用 Socket Pointer 做伪 Key)。注：当前实现可能暂未利用此事件做复杂关联，仅作日志打印。


### 1.2 `kprobe:tcp_connect`
*   **顺序**: **第 2 步** (内核完成路由选择后)
*   **底层签名**: `int tcp_connect(struct sock *sk)`
*   **关键参数**:
    *   `sk` (Register/Stack): 内核 socket 结构体指针。
        *   `sk->__sk_common.skc_rcv_saddr` (+4): **[关键]** 源 IP (Source IP)。
        *   `sk->__sk_common.skc_num` (+14): **[关键]** 源端口 (Source Port)。
*   **注意**: 这里的偏移量 (`+4` / `+14`) 是基于特定内核版本的 `struct sock` 布局，升级内核可能需要适配 (CO-RE)。
*   **关联密钥**: **PID (Thread ID)**
    *   **原理**: `connect` 是同步系统调用。
    *   Step 1 (`sys_enter_connect`) 和 Step 2 (`tcp_connect`) 发生在**同一个线程 (PID)** 的同一次调用栈中。
    *   因此，我们可以用 **PID** 作为桥梁。
*   **用户态动作**:
    1.  获取当前事件的 **PID**。
    2.  去 `pending_connects` 表查 `PID` 对应的 `Key(FD, CgroupID)` (由 Step 1 写入)。
    3.  找到 `FD` 后，就能更新主表 `connections` 中的源 IP 信息。

---

## 2. 数据发送阶段 (TX / Request)

### 2.1 `tracepoint:syscalls/sys_enter_write` (及 sendto)
*   **顺序**: **第 3 步** (应用层发送请求数据)
*   **底层签名**: `ssize_t write(int fd, const void *buf, size_t count)`
*   **关键参数**:
    *   `fd` (Offset 16): **[索引]** 用来查 IP。
    *   `buf` (Offset 24): **[关键]** 用户态数据指针 (存放 `GET /...`)。
    *   `count` (Offset 32): 写入长度。
*   **功能**: 有效载荷捕获 (Payload Capture)。
*   **用户态动作**: 解析 HTTP 协议，记录 Latency Start Time。

### 2.2 `tracepoint:syscalls/sys_enter_sendto`
*   **适用场景**: UDP 通信 (DNS) 或 带 Flag 的 TCP 发送。
*   **底层签名**: `ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, ...)`
*   **关键参数**:
    *   **布局与 Write 完全一致**：
    *   `fd` (Offset 16): 文件描述符。
    *   `buf` (Offset 24): 数据指针。
    *   `len` (Offset 32): 数据长度。
*   **功能**: 很多 HTTP 客户端 (如 Curl) 或 DNS 查询不直接用 `write` 而是用 `sendto`。如果我们只抓 `write` 就会漏数据，所以必须同时监听它。

---

## 3. 数据接收阶段 (RX / Response)

由于读取数据分为“准备 buffer”和“填入数据”两步，我们需要两个探针配合。

> **注意：互斥关系**
> 应用程序通常**只会选择其中一种**方式来接收数据：
> *   要么用 `read` (通用文件读取)
> *   要么用 `recvfrom` (Socket 专用读取)
>
> 它们是**“或”**的关系，不会同时触发。我们同时监听是为了**防止漏网之鱼**。

### 3.1 `tracepoint:syscalls/sys_enter_read` (及 recvfrom)
*   **顺序**: **第 4 步** (准备接收数据)
*   **底层签名**: `ssize_t read(int fd, void *buf, size_t count)`
*   **关键参数**:
    *   `fd` (Offset 16): **[索引]**。
    *   `buf` (Offset 24): **[容器]** 这里的指针指向一块**空内存** (Empty Container)。
    *   **区别于 Write**: 2.1 的 `buf` 里全是数据，可以直接读；这里 3.1 的 `buf` 是空的，千万别读！
*   **功能**: 锚点记录。我们得记住“数据要写到哪”。
*   **用户态动作**: 暂存 `Map<PID, BufAddr>`。

### 3.2 `tracepoint:syscalls/sys_exit_read`
*   **顺序**: **第 5 步** (数据接收完成)
*   **底层签名**: `long ret` (返回值)
*   **关键参数**:
    *   `ret` (Offset 16): **[关键]** 实际读取到的字节数。如果 `<=0` 说明读取失败或结束。
*   **逻辑**: 回调 3.1 中记录的 `BufAddr`，现在里面已经有数据了 (如 `HTTP/1.1 200 OK`)。
*   **用户态动作**: 解析 HTTP 响应，计算 `Latency = Now - StartTime`。

### 3.3 `tracepoint:syscalls/sys_enter_recvfrom`
*   **适用场景**: UDP 接收 或 带 Flag 的 TCP 接收。
*   **底层签名**: `ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)`
*   **关键参数**:
    *   `fd` (Offset 16): 索引。
    *   `buf` (Offset 24): **[容器]** 记录空 Buffer 地址。等待内核填充数据。
*   **功能**: 类似于 `read` 的 Enter 阶段。记录 "空盘子" 的位置。

### 3.4 `tracepoint:syscalls/sys_exit_recvfrom`
*   **触发时机**: `recvfrom` 系统调用返回后。
*   **底层签名**: `long ret` (返回值)
*   **关键参数**:
    *   `ret` (Offset 16): 实际读取长度。
*   **逻辑**:
    1.  从 Map 中取出 3.3 存的 `buf` 地址。
    2.  确认 `ret > 0`。
    3.  读取 `buf` 内容。
*   **功能**: 类似于 `read` 的 Exit 阶段。真正的 "上菜" 时刻。用户态动作与 `sys_exit_read` 完全一致。

---

## 总结映射表

| 阶段 | 函数名 | 关键参数 (C/Offset) | 我们的用途 |
| :--- | :--- | :--- | :--- |
| **Connect** | `sys_enter_connect` | `fd`(16), `addr`(24) | 谁(FD) 连了 哪(IP) |
| **IP Info** | `tcp_connect` | `sk`(Reg) -> `+4/+14` | 我(SourceIP) 是谁 |
| **Request** | `sys_enter_write` | `buf`(24) | 说了什么 (HTTP Request) |
| **Response** | `sys_exit_read` | `ret`(16) + `SavedBuf` | 回了什么 (HTTP Response) |
