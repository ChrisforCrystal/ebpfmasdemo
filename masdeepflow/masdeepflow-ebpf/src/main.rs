#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_msg_redirect_hash, bpf_sock_hash_update, r#gen,
    },
    macros::{kprobe, kretprobe, map, sk_msg, sock_ops, tracepoint},
    maps::{PerfEventArray, SockHash},
    programs::{ProbeContext, RetProbeContext, SkMsgContext, SockOpsContext, TracePointContext},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockKey {
    pub sip: u32,
    pub dip: u32,
    pub sport: u32,
    pub dport: u32,
}

#[map]
static INTERCEPT_MAP: SockHash<SockKey> = SockHash::with_max_entries(65535, 0);
use masdeepflow_common::{ProcessEvent, TcpEvent};

#[inline(always)]
fn is_infra_process(comm: &[u8; 16]) -> bool {
    let c0 = comm[0];

    // 1. Check "masdeepflow" (11 chars)
    if c0 == b'm' {
        let target = b"masdeepflow";
        for i in 1..11 {
            if comm[i] != target[i] {
                return false;
            }
        }
        return true;
    }

    // 2. Check "docker" (6) or "dockerd" (7)
    if c0 == b'd' {
        let prefix = b"docker";
        for i in 1..6 {
            if comm[i] != prefix[i] {
                return false;
            }
        }
        // Matches "docker" prefix.
        // Check for exact "docker\0"
        if comm[6] == 0 {
            return true;
        }
        // Check for "dockerd\0"
        if comm[6] == b'd' && comm[7] == 0 {
            return true;
        }
        return false;
    }

    // 3. Check "containerd" (10) or "containerd-shim" (15)
    if c0 == b'c' {
        let prefix = b"containerd";
        for i in 1..10 {
            if comm[i] != prefix[i] {
                return false;
            }
        }
        // Matches "containerd" prefix.
        // Check for exact "containerd\0"
        if comm[10] == 0 {
            return true;
        }
        // Check for "containerd-shim"
        let shim_suffix = b"-shim";
        for i in 0..5 {
            if comm[10 + i] != shim_suffix[i] {
                return false;
            }
        }
        return true;
    }

    false
}

// 定义两个 PerfEventArray Map，用于将内核态事件高性能地传输给用户态
#[map]
static PROCESS_EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[map]
static TCP_EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::new(0);

// [Phase 2.5] Struct to pass context from _enter to _exit probes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadInfo {
    pub buf_ptr: u64,
    pub fd: u32,
}

// [Phase 2.5 Fix] Robust Self-Exclusion via PID
#[map]
static FILTER_PID: aya_ebpf::maps::HashMap<u32, u8> =
    aya_ebpf::maps::HashMap::with_max_entries(16, 0);

// --- 模块一：进程监控 (Process Monitoring) ---

// 挂载点: tracepoint:sched/sched_process_exec
// 触发时机: 每当有新进程执行 exec 系统调用时（通常是新程序启动）
#[tracepoint]
pub fn masdeepflow_exec(ctx: TracePointContext) -> u32 {
    // 获取当前进程 ID (PID 在低 32 位)
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // 关键步骤：获取当前进程所属的 Cgroup ID
    // 这将用于在用户态关联 Kubernetes Pod 信息
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // 获取进程命令名 (如 "ls", "curl")
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);

    // 构建事件结构体
    let event = ProcessEvent {
        pid,
        cgroup_id,
        comm,
    };
    // 发送事件到用户态
    PROCESS_EVENTS.output(&ctx, &event, 0);
    0
}

// --- 模块二：网络监控 (Network Monitoring) ---

// 挂载点: kprobe/tcp_v4_connect
// 触发时机: 进程发起 TCP 连接时 (Connect 阶段)
// 挂载点: kprobe/tcp_v4_connect
// 触发时机: 进程发起 TCP 连接时 (Connect 阶段)
// 挂载点: tracepoint:syscalls/sys_enter_connect
// 触发时机: 进程发起 connect 系统调用。相比 kprobe，这里能直接拿到 FD。
// 挂载点: tracepoint:syscalls/sys_enter_connect
// 触发时机: 应用程序调用 `connect` 系统调用发起 TCP 连接时。
// 作用: 捕获连接的目标 IP、目标端口以及最重要的文件描述符 (FD)。
//       这是唯一能将 FD 与目标地址关联起来的地方。
#[tracepoint]
pub fn masdeepflow_tcp_connect(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // sys_enter_connect 的参数布局:
    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    // 偏移量 (x86_64/arm64 通用 tracepoint 格式):
    // 16: fd (sockfd)
    // 24: addr指针 (uservaddr)
    // 32: addr长度 (addrlen)

    let fd: u64 = unsafe { ctx.read_at::<u64>(16).unwrap_or(0) };
    let addr_ptr: u64 = unsafe { ctx.read_at::<u64>(24).unwrap_or(0) };
    let addr_len: u64 = unsafe { ctx.read_at::<u64>(32).unwrap_or(0) };

    // 过滤: 只处理 IPv4 (sockaddr_in 的大小至少为此)
    if addr_len < 16 {
        return 0;
    }

    // struct sockaddr_in {
    //   short sin_family;        // 2 bytes (协议族)
    //   ushort sin_port;         // 2 bytes (目标端口, 大端序)
    //   struct in_addr sin_addr; // 4 bytes (目标IP, 大端序)
    //   char sin_zero[8];        // 填充
    // }

    let mut sin_family: u16 = 0;
    let mut dport: u16 = 0;
    let mut daddr: u32 = 0;

    unsafe {
        // [步骤 1] 读取协议族 (Family)
        // 从用户空间地址 (addr_ptr) 读取前 2 个字节
        // 这是为了确认 socket 是否为 IPv4 (AF_INET = 2)
        let _ = r#gen::bpf_probe_read_user(
            &mut sin_family as *mut _ as *mut _,
            2,
            addr_ptr as *const _,
        );

        // 过滤: 只处理 AF_INET (IPv4 = 2)
        if sin_family != 2 {
            return 0;
        }

        // [步骤 2] 读取目标端口 (Port)
        // 偏移量 +2 (跳过 family)
        // 读取 2 个字节 (u16)，注意这里是大端序 (Big Endian)
        let _ = r#gen::bpf_probe_read_user(
            &mut dport as *mut _ as *mut _,
            2,
            (addr_ptr + 2) as *const _,
        );

        // [步骤 3] 读取目标 IP (Addr)
        // 偏移量 +4 (跳过 family 和 port)
        // 读取 4 个字节 (u32)，即 IPv4 地址
        let _ = r#gen::bpf_probe_read_user(
            &mut daddr as *mut _ as *mut _,
            4,
            (addr_ptr + 4) as *const _,
        );
    }

    let event = TcpEvent {
        pid,
        fd: fd as u32,
        cgroup_id,
        // [关键点] 为什么 source ip 是 0？
        // 因为这是 connect 的入口点，内核还未进行路由选择和源地址绑定。
        // 我们需要下面的 tcp_connect kprobe 来补充这个字段。
        saddr: 0,
        daddr,
        sport: 0, // 源端口同理，稍后通过 kprobe 获取
        dport,
        family: 2,
        direction: 0, // 0 = CONNECT 事件 (用于在用户态建立 FD 映射)
        data_len: 0,
        payload: [0; 128],
    };
    TCP_EVENTS.output(&ctx, &event, 0);
    0
}

// 挂载点: kprobe/tcp_connect
// 触发时机: 三次握手发送 SYN 包之前。此时内核已完成路由选择，分配了 Source IP/Port。
// 作用: 补全 Source IP 信息。
#[kprobe]
pub fn masdeepflow_tcp_connect_detailed(ctx: ProbeContext) -> u32 {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // tcp_connect(struct sock *sk)
    let sk: *mut u8 = ctx.arg(0).unwrap_or(core::ptr::null_mut());

    // offsets based on common kernel structs (check your kernel version if failing)
    // struct sock_common {
    //   ...
    //   __be32 skc_daddr; // offset 0 (union) - sometimes?
    //   __be32 skc_rcv_saddr; // offset 4 (union)
    // }
    // NOTE: Offsets vary by kernel. Using the ones that worked for `tcp_v4_connect` logic previously?
    // In `tcp_v4_connect`, saddr was at offset 4.

    let saddr: u32 = unsafe {
        let mut val = 0u32;
        let _ =
            r#gen::bpf_probe_read_kernel(&mut val as *mut _ as *mut _, 4, sk.add(4) as *const _);
        val
    };

    let sport: u16 = unsafe {
        let mut val = 0u16;
        let _ =
            r#gen::bpf_probe_read_kernel(&mut val as *mut _ as *mut _, 2, sk.add(14) as *const _);
        val
    };

    // Note: accessing daddr from sk directly here
    // In many kernels skc_daddr is at offset 0 for struct sock_common?
    // Let's rely on `tcp_v4_connect` behavior usually having daddr in external struct.
    // But here we only have `sk`.
    // Let's assume standard layout:
    // skc_daddr is often at offset 0 inside checking logic?
    // Let's try reading offset 0 for daddr.
    let daddr: u32 = unsafe {
        let mut val = 0u32;
        // struct sock { struct sock_common ... }
        // struct sock_common { union { ... skc_daddr } ... } -> offset 0 usually?
        // CAUTION: If this is wrong, daddr might be garbage.
        // But userspace has daddr from tracepoint. We primarily need saddr.
        let _ = r#gen::bpf_probe_read_kernel(&mut val as *mut _ as *mut _, 4, sk as *const _);
        val
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let event = TcpEvent {
        pid,
        fd: 0, // Unknown in kprobe
        cgroup_id,
        saddr,
        daddr,
        sport,
        dport: 0, // We have dport from tracepoint
        family: 2,
        direction: 4, // 4 = IP_INFO (Supplement)
        data_len: 0,
        payload: [0; 128],
    };
    TCP_EVENTS.output(&ctx, &event, 0);
    0
}

// 挂载点: kretprobe/inet_csk_accept
// 触发时机: 服务端成功 Accept 一个连接后返回时
#[kretprobe]
pub fn masdeepflow_tcp_accept(ctx: RetProbeContext) -> u32 {
    let ret: *mut u8 = ctx.ret().unwrap_or(core::ptr::null_mut());

    if !ret.is_null() {
        let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        // ret 即为 struct sock *newsk
        let sk = ret;

        let daddr: u32 = unsafe {
            let mut val = 0u32;
            let _ = r#gen::bpf_probe_read_kernel(
                &mut val as *mut _ as *mut _,
                4,
                sk.add(0) as *const _,
            );
            val
        };

        let saddr: u32 = unsafe {
            let mut val = 0u32;
            let _ = r#gen::bpf_probe_read_kernel(
                &mut val as *mut _ as *mut _,
                4,
                sk.add(4) as *const _,
            );
            val
        };

        let dport: u16 = unsafe {
            let mut val = 0u16;
            let _ = r#gen::bpf_probe_read_kernel(
                &mut val as *mut _ as *mut _,
                2,
                sk.add(12) as *const _,
            );
            val
        };

        // Accept 时作为服务端，源端口是 Local Port (skc_num)
        let sport: u16 = unsafe {
            let mut val = 0u16;
            let _ = r#gen::bpf_probe_read_kernel(
                &mut val as *mut _ as *mut _,
                2,
                sk.add(14) as *const _,
            );
            val
        };

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = TcpEvent {
            pid,
            fd: 0, // Not applicable for accept kretprobe
            cgroup_id,
            saddr,
            daddr,
            sport,
            dport,
            family: 2,
            direction: 1, // Accept
            data_len: 0,
            payload: [0; 128],
        };
        TCP_EVENTS.output(&ctx, &event, 0);
    }
    0
}

// --- 模块三：L7 应用层监控 (L7/HTTP Observability) ---

// 挂载点: tracepoint:syscalls/sys_enter_write
// 触发时机: 进程调用 write 系统调用写入数据时
// 相比 kprobe/tcp_sendmsg，拦截系统调用更容易直接读取用户态 buffer
#[tracepoint]
pub fn masdeepflow_write(ctx: TracePointContext) -> u32 {
    let _pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // 4. [Critical Fix] 防止自回环 (Self-Tracing Loop)
    // 既然我们还在把 Log 写到 stdout，那必须过滤掉 Agent 自己的写入行为，否则会死锁
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if is_infra_process(&comm) {
        return 0;
    }

    // [Critical Fix] Prevent Self-Tracing via PID
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { FILTER_PID.get(&tgid).is_some() } {
        return 0;
    }

    // sys_enter_write 参数: (int fd, const char *buf, size_t count)
    // Offset分析 (x86_64):
    // 0: common_fields (8 bytes)
    // 8: syscall_nr (8 bytes)
    // 16: fd (8 bytes)
    // 24: buf (8 bytes) -> 数据指针
    // 32: count (8 bytes) -> 数据长度

    // [Critical Fix] Filter Stdout/Stderr (FD 0, 1, 2)
    let fd: u64 = unsafe { ctx.read_at::<u64>(16).unwrap_or(0) };
    if fd <= 2 {
        return 0;
    }

    // 1. 获取 buffer 指针 (源数据地址)
    let buf_ptr: *const u8 = unsafe { ctx.read_at::<u64>(24).unwrap_or(0) as *const u8 };

    // 2. 获取数据长度
    let count: u64 = unsafe { ctx.read_at::<u64>(32).unwrap_or(0) };

    // 3. 读取用户态数据 (Payload Capture)
    let mut payload = [0u8; 128];
    // 只读取 min(count, 128)
    let read_len = if count > 128 { 128 } else { count as usize };

    // 使用 helper 从用户空间读取数据
    if read_len > 0 {
        unsafe {
            let _ = r#gen::bpf_probe_read_user(
                payload.as_mut_ptr() as *mut _,
                read_len as u32,
                buf_ptr as *const _,
            );
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let event = TcpEvent {
        pid,
        fd: fd as u32,
        cgroup_id,
        saddr: 0,
        daddr: 0,
        sport: 0,
        dport: 0,
        family: 2,
        direction: 2, // 2 = TX (Outgoing/Write)
        data_len: count as u32,
        payload,
    };
    TCP_EVENTS.output(&ctx, &event, 0);
    0
}

// 挂载点: tracepoint:syscalls/sys_enter_sendto
// 触发时机: 进程调用 sendto 系统调用发送数据时
#[tracepoint]
pub fn masdeepflow_sendto(ctx: TracePointContext) -> u32 {
    let _pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Self-Tracing Loop Protection
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if is_infra_process(&comm) {
        return 0;
    }

    // Self-Tracing Loop Protection (PID)
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { FILTER_PID.get(&tgid).is_some() } {
        return 0;
    }

    // sys_enter_sendto 参数: (int fd, void *buff, size_t len, unsigned int flags, ...)
    // 前三个参数布局与 write 一致
    // 16: fd
    // 24: buff
    // 32: len

    // [Critical Fix] Filter Stdout/Stderr (FD 0, 1, 2)
    // Same as write, fd is at offset 16
    let fd: u64 = unsafe { ctx.read_at::<u64>(16).unwrap_or(0) };
    if fd <= 2 {
        return 0;
    }

    let buf_ptr: *const u8 = unsafe { ctx.read_at::<u64>(24).unwrap_or(0) as *const u8 };
    let count: u64 = unsafe { ctx.read_at::<u64>(32).unwrap_or(0) };

    let mut payload = [0u8; 128];
    let read_len = if count > 128 { 128 } else { count as usize };

    if read_len > 0 {
        unsafe {
            let _ = r#gen::bpf_probe_read_user(
                payload.as_mut_ptr() as *mut _,
                read_len as u32,
                buf_ptr as *const _,
            );
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let event = TcpEvent {
        pid,
        fd: fd as u32,
        cgroup_id,
        saddr: 0,
        daddr: 0,
        sport: 0,
        dport: 0,
        family: 2,
        direction: 2, // 2 = TX (Outgoing/Write) - Corrected from 3
        data_len: count as u32,
        payload,
    };
    TCP_EVENTS.output(&ctx, &event, 0);
    0
}

// --- 模块四：接收数据监控 (Read/Recvfrom) ---
// [难点] read/recvfrom 的数据是在系统调用返回时才填充的
// 所以我们需要 "Enter" 探针记录参数(Buf地址)，"Exit" 探针记录返回值(读取长度)并行读取内容

// 辅助 Map: 暂时存储 Enter 阶段的参数
#[map]
static READ_ARGS: aya_ebpf::maps::HashMap<u32, ReadInfo> =
    aya_ebpf::maps::HashMap::with_max_entries(1024, 0);

// 挂载点: tracepoint:syscalls/sys_enter_read
// 触发时机: 调用 read 读取数据之前
// 作用: 抢先记录 buffer 指针地址，因为 Exit 阶段拿不到这个指针了
#[tracepoint]
pub fn masdeepflow_read_enter(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // 自监控过滤 (Comm)
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if is_infra_process(&comm) {
        return 0;
    }

    // 自监控过滤 (PID)
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { FILTER_PID.get(&tgid).is_some() } {
        return 0;
    }

    // sys_enter_read(fd, buf, count)
    // 16: fd
    // 24: buf (指针)
    let fd: u64 = unsafe { ctx.read_at::<u64>(16).unwrap_or(0) };
    if fd <= 2 {
        return 0;
    }
    let buf_ptr: u64 = unsafe { ctx.read_at::<u64>(24).unwrap_or(0) };

    if buf_ptr != 0 {
        let info = ReadInfo {
            buf_ptr,
            fd: fd as u32,
        };
        // 存入 Map，Key 是 PID。这假设同一线程的 enter/exit 是原子或顺序的
        let _ = READ_ARGS.insert(&pid, &info, 0);
    }
    0
}

// 挂载点: tracepoint:syscalls/sys_exit_read
// 触发时机: read 调用完成之后
// 作用: 此时 Kernel 已经把数据写到 buffer 里了，且我们知道了实际读取的字节数 (ret)
#[tracepoint]
pub fn masdeepflow_read_exit(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // 1. 取出 Enter 阶段存的上下文 (Buffer 地址)
    let info = match unsafe { READ_ARGS.get(&pid) } {
        Some(ptr) => *ptr,
        None => return 0,
    };
    // 用完即焚，保证 Map 不泄露
    let _ = READ_ARGS.remove(&pid);

    let fd = info.fd;
    let buf_ptr = info.buf_ptr;

    // sys_exit_read -> ret (返回值，即读取到的字节数) @ offset 16
    let ret: i64 = unsafe { ctx.read_at::<i64>(16).unwrap_or(0) };

    // 读取失败或无数据则忽略
    if ret <= 0 {
        return 0;
    }

    let count = ret as u64;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // 2. 读取 buffer 内容 (Payload Capture)
    let mut payload = [0u8; 128];
    let read_len = if count > 128 { 128 } else { count as usize };

    if read_len > 0 {
        unsafe {
            let _ = r#gen::bpf_probe_read_user(
                payload.as_mut_ptr() as *mut _,
                read_len as u32,
                buf_ptr as *const _,
            );
        }
    }

    let event = TcpEvent {
        pid,
        fd,
        cgroup_id,
        saddr: 0,
        daddr: 0,
        sport: 0,
        dport: 0,
        family: 2,
        direction: 3, // 3 = RX (Incoming/Read) - 用户态会看到这个
        data_len: count as u32,
        payload,
    };
    TCP_EVENTS.output(&ctx, &event, 0);
    0
}

// [补充支持] masdeepflow_recvfrom_enter
// 很多应用 (如 DNS, 部分 HTTP 库) 使用 recvfrom 而不是 read
// 逻辑同上: Enter 存指针，Exit 读数据
#[tracepoint]
pub fn masdeepflow_recvfrom_enter(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    // Self-Tracing Check (Comm)
    if is_infra_process(&comm) {
        return 0;
    }

    // Self-Tracing Check (PID)
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { FILTER_PID.get(&tgid).is_some() } {
        return 0;
    }

    // sys_enter_recvfrom(int fd, void *ubuf, size_t size, ...)
    // 16: fd
    // 24: ubuf (指针)
    let fd: u64 = unsafe { ctx.read_at::<u64>(16).unwrap_or(0) };
    let buf_ptr: u64 = unsafe { ctx.read_at::<u64>(24).unwrap_or(0) };
    if buf_ptr != 0 {
        let info = ReadInfo {
            buf_ptr,
            fd: fd as u32,
        };
        let _ = READ_ARGS.insert(&pid, &info, 0);
    }
    0
}

// [补充支持] masdeepflow_recvfrom_exit
#[tracepoint]
pub fn masdeepflow_recvfrom_exit(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let info = match unsafe { READ_ARGS.get(&pid) } {
        Some(ptr) => *ptr,
        None => return 0,
    };
    let _ = READ_ARGS.remove(&pid);
    let buf_ptr = info.buf_ptr;
    let fd = info.fd;

    let ret: i64 = unsafe { ctx.read_at::<i64>(16).unwrap_or(0) };
    if ret <= 0 {
        return 0;
    }

    let count = ret as u64;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let mut payload = [0u8; 128];
    let read_len = if count > 128 { 128 } else { count as usize };

    if read_len > 0 {
        unsafe {
            let _ = r#gen::bpf_probe_read_user(
                payload.as_mut_ptr() as *mut _,
                read_len as u32,
                buf_ptr as *const _,
            );
        }
    }

    let event = TcpEvent {
        pid,
        fd,
        cgroup_id,
        saddr: 0,
        daddr: 0,
        sport: 0,
        dport: 0,
        family: 2,
        direction: 3, // 3 = RX (Incoming/Read)
        data_len: count as u32,
        payload,
    };
    TCP_EVENTS.output(&ctx, &event, 0);
    0
}

// =========================================================================================
// Phase 8: High Performance Gateway (Socket Acceleration / L7 Splicing)
// =========================================================================================
// 原理: Socket Splicing (短路/拼接)
// 传统路径: Box A App -> Socket -> TCP Stack -> IP -> vEth -> Bridge -> vEth -> IP -> TCP Stack -> Socket -> Box B App
// 加速路径: Box A App -> Socket -> [eBPF Redirect] -> Socket -> Box B App
// 收益:
// 1. 绕过 TCP/IP 协议栈的大部分处理 (Slow Path)。
// 2. 减少 CPU 上下文切换和内存拷贝。
// 3. 实现 Localhost 级别的通信延迟 (Microseconds)。

#[sock_ops]
pub fn handle_sock_ops(ctx: SockOpsContext) -> u32 {
    let ops = ctx.ops;
    let op = unsafe { (*ops).op };

    // [入口过滤]
    // 我们只关注连接建立完成的时刻。
    // BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB (0): 服务端收到 SYN+ACK，连接变为 ESTABLISHED。
    // BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB (1): 客户端收到 ACK，连接变为 ESTABLISHED。
    if op != 0 && op != 1 {
        return 0;
    }

    // AF_INET = 2 (仅处理 IPv4)
    let family = unsafe { (*ops).family };
    if family != 2 {
        return 0;
    }

    // [提取四元组]
    // 注意: eBPF 中的 IP 是网络字节序 (Big Endian)，Port 也是。
    // 但 (*ops).local_port 在某些内核版本/上下文中可能是 Host Endian。
    // 这里我们假设 local_port 是 Host Endian (aya/kernel 惯例对于 sock_ops 字段)，
    // 而 remote_port 是 Network Endian。
    let remote_ip4 = unsafe { (*ops).remote_ip4 };
    let local_ip4 = unsafe { (*ops).local_ip4 };
    let local_port = unsafe { (*ops).local_port };
    let remote_port = unsafe { (*ops).remote_port };

    // [关键: 字节序归一化]
    // 为了作为 Map 的 Key，必须保证 Key 的格式统一。
    // 我们约定 Map Key 中的 Port 全部使用 Host Endian (大端转小端，如果在 x86 上)。
    // local_port 已经是 Host Endian (sock_ops 特性)。
    // remote_port 是 Network Endian，需要转换。
    let remote_port_host = u32::from_be(remote_port);

    let key = SockKey {
        sip: local_ip4,
        dip: remote_ip4,
        sport: local_port,
        dport: remote_port_host,
    };

    // [注册 Socket]
    // 将当前 Socket (ctx) 放入 SockHash Map。
    // 这样，当另一个 Socket (对端) 想要发送数据给这个四元组时，
    // 就可以通过 lookup 这个 Map 找到当前 Socket 的句柄，直接 Redirect。
    unsafe {
        let _ = bpf_sock_hash_update(
            ops as *mut _,
            &INTERCEPT_MAP as *const _ as *mut _,
            &key as *const _ as *mut _,
            0, // BPF_ANY (覆盖更新)
        );
    }

    0
}

#[sk_msg]
pub fn redirect_traffic(ctx: SkMsgContext) -> u32 {
    let msg = ctx.msg;

    // AF_INET = 2
    let family = unsafe { (*msg).family };
    if family != 2 {
        return 1; // SK_PASS = 1 (放行，走标准协议栈)
    }

    let remote_ip4 = unsafe { (*msg).remote_ip4 };
    let local_ip4 = unsafe { (*msg).local_ip4 };
    let local_port = unsafe { (*msg).local_port };
    let remote_port = unsafe { (*msg).remote_port };

    // [归一化]
    let remote_port_host = u32::from_be(remote_port);

    // [构造反向查询 Key]
    // 场景: Socket A (Local) 发送给 Socket B (Remote)。
    // 我们想把数据直接 Redirect 给 Socket B。
    // Socket B 在 Map 中注册的 Key 是什么？
    // B 注册时: SIP=B_IP, DIP=A_IP, SPort=B_Port, DPort=A_Port.
    // 我们 (A) 持有的信息: Local=A_IP, Remote=B_IP, LocP=A_Port, RemP=B_Port.
    // 所以，我们要查找的 Key 应该是 (Remote, Local, RemP, LocP)。

    let key = SockKey {
        sip: remote_ip4,         // 对应 B 的 SIP
        dip: local_ip4,          // 对应 B 的 DIP
        sport: remote_port_host, // 对应 B 的 SPort
        dport: local_port,       // 对应 B 的 DPort
    };

    unsafe {
        // [核心加速动作: Redirect]
        // bpf_msg_redirect_hash: 尝试在 Map 中找到 Key 对应的 Socket。
        // 如果找到: 将数据直接注入该 Socket 的接收队列 (Ingress Queue)。
        // flag 1 = BPF_F_INGRESS (注入接收方向，让应用层就像读到了网络数据一样)
        // 返回值:
        //   SK_PASS (1): 没找到 (Redirect 失败)，回退走标准协议栈。
        //   其他: Redirect 成功，数据被“偷”走了，内核协议栈不会再处理它。
        let _ = bpf_msg_redirect_hash(
            msg as *mut _,
            &INTERCEPT_MAP as *const _ as *mut _,
            &key as *const _ as *mut _,
            1,
        );
    }

    1 // SK_PASS = 1 (总是返回 Pass，如果 Redirect 成功，这个 Pass 会被 Redirect 覆盖/接管)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
