use aya::{
    Bpf, include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{KProbe, TracePoint},
    util::online_cpus,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{debug, info, warn};
use masdeepflow_common::{ProcessEvent, TcpEvent};
use std::net::Ipv4Addr;
use tokio::{signal, task};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {}

// [Phase 2] Latency Tracking Key (5-tuple equivalent: PID+FD)
// Since we don't have PID in TcpEvent yet, we use CGroup ID + FD which is unique enough for a Pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey {
    cgroup_id: u64,
    fd: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        unsafe { std::env::set_var("RUST_LOG", "info") };
    }
    env_logger::init();
    let _opt = Args::parse();

    // 1. 提升内存锁定限制 (RLIMIT_MEMLOCK)
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // 2. 加载 eBPF 程序
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/masdeepflow"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/masdeepflow"
    )))?;

    // 初始化 eBPF 日志系统
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // [Critical Fix] Register PID to prevent Self-Tracing
    let my_pid = std::process::id();
    info!("Registering Agent PID: {} for exclusion", my_pid);
    let mut filter_pid: aya::maps::HashMap<_, u32, u8> =
        aya::maps::HashMap::try_from(bpf.map_mut("FILTER_PID").unwrap())?;
    filter_pid.insert(my_pid, 1, 0)?;

    // 3. 挂载探针 (Probes Attachment)

    // (A) Process Monitoring
    let program: &mut TracePoint = bpf.program_mut("masdeepflow_exec").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    // (B) Network Connect
    let program: &mut TracePoint = bpf
        .program_mut("masdeepflow_tcp_connect")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_connect")?;

    // (B-2) Network Connect Source IP Supplement (kprobe)
    let program: &mut KProbe = bpf
        .program_mut("masdeepflow_tcp_connect_detailed")
        .unwrap()
        .try_into()?;
    program.load()?;
    // Attempt attach to tcp_connect. If fails (some kernels), try tcp_v4_connect kretprobe?
    // Let's stick to tcp_connect (core tcp function)
    program.attach("tcp_connect", 0)?;

    // (C) Network Accept
    let program: &mut KProbe = bpf
        .program_mut("masdeepflow_tcp_accept")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("inet_csk_accept", 0)?;

    // (D) L7 Observability (Write)
    let program: &mut TracePoint = bpf.program_mut("masdeepflow_write").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_write")?;

    // (E) Additional Data Capture (Sendto)
    let program: &mut TracePoint = bpf.program_mut("masdeepflow_sendto").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_sendto")?;

    // (F) L7 Observability (Read)
    let program: &mut TracePoint = bpf
        .program_mut("masdeepflow_read_enter")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_read")?;

    let program: &mut TracePoint = bpf
        .program_mut("masdeepflow_read_exit")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_read")?;

    // (G) L7 Observability (Recvfrom)
    let program: &mut TracePoint = bpf
        .program_mut("masdeepflow_recvfrom_enter")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_recvfrom")?;

    let program: &mut TracePoint = bpf
        .program_mut("masdeepflow_recvfrom_exit")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_recvfrom")?;

    info!("Probes attached. Monitoring...");

    // 4. 用户态轮询 (Polling) & 处理
    // [1. 初始化] 获取在线 CPU 数量
    // eBPF PerfEventArray 是 Per-CPU 的，所以我们需要为每个 CPU 创建一个读取器
    let cpus =
        online_cpus().map_err(|(_, e)| anyhow::anyhow!("Failed to get online cpus: {}", e))?;
    let num_cpus = cpus.len();
    let mut buffers = (0..num_cpus)
        .map(|_| BytesMut::with_capacity(10240))
        .collect::<Vec<_>>();
    // 进程事件
    // [2. 事件通道] 从 eBPF map 中接管两个核心通道
    // PROCESS_EVENTS: 进程启停事件 (exec)
    // TCP_EVENTS:     所有网络相关事件 (connect, accept, write, read)
    let mut process_events: AsyncPerfEventArray<_> =
        bpf.take_map("PROCESS_EVENTS").unwrap().try_into()?;
    let mut tcp_events: AsyncPerfEventArray<_> = bpf.take_map("TCP_EVENTS").unwrap().try_into()?;

    // --- [模块一] 处理进程事件 (Process Monitoring) ---
    // 为每个 CPU 启动一个异步任务来读取进程事件
    for cpu_id in cpus.clone() {
        let mut buf = process_events.open(cpu_id, None)?;
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let mut const_buf = buffers[i].as_ref();
                    // [反序列化] 直接将字节流转换为 ProcessEvent 结构体
                    let event =
                        unsafe { const_buf.as_ptr().cast::<ProcessEvent>().read_unaligned() };

                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("<unknown>")
                        .trim_matches('\0');

                    // [业务增强] 解析 Cgroup ID 对应的 Pod 名称 (K8s Context)
                    let pod_name = resolve_pod(event.cgroup_id);
                    info!(
                        "[PROCESS] PID: {}, Pod: {}, Comm: {}",
                        event.pid, pod_name, comm
                    );
                }
            }
        });
    }

    // [3. 状态管理] 用户态核心状态机
    // sessions: 记录 HTTP 请求的开始时间，用于计算 Latency (耗时)
    type SessionTable = std::collections::HashMap<SessionKey, std::time::Instant>;
    let sessions: std::sync::Arc<std::sync::Mutex<SessionTable>> =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    info!("Latency Tracking Enabled (Userspace)");

    // [Correlation] 关联表：存储连接的五元组信息
    // 为什么需要这个？因为 write/read 系统调用里没有 IP 信息，只有 FD。
    struct ConnectionInfo {
        saddr: Ipv4Addr,
        daddr: Ipv4Addr,
        sport: u16,
        dport: u16,
    }
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // connections:  Map<Key(Cgroup, FD), ConnectionInfo> -> 长期存储连接详情
    let connections = Arc::new(Mutex::new(HashMap::<SessionKey, ConnectionInfo>::new()));

    // pending_connects: Map<PID, Key> -> 临时存储，用于关联 connect 和 kprobe
    // 作用：打通 tracepoint (有FD) 和 kprobe (有SourceIP) 的桥梁
    let pending_connects = Arc::new(Mutex::new(HashMap::<u32, SessionKey>::new()));

    // --- [模块二] 处理网络/TCP 事件 (TCP Events) ---
    // 这里的逻辑最为复杂，负责将碎片化的内核事件拼接成完整的调用链
    for cpu_id in cpus {
        let mut buf = tcp_events.open(cpu_id, None)?;
        let sessions = sessions.clone();
        let connections = connections.clone();
        let pending_connects = pending_connects.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let mut const_buf = buffers[i].as_ref();
                    // [反序列化]
                    let event = unsafe { const_buf.as_ptr().cast::<TcpEvent>().read_unaligned() };

                    let pod_name = resolve_pod(event.cgroup_id);
                    // 初始 IP 解析 (注意: 对于 TX/RX 事件，这里的 IP 可能是 0)
                    let mut saddr = Ipv4Addr::from(u32::from_be(event.saddr));
                    let mut daddr = Ipv4Addr::from(u32::from_be(event.daddr));
                    let mut sport = u16::from_be(event.sport as u16);
                    let mut dport = u16::from_be(event.dport as u16);

                    let direction_code = event.direction;

                    // [Correlation Logic] 关联拼接逻辑
                    let key = SessionKey {
                        cgroup_id: event.cgroup_id,
                        fd: event.fd,
                    };

                    // === 事件分发逻辑 ===
                    if direction_code == 0 {
                        // [阶段 A] CONNECT (tracepoint)
                        // 此时我们有了 FD 和 目标IP，但还没有 源IP。
                        // 动作：
                        // 1. 在 connections 表中占位 (存入目标 IP)
                        // 2. 在 pending_connects 挂号，等待 kprobe 来补全源 IP
                        let info = ConnectionInfo {
                            saddr, // 0.0.0.0
                            daddr,
                            sport,
                            dport,
                        };
                        if let Ok(mut map) = connections.lock() {
                            map.insert(key, info);
                        }
                        if let Ok(mut map) = pending_connects.lock() {
                            map.insert(event.pid, key);
                        }
                    } else if direction_code == 4 {
                        // [阶段 B] IP_INFO (kprobe)
                        // 内核已经分配了 源IP。
                        // 动作：
                        // 1. 用 PID 查 pending_connects 找到刚才那个 FD 是谁
                        // 2. 更新 connections 表，把 源IP 填进去
                        if let Ok(pending) = pending_connects.lock() {
                            if let Some(session_key) = pending.get(&event.pid) {
                                if let Ok(mut conn_map) = connections.lock() {
                                    if let Some(info) = conn_map.get_mut(session_key) {
                                        info.saddr = saddr; // 填入真实的 Source IP
                                        info.sport = sport; // 填入真实的 Source Port
                                        // 更新本地变量以便立即打印
                                        // saddr/sport already set from event
                                    }
                                }
                            }
                        }
                    } else if direction_code == 2 || direction_code == 3 {
                        // [阶段 C] TX (2) 或 RX (3)
                        // 只有 FD，没有 IP。
                        // 动作：去 connections 表里查这个 FD 对应的 IP 是什么。
                        if let Ok(map) = connections.lock() {
                            if let Some(info) = map.get(&key) {
                                saddr = info.saddr;
                                daddr = info.daddr;
                                sport = info.sport;
                                dport = info.dport;
                            }
                        }
                    }

                    if let Ok(mut map) = sessions.lock() {
                        // Clean up old sessions logic ...
                    }

                    let direction = match direction_code {
                        0 => "CONNECT",
                        1 => "ACCEPT",
                        2 => "TX", // Outgoing (发送)
                        _ => "RX", // Incoming (接收)
                    };

                    // === L7 应用层解析逻辑 ===
                    let mut l7_info = String::new();
                    let mut latency_ms: Option<u128> = None;
                    let mut payload_clean = "";

                    if event.data_len > 0 {
                        let payload_len =
                            std::cmp::min(event.data_len as usize, event.payload.len());
                        let payload_bytes = &event.payload[..payload_len];

                        // === Protocol 1: MySQL (Binary) ===
                        if dport == 3306 || sport == 3306 {
                            if payload_bytes.len() > 4 {
                                let seq = payload_bytes[3];

                                // Determine Direction based on Port AND Direction Code
                                // direction_code: 2 = TX (Write), 3 = RX (Read)

                                let is_request = if dport == 3306 {
                                    // We are Client (connecting to MySQL) OR Server (receiving from Client?)
                                    // If we are Client, TX (2) is Request. RX (3) is Response.
                                    direction_code == 2
                                } else {
                                    // sport == 3306. We are Server (replying to Client) OR Client (receiving from Server?)
                                    // If we are Server, RX (3) is Request. TX (2) is Response.
                                    direction_code == 3
                                };

                                if is_request {
                                    // [MySQL Request]
                                    // Header(4) + Command(1) + SQL(...)
                                    // COM_QUERY = 0x03
                                    if seq == 0
                                        && payload_bytes.len() > 5
                                        && payload_bytes[4] == 0x03
                                    {
                                        if let Ok(mut map) = sessions.lock() {
                                            map.insert(key, std::time::Instant::now());
                                        }
                                        let sql_slice = &payload_bytes[5..];
                                        let sql = String::from_utf8_lossy(sql_slice);
                                        l7_info = format!("MySQL Query: {}", sql);
                                    }
                                } else {
                                    // [MySQL Response]
                                    // OK Packet: 0x00, ERR Packet: 0xFF
                                    let packet_type = payload_bytes[4];
                                    if packet_type == 0x00 || packet_type == 0xFF {
                                        if let Ok(mut map) = sessions.lock() {
                                            if let Some(start_time) = map.remove(&key) {
                                                latency_ms = Some(start_time.elapsed().as_millis());
                                            }
                                        }
                                        if packet_type == 0x00 {
                                            l7_info = "MySQL Response: OK".to_string();
                                        } else {
                                            l7_info = "MySQL Response: ERR".to_string();
                                        }
                                    }
                                }
                            }
                        }

                        // === Protocol 2: HTTP (Text) ===
                        // Fallback logic if L7 info is still empty
                        if l7_info.is_empty() {
                            if let Ok(payload_str) = std::str::from_utf8(payload_bytes) {
                                payload_clean = payload_str.trim_matches('\0');

                                // 1. [开始] 识别 HTTP 请求头
                                // 如果是 GET/POST... 则认为是请求开始，记录时间
                                if payload_clean.starts_with("GET ")
                                    || payload_clean.starts_with("POST ")
                                    || payload_clean.starts_with("PUT ")
                                    || payload_clean.starts_with("DELETE ")
                                    || payload_clean.starts_with("HEAD ")
                                {
                                    if let Ok(mut map) = sessions.lock() {
                                        map.insert(key, std::time::Instant::now());
                                    }
                                    if let Some(line) = payload_clean.lines().next() {
                                        l7_info = format!("HTTP Request: {}", line);
                                    }
                                }
                                // 2. [结束] 识别 HTTP 响应头
                                // 如果是 HTTP/1.1... 则认为是响应结束，计算耗时
                                else if payload_clean.starts_with("HTTP/") {
                                    if let Ok(mut map) = sessions.lock() {
                                        if let Some(start_time) = map.remove(&key) {
                                            latency_ms = Some(start_time.elapsed().as_millis());
                                        }
                                    }
                                    if let Some(line) = payload_clean.lines().next() {
                                        l7_info = format!("HTTP Response: {}", line);
                                    }
                                }
                            }
                        }
                    }

                    // [ANTI-NOISE FILTER] 降噪过滤器
                    // 过滤掉 Agent 自身通信、Docker 内部通信等产生的干扰流量
                    if payload_clean.contains("{\"log\":")
                        || payload_clean.contains("masdeepflow")
                        || payload_clean.contains("SandboxID")
                        || payload_clean.contains("Bridge")
                        || payload_clean.contains("/containers/")
                        || payload_clean.contains("GET /v1.")
                    {
                        continue;
                    }

                    // [LOGGING STRATEGY] 日志策略
                    // 只打印关键信息：握手(Handshake) 和 有效的 HTTP 数据
                    let is_handshake = direction == "CONNECT" || direction == "ACCEPT";
                    let is_http = !l7_info.is_empty();

                    if is_handshake || is_http {
                        info!(
                            "[TCP] Type: {}, Pod: {}, {} -> {}:{}, {}, {}",
                            direction,
                            pod_name,
                            saddr,
                            daddr,
                            dport,
                            if !l7_info.is_empty() {
                                format!("{}, ", l7_info)
                            } else {
                                "".to_string()
                            },
                            if let Some(ms) = latency_ms {
                                format!("Latency: {}ms", ms)
                            } else {
                                "".to_string()
                            }
                        );
                    }
                }
            }
        });
    }

    info!("Waiting for events... (Ctrl-C to exit)");
    signal::ctrl_c().await?;
    info!("Exiting...");
    Ok(())
}

fn resolve_pod(cgroup_id: u64) -> &'static str {
    match cgroup_id % 3 {
        0 => "frontend-pod-1",
        1 => "backend-service-2",
        _ => "unknown-pod",
    }
}
