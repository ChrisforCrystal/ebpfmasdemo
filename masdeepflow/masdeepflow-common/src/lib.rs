#![no_std]

// 使用 #[repr(C)] 确保内存布局与 C 语言结构体一致
// 这是 eBPF 内核态与用户态进行二进制数据交换的基础
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub pid: u32,       // 进程 ID
    pub cgroup_id: u64, // Cgroup ID，用于关联 K8s Pod (如: /kubepods/burstable/pod-uuid)
    pub comm: [u8; 16], // 进程命令名称 (最多 16 字节，如 "nginx", "curl")
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpEvent {
    pub pid: u32,           // Process ID for correlation
    pub fd: u32,            // Socket File Descriptor (syscall correlation)
    pub cgroup_id: u64,     // 关联的 Pod Cgroup ID
    pub saddr: u32,         // 源 IPv4 地址 (大端序)
    pub daddr: u32,         // 目的 IPv4 地址 (大端序)
    pub sport: u16,         // 源端口
    pub dport: u16,         // 目的端口
    pub family: u16,        // 协议族 (AF_INET = 2)
    pub direction: u8,      // 数据流向: 0=Connect(出向), 1=Accept(入向), 3=Data(数据传输)
    pub data_len: u32,      // 数据包载荷长度 (仅在 Data 事件有效)
    pub payload: [u8; 128], // L7 应用层数据前缀 (用于解析 HTTP 方法和 URL)
}

// 只有在用户态 (feature = "user") 编译时，才实现 aya::Pod trait
// 这使得 aya 能够安全地从字节数组中转换出结构体
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpEvent {}
