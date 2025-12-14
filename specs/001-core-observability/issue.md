# 技术问题记录 (Issue Log)

## 问题 1: Aya 0.13 API 兼容性问题 (SockOps)

**状态**: 已解决 ✅
**影响**: 高 (无法激活加速功能)

### 问题描述
在用户态加载器中实现 `SockOps` (Socket Operator) 程序挂载时，遇到了 `attach` 方法签名的编译错误。
- 初始错误: `cannot find value SockOpsAttachType`。
- 二次错误: `expected 2 arguments, found 1` (尝试盲目移除参数时)。
- 三次错误: `mismatched types` (尝试直接将 `SockHash` 传给 `SkMsg` 挂载时)。

### 根因分析
我们使用的 `aya` crate (版本 0.13) 相比旧版文档/示例代码发生了 API 变更。
1.  **挂载模式类型变更**: `SockOps` 的挂载类型枚举现在位于 `aya::programs::links::CgroupAttachMode`，而不是 `aya::programs::sock_ops::SockOpsAttachType`。
2.  **Attach 签名变更**: `SockOps::attach` 依然需要两个参数：cgroup 文件描述符 和 `CgroupAttachMode`。
3.  **SkMsg 挂载变更**: `SkMsg::attach` 期望接收一个 `SockMapFd` (原始文件描述符包装)，而不是高层的 `SockHash` 对象。

### 解决方案
1.  **修正引用**:
    ```rust
    use aya::programs::links::CgroupAttachMode;
    ```
2.  **修正 SockOps 调用**:
    ```rust
    program.attach(cgroup_file, CgroupAttachMode::Single)?;
    ```
3.  **修正 SkMsg 调用**:
    需要从 Map 对象中提取 FD 并 clone (以处理所有权借用问题)：
    ```rust
    let map_fd = intercept_map.fd().try_clone()?;
    program.attach(&map_fd)?;
    ```

---

## 问题 2: Libc 缺失 `CLOCK_BOOTTIME` 定义

**状态**: 已解决 ✅
**影响**: 高 (Docker 内构建失败)

### 问题描述
代码在 macOS 本地检查时只有警告，但在 Docker (Linux) 容器内构建时报错：
`cannot find value CLOCK_BOOTTIME in crate libc` (报错源自 `aya` 源码)。

### 根因分析
`Cargo.toml` 中的依赖配置过于激进，禁用了 `libc` 的默认特性：
```toml
libc = { version = "0.2", default-features = false }
```
这导致在 Linux 目标平台编译时，一些必要的操作系统常量（如 `CLOCK_BOOTTIME`）被裁剪掉了，而 `aya` 库依赖这些常量。

### 解决方案
在 `Cargo.toml` 中恢复 `libc` 和 `aya` 的默认特性：
```toml
libc = { version = "0.2.159" } # 隐含 default-features = true
aya = { version = "0.13" }
```

---

## 问题 3: Rust Borrow Checker (所有权) 冲突

**状态**: 已解决 ✅
**影响**: 中 (编译报错)

### 问题描述
在加载 `SkMsg` 程序时报错 `cannot borrow bpf as mutable more than once`。原因是 `intercept_map` 借用了 `bpf` 的可变引用，而在 `intercept_map` 存活期间，我们又试图调用 `bpf.program_mut()`。

### 解决方案
使用代码块 (Scope) 限制 `intercept_map` 的生命周期。我们在块内提取并克隆出需要的 FD (`map_fd`)，然后让 `intercept_map` 离开作用域释放借用，再进行后续的程序加载。

```rust
let map_fd = {
    // 借用开始
    let map = bpf.map_mut("...")?;
    map.fd().try_clone()?
}; // map 离开作用域，借用释放

// 此时可以安全地再次借用 bpf
let prog = bpf.program_mut(...)
```
