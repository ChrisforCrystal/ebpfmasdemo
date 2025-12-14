# 核心功能验证指南 (Core Observability)

本文档将指导你如何使用 Docker 环境快速验证 masDeepFlow Agent 的核心功能。

## 1. 启动环境

我们使用 Docker 来模拟 Linux 内核环境并加载 eBPF 程序。

1.  **构建并启动 Agent**:
    在项目根目录运行：
    ```bash
    ./run-in-docker.sh
    ```
    *首次运行需要几分钟构建镜像。*
    *成功启动后，你会看到日志显示:* `Waiting for events...`

## 2. 验证场景

保持上面的终端窗口运行 Agent 不动，**打开一个新的终端窗口** 来触发测试事件。

### 进入容器
```bash
# 进入正在运行的测试容器
docker exec -it masdeepflow-demo bash
```

### 场景 A: 进程监控 (Process Monitoring)
验证 Agent 能否捕获进程启动信息及 K8s Pod 关联。

在容器内执行：
```bash
ls -la /tmp
```

**去第一个窗口查看日志**:
> `[PROCESS] PID: <数字>, Pod: frontend-pod-1, Comm: ls`

*注意: "frontend-pod-1" 是基于 Cgroup ID 模拟生成的 Pod 名称。*

---

### 场景 B: 对外连接监控 (Outbound Connection)
验证 Agent 能否捕获 TCP 建连及目标地址。

在容器内执行：
```bash
curl -I http://1.1.1.1
```

**查看日志**:
> `[TCP] Type: CONNECT, Pod: frontend-pod-1, <本机IP> -> 1.1.1.1:80, HTTP: HEAD / HTTP/1.1`

---

### 场景 C: HTTP 应用层透视 (L7 Observability)
验证 Agent 能否解析 HTTP 请求的 URL。

在容器内执行：
```bash
curl http://example.com/api/v1/login
```

**查看日志**:
> `[TCP] ... HTTP: GET /api/v1/login`

*成功！Agent 成功从 TCP 数据包中提取出了 HTTP 方法和 URL 路径。*

---

### 场景 D: 入向流量监控 (Inbound Traffic)
验证 Agent 能否捕获服务端接收到的连接。

在容器内执行：
```bash
# 1. 在后台启动一个监听 8080 端口的服务
nc -l -p 8080 &

# 2. 连接这个服务
echo "Hello eBPF" | nc localhost 8080
```

**查看日志**:
> `[TCP] Type: ACCEPT ...` (服务端接受连接)
> `[TCP] Type: DATA ... Bytes: 11` (数据传输)

## 3. 常见问题排查 (Troubleshooting)

- **构建失败**: 请确保本地已安装 Docker 且 Docker Desktop 正在运行。
- **Permission Denied**: eBPF 需要特权模式，请确保使用 `./run-in-docker.sh` 脚本启动（它会自动加上 `--privileged` 参数）。
- **看不到 HTTP 日志**: 
    - 确保 `curl` 的是 `http://` 而不是 `https://`。加密流量如果不配合 OpenSSL UProbe 是无法直接解析的。
    - 确保有数据传输（`curl -I` 可能只发 HEAD 请求，有时数据量极小，但也会被捕捉到）。
