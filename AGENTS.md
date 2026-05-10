# VulfocusExp - AGENTS.md

## 项目用途

Vulfocus CTF 靶场的 Exploit 库，用于快速获取 flag。

## 目录结构

```
/home/zz/Documents/WP/Exp/
├── tool/                                    # 核心工具库
│   ├── base.py                              # match_flag, process_with, parse_ip_port, run_cmd, RunCmd, TargetGroup
│   ├── http_repeater.py                     # HTTP 请求发送（原始请求重放）
│   ├── http_server.py                      # HttpEcho, HttpFile 简易服务器
│   ├── port_scan.py                         # 端口服务检测
│   ├── bash_obf.py                          # Bash 命令混淆（17种方法）
│   ├── local_ip.py                          # 本机 IP 获取
│   ├── log.py                               # 调试日志
│   ├── code.py                              # 漏洞利用代码模板（JNDI）
│   └── shell_rb.py                          # TCP 反向/绑定 Shell 管理器
├── .agents/skills/                          # Agent Skill 系统（20个）
│   ├── ctf-crypto/  ctf-forensics/  ctf-web/  ctf-misc/  ctf-malware/
│   ├── java-*-audit/  vulfocus_solve/  vulnerability-rating/
│   └── xlsx/  dirsearch-command-generator/  flutter-ssl-analysis/
├── [题目名].py                              # 各题目的 Exp 实现
└── main.py                                  # 主入口（批量处理）⚠️ 待实现
```

## 依赖安装

```bash
uv sync
```

## Exp 编写规范

```python
from tool.base import match_flag, process_with, get_local_ip, run_cmd, RunCmd, wait
from tool.http_repeater import repeater
from tool.http_server import HttpEcho, HttpFile

def run(target: tuple[str, int]) -> tuple[bool, str | list[str], str]:
    # target 是 (ip, port) 元组
    # 返回 (ok, flag, error)
    exp = f"""GET /path HTTP/1.1
Host: {target[0]}:{target[1]}

"""
    resp = repeater(exp)
    if not resp:
        return False, "", resp.error

    flag = match_flag(resp.text())
    if not flag:
        return False, "", "flag 未匹配"

    return True, flag, ""

def main(ip_port: str):
    process_with(ip_port, run)

if __name__ == "__main__":
    __import__("tool.base", fromlist=["set_debug"]).set_debug()   # 调试脚本时添加
    main("192.168.192.148:42740")
```

## 关键命令

- 运行单个 Exp: `python [漏洞名].py`
- 命令执行: `from tool.base import run_cmd; run_cmd("ls")`
- 端口扫描: `from tool.base import parse_ip_port; tg = parse_ip_port("ip:port"); tg.detect_services()`
- RCE 回显（盲打）: `from tool.http_server import HttpEcho; with HttpEcho() as e: ... wait(lambda: len(e.requests()) > 0)`
- Shell 管理: `from tool.shell_rb import TcpShellR, gen_shell_r_cmd`

## 常用工具函数

| 函数 | 用途 |
|------|------|
| `match_flag(text)` | 从文本提取单个 flag |
| `match_flags(text)` | 从文本提取所有 flag |
| `parse_ip_port(str)` | 解析 "ip:port,port" 格式返回 TargetGroup |
| `process_with(ip_port, run)` | 自动遍历端口并调用 run 函数 |
| `repeater(raw_http)` | 发送原始 HTTP 请求 |
| `wait(func, timeout, interval)` | 轮询等待条件函数返回 True |
| `get_local_ip()` | 获取本机出口 IP |
| `run_cmd(command, timeout)` | 同步执行 shell 命令 |
| `RunCmd(command)` | 非阻塞命令执行器（支持上下文管理器） |
| `HttpEcho(port=8000)` | 启动回显服务器，记录请求 |
| `HttpFile(files, port=8001)` | 启动文件服务器，提供恶意文件 |
| `TcpShellR()` | TCP 反向 Shell 服务器 |
| `gen_shell_r_cmd(name, ip, port)` | 生成反向 Shell 命令 |
| `apply_obfs(cmd, obf=["base64", "bash_c_ifs1"])` | 命令混淆 |
| `random_obf(cmd, depth=3)` | 随机深度混淆 |

## Agent Skill 加载

```python
# 使用 skill 工具加载
skill("vulfocus_solve")  # Vulfocus 做题流程
skill("ctf-web")       # Web 渗透（SQLi/XSS/SSTI/反序列化）
skill("ctf-crypto")   # 密码学攻击（RSA/AES/ECC/格）

# RCE 盲打回显优先级
# 1. 有回显: ls /tmp, env
# 2. 无回显: HttpEcho + curl/wget 回连
# 3. 命令混淆: apply_obfs(cmd, obf=["base64", "bash_c_ifs1"])
```

## 注意事项

- 靶场 IP:port 格式如 `192.168.192.148:42740`，只支持单个端口时也需加冒号
- HTTP 请求使用原始格式，每行以 `\n` 分隔
- flag 格式: `flag-{xxx}` 或 `flag{xxx}`（不区分大小写）
- 优先使用 `tool/http_repeater` 发送 HTTP 请求，避免 curl/wget 依赖
- 调试模式：设置环境变量 `EXP_DEBUG=true` 可查看详细执行日志
- 阅读README.md: 阅读README.md用于确认已有的工具以及工具接口和项目规范。