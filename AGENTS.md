# VulfocusExp - AGENTS.md

## 项目用途

Vulfocus CTF 靶场的 Exploit 库，用于快速获取 flag。

## 目录结构

```
/home/zz/Documents/WP/Exp/
├── tool/                    # 核心工具库
│   ├── base.py            # match_flag, process_with, parse_ip_port, run_cmd, TargetGroup
│   ├── http_repeater.py   # HTTP 请求发送（原始请求重放）
│   ├── http_server.py     # HttpEcho, HttpFile 简易服务器
│   ├── port_scan.py       # 端口服务检测
│   └── code.py           # 漏洞利用代码模板
├── [题目名].py           # 各题目的 Exp 实现
└── main.py               # 主入口（暂未实现）
```

## Exp 编写规范

```python
# [漏洞名].py
from tool.base import match_flag, process_with
from tool.http_repeater import repeater

def run(target: tuple[str, int]) -> tuple[bool, str | list[str], str]:
    # target 是 (ip, port) 元组
    # 返回 (ok, flag, error)
    exp = f"GET /path HTTP/1.1\nHost: {target[0]}:{target[1]}\n\n"
    resp = repeater(exp)
    if not resp:
        return False, "", resp.error
    
    flag = match_flag(resp.text())
    if not flag:
        return False, "", "flag 未匹配"
    
    return True, flag, ""

def main(ip_port: str):
    # ip_port 格式: "192.168.1.1:8000,8001" 或单个端口 "192.168.1.1:8000"
    process_with(ip_port, run)

if __name__ == "__main__":
    main("192.168.192.148:42740")
```

## 关键命令

- 运行单个 Exp: `python [漏洞名].py`
- 命令执行: `from tool.base import run_cmd; run_cmd("ls")`
- 端口扫描: `from tool.base import parse_ip_port; tg = parse_ip_port("ip:port"); tg.detect_services()`

## 常用工具函数

| 函数 | 用途 |
|------|------|
| `match_flag(text)` | 从文本提取单个 flag |
| `match_flags(text)` | 提取所有 flag |
| `parse_ip_port(str)` | 解析 "ip:port,port" 格式返回 TargetGroup |
| `process_with(ip_port, run)` | 自动遍历端口并调用 run 函数 |
| `repeater(raw_http)` | 发送原始 HTTP 请求 |

## 注意事项

- 靶场 IP:port 格式如 `192.168.192.148:42740`，只支持单个端口时也需加冒号
- HTTP 请求使用原始格式，每行以 `\n` 分隔
- flag 格式: `flag-{xxx}` 或 `flag{xxx}`（不区分大小写）
- 优先使用 tool/http_repeater 发送 HTTP 请求，避免 curl/wget 依赖