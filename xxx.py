from tool.base import parse_ip_port



if __name__ ==  "__main__":
    ip_port = "node5.buuoj.cn:26115"
    tg = parse_ip_port(ip_port)
    for p,s in tg.detect_services():
        print(f"[{p}] {s}")

