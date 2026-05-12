from tool.base import parse_ip_port



if __name__ ==  "__main__":
    ip_port = "192.168.192.148:32825"
    tg = parse_ip_port(ip_port)
    for p,s in tg.detect_services():
        print(f"[{p}] {s}")

