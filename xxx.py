from tool.base import parse_ip_port



if __name__ ==  "__main__":
    ip_port = "192.168.192.148:42245,24415,41904,27180,21788,40858,41550,52297"
    tg = parse_ip_port(ip_port)
    for p,s in tg.detect_services():
        print(f"[{p}] {s}")

