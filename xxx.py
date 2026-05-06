from tool.base import parse_ip_port

import socket

def get_source_ip_for(target_ip: str, port: int = 80) -> str | None:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, port))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        if s:
            s.close()

if __name__ ==  "__main__":
    # ip_port = "192.168.192.148:21734,28815"
    # tg = parse_ip_port(ip_port)
    # for p,s in tg.detect_services():
    #     print(f"[{p}] {s}")

    print(get_source_ip_for("192.168.192.148", 2025))