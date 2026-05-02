import re
from dataclasses import dataclass
from typing import Any, Callable

_FLAG_PATTERN = re.compile(r"flag-\{[a-zA-Z0-9_-]+\}", re.IGNORECASE)


def match_flag(text: str) -> str | None:
    if not text:
        return None
    match = _FLAG_PATTERN.search(text)
    return match.group(0) if match else None


def get_local_ip() -> str | None:
    """
    获取当前主机对外通信使用的IP地址（出口IP）
    """
    import socket

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 连接一个外部地址（不实际发送数据）
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        return ip
    except Exception:
        return None
    finally:
        if s:
            s.close()


@dataclass
class CommandResult:
    ok: bool
    output: str
    error: str


def run_cmd(command: str, timeout: int = 120) -> CommandResult:
    import subprocess

    try:
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

        return CommandResult(
            ok=(result.returncode == 0),
            output=result.stdout.strip(),
            error=result.stderr.strip(),
        )

    except Exception as e:
        return CommandResult(ok=False, output="", error=f"Exception: {str(e)}")


@dataclass
class TargetGroup:
    ip: str
    ports: list[int]
    ok: bool = True
    error: str = ""

    def build_urls(self):
        from .port_scan import Service

        results = self.detect_services()

        http_ports = [p for p, s in results if s == Service.HTTP]
        https_ports = [p for p, s in results if s == Service.HTTPS]

        urls = []
        for p in https_ports:
            urls.append(f"https://{self.ip}:{p}")
        for p in http_ports:
            urls.append(f"http://{self.ip}:{p}")

        return urls

    def ip_port(self) -> list[tuple[str, int]]:
        """
        返回 (ip, port) 元组列表
        """
        return [(self.ip, p) for p in self.ports]

    def detect_services(self, timeout=3):
        from .port_scan import detect_services_fast

        return detect_services_fast((self.ip, self.ports), timeout)


def parse_ip_port(ip_port: str) -> TargetGroup:
    """
    解析输入格式: "ip:port1,port2,..."
    返回: TargetGroup
    """
    try:
        ip, ports_str = ip_port.strip().split(":", 1)

        ports = []
        for p in ports_str.split(","):
            p = p.strip()
            if not p:
                continue
            ports.append(int(p))

        if not ip or not ports:
            raise ValueError

        return TargetGroup(ip=ip, ports=ports)

    except ValueError:
        return TargetGroup(
            ip="", ports=[], ok=False, error="输入格式错误，应为: ip:port1,port2,..."
        )


def process(
    ip_port: str,
    run: Callable[[Any], tuple[bool, str, str]],
    on_process: Callable[[str], Any] | None = None,
):
    targets = []
    try:
        if on_process:
            targets = on_process(ip_port)
        else:
            tg = parse_ip_port(ip_port)
            if not tg.ok:
                print(tg.error)
                return
            targets = tg.build_urls()
    except Exception as e:
        print(f"[!] 异常: {str(e)}")

    for target in targets:
        try:
            ok, result, err = run(target)
            if ok:
                print(f"[+] 成功: {target} -> {result}")
            else:
                print(f"[-] 失败: {target} -> {err}")
        except Exception as e:
            print(f"[!] 异常: {target} -> {str(e)}")


# 使用示例
if __name__ == "__main__":
    ip_port = "192.168.192.148:18790,45334,49914"
    print(ip_port)
    target = parse_ip_port(ip_port)

    if target.ok:
        print("=== 基本服务检测 ===")
        services = target.detect_services()
        for port, service_type in services:
            print(f"端口 {port}: {service_type.value}")
