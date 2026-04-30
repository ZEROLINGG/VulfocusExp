import re
from dataclasses import dataclass

_FLAG_PATTERN = re.compile(r"flag-\{[a-zA-Z0-9_-]+\}", re.IGNORECASE)


def match_flag(text: str) -> str | None:
    if not text:
        return None
    match = _FLAG_PATTERN.search(text)
    return match.group(0) if match else None


def get_local_ip() -> str | None:
    """
    获取当前主机对外通信使用的IP地址（出口IP）
    适用于大多数Linux / Windows / macOS环境
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
    return_code: int
    output: str
    error: str


def run_cmd(command: str, timeout: int = 120) -> CommandResult:
    """
    执行系统命令并返回结构化结果
    """
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
            return_code=result.returncode,
            output=result.stdout.strip(),
            error=result.stderr.strip(),
        )
    except Exception as e:
        return CommandResult(return_code=-1, output="", error=f"Exception: {str(e)}")


@dataclass
class TargetGroup:
    ip: str
    ports: list[str]
    ok: bool = True
    error: str = ""

    def build_urls(self, scheme: str = "http") -> list[str]:
        """
        生成完整 URL 列表
        """
        return [f"{scheme}://{self.ip}:{port}" for port in self.ports]


def parse_ip_port(ip_port: str) -> TargetGroup:
    """
    解析输入格式: "ip:port1,port2,..."
    返回: TargetGroup
    """
    try:
        ip, ports_str = ip_port.split(":", 1)
        ports = [p.strip() for p in ports_str.split(",") if p.strip()]

        if not ip or not ports:
            raise ValueError

        return TargetGroup(ip=ip, ports=ports)

    except ValueError:
        return TargetGroup(
            ip="", ports=[], ok=False, error="输入格式错误，应为: ip:port1,port2,..."
        )
