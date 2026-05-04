import re
from dataclasses import dataclass
from typing import Any, Callable

from .port_scan import Service

_FLAG_PATTERN = re.compile(r"flag-?\{[a-zA-Z0-9_-]+\}", re.IGNORECASE)


def match_flag(text: str) -> str | None:
    if not text:
        return None
    match = _FLAG_PATTERN.search(text)
    return match.group(0) if match else None


def match_flags(text: str) -> list[str]:
    if not text:
        return []
    return _FLAG_PATTERN.findall(text)


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
        return CommandResult(
            ok=False, output="", error=f"[run_cmd] Exception: {str(e)}"
        )


class RunCmd:
    def __init__(self, command: str, timeout: int = 300):
        self.command = command
        self.timeout = timeout
        self.process = None
        self._result = None

    def run(self) -> tuple[bool, str]:
        """
        启动命令执行（非阻塞）
        返回: (是否成功启动, 消息)
        """
        import subprocess

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return (True, f"[RunCmd] 命令已启动，PID: {self.process.pid}")
        except Exception as e:
            return (False, f"[RunCmd] 启动失败: {str(e)}")

    def join(self) -> CommandResult:
        """
        等待命令执行完成并返回结果
        """
        import subprocess

        if self.process is None:
            return CommandResult(ok=False, output="", error="[RunCmd] 进程未启动")

        if self._result is not None:
            return self._result

        try:
            stdout, stderr = self.process.communicate(timeout=self.timeout)

            self._result = CommandResult(
                ok=(self.process.returncode == 0),
                output=stdout.strip(),
                error=stderr.strip(),
            )
            return self._result

        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()  # 清理
            self._result = CommandResult(
                ok=False,
                output="",
                error=f"[RunCmd] 命令执行超时 ({self.timeout}s)",
            )
            return self._result
        except Exception as e:
            self._result = CommandResult(
                ok=False,
                output="",
                error=f"[RunCmd] Exception: {str(e)}",
            )
            return self._result

    def stop(self) -> CommandResult:
        """
        强制停止命令执行
        """
        import subprocess

        if self.process is None:
            return CommandResult(ok=False, output="", error="[RunCmd] 进程未启动")

        try:
            if self.process.poll() is not None:
                if self._result:
                    return self._result
                return CommandResult(
                    ok=False,
                    output="",
                    error="[RunCmd] 进程已结束",
                )

            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

            stdout, stderr = self.process.communicate()

            self._result = CommandResult(
                ok=False,
                output=stdout.strip() if stdout else "",
                error=f"[RunCmd] 进程已被停止\n{stderr.strip() if stderr else ''}",
            )
            return self._result

        except Exception as e:
            return CommandResult(
                ok=False,
                output="",
                error=f"[RunCmd] 停止失败: {str(e)}",
            )


@dataclass
class TargetGroup:
    ip: str
    ports: list[int]
    ok: bool = True
    error: str = ""

    def build_urls(self):
        results = self.detect_services()

        http_ports = [p for p, s in results if s == Service.HTTP]
        https_ports = [p for p, s in results if s == Service.HTTPS]

        urls = []
        for p in https_ports:
            urls.append(f"https://{self.ip}:{p}")
        for p in http_ports:
            urls.append(f"http://{self.ip}:{p}")

        return urls

    def ip_port_with(
        self, types: list[Service] = [Service.HTTP, Service.HTTPS]
    ) -> list[tuple[str, int]]:
        """
        返回 (ip, port) 元组列表
        """
        ports = []
        results = self.detect_services()
        for type in types:
            ports += [p for p, s in results if s == type]

        return [(self.ip, p) for p in ports]

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
    run: Callable[[Any], tuple[bool, str | list[str], str]],
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


def process_with(
    ip_port: str,
    run: Callable[[tuple[str, int]], tuple[bool, str | list[str], str]],
    types: list[Service] = [Service.HTTP, Service.HTTPS],
):
    def on_process(ip_port: str):
        tg = parse_ip_port(ip_port)
        if not tg.ok:
            return []
        return tg.ip_port_with(types)

    return process(ip_port, run, on_process)


# 使用示例
if __name__ == "__main__":
    ip_port = "192.168.192.148:30652,35174,62007"
    print(ip_port)
    target = parse_ip_port(ip_port)

    if target.ok:
        print("=== 基本服务检测 ===")
        services = target.detect_services()
        for port, service_type in services:
            print(f"端口 {port}: {service_type.value}")
