from __future__ import annotations

import re
import socket
import subprocess
import threading
from dataclasses import dataclass
from typing import Any, Callable

from tool.port_scan import Service

_FLAG_PATTERN = re.compile(r"flag-?\{[a-zA-Z0-9_-]+}", re.IGNORECASE)


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
    """获取当前主机对外通信使用的 IP 地址（出口 IP）。"""
    s: socket.socket | None = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        assert(isinstance(s, socket.socket))
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
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
    try:
        result = subprocess.run(  # noqa: S603
            command,
            shell=True,  # noqa: S602
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
        return CommandResult(ok=False, output="", error=f"[run_cmd] Exception: {e}")


class RunCmd:
    """
    非阻塞命令执行器，支持自动资源清理。

    用法::

        cmd = RunCmd("sleep 5 && echo done")
        ok, msg = cmd.run()
        result = cmd.join()   # 等待完成
        result = cmd.stop()   # 提前终止

    推荐使用上下文管理器，离开时自动 stop() + 清理管道::

        with RunCmd("long_task") as cmd:
            cmd.run()
            result = cmd.join()
    """

    def __init__(self, command: str, timeout: int = 300) -> None:
        self.command = command
        self.timeout = timeout

        self._process: subprocess.Popen[str] | None = None
        self._result: CommandResult | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def run(self) -> tuple[bool, str]:
        """启动命令（非阻塞）。返回 (是否成功启动, 消息)。"""
        with self._lock:
            if self._process is not None:
                return False, "[RunCmd] 已有进程在运行，请先 stop() 或等待完成"
            try:
                self._process = subprocess.Popen(  # noqa: S603
                    self.command,
                    shell=True,  # noqa: S602
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                assert(isinstance(self._process, subprocess.Popen))
                return True, f"[RunCmd] 命令已启动，PID: {self._process.pid}"
            except Exception as e:
                return False, f"[RunCmd] 启动失败: {e}"

    def join(self) -> CommandResult:
        """阻塞等待命令完成，返回结果。可安全多次调用。"""
        with self._lock:
            if self._process is None:
                return CommandResult(ok=False, output="", error="[RunCmd] 进程未启动")
            if self._result is not None:
                return self._result
            proc = self._process

        try:
            stdout, stderr = proc.communicate(timeout=self.timeout)
            self._result = CommandResult(
                ok=(proc.returncode == 0),
                output=stdout.strip(),
                error=stderr.strip(),
            )
        except subprocess.TimeoutExpired:
            self._kill_and_drain(proc)
            self._result = CommandResult(
                ok=False,
                output="",
                error=f"[RunCmd] 命令执行超时 ({self.timeout}s)",
            )
        except Exception as e:
            self._result = CommandResult(
                ok=False,
                output="",
                error=f"[RunCmd] Exception: {e}",
            )
        assert(isinstance(self._result, CommandResult))
        return self._result

    def stop(self) -> CommandResult:
        """
        终止进程并返回已收集到的输出。

        - 进程已自然结束 → 返回真实结果（含 returncode）
        - 进程仍在运行  → SIGTERM，5 s 后仍存活则 SIGKILL

        可安全多次调用。
        """
        with self._lock:
            if self._process is None:
                return CommandResult(ok=False, output="", error="[RunCmd] 进程未启动")
            if self._result is not None:
                return self._result
            proc = self._process

            if proc.poll() is not None:
                self._result = self._collect_finished(proc)
                assert (isinstance(self._result, CommandResult))
                return self._result

        # 进程仍在运行，锁外执行 I/O
        result = self._terminate_and_collect(proc)
        self._result = result
        return result

    def reset(self) -> None:
        """停止当前进程并重置状态，允许重新 run()。"""
        self.stop()
        with self._lock:
            self._process = None
            self._result = None

    def __enter__(self) -> RunCmd:
        return self

    def __exit__(self, *_: object) -> None:
        """离开 with 块时自动终止进程并释放管道资源。"""
        self.stop()

    @staticmethod
    def _collect_finished(proc: subprocess.Popen[str]) -> CommandResult:
        """进程已结束但管道尚未读取时调用，排空缓冲区并返回结果。"""
        try:
            stdout, stderr = proc.communicate()
            return CommandResult(
                ok=(proc.returncode == 0),
                output=stdout.strip() if stdout else "",
                error=stderr.strip() if stderr else "",
            )
        except Exception as e:
            return CommandResult(
                ok=False,
                output="",
                error=f"[RunCmd] 读取输出失败: {e}",
            )

    @staticmethod
    def _terminate_and_collect(proc: subprocess.Popen[str]) -> CommandResult:
        """发送 SIGTERM，超时后 SIGKILL，然后排空管道返回结果。"""
        stdout_str = ""
        stderr_str = ""
        try:
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=5)
                stdout_str = stdout.strip() if stdout else ""
                stderr_str = stderr.strip() if stderr else ""
            except subprocess.TimeoutExpired:
                RunCmd._kill_and_drain(proc)
        except Exception as e:
            return CommandResult(
                ok=False,
                output="",
                error=f"[RunCmd] 终止失败: {e}",
            )

        error_msg = "[RunCmd] 进程已被终止"
        if stderr_str:
            error_msg = f"{error_msg}\n{stderr_str}"
        return CommandResult(ok=False, output=stdout_str, error=error_msg)

    @staticmethod
    def _kill_and_drain(proc: subprocess.Popen[str]) -> None:
        """SIGKILL 后排空管道，防止僵尸进程或管道缓冲区阻塞。"""
        try:
            proc.kill()
            proc.communicate()
        except Exception as _:
            pass


@dataclass
class TargetGroup:
    ip: str
    ports: list[int]
    ok: bool = True
    error: str = ""

    def build_urls(self) -> list[str]:
        results = self.detect_services()

        http_ports = [p for p, s in results if s == Service.HTTP]
        https_ports = [p for p, s in results if s == Service.HTTPS]

        urls: list[str] = []
        for p in https_ports:
            urls.append(f"https://{self.ip}:{p}")
        for p in http_ports:
            urls.append(f"http://{self.ip}:{p}")
        return urls

    def ip_port_with(
        self, types: list[Service] | None = None
    ) -> list[tuple[str, int]]:
        """
        返回 (ip, port) 元组列表
        """
        if types is None:
            types = [Service.HTTP, Service.HTTPS]
        assert types is not None
        ports = []
        results = self.detect_services()
        for t in types:
            ports += [p for p, s in results if s == t]

        return [(self.ip, p) for p in ports]

    def ip_port(self) -> list[tuple[str, int]]:
        """返回所有端口的 (ip, port) 元组列表，不做服务类型过滤。"""
        return [(self.ip, p) for p in self.ports]

    def detect_services(self, timeout: int = 3) -> list[tuple[int, Service]]:
        from tool.port_scan import detect_services_fast

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
    on_process: Callable[[str], list[Any]] | None = None,
) -> None:
    targets: list[Any] = []
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
        print(f"[!] 异常: {e}")

    for target in targets:
        try:
            ok, result, err = run(target)
            if ok:
                print(f"[+] 成功: {target} -> {result}")
            else:
                print(f"[-] 失败: {target} -> {err}")
        except Exception as e:
            print(f"[!] 异常: {target} -> {e}")


def process_with(
    ip_port: str,
    run: Callable[[tuple[str, int]], tuple[bool, str | list[str], str]],
    types: list[Service] | None = None,
) -> None:
    def on_process(addr: str) -> list[tuple[str, int]]:
        tg = parse_ip_port(addr)
        if not tg.ok:
            return []
        return tg.ip_port_with(types)

    process(ip_port, run, on_process)


# 使用示例
if __name__ == "__main__":
    ip_port = "192.168.192.148:56832,25968,41569,13223"
    print(ip_port)
    target = parse_ip_port(ip_port)

    if target.ok:
        print("=== 基本服务检测 ===")
        services = target.detect_services()
        for port, service_type in services:
            print(f"端口 {port}: {service_type.value}")
