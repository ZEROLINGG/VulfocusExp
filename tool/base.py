from __future__ import annotations

import re
import time
from typing import Callable
import subprocess
import threading
from dataclasses import dataclass
from typing import Any, Callable
import os

from tool.port_scan import Service
from tool.local_ip import get_ip
from tool.log import debug_log,set_debug as _set_debug,set_no_debug as _set_no_debug

_FLAG_PATTERN = re.compile(r"flag-?\{[a-zA-Z0-9_-]+}", re.IGNORECASE)




def set_debug():
    _set_debug()
def set_no_debug():
    _set_no_debug()


def wait(
    func: Callable[[], bool],
    timeout: float = 15,
    interval: float = 0.3,
) -> bool:
    if timeout < 0:
        debug_log("timeout 必须 >= 0","wait")
        return False
    if interval <= 0:
        debug_log("interval 必须 > 0", "wait")
        return False

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if func():
                return True
        except Exception:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))
    return False

def match_flag(text: str) -> str | None:
    debug_log(f"输入文本: {text[:100] if text else 'None'}...", "match_flag")
    if not text:
        debug_log("文本为空，返回 None", "match_flag")
        return None
    match = _FLAG_PATTERN.search(text)
    result = match.group(0) if match else None
    # debug_log(f"匹配结果: {result}", "match_flag")
    return result


def match_flags(text: str) -> list[str]:
    debug_log(f"输入文本: {text[:100] if text else 'None'}...", "match_flags")
    if not text:
        debug_log("文本为空，返回空列表", "match_flags")
        return []
    results = _FLAG_PATTERN.findall(text)
    debug_log(f"匹配到 {len(results)} 个 flag", "match_flags")
    return results


def get_local_ip() -> str | None:
    """获取当前主机对外通信使用的 IP 地址"""
    return get_ip()


@dataclass
class CommandResult:
    ok: bool
    output: str
    error: str


def run_cmd(command: str, timeout: int = 120) -> CommandResult:
    debug_log(f"执行命令: {command}, timeout={timeout}", "run_cmd")
    try:
        result = subprocess.run(  # noqa: S603
            command,
            shell=True,  # noqa: S602
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        cmd_result = CommandResult(
            ok=(result.returncode == 0),
            output=result.stdout.strip(),
            error=result.stderr.strip(),
        )
        debug_log(f"命令执行完成: ok={cmd_result.ok}, returncode={result.returncode}", "run_cmd")
        return cmd_result
    except Exception as e:
        debug_log(f"命令执行异常: {e}", "run_cmd")
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

        debug_log(f"初始化 RunCmd: command={command}, timeout={timeout}", "RunCmd.__init__")

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def run(self) -> tuple[bool, str]:
        """启动命令（非阻塞）。返回 (是否成功启动, 消息)。"""
        debug_log(f"尝试启动命令: {self.command}", "RunCmd.run")
        with self._lock:
            if self._process is not None:
                debug_log("进程已在运行", "RunCmd.run")
                return False, "[RunCmd] 已有进程在运行，请先 stop() 或等待完成"
            try:
                self._process = subprocess.Popen(  # noqa: S603
                    self.command,
                    shell=True,  # noqa: S602
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                assert (isinstance(self._process, subprocess.Popen))
                debug_log(f"命令启动成功，PID: {self._process.pid}", "RunCmd.run")
                return True, f"[RunCmd] 命令已启动，PID: {self._process.pid}"
            except Exception as e:
                debug_log(f"命令启动失败: {e}", "RunCmd.run")
                return False, f"[RunCmd] 启动失败: {e}"

    def join(self) -> CommandResult:
        """阻塞等待命令完成，返回结果。可安全多次调用。"""
        debug_log("join() 开始等待命令完成", "RunCmd.join")
        with self._lock:
            if self._process is None:
                debug_log("进程未启动", "RunCmd.join")
                return CommandResult(ok=False, output="", error="[RunCmd] 进程未启动")
            if self._result is not None:
                debug_log("返回已缓存的结果", "RunCmd.join")
                return self._result
            proc = self._process

        try:
            debug_log(f"等待进程完成，timeout={self.timeout}", "RunCmd.join")
            stdout, stderr = proc.communicate(timeout=self.timeout)
            self._result = CommandResult(
                ok=(proc.returncode == 0),
                output=stdout.strip(),
                error=stderr.strip(),
            )
            debug_log(f"进程完成: returncode={proc.returncode}", "RunCmd.join")
        except subprocess.TimeoutExpired:
            debug_log(f"进程超时 ({self.timeout}s)，开始终止", "RunCmd.join")
            self._kill_and_drain(proc)
            self._result = CommandResult(
                ok=False,
                output="",
                error=f"[RunCmd] 命令执行超时 ({self.timeout}s)",
            )
        except Exception as e:
            debug_log(f"join() 异常: {e}", "RunCmd.join")
            self._result = CommandResult(
                ok=False,
                output="",
                error=f"[RunCmd] Exception: {e}",
            )
        assert (isinstance(self._result, CommandResult))
        return self._result

    def stop(self) -> CommandResult:
        """
        终止进程并返回已收集到的输出。

        - 进程已自然结束 → 返回真实结果（含 returncode）
        - 进程仍在运行  → SIGTERM，5 s 后仍存活则 SIGKILL

        可安全多次调用。
        """
        debug_log("stop() 开始终止进程", "RunCmd.stop")
        with self._lock:
            if self._process is None:
                debug_log("进程未启动", "RunCmd.stop")
                return CommandResult(ok=False, output="", error="[RunCmd] 进程未启动")
            if self._result is not None:
                debug_log("返回已缓存的结果", "RunCmd.stop")
                return self._result
            proc = self._process

            if proc.poll() is not None:
                debug_log(f"进程已自然结束，returncode={proc.returncode}", "RunCmd.stop")
                self._result = self._collect_finished(proc)
                assert (isinstance(self._result, CommandResult))
                return self._result

        # 进程仍在运行，锁外执行 I/O
        debug_log("进程仍在运行，开始终止", "RunCmd.stop")
        result = self._terminate_and_collect(proc)
        self._result = result
        return result

    def reset(self) -> None:
        """停止当前进程并重置状态，允许重新 run()。"""
        debug_log("reset() 重置状态", "RunCmd.reset")
        self.stop()
        with self._lock:
            self._process = None
            self._result = None

    def __enter__(self) -> RunCmd:
        debug_log("进入上下文管理器", "RunCmd.__enter__")
        return self

    def __exit__(self, *_: object) -> None:
        """离开 with 块时自动终止进程并释放管道资源。"""
        debug_log("退出上下文管理器", "RunCmd.__exit__")
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

        result = [(self.ip, p) for p in ports]
        return result

    def ip_port(self) -> list[tuple[str, int]]:
        """返回所有端口的 (ip, port) 元组列表，不做服务类型过滤。"""
        result = [(self.ip, p) for p in self.ports]
        return result

    def detect_services(self, timeout: int = 3) -> list[tuple[int, Service]]:
        from tool.port_scan import detect_services_fast

        results = detect_services_fast((self.ip, self.ports), timeout)
        return results


def parse_ip_port(ip_port: str) -> TargetGroup:
    """
    解析输入格式: "ip:port1,port2,..."
    返回: TargetGroup
    """
    # debug_log(f"解析输入: {ip_port}", "parse_ip_port")
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
    except ValueError as e:
        debug_log(f"解析失败: {e}", "parse_ip_port")
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
            # debug_log("使用自定义 on_process", "process")
            targets = on_process(ip_port)
        else:
            tg = parse_ip_port(ip_port)
            if not tg.ok:
                print(tg.error)
                return
            targets = tg.build_urls()

        debug_log(f"获得 {len(targets)} 个目标: {targets}", "process")
    except Exception as e:
        debug_log(f"处理异常: {e}", "process")
        print(f"[!] 异常: {e}")

    for idx, target in enumerate(targets):
        debug_log(f"处理目标 [{idx + 1}/{len(targets)}]: {target}", "process")
        try:
            ok, result, err = run(target)
            if ok:
                print(f"[+] 成功: {target} -> {result}")
            else:
                print(f"[-] 失败: {target} -> {err}")
        except Exception as e:
            debug_log(f"运行异常: {e}", "process")
            print(f"[!] 异常: {target} -> {e}")


def process_with(
        ip_port: str,
        run: Callable[[tuple[str, int]], tuple[bool, str | list[str], str]],
        types: list[Service] | None = None,
) -> None:
    debug_log(f"开始 process_with: {ip_port}, types={types if types is not None else "[Service.HTTP, Service.HTTPS]"}", "process_with")

    def on_process(addr: str) -> list[tuple[str, int]]:
        tg = parse_ip_port(addr)
        if not tg.ok:
            return []
        return tg.ip_port_with(types)

    process(ip_port, run, on_process)


# 使用示例
if __name__ == "__main__":
    _ip_port = "192.168.192.148:63945,37151,16620"
    print(_ip_port)
    _target = parse_ip_port(_ip_port)

    if _target.ok:
        print("=== 基本服务检测 ===")
        services = _target.detect_services()
        for port, service_type in services:
            print(f"端口 {port}: {service_type.value}")