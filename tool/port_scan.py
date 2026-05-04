import asyncio
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Service(Enum):
    """服务类型枚举"""

    HTTP = "http"
    HTTPS = "https"
    MYSQL = "mysql"
    REDIS = "redis"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    TELNET = "telnet"
    POP3 = "pop3"
    IMAP = "imap"
    SMB = "smb"
    RDP = "rdp"
    VNC = "vnc"
    MONGODB = "mongodb"
    POSTGRESQL = "postgresql"
    ELASTICSEARCH = "elasticsearch"
    TCP = "tcp"  # 通用TCP服务
    UNKNOWN = "unknown"  # 端口开放但无法识别
    NONE = "none"  # 端口未开放/无响应


@dataclass
class ServiceProbe:
    """服务探测配置"""

    service_type: Service
    probe_data: Optional[bytes]  # 主动探测数据，None表示仅被动接收
    match_patterns: list[bytes]  # 响应匹配规则
    priority: int = 1  # 优先级，数字越小优先级越高


# 统一的服务探测规则配置（按优先级排序）
SERVICE_PROBES = [
    # 高优先级：常见服务
    ServiceProbe(
        service_type=Service.HTTPS,
        probe_data=b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03",  # 简化的ClientHello
        match_patterns=[
            b"\x16\x03\x01",  # TLS 1.0 ServerHello
            b"\x16\x03\x03",  # TLS 1.2 ServerHello
            b"\x15\x03",  # TLS Alert
        ],
        priority=1,
    ),
    ServiceProbe(
        service_type=Service.HTTP,
        probe_data=b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        match_patterns=[b"http/", b"<html", b"<head", b"<!doctype", b"server:"],
        priority=1,
    ),
    ServiceProbe(
        service_type=Service.SSH,
        probe_data=None,
        match_patterns=[b"ssh-"],
        priority=1,
    ),
    # 中优先级：数据库服务
    ServiceProbe(
        service_type=Service.MYSQL,
        probe_data=None,
        match_patterns=[b"\x00\x00\x00\x0a", b"mysql", b"\x4a\x00\x00\x00\x0a"],
        priority=2,
    ),
    ServiceProbe(
        service_type=Service.REDIS,
        probe_data=b"PING\r\n",
        match_patterns=[b"+pong", b"-noauth", b"-err", b"redis"],
        priority=2,
    ),
    ServiceProbe(
        service_type=Service.POSTGRESQL,
        probe_data=None,
        match_patterns=[b"postgres", b"invalid length of startup packet"],
        priority=2,
    ),
    ServiceProbe(
        service_type=Service.MONGODB,
        probe_data=None,
        match_patterns=[b"mongodb", b"version"],
        priority=2,
    ),
    # 低优先级：其他服务
    ServiceProbe(
        service_type=Service.FTP,
        probe_data=None,
        match_patterns=[b"220 ", b"220-", b"ftp"],
        priority=3,
    ),
    ServiceProbe(
        service_type=Service.SMTP,
        probe_data=b"EHLO probe\r\n",
        match_patterns=[b"220 ", b"smtp", b"esmtp", b"mail"],
        priority=3,
    ),
]

# 按优先级排序
SERVICE_PROBES.sort(key=lambda x: x.priority)


def create_socket() -> socket.socket:
    """创建并优化socket配置"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
    # 启用TCP keepalive
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setblocking(False)
    return sock


def match_service(data: bytes) -> Optional[Service]:
    """统一的服务匹配逻辑"""
    if not data:
        return None

    data_lower = data.lower()

    # 特殊规则优先匹配
    # FTP: 220开头且包含ftp
    if data.startswith(b"220") and b"ftp" in data_lower:
        return Service.FTP

    # SMTP: 220开头且包含smtp/mail/esmtp
    if data.startswith(b"220") and any(
        kw in data_lower for kw in [b"smtp", b"esmtp", b"mail"]
    ):
        return Service.SMTP

    # 遍历所有探测规则（按优先级）
    for probe in SERVICE_PROBES:
        for pattern in probe.match_patterns:
            if pattern.lower() in data_lower:
                return probe.service_type

    return None


async def passive_banner_probe(
    ip: str, port: int, timeout: float
) -> tuple[bool, Optional[Service]]:
    """
    被动探测：建立独立连接后等待服务器主动发送banner
    返回: (连接是否成功, 服务类型)
    """
    sock = None
    try:
        sock = create_socket()

        await asyncio.wait_for(
            asyncio.get_event_loop().sock_connect(sock, (ip, port)), timeout=timeout
        )

        # 等待接收banner（部分服务会主动发送）
        data = await asyncio.wait_for(
            asyncio.get_event_loop().sock_recv(sock, 2048), timeout=1.5
        )

        service_type = match_service(data)
        return True, service_type

    except asyncio.TimeoutError:
        # 超时但连接成功
        return True, None
    except Exception:
        return False, None
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


async def active_probe(
    ip: str, port: int, timeout: float
) -> tuple[bool, Optional[Service]]:
    """
    主动探测：为每种探测创建独立连接并并行发送
    返回: (连接是否成功, 服务类型)
    """
    # 只探测有probe_data的服务（按优先级）
    active_probes = [p for p in SERVICE_PROBES if p.probe_data is not None]

    # 创建任务列表
    async def probe_with_single_connection(
        probe: ServiceProbe,
    ) -> Optional[Service]:
        if probe.probe_data is None:
            return None
        sock = None
        try:
            sock = create_socket()
            await asyncio.wait_for(
                asyncio.get_event_loop().sock_connect(sock, (ip, port)),
                timeout=timeout / 2,
            )
            await asyncio.get_event_loop().sock_sendall(sock, probe.probe_data)
            data = await asyncio.wait_for(
                asyncio.get_event_loop().sock_recv(sock, 2048), timeout=timeout / 2
            )

            # 检查响应是否匹配当前探测规则
            data_lower = data.lower()
            for pattern in probe.match_patterns:
                if pattern.lower() in data_lower:
                    return probe.service_type

            # 使用通用匹配逻辑尝试识别其他服务
            return match_service(data)
        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

    # 并行执行所有探测
    tasks = [
        asyncio.create_task(probe_with_single_connection(probe))
        for probe in active_probes
    ]

    try:
        # 等待第一个成功的结果或所有任务完成
        for task_completed in asyncio.as_completed(tasks, timeout=timeout):
            try:
                result = await task_completed
                if result:
                    # 找到服务类型，取消其他任务
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    return True, result
            except Exception:
                pass

        # 检查是否有任务成功完成但未识别到服务
        connected = False
        for task in tasks:
            if task.done() and not task.cancelled() and not task.exception():
                connected = True
                break

        return connected, None
    except asyncio.TimeoutError:
        # 所有任务超时
        return False, None
    finally:
        # 确保所有任务都被取消并清理
        for task in tasks:
            if not task.done():
                task.cancel()


async def probe_service(ip: str, port: int, timeout: float = 2.5) -> Service:
    """
    异步探测单个端口服务

    同时启动两个独立的探测方式：
    1. 被动探测：等待接收服务器banner
    2. 主动探测：并行发送多种探测数据，每种用独立连接

    一旦任一方式匹配到协议特征，立即取消其他任务并返回结果
    """
    passive_task = asyncio.create_task(passive_banner_probe(ip, port, timeout))
    active_task = asyncio.create_task(active_probe(ip, port, timeout))

    connected = False

    try:
        # 等待任一任务完成
        done, pending = await asyncio.wait(
            {passive_task, active_task}, return_when=asyncio.FIRST_COMPLETED
        )

        # 处理已完成的任务
        for task in done:
            try:
                task_connected, service_type = task.result()

                # 记录连接状态
                if task_connected:
                    connected = True

                # 如果识别出服务类型，取消其他任务并返回
                if service_type:
                    for p in pending:
                        p.cancel()
                    return service_type
            except Exception:
                pass

        # 处理剩余任务
        if pending:
            try:
                done2, _ = await asyncio.wait(pending, timeout=timeout / 2)
                for task in done2:
                    try:
                        task_connected, service_type = task.result()
                        if task_connected:
                            connected = True
                        if service_type:
                            return service_type
                    except Exception:
                        pass
            except Exception:
                pass
            finally:
                for task in pending:
                    if not task.done():
                        task.cancel()

        # 所有探测完成但未识别服务
        return Service.UNKNOWN if connected else Service.NONE

    except Exception:
        return Service.NONE
    finally:
        # 清理任务
        for task in [passive_task, active_task]:
            if not task.done():
                task.cancel()


def get_optimal_concurrency(port_count: int) -> int:
    """根据端口数量自动计算最优并发数"""
    if port_count <= 10:
        return port_count  # 少量端口，全并发
    elif port_count <= 50:
        return 20  # 中等数量
    elif port_count <= 200:
        return 50  # 较多端口
    else:
        return 100  # 大量端口


async def detect_services_async(
    target: tuple[str, list[int]], timeout: float = 2.5
) -> list[tuple[int, Service]]:
    """
    异步并发探测所有端口

    Args:
        target: (ip, ports)
        timeout: 单个端口探测超时时间

    Returns:
        [(端口, 服务类型), ...]
    """

    ip, ports = target

    # 过滤有效端口（已经是 int 了，直接使用）
    valid_ports = [p for p in ports if isinstance(p, int) or str(p).isdigit()]
    valid_ports = [int(p) for p in valid_ports]

    # 自动计算最优并发数
    max_concurrent = get_optimal_concurrency(len(valid_ports))
    semaphore = asyncio.Semaphore(max_concurrent)

    async def probe_with_limit(port: int) -> tuple[int, Service]:
        async with semaphore:
            return port, await probe_service(ip, port, timeout)

    # 并发探测所有端口
    tasks = [probe_with_limit(port) for port in valid_ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 处理结果
    valid_results: list[tuple[int, Service]] = []
    for i, result in enumerate(results):
        if isinstance(result, tuple) and len(result) == 2:
            port, service = result
            if isinstance(port, int) and isinstance(service, Service):
                valid_results.append((port, service))
            else:
                valid_results.append((valid_ports[i], Service.NONE))
        else:
            valid_results.append((valid_ports[i], Service.NONE))

    return sorted(valid_results, key=lambda x: x[0])


def detect_services_fast(
    target: tuple[str, list[int]], timeout: float = 2.5
) -> list[tuple[int, Service]]:
    """
    并发探测所有端口（同步接口封装）

    Args:
        target: 目标组
        timeout: 超时时间（默认2.5秒）

    Returns:
        [(端口, 服务类型), ...]
    """
    return asyncio.run(detect_services_async(target, timeout))


if __name__ == "__main__":
    print(detect_services_fast(("127.0.0.1", 8080)))