import re
import socket
import ssl
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Union


@dataclass
class RawResponse:
    """原始HTTP响应结构"""

    ok: bool
    error: str
    resp: bytes

    def __bool__(self) -> bool:
        """支持 if response: 的用法"""
        return self.ok

    def text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        """将响应解码为文本"""
        return self.resp.decode(encoding, errors=errors)

    def status_line(self) -> str:
        """提取HTTP状态行"""
        if not self.ok:
            return ""
        try:
            first_line = self.resp.split(b"\r\n")[0]
            return first_line.decode("utf-8", errors="replace")
        except Exception:
            return ""


def _extract_host_and_port(raw: bytes) -> Optional[Tuple[str, Optional[int]]]:
    """从原始HTTP请求中提取Host头和端口

    返回:
        (host, port) 元组，port 可能为 None
        如果提取失败返回 None
    """
    try:
        lower = raw.lower()
        key = b"\r\nhost:"
        idx = lower.find(key)
        if idx == -1:
            return None

        start = idx + len(key)
        end = lower.find(b"\r\n", start)
        if end == -1:
            end = len(raw)

        host_value = raw[start:end].strip().decode()

        # 处理 IPv6 地址格式 [::1]:8080
        if host_value.startswith("["):
            bracket_end = host_value.find("]")
            if bracket_end != -1:
                host = host_value[1:bracket_end]
                port_part = host_value[bracket_end + 1 :]
                if port_part.startswith(":"):
                    try:
                        port = int(port_part[1:])
                        return (host, port)
                    except ValueError:
                        pass
                return (host, None)

        # 处理普通 host:port 格式
        if ":" in host_value:
            parts = host_value.rsplit(":", 1)  # 从右侧分割一次
            try:
                return (parts[0], int(parts[1]))
            except (ValueError, IndexError):
                pass

        return (host_value, None)
    except Exception:
        return None


def _parse_headers(header_bytes: bytes) -> Tuple[Dict[str, str], bytes]:
    """解析HTTP响应头"""
    headers = {}
    header_separator = b"\r\n\r\n"
    separator_index = header_bytes.find(header_separator)
    if separator_index == -1:
        header_part = header_bytes
        body_part = b""
    else:
        header_part = header_bytes[:separator_index]
        body_part = header_bytes[separator_index + len(header_separator) :]

    header_lines = re.split(b"\r\n", header_part)
    for line in header_lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers[key.decode("utf-8").strip().lower()] = value.decode("utf-8").strip()

    return headers, body_part


def send_raw_request(
    raw_request: bytes,
    port: Optional[int] = None,
    host: Optional[str] = None,
    use_ssl: bool = False,
    verify_ssl: bool = False,
    timeout: int = 8,
    max_response_size: int = 3 * 1024 * 1024,
) -> RawResponse:
    """
    发送原始HTTP请求并接收响应
    """
    conn = None

    try:
        if not port or not host:
            host_port = _extract_host_and_port(raw_request)
            if not host_port:
                return RawResponse(
                    ok=False, error="Host header not found in request", resp=b""
                )
            if not port and not host_port[1]:
                port = 443 if use_ssl else 80
            elif not port:
                port = host_port[1]

            if not host and not host_port[0]:
                return RawResponse(ok=False, error="Host header error", resp=b"")
            elif not host:
                host = host_port[0]

        # 创建TCP连接
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except socket.timeout:
            return RawResponse(
                ok=False, error=f"Connection timeout to {host}:{port}", resp=b""
            )
        except socket.gaierror as e:
            return RawResponse(
                ok=False, error=f"DNS resolution failed for {host}: {str(e)}", resp=b""
            )
        except ConnectionRefusedError:
            return RawResponse(
                ok=False, error=f"Connection refused to {host}:{port}", resp=b""
            )
        except OSError as e:
            return RawResponse(ok=False, error=f"Network error: {str(e)}", resp=b"")

        # SSL包装
        if use_ssl:
            try:
                if verify_ssl:
                    context = ssl.create_default_context()
                else:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                conn = context.wrap_socket(sock, server_hostname=host)
            except ssl.SSLError as e:
                sock.close()
                return RawResponse(ok=False, error=f"SSL error: {str(e)}", resp=b"")
            except Exception as e:
                sock.close()
                return RawResponse(
                    ok=False, error=f"SSL handshake failed: {str(e)}", resp=b""
                )
        else:
            conn = sock

        try:
            conn.settimeout(timeout)
            conn.sendall(raw_request)
        except socket.timeout:
            return RawResponse(ok=False, error="Send timeout", resp=b"")
        except Exception as e:
            return RawResponse(ok=False, error=f"Send failed: {str(e)}", resp=b"")

        header_data = b""
        body_start = b""
        header_separator = b"\r\n\r\n"

        try:
            while header_separator not in header_data:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                header_data += chunk

                if len(header_data) > max_response_size:
                    return RawResponse(
                        ok=False,
                        error="Response headers too large or invalid",
                        resp=header_data,
                    )

            if header_separator in header_data:
                separator_index = header_data.find(header_separator)
                body_start = header_data[separator_index + len(header_separator) :]
                header_data = header_data[: separator_index + len(header_separator)]

        except socket.timeout:
            if not header_data:
                return RawResponse(
                    ok=False,
                    error="Timeout while waiting for response headers",
                    resp=b"",
                )
        headers, _ = _parse_headers(header_data)
        content_length_str = headers.get("content-length")
        content_length = (
            int(content_length_str)
            if content_length_str and content_length_str.isdigit()
            else None
        )

        response_parts = [header_data, body_start]
        total_received = len(header_data) + len(body_start)

        if content_length is not None:
            body_length_to_read = content_length - len(body_start)

            while body_length_to_read > 0:
                if total_received > max_response_size:
                    return RawResponse(
                        ok=False,
                        error=f"Response exceeded maximum size limit of {max_response_size} bytes",
                        resp=b"".join(response_parts),
                    )

                try:
                    chunk = conn.recv(min(body_length_to_read, 65536))
                    if not chunk:
                        break
                    response_parts.append(chunk)
                    body_length_to_read -= len(chunk)
                    total_received += len(chunk)
                except socket.timeout:
                    return RawResponse(
                        ok=False,
                        error="Timeout while receiving response body (Content-Length specified)",
                        resp=b"".join(response_parts),
                    )
                except Exception as e:
                    return RawResponse(
                        ok=False,
                        error=f"Receive error: {str(e)}",
                        resp=b"".join(response_parts),
                    )

        else:
            while True:
                if total_received > max_response_size:
                    return RawResponse(
                        ok=False,
                        error=f"Response exceeded maximum size limit of {max_response_size} bytes",
                        resp=b"".join(response_parts),
                    )
                try:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    response_parts.append(chunk)
                    total_received += len(chunk)
                except socket.timeout:
                    break
                except Exception as e:
                    return RawResponse(
                        ok=False,
                        error=f"Receive error: {str(e)}",
                        resp=b"".join(response_parts),
                    )

        response_data = b"".join(response_parts)

        if not response_data:
            return RawResponse(
                ok=False, error="No response received from server", resp=b""
            )

        return RawResponse(ok=True, error="", resp=response_data)

    except Exception as e:
        return RawResponse(ok=False, error=f"Unexpected error: {str(e)}", resp=b"")

    finally:
        if conn:
            try:
                # 无论如何，最后都关闭连接
                conn.close()
            except Exception:
                pass


def repeater(
    raw_request: Union[str, bytes],
    port: Optional[int] = None,
    host: Optional[str] = None,
    use_ssl: bool = False,
    verify_ssl: bool = False,
    timeout: int = 8,
    max_response_size: int = 3 * 1024 * 1024,
) -> RawResponse:
    """
    send_raw_request 的包装器：
    - 支持 str / bytes 输入
    - str 自动转换为 HTTP 原始请求格式
    """

    if isinstance(raw_request, str):
        raw_request = raw_request.replace("\n", "\r\n").encode("utf-8")

    return send_raw_request(
        raw_request=raw_request,
        port=port,
        host=host,
        use_ssl=use_ssl,
        verify_ssl=verify_ssl,
        timeout=timeout,
        max_response_size=max_response_size,
    )


if __name__ == "__main__":
    http_request_local = """
GET /index.php?m=--><?=phpinfo();?> HTTP/1.1
Host: 192.168.192.148:30803

""".replace("\n", "\r\n").encode("utf-8")
    response_local = send_raw_request(raw_request=http_request_local)
    if response_local.ok:
        print(f"✓ 成功, 响应大小: {len(response_local.resp)} 字节")
        print(f"状态行: {response_local.status_line()}")
        print(f"\n响应预览:\n{response_local.text()}")
    else:
        print(f"✗ 失败: {response_local.error}")
