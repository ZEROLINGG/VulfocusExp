import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class HttpEcho:
    def __init__(self, on_body=None, port=8000, verbose=False):
        self.host = "0.0.0.0"
        self.port = port
        self.on_body = on_body or (lambda body: None)
        self.verbose = verbose

        self._server = None
        self._thread = None

    def _make_handler(self):
        on_body = self.on_body
        verbose = self.verbose

        class CustomHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length)

                try:
                    on_body(body)
                except Exception as e:
                    print("on_body error:", e)

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, format, *args):
                if verbose:
                    super().log_message(format, *args)

        return CustomHandler

    def start(self):
        if self._server:
            return

        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if not self._server:
            return

        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join()

        self._server = None
        self._thread = None


class HttpFile:
    def __init__(self, files: dict[str, bytes | str], port=8001, verbose=False):
        """
        初始化文件下载服务器。
        :param files: 一个字典，键为提供给客户端的文件名，值为文件内容(bytes)或文件在服务器上的路径(str)。
        :param port: 服务器监听的端口。
        :param verbose: 是否打印HTTP访问日志，默认False。
        """
        self.host = "0.0.0.0"
        self.port = port
        self.files = files
        self.verbose = verbose

        self._server = None
        self._thread = None

    def _make_handler(self):
        files_to_serve = self.files
        verbose = self.verbose

        class FileDownloadHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                filename = self.path.lstrip("/")

                if filename not in files_to_serve:
                    self.send_error(404, "File Not Found")
                    return

                file_data_or_path = files_to_serve[filename]
                content = None

                try:
                    if isinstance(file_data_or_path, bytes):
                        content = file_data_or_path
                    elif isinstance(file_data_or_path, str):
                        with open(file_data_or_path, "rb") as f:
                            content = f.read()
                    else:
                        raise TypeError("File data must be bytes or a filepath string.")

                except FileNotFoundError:
                    self.send_error(404, "File Not Found on Server Disk")
                    return
                except Exception as e:
                    print(f"Error serving file {filename}: {e}")
                    self.send_error(500, "Internal Server Error")
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{filename}"'
                )
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()

                self.wfile.write(content)

            def log_message(self, format, *args):
                if verbose:
                    super().log_message(format, *args)

        return FileDownloadHandler

    def start(self):
        """启动HTTP服务器。"""
        if self._server:
            return

        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        """停止HTTP服务器。"""
        if not self._server:
            return

        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join()

        self._server = None
        self._thread = None


if __name__ == "__main__":
    from base import run_cmd

    def handle_body(body):
        print(body.decode())

    # 启用日志打印
    http = HttpEcho(handle_body, verbose=True)
    http.start()
    run_cmd("curl http://0.0.0.0:8000 -d 'HttpEcho with logs'")
    # run_cmd("sleep 333")
    http.stop()

    # 启用日志打印
    http = HttpFile({"abc.txt": b"HttpFile"}, verbose=True)
    http.start()
    cr = run_cmd("curl http://0.0.0.0:8001/abc.txt -o /tmp/abc.txt;cat /tmp/abc.txt")
    print(cr.output)
    http.stop()
