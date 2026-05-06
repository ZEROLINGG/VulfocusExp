import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _BaseHttpServer:
    def __init__(self, port, verbose):
        self.host = "0.0.0.0"
        self.port = port
        self.verbose = verbose
        self._server = None
        self._thread = None

    def _make_handler(self):
        raise NotImplementedError

    def start(self):
        if self._server:
            return self
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if not self._server:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join()
        self._server = None
        self._thread = None

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


class HttpEcho(_BaseHttpServer):
    def __init__(self, on_body=None, port=8000, verbose=False):
        super().__init__(port, verbose)
        self.on_body = on_body or (lambda body: None)

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

            def log_message(self, _format, *args):
                if verbose:
                    super().log_message(_format, *args)

        return CustomHandler


class HttpFile(_BaseHttpServer):
    def __init__(self, files: dict[str, bytes | str], port=8001, verbose=False):
        super().__init__(port, verbose)
        self.files = files

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
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, _format, *args):
                if verbose:
                    super().log_message(_format, *args)

        return FileDownloadHandler


if __name__ == "__main__":
    from base import run_cmd

    def handle_body(body):
        print(body.decode())

    # with 用法
    with HttpEcho(handle_body, verbose=True):
        run_cmd("curl http://0.0.0.0:8000 -d 'HttpEcho with logs'")

    with HttpFile({"abc.txt": b"HttpFile"}, verbose=True):
        cr = run_cmd("curl http://0.0.0.0:8001/abc.txt -o /tmp/abc.txt;cat /tmp/abc.txt")
        print(cr.output)

    # 传统用法保持兼容
    http = HttpEcho(handle_body, port=80, verbose=True)
    http.start()
    input(">")
    http.stop()