# WEB 3 DataPulse — 分析记录（未完成）

> 状态：**未拿到 flag**。确认了 SSRF 与白名单绕过，卡在 admin 的角色/白名单双重校验。

## 1. 应用

- 靶机：`nc/8000 -> 1.14.76.59:32210`（gunicorn/Flask）
- 首页 `/`、`/login/`、`/register/`、`/dashboard/`、`/api/v1/status/`
- 注册/登录为 JSON API，返回 `api_token`（同时下发会话 cookie）
- Dashboard 功能：
  - `POST /tasks/create/`  body `{name, type, parameters:{data}, webhook_url}`
  - `GET /tasks/list/`
  - `POST /tasks/<id>/retry-webhook/` body `{url}`
  - `GET /tasks/<id>/webhook-logs/`（返回 url/status_code/response_body/error）
- 任务类型白名单：`csv_analysis` / `statistics` / `aggregation`

## 2. 已确认漏洞：Webhook SSRF + 校验绕过

`retry-webhook` 会用服务端身份请求任意 URL，并对内网地址做校验。以下写法**全部绕过**：

| Payload | 结果 |
|---|---|
| `http://127.0.0.1:8000/` | ❌ 被拦（URL validation failed） |
| `http://127.1:8000/` | ✅ 200，返回应用首页 |
| `http://2130706433:8000/` | ✅ 200 |
| `http://0177.0.0.1:8000/` | ✅ 200 |
| `http://127.0.0.1.nip.io:8000/` | ✅ 200 |
| `http://localhost:8000/` | ❌ 被拦 |
| `http://[::1]:8000/` | ❌ 被拦 |
| `file:///etc/passwd` | ❌ 被拦（只允许 http/https） |

内部端口探测：**只有 6379 (Redis) 开放**，其余（80/5000/8080/8001/3000/5432/2375 等）全部 connection refused。

## 3. 内部信息

`GET /api/v1/status/`（经 SSRF）返回：

```json
{"service":"DataPulse Analytics Platform","version":"2.4.1","status":"operational",
 "uptime":...,"components":{"web":"healthy","task_queue":"healthy","cache":"healthy"}}
```

`GET /api/v1/admin/` 返回：

```json
{"error":"Access denied","detail":"Your IP is not in the admin whitelist. Contact system administrator.",
 "required_role":"platform_admin","whitelist_check":"failed"}
```

- 外部 IP、`127.0.0.1`（SSRF）、容器公网出口 IP（`1.14.109.79`，经 webhook.site 观察到）**都过不了白名单**
- `X-Forwarded-For` / `X-Real-IP` / `Forwarded` 伪造无效
- 注册 `admin` / `platform_admin` 用户名无效；注册时传 `role`/`is_admin` 字段被忽略
- 默认口令（admin/admin、admin/admin123 等）无效

## 4. 其他确认

- **Webhook 回调携带任务结果**：用 webhook.site 抓到
  `{"task_id":"...","status":"completed","result":"{\"count\":4,\"mean\":2.5,...}"}`
- 任务 `data` 无 SSTI / eval：`{{7*7}}`、`__import__('os')...` 均按 CSV/数字解析
- `parameters` 传 `file`/`path`/`url` 不触发文件读取（返回 "No data provided"）
- 无源码泄露：`app.py`、`.git/HEAD`、`.env`、`backup.zip` 等均 404
- Redis 6379 开放，但 urllib/requests 不支持 gopher/dict，无法直接协议打 Redis

## 5. 卡点

Admin 接口要求 **platform_admin 角色 + IP 白名单** 双重条件，二者都无法通过现有原语满足：

- 角色：注册接口无 mass assignment，无 SQLi（登录参数化）
- 白名单：`request.remote_addr` 不可伪造；能拿到的源 IP（127.0.0.1 / 出口 IP）都不在白名单

可能的后续方向：
1. 通过 Redis 写 session/权限（需要 gopher 或 Redis 未授权 + 可写配置）
2. 找到泄露 `SECRET_KEY` 或 admin token 的端点
3. webhook 回调的 `result` 反序列化（若下游有服务消费）

## 5.1 第二轮补充（仍未解出）

| 测试 | 结果 |
|---|---|
| 会话机制 | `dp_session` = 32 位小写字母+数字随机串，服务端会话（存 Redis），非 Flask 签名 cookie |
| `GET /api/v1/profile/` | 返回 username/email/**role("analyst")**/api_token/created_at |
| `PATCH/PUT/POST /api/v1/profile/` | 均 200 但**任何字段都不落库**（改 email 也不变） |
| 注册时传 role=platform_admin/admin/superadmin | 一律被忽略，role 恒为 analyst |
| admin 鉴权顺序 | 未登录也是同一个 403（`whitelist_check: failed`）→ **IP 白名单在鉴权之前** |
| 内网 IP 扫描 172.17-22/10.0.x/192.168.1 的 :8000 | 全部 refused，应用只监听回环 |
| 任务名命令注入（`; sleep 5`、`$(sleep 5)`、反引号、`|`、`&&`） | 创建耗时均 ~0.1s，无注入 |
| `data` 字段是否为 URL 抓取（csv/statistics/aggregation） | 否，按 CSV/数字/JSON 解析 |
| 请求头透传（webhook 是否转发 Origin 请求的 XFF / X-API-Token / Cookie） | 否，SSRF 请求不带任何原请求头 |
| 回环变体 | `127.0.0.2` 可绕过 URL 校验（`127.0.0.1`/`0.0.0.0`/`localhost` 被拦），但 admin 仍 403 |

结论：admin 的 IP 白名单校验在鉴权前，且白名单内的 IP（既非 127.0.0.1、也非容器出口 1.14.109.79）
无法由 HTTP-only 的 SSRF 伪造或命中；Redis(6379) 虽有会话存储但 urllib 不支持 gopher/dict 协议。

## 5.2 第三轮补充

| 测试 | 结果 |
|---|---|
| 重定向绕过 scheme 校验（httpbin redirect-to） | ✅ 可 redirect 到 `http://127.1:8000/...`（IP 校验只查初始 URL）；❌ redirect 到 `file:///etc/passwd` 被 urllib 显式拒绝（"Redirection to url 'file://...' is not allowed"） |
| 登录/注册 SQL 注入（`' --`、`'#`、`OR 1=1`、`o'brien`） | 全部无效，注册含单引号用户名正常，登录参数化 |
| Host/vhost 路由（`admin.127.0.0.1.nip.io` 等 6 个子域） | 全部 403，Flask 无 vhost 路由 |
| 靶机公网端口（6379/8000/5000/8080/22/80） | 除分配的 32210 外全部 closed |
| 回环变体 | `127.0.0.2` 可绕过 URL 校验，但 admin 仍 403（源 IP 仍是 127.0.0.1） |



## 6. 复现脚本

| 文件 | 用途 |
|---|---|
| `work/datapulse/dp_auth.sh` | 注册/登录/取 dashboard |
| `work/datapulse/dp_ssrf.sh` `dp_ssrf2.sh` | 任务创建 + SSRF 初测 |
| `work/datapulse/dp_bypass.sh` | 校验绕过 payload 全集 |
| `work/datapulse/dp_probe.sh` `dp_ports.sh` | 内部路径/端口探测 |
| `work/datapulse/dp_hook.sh` | webhook.site 抓回调 |
| `work/datapulse/dp_inject.sh` `dp_params.sh` | 参数注入测试 |
