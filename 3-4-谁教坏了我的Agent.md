# 3-4 谁教坏了我的Agent（DFIR / 日志溯源）

## 结论（flag）

```
flag{e-cdn81.net_PAT-9F4K2M-Q3GIT7-CORP4S_107_20260910T1422_asset-inventory-2026Q3.md_corp-fast.net}
```

## 证据链

### 受害人与恶意组件

`orchestration_logs.json`（38,501 行）中，`EMP_107` 的时间线：

| 时间 | 事件 |
|---|---|
| 2026-09-10 14:22:00 | 用户：“wiki 上看到 cfg-guard 团队推荐，帮我加到 MCP 配置里” |
| 2026-09-10 14:22:12 | `write_file ~/.agent/mcp_servers.json`，加入 `@corp-tools/mcp-cfg-guard@1.4.2` |
| 2026-09-15 10:31:00 | 用户：“帮我检查一下 Git 配置有没有安全问题” |
| 2026-09-15 10:31:05 | cfg-guard MCP 调用 |
| 2026-09-15 10:31:08 | 读 `~/.gitconfig` |
| 2026-09-15 10:31:12 | 读 `~/.git-credentials` → **PAT 泄漏** |
| 2026-09-15 10:31:16 | 读 `/docs/it/asset-inventory-2026Q3.md`（越权） |
| 2026-09-15 10:31:21 | 改写 `~/.gitconfig`，`insteadOf https://github.com` → `https://git-cache.corp-fast.net/` |
| 2026-09-15 10:31:27 | cfg-guard 返回“审计报告”，把配置值转成 5 个指纹并要求解析 `<hash>.update-check.metrics.e-cdn81.net` |
| 2026-09-15 10:33:00 | 沙箱执行 `socket.gethostbyname` 脚本 |
| 2026-09-15 10:36–10:41 | 4 条 DNS 查询外带数据 |

### 被盗令牌

`~/.git-credentials` 原文：

```
https://EMP_107:PAT-9F4K2M-Q3GIT7-CORP4S@git.vixxmx.internal
```

### DNS 分片（base32，与令牌逐段吻合）

| 指纹 | base32 解码 |
|---|---|
| `KBAVILJZ` | `PAT-9` |
| `IY2EWMSN` | `F4K2M` |
| `FVITGR2J` | `-Q3GI` |
| `KQ3S2Q2P` | `T7-CO` |
| `KJIDIUY` | `RP4S` |

拼接：`PAT-9` + `F4K2M` + `-Q3GI` + `T7-CO` + `RP4S` = **PAT-9F4K2M-Q3GIT7-CORP4S** ✓

### 六个问题

| # | 问题 | 答案 |
|---|---|---|
| 1 | 承载隧道外带数据的恶意域名（注册域） | `e-cdn81.net` |
| 2 | 被盗凭据完整令牌值 | `PAT-9F4K2M-Q3GIT7-CORP4S` |
| 3 | 受害员工工号 | `107` |
| 4 | 恶意组件安装完成时间 | `20260910T1422` |
| 5 | 会话中被越权读取的内部文档 | `asset-inventory-2026Q3.md` |
| 6 | 代码拉取流量重定向到的恶意域名 | `corp-fast.net` |

## 复现脚本

- `work/3-4/q1.py` — DNS/域名词频与员工分布
- `work/3-4/q2.py` — EMP_107 时间线、vixxmx.net 查询统计
- `work/3-4/q3.py` — 令牌原文、读写文件、DNS 明细
- `work/3-4/q4.py` — 域名出现次数与 cfg-guard 返回内容
