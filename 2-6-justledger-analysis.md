# 2-6 justledger — 分析记录（未完成）

## 服务

靶机 `nc 1.14.76.59:20244`，banner `justledger`，是一个 **SQLite SQL 控制台**：逐行读 SQL，执行后输出 `ROW <hex>` / `OK` / `ERR`。

附件包含：`justledger`（控制台）、`listener`、`ledgerbroker`、`ledgervault`、`ledgerprobe.so`（SQLite 扩展）、`libsqlite3.so.0`。

- 控制台启动时 `SELECT load_extension("/home/ctf/ledgerprobe.so")`（SQLite 自动补 `.so`）
- `CREATE VIRTUAL TABLE ledger USING ledgerprobe`，表结构 `x(record, seal HIDDEN)`

## 可用的 SQL 面

```sql
SELECT record, seal FROM ledger;   -- ROW "entry" / "-"
SELECT * FROM ledger;              -- 触发 "authorization denied"
PRAGMA database_list;              -- not authorized
ATTACH DATABASE '/flag' AS f;      -- not authorized / ERR
SELECT rowid FROM ledger;          -- ROW "1"
```

## 扩展导出的函数（from ledgerprobe.so 反汇编）

| 函数 | 参数 | 回调 | 语义线索 |
|---|---|---|---|
| `ledger_seed()` | 0 | 0x1a20 | 返回 "-" |
| `ledger_bind(a,b)` | 2 | 0x13b0 | 检查全局状态，调用宿主 `[api+0x6e8](xored_ptr, "ledger.lease")`，返回 `&0x5460` 才置状态位 `[0x5464]=1` |
| `ledger_make(blob96,a,b)` | 3 | 0x1680 | arg0 必须恰好 96 字节 BLOB；创建 0x2d8 记录，魔数 `0x524f5554`（"TOUR"），按 arg 类型填 vtable |
| `ledger_mark(blob8)` | 1 | 0x1b20 | — |
| `ledger_drop(x)` | 1 | 0x1a70 | — |
| `ledger_audit()` | 0 | 0x1bb0 | — |
| `ledger_touch(blob8)` | 1 | 0x15a0 | 把 blob 前 8 字节写到 `*[0x5410]`（潜在任意写） |
| `ledger_fire()` | 0 | 0x1460 | 校验 token（`[0x5110]^[0x53f0]` 旋转后与 `[0x5118]` 比较），再调宿主 lease 接口 |

## 实测

```
SELECT ledger_seed();                    -> ROW - / OK
SELECT ledger_bind(1,1);                 -> ROW - / OK
SELECT ledger_make(x'41'*96,0,0);        -> ERR ledger state
SELECT ledger_mark(x'00'*8);             -> ERR ledger state
SELECT ledger_touch(x'00'*8);            -> ERR ledger state
SELECT ledger_audit();                   -> ERR ledger state
SELECT ledger_fire();                    -> ERR ledger state
```

结论：`bind` 没有真正拿到宿主 lease（需要宿主 `[api+0x6e8]` 返回 `&0x5460`），因此状态机卡在状态 0，`make` 及其后全部 `ERR ledger state`。

## 漏洞点猜想

- `ledger_make` 按 SQLite 类型（int/float/text/blob）创建带 vtable 的记录对象，类型混淆可能改写函数指针
- `ledger_touch(blob8)` 把 8 字节写入 `*[0x5410]`，若 `[0x5410]` 可被前序对象控制，就是任意写
- `ledger_drop` 与 `ledger_mark` 的对象生命周期可能构成 UAF

正解需要先在宿主 lease 协议上拿到有效状态（可能与 `ledgerbroker`/`ledgervault` 的 socket 交互），再走内存破坏链读取 vault 中的 flag。远端只能从 SQL 侧操作，无法直接构造 lease。

## 复现脚本

- `work/2-6/probe.py` — 服务 banner 探测
- `work/2-6/sql.py` / `sql2.py` / `sql3.py` / `sql4.py` — 表结构与查询
- `work/2-6/probe_fn.py` — 各函数参数个数探测
- `work/2-6/seq.py` / `seq2.py` — 状态机顺序调用
- `work/2-6/attach.py` — ATTACH / hidden 列旁路
- `work/2-6/patch_local.py` / `patch2.py` — 本地运行补丁（模块路径）
