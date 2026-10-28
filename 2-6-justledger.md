# PWN 5 justledger — 逆向记录（未完成）

> 状态：**未拿到 flag**。已逆清虚拟表与状态机机制，卡在状态机的 lease 前置条件。

## 1. 架构

```
listener  --/tmp/ledgerbroker.sock-->  ledgerbroker  --/tmp/ledgervault.sock-->  ledgervault
                                                                                  └── /home/ctf/flag
justledger（SQLite shell）加载 /home/ctf/ledgerprobe.so 扩展
```

- 靶机：`nc/9999 -> 1.14.76.59:20244`，交互式 SQL，输出格式 `ROW <hex>` / `OK` / `ERR <msg>`
- SQLite 3.37.2，`sqlite3_enable_load_extension` 打开，authorizer 拒绝 `pragma function_list/module_list`
- 唯一表：`ledger`，schema 为 `CREATE VIRTUAL TABLE ledger USING ledgerprobe`
- 查询 `select * from ledger` 返回一行 `record = "entry"`，`select rowid from ledger` 返回 31

## 2. ledgerprobe.so 模块结构

`.data` 0x5000 处的 `sqlite3_module` 函数表（按 SQLite 布局）：

| 偏移 | 函数 | 地址 |
|---|---|---|
| xCreate/xConnect | 0x1940 | 声明 `CREATE TABLE x(record, seal HIDDEN)` |
| xBestIndex | 0x1270 | 只接受 `iColumn==1`(seal)、`op==EQ`、usable 的约束，设 argvIndex=1、omit=1、idxNum=3 |
| xDisconnect/xDestroy | 0x12e0 | – |
| xOpen | 0x14e0 | 分配 0x10 游标 |
| xClose | 0x1300 | **置全局 0x5468 = 1** |
| xFilter | 0x1330 | 要求 idxNum==3、argc==1；`0x5488 = argv[0] ^ 0x5480`；`0x5470 = [0x5478]`；**置 0x5468 = 0** |
| xNext/xEof | 0x1380/0x1390 | – |
| xColumn | 0x19d0 | col0 返回 "entry"，col1 返回 NULL |
| xRowid | 0x13a0 | 返回 1 |

### 注册的 SQL 函数（.rodata 0x302c–0x3082）

| 函数 | 参数 | 实现 | 作用 |
|---|---|---|---|
| `ledger_seed()` | 0 | 0x1a20 | 初始化 lease（调 `[api+0x6e0]`，参数 "ledger.lease"） |
| `ledger_bind(a,b)` | 2 | 0x13b0 | 校验 `0x5488!=0`、`0x5468!=0`、`0x5470!=[0x5478]`，通过则置 `0x5464=1` |
| `ledger_make(a,b,blob96)` | 3 | 0x1680 | 要求 state!=0 且第 3 参为 **96 字节 BLOB**；造对象（"TOUR" 魔数、表 0x5420、函数指针 0x1260） |
| `ledger_mark(i)` | 1 | 0x1b20 | 从表 0x5420[i] 取对象，存到 0x5410 |
| `ledger_drop(i)` | 1 | 0x1a70 | 释放/清空表项，写回编码指针 |
| `ledger_audit()` | 0 | 0x1bb0 | 用 0x5410 对象 +0x20 调 `[api+0x270]`（32 字节） |
| `ledger_touch(blob8)` | 1 | 0x15a0 | **写原语**：把 blob8 的 8 字节写到 `[0x5410]` 指向处 |
| `ledger_fire()` | 0 | 0x1460 | 校验 0x5110/0x5118 校验和，然后 **`jmp [0x5110]`** |

### 关键全局

```
0x5464  state（0/1）
0x5468  cursor 标志（xClose 置 1、xFilter 清 0）
0x5470/0x5478  lease 计数/副本
0x5480  getrandom cookie
0x5488  seal ^ cookie
0x5410  当前对象指针（mark 设置）
0x5420  8 项对象表
0x5110  fire 跳转目标（init 写入 (0x5110>>12)=5，看起来是占位/校验）
0x5118  fire 的校验和
```

### 还有一个 stdin↔fd3 代理循环（0x1c10）

poll(0,3) + read + sendmsg 双向转发——如果能把 0x5110 指向它，fire 就会把当前连接直接接到 vault 服务（fd 3），之后可手工说 vault 协议读 flag。

## 3. 卡点

`ledger_bind` 是 make 的前置（置 state=1），但它要求：

- `0x5468 != 0`：只有 xClose 置 1，而任何一次 xFilter 都会清 0；
- `0x5470 != [0x5478]`：xFilter 恰好把 0x5470 设成 `[0x5478]`，相等。

两者在“查询表→bind”的顺序下必然冲突；实测无论 `seed→table→bind`、`table→seed→bind`、`seed→table→seed→bind` 还是交错多次，`ledger_bind` 都返回 NULL（失败），随后 make 报 `ledger state`。

## 4. 已确认的原语（若突破状态机）

- `ledger_mark(i)` 把 0x5420[i] 指针对到 0x5410；
- `ledger_touch(blob8)` 往该指针写 8 字节 → **任意地址写 8 字节**；
- `ledger_fire()` 跳 `[0x5110]` → 若能用 touch 把 0x5110 改成 0x1c10（代理）或 system，即可拿 shell/直连 vault。

## 5. 复现脚本

| 文件 | 用途 |
|---|---|
| `work/justledger/conn.py` | 协议/banner 探测 |
| `work/justledger/sql1..6.py` | 表/函数枚举 |
| `work/justledger/seq1..5.py` | 状态机顺序实验 |
| `work/justledger/rev1.sh` `probe1.sh` `jstr.sh` | 二进制逆向 |
