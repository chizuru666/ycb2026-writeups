# 2-6 本地环境配置记录

## 已完成

1. **sudo 可用**（免密），已创建 `/home/ctf` 并部署：
   ```
   /home/ctf/{justledger,ledgerbroker,ledgervault,listener,ledgerprobe.so,
              ld-linux-x86-64.so.2,libc.so.6,libm.so.6,libsqlite3.so.0}
   /home/ctf/flag   (测试 flag: DASCTF{local_test_flag_1234})
   ```

2. **工具**：patchelf、gdb、strace、r2、Ghidra headless 均可用；系统 libsqlite3 版本与附件不符，需要用附件自带的 `ld-linux + --library-path /home/ctf` 运行。

3. **服务拓扑**（反汇编 listener 得到）：
   ```
   listener:
     - TCP bind/listen/accept
     - fork; setuid
     - connect("/tmp/ledgerbroker.sock")  → dup2(fd, 3)
     - chdir("/home/ctf")
     - execve("/home/ctf/ld-linux-x86-64.so.2",
              ["/home/ctf/ld-linux-x86-64.so.2","--library-path","/home/ctf","/home/ctf/justledger"],
              environ)
   ledgervault : /tmp/ledgervault.sock，读 /home/ctf/flag
   ledgerbroker: /tmp/ledgerbroker.sock ↔ /tmp/ledgervault.sock
   ```

4. **模拟 listener**：`launcher2.py`（连 broker、fd 3、exec console、管道喂 SQL）。

## 当前卡点

`justledger` 本地运行后**静默退出**（rc=0），不读 stdin、无输出：

- 已确认扩展 `/home/ctf/ledgerprobe.so` 被 dlopen（strace 可见）
- 用系统 libsqlite3 时扩展 init 后 exit(0)；用附带 libsqlite3 时 SIGSEGV（说明 API 表版本敏感）
- 通过 broker fd 3 启动（模拟 listener）仍然无输出

嫌疑：`justledger` 需要 fd 3 上 broker 的**握手数据**（listener 只是把连接 dup 过去，broker 可能主动发一个 hello/lease），或者需要以特定 uid（setuid 后的用户）运行。

## 已知函数签名（远端验证 + 反汇编）

| 函数 | 参数 | 说明 |
|---|---|---|
| ledger_seed() | 0 | 返回 "-" |
| ledger_bind(a,b) | 2 | 调宿主打开 "ledger.lease"，成功才置 [0x5464]=1 |
| ledger_make(blob96,a,b) | 3 | 建 0x2d8 记录（魔数 "TOUR"） |
| ledger_mark(blob8) | 1 | — |
| ledger_drop(x) | 1 | — |
| ledger_audit() | 0 | — |
| ledger_touch(blob8) | 1 | 写 8 字节到 *[0x5410] |
| ledger_fire() | 0 | token 校验 + lease 调用 |

## 下一步（若环境能跑起来）

1. 用 gdb 跟 `ledger_bind` 里 `[api+0x6e8](xored_ptr, "ledger.lease")`，确认这是哪个 sqlite3 函数/宿主回调；
2. 在 broker/vault 侧下断点，看 fd 3 上是否有握手字节；
3. 环境跑通后即可动态调试 `make/mark/touch/drop` 的对象生命周期，找类型混淆/任意写。
