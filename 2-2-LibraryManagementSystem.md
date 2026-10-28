# 2-2 LibraryManagementSystem — 进展记录

## 平台侧

- 靶机：`nc/9999 -> 1.14.76.59:29762`
- **该端口不是 main.exe 本体**，而是一个 key 校验服务：
  ```
  Please contact pwn customer service to input key get flag
  key:
  ```
  输入错误返回 `Error!`。推测 key 是本地打通后应取得的凭据，需先完成本地利用。

## 本地环境（Windows 11 VM）

- VM：`D:\COMPETITIOM\YCB\Win11 x64 26h1\Windows 11 x64 26h1.vmx`
- 账号：`ctfer/123`（普通用户）、`Admin/123`（仅环境调试）
- 题目文件：`C:\Users\ctfer\main.exe`、`win_server.exe`
- flag：`C:\flag.txt`（15 字节，**ctfer 拒绝访问**，需管理员）

### 网络打通步骤

VM 原本没有可用网卡（APIPA）。处理：

1. 备份 vmx（`.bak3`），关机；
2. 追加：
   ```
   ethernet0.connectionType = "hostonly"
   ethernet0.startConnected = "TRUE"
   ```
3. 开机后 guest 获得 `192.168.245.128`；
4. Windows 防火墙默认 BlockInbound，用已知 Admin 凭据建计划任务放行 9999：
   ```
   schtasks /create /tn lmsfw /tr "netsh advfirewall firewall add rule name=lms dir=in action=allow protocol=TCP localport=9999" /sc once /st 23:59 /ru Admin /rp 123 /f
   schtasks /run /tn lmsfw
   ```
5. 服务启动：
   ```
   win_server.exe -p 9999 main.exe
   ```
   宿主机 `Test-NetConnection 192.168.245.128 -Port 9999` → True。
   **注意 WSL 到不了 VMnet 子网**，交互需在 Windows 侧（或 VM 内）进行。

## 关键发现：VM 里残留了前人的利用脚本

`C:\Users\ctfer\` 下有多份 09:05–10:13 留下的文件：

| 文件 | 内容 |
|---|---|
| `lib_uaf.ps1` | 完整的 UAF 利用流程（注册 17 人 → 管理员登录 → Add/Delete/Amend 毒化 LFH） |
| `lib_leak.ps1` | 读者 feedback（0xc8 字节）栈泄漏尝试 |
| `probe.ps1` | BabyMenu 驱动探测（另一题） |
| `out_leak.bin`/`uaf.bin` | 交互输出，含 `SSO Authorization Key: 0x...` |
| `ycb_copy.txt` | 内容 `HELLO`（可能是任意写测试目标） |

### 泄漏机制

每次注册读者都会打印：

```
SSO Authorization Key: 0x3433bcc5bdabe7bc
```

前人的脚本把它当作 LFH 指针的 XOR 密钥：

```powershell
$enc = $key -bxor [BitConverter]::ToUInt64([Text.Encoding]::ASCII.GetBytes('pass1234'), 0)
```

然后 `Amend` 把 8 字节 `$enc` 写进已释放的 48 字节 chunk（毒化 free list 的 next），
再连续 `Add` 触发分配落到目标地址。

前人把目标设成了 `pass1234` 的 ASCII（无效地址），因此失败（预期会崩溃）。

## 已确认的程序行为（静态+动态）

- 管理系统：主菜单 → 读者自助（注册/登录/feedback）或 管理员（口令）。
- 注册 17 人时，第 17 人的密码字段正好覆盖管理员口令缓冲区（`0x140019480`）→ 认证绕过。
- 记录槽 UAF：Delete 只 `HeapFree`，不清指针/长度；Amend 可写已释放 chunk；Inspect 打印它。
- 二进制 gadget 极少：有 `pop rcx;ret`、`pop rax;ret`、`jmp rsp`、`pop rsp;ret`，
  **无 `pop rdx/r8/r9`、无 syscall**。
- 未导入 `VirtualAlloc`/`VirtualProtect`；`.idata` 只读。

## 计划中的利用链（未完成）

1. 用 SSO key 编码 LFH next 指针，毒化到目标地址（如 `.data` 的函数指针表 `0x140013280` 或描述符表指针 `0x140019690`）；
2. 通过 Add/Amend 获得任意写；
3. 改描述符表指针 → Inspect/Amend 变成任意读写；
4. 找可执行目标：`.data` 函数指针表在启动后不再调用，需另找（退出表/SEH/栈返回地址）；
5. 由于本 VM 中服务以 ctfer 运行，即便拿到 shell 也读不了 `C:\flag.txt`（admin-only），
   远程靶机大概率以 admin 运行 main.exe。

## 结论

- 利用原语和交互已完全摸清，且有前人脚本可参考；
- 剩余工作：把 LFH 毒化目标定到可利用的函数指针，并处理 Windows 11 的 LFH/CFG 细节；
- 时间不足，未完成。

## 追加：毒化原语的实测结果

1. 前人脚本 `lib_uaf.ps1` 在 VM 里完整跑通：
   - 17 次注册成功（每次打印同一个 per-process `SSO Authorization Key`）
   - 管理员登录成功（`ARCHIVES ADMINISTRATION CONSOLE`）
   - Add/Delete/Amend 全部可用
   - **没有崩溃**（`Critical`/`Error` 计数为 0）

2. 但毒化没有生效：脚本用 `key ^ "pass1234"` 作为 LFH next，理论上下一次 Add 会返回
   非法地址 `0x3433323173736170` 并立即崩溃；实际程序继续运行。
   → **SSO Key 不是 LFH 编码密钥**（或编码公式还含 chunk 地址项）。

3. 用 `Inspect` 读已释放的 48 字节块（`probe_uaf.ps1`），输出为：

   ```
   >>> P\x01T
   ```

   即编码后的 next 指针前 3 字节是 `50 01 54`，第 4 字节是 `00`（被 `%s` 截断）。
   无调试器时无法从这 3 字节反推出完整编码。

4. 结论：要确定 LFH 编码公式，需要在 guest 里用 WinDbg 观察
   `_HEAP->LfhKey` / `RtlpHpHeapGlobals`；本 VM 无调试器、无网络、ctfer 无安装权限。

## 追加二：尝试直接求 K_c（编码 NULL 的值）

思路：如果让被释放块的 next 为 NULL，那么泄漏出来的编码值就是 `chunk>>4 ^ key`（记作 K_c），
之后毒化到目标 T 只需写 `T ^ K_c`，不必分别知道 key 和 chunk 地址。

实测（`leak_kc.ps1`：8 块全释放 → 再分配 8 块抽干 free list → 分配 slot 8 → 释放 → Inspect）：

```
>>> 50 01 bb \r\n
```

只有 **3 字节** `50 01 bb` 就被 NUL 截断。如果这是 64 位编码指针，值约为 `0x00bb0150`，
量级太小，不符合“随机 64 位 XOR 编码”的预期。

可能原因：
- 48 字节这个尺寸类在 Windows 11 上不走 LFH 编码的 freelist（走的是别的结构）；
- 或 chunk 首 8 字节并非 next 指针，而是 LFH 的其它元数据。

无论哪种，**没有调试器就无法确定**，毒化公式也因此无法写出。


