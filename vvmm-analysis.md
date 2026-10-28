# VVMM — 分析记录（未完成）

## 题目

`VVMM.exe`（PE32+ x86-64, 47KB）—— 自带反汇编器的字节码 VM：

```
check <candidate>   执行 VM 并输出 ACCEPT/REJECT
run <candidate>     执行并输出报告（steps/pc/acc/zero/halt）
disasm [count]      反汇编 VM 指令
layout              VM 镜像信息
```

## layout

```
vm container  : VMC2 / multi-entry encrypted bytecode
vm blob bytes : 20016
entries       : 2
program bytes : 19696
instructions  : 2462
registers     : 8 x u32
memory        : 128 bytes
rounds        : 7 global rounds
```

## 程序结构（disasm）

- 每条指令 8 字节：opcode + 3 个操作数 + imm32；
- 入口 0x18：先对输入 31 字节逐字节做 `LDB → XORI → ADDI → ROLI → STAGE → STM`；
- 随后 7 轮混合：`LDM r0,i; LDM r1,j; ADDR r0,r1; LDM r1,k; XORR r0,r1; ROLI; ADDI; STM r0,i`；
- 最后逐字节 `LDM r0,i; CMPI8 r0, imm; JNZ reject`，共 31 个期望值：
  `fd bd 28 ce b1 91 f6 39 d7 e5 31 8e 96 d7 02 15 f0 9b 38 bd ...`

## 已尝试

- 逐字节逆变换（忽略 7 轮混合）→ 乱码；
- 8 位语义反向执行 → 乱码；
- 32 位语义反向执行 → 乱码（寄存器活跃性问题）；
- z3 符号执行（32 位寄存器 + 32 位内存 + 低字节约束）→ 运行 >20 分钟未出结果；
- 混合模型（8 位内存 + 32 位寄存器）→ UNSAT；
- 纯 8 位模型 → UNSAT；
- 步数 oracle：任意错误输入的 steps 都是 2370，无法按字节定位；
- `acc` 随输入变化（A→0x50, B→0x4e, 0x00→0x14, 0x01→0x6e, D→0x4f），但无法对应到单个字节。

## 结论

需要精确的 VM 语义（寄存器位宽、内存元素宽度、操作数顺序），
或对 VVMM.exe 的解释器做完整逆向。时间不足。
