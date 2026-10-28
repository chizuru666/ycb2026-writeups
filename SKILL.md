---
name: ctf-misc-reverse-playbook
description: Use for CTF misc/reverse/forensics challenges that ship game builds (Unreal/Unity/APK), custom VM bytecode, 4D Gaussian-splatting point clouds, CS:GO skin images, typewriter/typeball ciphers, or tiny stack-overflow binaries. Contains the concrete toolchain (retoc+Oodle, CUE4Parse/FModel/usmap, astcenc, adb, z3) and the failure modes learned from 2026 羊城杯初赛.
---

# CTF Misc / Reverse Playbook（2026 羊城杯复盘）

## 0. 总原则

1. **先判类型，再选工具链**。5 分钟内必须回答：这是 ①游戏包（APK/OBB/Paks）②自定义 VM ③4D/点云 ④图像隐写 ⑤密码/机械密码 ⑥pwn。
2. **模型假设要尽早用最小实验证伪**（例如：渲染一帧能否出字、VM 反向执行是否给出 0–255）。
3. **工具要预装**，不要比赛现场编译/下载（见第 8 节清单）。
4. **单题时间盒 40 分钟**：到点必须换题或换路线，把假设写进 WP 交接。
5. 赛后第一时间搜 WP（微信文章 + GitHub + 博客），把“没做出来”的题按下面模板归因。

## 1. Unreal Engine 游戏题（APK + OBB + IoStore）

### 1.1 解包链

```bash
# 1) APK 里的 OBB 通常是 assets/main.obb.png（其实是 zip）
unzip apk/assets/main.obb.png -d apk/obb

# 2) 安装/编译 retoc（必须用支持 EIoContainerHeaderVersion=5 的新版）
git clone https://github.com/trumank/retoc && cd retoc
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release

# 3) Oodle 运行库（retoc 的 oodle_loader 会去 GitHub 下，SSL 失败时手动放）
curl -L 'https://ghproxy.net/https://github.com/WorkingRobot/OodleUE/raw/refs/heads/main/Engine/Source/Programs/Shared/EpicGames.Oodle/Sdk/2.9.10/linux/lib/liboo2corelinux64.so.9' \
  -o target/release/liboo2corelinux64.so.9
# 期望 sha256 ed7e98f70be1254a80644efd3ae442ff61f854a2fe9debb0b978b95289884e9c

# 4) 列 chunk / 全量转 legacy
retoc list <Paks>/*.utoc
retoc to-legacy <Paks> leg_full      # 成功输出形如 Extracted 414 (0 failed)
```

**关键现象与处置**

| 现象 | 原因 | 处置 |
|---|---|---|
| `invalid EIoContainerHeaderVersion value: 5` | retoc 太旧 | 用 master 重新编译 |
| 资源转换 0 failed 但只有 Engine 资源 | CTFGame 资源在另一个容器 | 传整个 `Paks/` 目录而不是单个 utoc |
| `Failed to find decompression method` / 全部失败 | 缺 Oodle | 放 `liboo2corelinux64.so.9` |
| `global.utoc` 只有 1 个 chunk `ScriptObjects` | 名字池，不是代码 | 游戏逻辑在 C++/Verse/蓝图，继续找 |

### 1.2 资源解析（unversioned properties 是最大坑）

UE5 cooked 包默认 **unversioned properties**：

- `UAssetAPI` 会全部返回 `RawExport`；
- `CUE4Parse` 直接抛 `MappingException: Package has unversioned properties but mapping file is missing`。

**结论：没有 `.usmap` 就解不出属性/蓝图字节码。** 优先找游戏自带 usmap；没有就：

1. 用 **FModel**（GUI，按 IoStore 原生读取，最省事）；
2. 或 CUE4Parse 的 `JsonTypeMappingsProvider` / 自实现 `ITypeMappingsProvider`（`TypeMappings{Types, Enums}`，`Struct(name, super, props, count)` + `PropertyInfo(index, name, PropertyType)`）；
3. 或 `UnrealMappingsGenerator` 从引擎 .so 的 UObject 注册生成 usmap。

**不需要 usmap 的旁路技巧（很灵）**：

- **导入表顺序**能读出控件→贴图映射（UMG 按引用顺序建 import）；
- 在 `.uexp` 里直接搜导入索引（int32）序列，形状如 `42,43,...,57` 就是 16 个 tile 的绑定顺序；
- 若序列是 identity，说明题目没有用排列编码，别在这上面浪费时间。

### 1.3 贴图解码

先读 **文件头**（不要盲扫）：

```
offset 6  : SizeX (u32 LE)
offset 10 : SizeY
offset 96 : "PF_ASTC_6x6" / "PF_B8G8R8A8" ...
payload   : len - ceil(W/6)*ceil(H/6)*16（ASTC 6x6）
            len - W*H*4（BGRA8）
```

- ASTC 用 **astcenc**（`apt install astcenc`），不要用 `texture2ddecoder`（部分块会段错误）：
  ```bash
  # 构造 .astc 头：13 AB A1 5C + block(6,6,1) + dims(3B each) + payload
  astcenc -dl in.astc out.png -silent
  ```
- 先判断是否压缩：尺寸精确等于 ASTC 块数 → 明文；显著更小 → Oodle/zstd。
- Oodle 用 ctypes 调 `OodleLZ_Decompress` 验证（返回 0 即不是 Oodle）。
- 贴图可能是 **1600×900 BGRA8**（未压缩背景图），别默认 ASTC。

### 1.4 动态（最终手段）

题目提示“真机/模拟器均测试通过”= 允许模拟器：

```bash
adb install -r game.apk
adb push obb /sdcard/Android/obb/<pkg>/
adb shell monkey -p <pkg> 1
adb shell input tap X Y     # 循环点击
adb logcat | grep -i flag
```

没有 adb/模拟器时：WSL 有 `/dev/kvm` + `qemu-system-x86_64` 时可跑 Android-x86；否则装 LDPlayer/MuMu（需管理员）。

## 2. CS:GO / CS2 皮肤题（“你喜欢cs吗”）

考点不是隐写，而是 **图案种子（pattern seed / paint index）**：

1. 图片是某把枪某皮肤的渲染图（黑底、固定机位）；
2. 用站点（csgostash / csgoskins）找到同皮肤的参考图，按尺寸裁剪对齐（常见：附件 1920×1296 对应参考 1920×1440，裁底部 144 行）；
3. 像素级对齐后，**图案编号**就是该图对应的 seed；
4. `seed → ASCII`（如 71→'G'、87→'W'…）直接得到 flag（可能是 `GWHT{...}`）。

**坑**：同一武器内部名不同（M4A4=`weapon_m4a1`，M4A1-S=`weapon_m4a1_silencer`）；相近皮肤只按颜色会混（USP-S Sleeping Potion 等），必须逐张核对页面。

## 3. Selectric 字球 / 机械打字机密码（Jammed）

场景：Correcting Selectric II，两张记录（A/B）是同一字球在两种卡位状态下的输出。

- 每个字符由 **行号 + 列号** 定位；
- A 页保留行号 **高位**，B 页保留 **低位**（或反之，需按数据验证）；
- 合并：`原始行 = (A_row & high_mask) | (B_row & low_mask)`，再查字球表取字符；
- 按序号连接两字符片段 → 48 字符密码 → 解 ZIP。

**教训**：不要一头扎进“QWERTY 移位/全排列”爆破；先假设机械结构（行/列位分离），用几对字符验证位运算假设。

## 4. 4D Gaussian Splatting 点云（Chronos-Vault）

### 4.1 数据

PLY 80,000 点 × 62 字段：`xyz(3) normal(3) f_dc(3) f_rest(45) opacity(1) logscale(3) quat(4)`。
`f_rest` 的 reshape 是 `(N,3,15)`（按通道），不是 `(N,15,3)`。

### 4.2 形变网络前向（Gaussian-Flow 系）

```
归一化: -xyz/6（aabb 上界在前，代入公式后就是 -p/6）
HexPlane: 每层 6 平面 xy,xz,xt,yz,yt,zt，同层平面特征相乘，两层拼接 → 32 维
输入编码: [f, sin(2f), cos(2f)] → 96 维（对应 feature_out.0 的 96）
位置: p(t) = p_orig * mask + dx   （mask 来自 empty_voxel，真实点恰为 0.5）
颜色: SH 按方向 d 求值（DC + rest），d 是待求的相机方向
```

### 4.3 解题流程

1. `opacity logit > 8` 过滤 → 70,560 点；按原始 z 分 6 组（各 11,760）；
2. 每组内部 7 个连通分量 = 厚度层（**不是 7 个字**）；
3. 对每组在 t 上搜索，使 7 层投影回平面时成为规则网格（平面性/仿射误差最小）→ 得到 6 个共振时刻；
4. 对每个时刻，搜索相机方向 d，使背景 RGB≈0、颜色有效；
5. 投影到 60×28 整数格（1680 点/层）→ 6 条 60×28 拼成 360×28 → 直接读字。

**教训**：形变网络的输出契约（mask、归一化方向、poc_fre）必须逐条与 checkpoint 形状对齐；只按“看起来像波浪”猜是错的。

## 5. 自定义 VM bytecode crackme（VVMM）

1. `.rdata` 里找容器（`VMC2` + 字节数 + entry 数）；
2. **解密入口**：容器多入口，其中一个是 **假入口**（magic `0xbadf00d`），必须丢弃；
3. `--disasm` 只是表象，真正校验在 31 个 `CMPI8` 常量；
4. 反向：逐条逆 `XORI/ADDI/ROLI/RORI/MULI`、`STM/LDM`、`ADDR/XORR`，以及 `STAGE` 的 32-bit mixer（初始 edx=0xA5，乘 0x9E3779B9）；
5. 逆完得到 31 字节 = candidate。

**教训**：正向执行 + 反向解释器要处理“寄存器初值未知”；更快的办法是把 opcode 语义完整实现后**正向符号执行**（z3）或直接逆（先确认每轮/每字节的变换是双射）。

## 6. 微型栈溢出 + 固定 read 调用点（Goodbye!shell）

- `read(0, rbp-0x20, 0x30)` 只溢出 saved rbp + RIP；
- 返回 `0x40122b`（read 调用点）形成循环：每次读 0x30 字节 = 0x20 数据 + 新 rbp + 新 RIP；
- 用这个循环把 ROP 链 **按 0x20 分块铺到一个可写页**，每块末尾写下一块的 rbp/RIP；
- 借 `seccomp_load@plt` 的调用（rdi 可控）泄漏 `write` 地址 → libc；
- 最后在同一页上做 `openat/read/write`（seccomp 只杀 execve/execveat）。

**教训**：溢出只有 0x10 时不要急着找 gadget；先找“**可重复的调用点**”，它本身就是任意写原语。

## 7. 赛后归因模板

| 题目 | 我们的路线 | WP 路线 | 失败根因 | 类型 |
|---|---|---|---|---|
| 2-1 Goodbye!shell | GOT 泄漏后卡在链空间 | 循环 read 铺链 + seccomp_load 泄漏 | 没想到调用点可循环铺链 | 思路 |
| 2-6 justledger | 未深入 | SQL 扩展劫持 + 窗口越界 + 格式化串 | 时间分配 | 执行 |
| 3-1 Chronos-Vault | 前向契约错、没做平面性搜索 | 见第 4 节 | 模型假设未验证 + 缺方法 | 方法 |
| 3-2 Jammed | 排列/移位爆破 | 字球行号高低位 | 假设错 | 思路 |
| 3-3 skin secret | LSB/差分隐写 | 皮肤 pattern seed | 领域知识/数据源缺失 | 领域 |
| 5-1 千千的咲 | UE 解包到蓝图，缺 usmap/模拟器 | 公开 WP 未覆盖 | 工具（usmap/模拟器） | 工具 |
| 6-1 VVMM | 反向解释器寄存器未知 | 解容器 + 丢假入口 + 逐字节逆 | 细节（假入口/STAGE mixer） | 细节 |
| 2-12 cacheline | 协议逆向 | 公开 WP 未覆盖 | 时间 | 执行 |

## 8. 预装工具清单（比赛前必须就绪）

| 工具 | 用途 | 安装 |
|---|---|---|
| retoc（master 编译） | UE IoStore 解包/转 legacy | `cargo build --release` |
| liboo2corelinux64.so.9 | Oodle 解压 | 见 1.1（sha256 校验） |
| FModel | UE 资源/贴图/蓝图 GUI | `D:\COMPETITIOM\YCB\tools\FModel\FModel.exe`（v4.4.4，已验证可启动；需 .NET 8 Desktop Runtime） |
| CUE4Parse (NuGet) | 脚本化解析 UE | `dotnet add package CUE4Parse`（需 .NET 10） |
| UAssetAPI (NuGet) | 轻量解析/导入表 | `dotnet add package UAssetAPI` |
| astcenc | ASTC 解码 | `apt install astcenc` |
| texture2ddecoder | 备选（会段错误） | `pip install texture2ddecoder` |
| scipy | 4DGS/聚类/优化 | `pip install --break-system-packages scipy` |
| z3-solver | VM/约束求解 | `pip install z3-solver` |
| adb + 模拟器 | APK 动态 | LDPlayer/MuMu 或 Android-x86+qemu |
| Chrome + CDP | 绕过微信反爬读 WP | `--remote-debugging-port=9222` |
| pypdfium2 | PDF 文本层 | `pip install pypdfium2` |

## 9. 赛后搜 WP 的正确姿势

1. 微信文章被反爬时，用本机 Chrome（CDP）打开真实浏览器；
2. 分享页（`/s/xxx`）正文只有摘要，真正文章 URL 在 HTML 里的 `__biz/mid/idx/sn`，拼成
   `https://mp.weixin.qq.com/s?__biz=...&mid=...&idx=1&sn=...&scene=45` 再抓；
3. 代码块在 `innerText` 里可能丢空格（`0for`、`whileTrue`），需要按编译错误逐个修；
4. GitHub 搜 `CTF-Archives/<year>-<event>` 通常有题目归档（README 只有题面，没有 flag）。
