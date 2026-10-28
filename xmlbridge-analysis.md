# xmlbridge — 阶段分析（未完成）

## 协议

`1 字节操作码 + 4 字节大端长度 + 正文`，普通返回 `OK\n`/`ERR\n`，文档返回 `DOC ` 前缀。

## 状态机（逆向自 xmlbridge，stripped）

全局状态 `0x60d0`：

| 状态 | 操作 | 要求 | 效果 |
|---|---|---|---|
| 0 | L | 根元素必须是 `<sheet>`，第一个子元素必须是 `<item>` | 保存 item 节点；state=1 |
| 1 | I | 根必须是 `<root>`，第一个子元素必须是 `<target>` | 新建 0x78 结构体；state=2 |
| 2 | R | 正文 ≤ 0x80 | `xmlNodeSetContent(template_item, body)`；state=3 |
| 3 | C | 无 | `xmlFreeNode(struct[0x18])` → **UAF**；state=4 |
| 4 | S | 无 | malloc struct2(0x78)、0x500 缓冲、0x80 缓冲；state=5 |
| 5 | E | 正文 ≤ 0x80 | `xmlNodeSetContent(root->children, body)` → 写已释放节点；state=6 |
| 6 | A | 无 | 建 push parser（外部实体加载器只允许 `file:///home/ctf/`）；state=7 |
| 7 | B | 需 well-formed 且 `0x60a0->[4]==1` | 输出 `DOC content`；state=8 |
| 8 | D | 需 `0x60a0->[4]==1` | 把正文发给归档服务（端口在 0x6010），返回其响应 |

## 关键点

- `C` 释放的 `<target>` 节点（0x78 字节）会被 `S` 的 `malloc(0x78)` 复用，`E` 的
  `xmlNodeSetContent(root->children, body)` 实际写的是 S 的结构体 → UAF 写。
- `B`/`D` 都检查 `0x60a0->[4] == 1`，但正常代码路径**从不置 1**（A 里 memset 为 0），
  必须靠堆破坏设置。
- Flag 在 `/home/ctf/flag`，只有 `oracle` 服务能读；`D` 会把正文转交给归档服务。

## 实测

- 正确序列：`L(<sheet><item>)` → `I(<root><target>)` → `R` → `C` → `S` → `E` → `A` 全部 OK；
- `B` 始终 ERR（门控未满足）；
- E 的正文 fuzz（空、A*0x40、0x7f 等）均无法让 B 通过。

## 结论

需要精确的堆布局/利用（tcache 复用 + 覆盖 `0x60a0+4`），本轮时间不足。
