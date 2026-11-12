# 企业门户本地登录撤销（Back-Channel Logout）演示

员工在统一身份源退出后，门户必须撤销其本地登录：**已有会话立即失效、在途登录不得建立会话、较晚的登录不受影响**。本仓库用 FastAPI + PyJWT + SQLite 实现该门户 API，并附带一个本地身份源（IdP）用于签发 RS256 令牌与推送注销通知。

## 架构

```
                ┌────────────────────────────┐
                │  idp  (本地身份源, :9000)    │
                │  /authorize  /token         │
                │  /logout  → 推送注销JWT ────┼──────────┐
                └──────────▲─────────────────┘          │
                           │ 授权码换身份JWT             ▼
        ┌──────────────────┴───┐          ┌────────────────────────┐
        │  portal1 (:8001)     │          │  portal2 (:8002)       │
        │  /login /me          │          │  /login /me            │
        │  /backchannel-logout │          │  /backchannel-logout   │
        └──────────┬───────────┘          └───────────┬────────────┘
                   │        共享命名卷 portal-data      │
                   └──────►  SQLite  portal.db  ◄──────┘
```

- **身份 JWT**（RS256）：`sub`、`sid`、`iat`、`exp`、`purpose="identity"`（另含 `iss`/`aud`/`jti`）。
- **注销 JWT**（RS256）：`iat`、`exp`、`jti`、`purpose="logout"`，以及唯一目标 `sid` 或 `sub`（两者同时给出时两个目标都生效）。
- 门户对两类令牌均核验：**签名**（固定配置的公钥）、**用途**（`purpose`）、**有效期**（`exp`/`iat`，含 30s 时钟容差）、**issuer/audience**（固定配置）。
- 收到注销后，门户按目标持久化保存**最大注销 iat**（`logout_cutoffs` 表，只升不降）；身份 JWT 的 `iat <=` 该值的：已有会话删除、在途登录拒绝（409）；`iat` 更大的登录正常放行。

## 快速开始

```bash
docker compose up --build
```

| 服务 | 地址 | Swagger UI |
|---|---|---|
| IdP | http://localhost:9000 | http://localhost:9000/docs |
| 门户副本 1 | http://localhost:8001 | http://localhost:8001/docs |
| 门户副本 2 | http://localhost:8002 | http://localhost:8002/docs |

状态保存在命名卷 `portal-data` 中：`docker compose restart`、`down` + `up` 后仍在；`docker compose down -v` 才会清空。

## 在 /docs 演示：延迟登录响应 → 注销 → 重新登录

打开两个标签页：IdP 的 http://localhost:9000/docs 和门户的 http://localhost:8001/docs 。

1. **登录（正常）**：IdP `POST /authorize` → Try it out → `{"sub":"alice","delay_seconds":0}` → 复制返回的 `code`；门户 `POST /login` → `{"code":"<粘贴>"}` → 得到 `session_id`。点页面右上角 **Authorize** 粘贴该 `session_id`，然后 `GET /me` → **200**。
2. **注销**：IdP `POST /logout` → `{"sub":"alice"}`。注销 JWT 被推送到两个门户副本（其中一个会显示 `duplicate`，同一 `jti` 的重复通知是空操作）。再 `GET /me` → **401**。
3. **延迟登录响应（核心场景）**：
   - IdP `POST /authorize` → `{"sub":"bob","delay_seconds":8}`，复制 `code`；
   - 门户 `POST /login` → Execute（响应约 8 秒，**等待期间不要关页面**）；
   - 趁等待立即在 IdP 标签页执行 `POST /logout` → `{"sub":"bob"}`；
   - 门户的 `/login` 返回 **409**：`login superseded by logout ... no session created` —— 迟到的登录响应未能恢复访问。
4. **重新登录**：IdP `POST /authorize` → `{"sub":"bob","delay_seconds":0}`，再走 `/login` → **200**，`GET /me` → **200**（新 `iat` 晚于注销截止时间，允许登录）。
5. **乱序/重复通知**（可选）：IdP `POST /logout` 支持 `iat_offset_seconds`（如 `-60`）模拟迟到的乱序通知——门户持久化的截止时间**不会回退**；在门户 `GET /debug/state` 可查看当前各目标的 `max_logout_iat`。

也可以一键跑完整演示（含双副本共享会话、在途登录被拒、重复/乱序注销）：

```bash
./scripts/demo.sh          # 需要 curl 和 jq
./scripts/stress-test.sh   # 并发登录+注销的串行等价性压力验证
```

## 串行等价与锁设计

- **两个 API 进程**共享同一个 SQLite 文件（WAL 模式，`busy_timeout=30s`）。
- 登录提交与注销处理各自是**一个 `BEGIN IMMEDIATE` 事务**（检查截止时间 + 写会话 / 更新截止时间 + 删会话 + 记录 `jti`），SQLite 写锁使这些临界区在**两个进程间互斥**，效果等价于某种串行顺序：
  - 注销先提交 → 迟到的登录在临界区内看到截止时间，拒绝建会话；
  - 登录先提交 → 注销随后删除该会话。
  两种交错下都不会留下 `iat <=` 截止时间的会话。
- **换令牌等待不持数据库写锁**：`/login` 先在事务外向 IdP 发起 HTTP 交换（可能很慢），拿到并验证身份 JWT 后才进入临界区。
- `/me` 会话验证是只读快照（WAL 下不被写阻塞），同样满足串行等价。
- 门户端点为同步 `def`（Starlette 线程池执行），慢速 `/login` 不会阻塞同进程的 `/backchannel-logout`。
- **幂等**：`processed_logout_jtis` 记录已处理的 `jti`，重复通知原样返回 `duplicate`，不扩大撤销范围；截止时间用 `max()` 语义更新，乱序通知不会降低它。

## API 摘要（门户）

| 方法/路径 | 说明 |
|---|---|
| `POST /login` | 凭授权码向 IdP 换身份 JWT，验证后建会话；被注销覆盖则 `409` |
| `POST /backchannel-logout` | 接收注销 JWT：持久化最大注销 `iat`、撤销覆盖会话；重复 `jti` 返回 `duplicate` |
| `GET /me` | 凭 `Authorization: Bearer <session_id>`（随机会话凭证）查询当前会话 |
| `GET /debug/state` | 演示辅助：当前持久化的截止时间与活跃会话 |

## API 摘要（IdP，本地样例）

| 方法/路径 | 说明 |
|---|---|
| `POST /authorize` | 签发一次性授权码；`delay_seconds` 模拟慢身份源（迟到的登录响应） |
| `POST /token` | 授权码换 RS256 身份 JWT（门户代调；`iat` 取授权时刻） |
| `POST /logout` | 签发注销 JWT 并推送到所有门户副本；`iat_offset_seconds` 模拟乱序通知 |
| `GET /public-key` | 查看公钥（门户侧为固定配置，不做运行时发现） |

## 配置（环境变量）

门户：`IDP_PUBLIC_KEY_PATH`、`IDP_ISSUER`、`IDP_AUDIENCE`、`IDP_TOKEN_URL`、`PORTAL_DB_PATH`、`IDP_TOKEN_EXCHANGE_TIMEOUT`、`TOKEN_CLOCK_LEEWAY`。
IdP：`IDP_PRIVATE_KEY_PATH`、`IDP_ISSUER`、`IDP_AUDIENCE`、`PORTAL_LOGOUT_URLS`（逗号分隔）、`IDP_IDENTITY_TOKEN_TTL`、`IDP_LOGOUT_TOKEN_TTL`。

## 说明与边界

- `deploy/keys/` 内为**演示专用**开发密钥（私钥随仓库分发仅为让 Compose 可直接启动）；生产环境应挂载真实密钥并限制私钥访问。
- IdP 的授权码保存在内存中（短期登录尝试）；所有需要持久化的状态（会话、注销截止时间、已处理 `jti`）都在门户的 SQLite 中，重启保留。
- 本地无 Docker 时的等价验证：分别用 `uvicorn app.main:app` 启动 `idp/`（9000）与两份 `portal/`（8001/8002，同一 `PORTAL_DB_PATH`），再运行 `scripts/demo.sh`。
