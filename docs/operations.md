# 部署与运维

## 健康检查

- API 存活：`GET /health/live`
- API 就绪：`GET /health/ready`
- PostgreSQL：`pg_isready`
- Redis：`redis-cli ping`
- MinIO：`mc ready local`
- ClamAV：`clamdcheck.sh`

## 关键监控

- API 错误率、p50/p95/p99 延迟。
- PostgreSQL 连接数、慢查询和磁盘使用率。
- Redis 内存、BullMQ 等待任务和失败任务。
- `media_assets` 中 `processing` 或 `failed` 数量。
- `manual_review` 媒体队列长度。
- `pending` 内容与评论队列长度。
- outbox `pending`、`failed` 数量。
- `delete_after <= now()` 的原图数量。
- 公开桶中是否存在未被数据库引用的对象。

## 备份

- PostgreSQL 每日全量备份并保留 WAL 或等价连续归档。
- MinIO 启用版本化和跨盘/跨区域容灾时，分别备份隔离桶和公开桶。
- `.env.production` 和密钥应保存在密钥管理系统，不进入镜像或仓库。
- 每季度执行一次恢复演练，验证数据库、公开媒体和迁移记录。

## 发布

1. 构建并锁定 API、Worker、Web 镜像。
2. 备份数据库。
3. 执行一次 `migrate` 容器。
4. 启动新 API 和 Worker。
5. 验证就绪检查、登录、地图查询和媒体处理。
6. 再切换 Caddy 流量。
7. 保留上一版本镜像用于回滚。

## 隐私事件

发现未模糊媒体或原图泄露时：

1. 立即停止相关媒体发布并删除公开对象。
2. 暂停媒体 Worker，防止继续复制到公开桶。
3. 根据对象访问日志确认影响范围。
4. 修复处理管线并执行全量扫描。
5. 删除或隔离受影响对象。
6. 记录事故、根因、修复和回归测试。
7. 按法律与运营要求通知用户。

## 数据保留

- 成功处理原图：24 小时。
- 失败处理原图：最多 7 天。
- 邮箱验证令牌：24 小时。
- 密码重置令牌：30 分钟。
- 过期刷新令牌：30 天清理。
- 账号删除冷静期：30 天。
- 审计与审核记录：默认 180 天，生产可按法务要求延长。
- 媒体凭证与签名公钥：永久保留（删除凭证是删除已发生的唯一证据）。

## 媒体签名密钥

Worker 和轮换 CLI 需要 `MEDIA_SIGNING_KEK`（至少 32 字符，生产环境使用密钥管理系统生成的随机值）。它派生两样东西：加密签名私钥的 AES-256-GCM 密钥，以及水印密钥。API 校验凭证只用公钥，不需要该变量。

- 首次启动时 Worker 自动在 `media_signing_keys` 中自举一把 active 密钥；部分唯一索引保证并发下只有一把。
- 轮换：`pnpm --filter @map/db forensics:rotate`。当前密钥转为 `retired`，新密钥成为 `active`。轮换在单个事务中完成，期间签发短暂失败，Worker 重试即可。
- retired 密钥的公钥永不删除：旧凭证按 `kid` 查公钥校验，`GET /api/v1/forensics/keys` 同时发布 active 和 retired 公钥供外部独立校验。
- `MEDIA_SIGNING_KEK` 本身轮换时需要先用旧 KEK 导出私钥、再用新 KEK 重新加密入库（当前版本不支持，变更前需停机维护）；丢失 KEK 等于丢失全部私钥，已签发凭证仍可用公开端点校验，但无法签发新凭证。
- 备份必须包含 `media_signing_keys` 和 `media_credentials` 两表；恢复演练时抽查一条凭证能通过公开端点校验。

## 取证核查

收到疑似本平台处理图的泄露图片时：

```bash
pnpm --filter @map/worker forensics:extract ./suspect.webp
```

输出水印指纹、校验和结果、匹配的处理凭证及签名校验结论。指纹命中且签名有效即可确认图片来源媒体与处理时间；校验和不匹配说明图片不是本平台处理产物或已被重度修改。
