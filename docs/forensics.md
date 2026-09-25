# 媒体取证与水印

服务端为每张处理图与每次删除签发**可验证凭证**，并在公开图中嵌入隐形水印。
凭证在密钥轮换后仍可用永久保留的公钥目录校验；公开地址不可由原图推导或枚举。

## 组件

代码位于 [`packages/forensics`](../packages/forensics/src/index.ts)，仅依赖 `node:crypto`、`sharp`、`zod`：

| 模块 | 职责 |
| --- | --- |
| `keys.ts` | Ed25519 签名密钥环；私钥用主密钥 AES-256-GCM 落库 |
| `credentials.ts` | 紧凑 JWS 凭证（`header.payload.signature`，含 `kid`）与严格校验 |
| `watermark.ts` | 蓝通道块均值量化扩频水印（方案 `bluespread-1`，64 位 id） |
| `addressing.ts` | HMAC 密封公开地址；原图加盐承诺 |
| `ledger.ts` / `store-pg.ts` | 只追加的凭证账本与 PG 适配器 |
| `service.ts` | 处理凭证、删除凭证、验签、密钥轮换、绑定校验编排 |

## 凭证

两类凭证均带签发密钥 id（`kid`），载荷用 zod `strictObject` 校验，固定 `alg: EdDSA`
（拒绝 `HS256` 等算法混淆）：

- `media.processed`：处理图 sha256、感知哈希、尺寸、缩略图 sha256、**原图加盐承诺**
  （仅 `salt` 与 `sha256(salt ‖ originalSha256)`，绝不出现原图哈希本身）、水印 id、
  密封 `publicId`、处理操作、模糊区域数。
- `media.deleted`：删除者身份、各对象（原图/处理图/缩略图/公开图/公开缩略图）是否删除、
  上一张凭证哈希（链式证据）、最后一次处理图哈希。删除事件按媒体唯一、不可变。

凭证哈希（token 的 sha256）用于凭证之间的前后链接。

## 密钥轮换

- 任意时刻至多一个 `active` 密钥（数据库部分唯一索引保证）。
- 轮换时新密钥变 `active`；旧密钥的**加密私钥被擦除**（`private_key_enc = NULL`），
  但**公钥永久保留**为 `retired`。
- 因此旧凭证轮换后仍可验证（测试覆盖：签发 → 轮换 → 旧凭证验签通过、新凭证由新密钥签发）。
- 轮换接口：`POST /api/v1/admin/forensics/rotate`（仅 admin，写审计日志）。

## 公开地址不泄露原图

公开对象键由服务端密钥派生，与**处理后**（已模糊、去元数据、重编码、加水印）字节绑定：

```text
publicId = "m" + HMAC(FORENSICS_ADDRESS_SECRET, "map:media:public-id:" ‖ mediaId ‖ 0x00 ‖ processedSha256) 前 43 hex
key      = media/<publicId>.webp
```

- 无密钥者无法计算或枚举地址（确认猜测也不行）。
- 地址不绑定原图：知道原图哈希无法推导地址；凭证只存原图的加盐承诺。
- 原图始终留在私有隔离桶，永不拷贝到公开桶；只有加水印后的处理图进入公开桶。

## 水印

- 64 位 id 由 `HMAC(FORENSICS_WATERMARK_SECRET, mediaId)` 派生；块访问顺序也由 HMAC 决定，
  观察者无法定位水印样本。
- 采用固定 **32×32 比例网格**：边界随图像缩放等比例移动，因此缩放 + WebP 重压后仍能恢复；
  每比特在多个块上多数投票。
- 处理图与缩略图嵌入同一 id。检测需持水印密钥，按候选 mediaId 比对（`detectWatermark` 返回
  比特匹配率与置信度）。
- 原始域 PSNR > 43 dB（测试断言），视觉不可感知；抗 87.5% 缩放 + q55 重压测试恢复率 100%。

## 接口

| 方法路径 | 权限 | 说明 |
| --- | --- | --- |
| `GET /api/v1/forensics/keys` | 公开 | 公钥目录（含已轮换的旧公钥） |
| `POST /api/v1/forensics/verify` | 公开 | 校验凭证并返回结构化载荷 |
| `GET /api/v1/media/:id/credentials` | 作者/审核员 | 列出该媒体的处理/删除凭证 |
| `POST /api/v1/admin/forensics/rotate` | admin | 轮换签名密钥 |
| `DELETE /api/v1/media/:id` | 作者/审核员 | 删除并在响应中返回删除凭证 |

## 配置（生产必须使用强随机值，三个密钥相互独立）

```env
FORENSICS_MASTER_KEY=<32+ 字节随机串，加密签名私钥>
FORENSICS_WATERMARK_SECRET=<32+ 字节随机串，水印密钥>
FORENSICS_ADDRESS_SECRET=<32+ 字节随机串，公开地址派生密钥>
```

轮换签名密钥不影响水印与地址密钥；更换 `FORENSICS_MASTER_KEY` 会使现有 active 私钥
无法解封，因此轮换主密钥前应先做密钥轮换并迁移。

## 校验流程

1. 取凭证 header 中的 `kid`；
2. 从公钥目录（含 retired）找到 Ed25519 公钥；
3. 校验签名与严格载荷结构；
4. 需要核对实际公开图时，调用 `ForensicsService.checkPublicBinding`：
   同时验证字节 sha256、密封地址、水印 id 三者一致。

数据库表见迁移 [`0003_forensics.sql`](../packages/db/migrations/0003_forensics.sql)。
