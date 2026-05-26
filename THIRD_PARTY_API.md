# 第三方 API 使用文档

第三方不需要 CDK，使用后台创建的 API Key 直接取号。计费按“成功收到短信次数”扣费。

## 认证

所有 `/api/v1/*` 接口使用 Bearer Token：

```http
Authorization: Bearer gptsms_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Content-Type: application/json
```

API Key 只在后台创建客户或重置 Key 时显示一次，请妥善保存。重置后旧 Key 会立即失效。

## 计费规则

- 获取号码：不扣费
- 查询等待：不扣费
- 更换号码：不扣费
- 号码 5 分钟过期未收到：不扣费，系统向上游退款
- 收到短信：扣费一次
- 同一个 session 重复查询：不重复扣费
- 退款失败：每 10 分钟自动重试

获取号码前需要余额大于等于单价，否则返回 `INSUFFICIENT_BALANCE`。

## 1. 查询余额

```http
GET /api/v1/balance
Authorization: Bearer <API_KEY>
```

响应：

```json
{
  "success": 1,
  "balance": 100,
  "pricePerSuccess": 1,
  "status": "active"
}
```

## 2. 获取号码

```http
POST /api/v1/number
Authorization: Bearer <API_KEY>
Content-Type: application/json
```

请求：

```json
{
  "externalId": "your_order_10001"
}
```

`externalId` 可选。传入后具有幂等效果：同一个客户、同一个 `externalId`，如果已有 `waiting` 或 `received` 会话，会直接返回已有会话和可用于查码的 `sessionToken`，避免重复占号。

响应：

```json
{
  "success": 1,
  "sessionId": "sess_xxx",
  "sessionToken": "tok_xxx",
  "phone": "+1234567890",
  "status": "waiting",
  "received": false,
  "reused": false,
  "expiresAt": "2026-05-25T10:05:00.000Z",
  "canChangeAt": "2026-05-25T10:02:00.000Z",
  "canChange": false,
  "externalId": "your_order_10001",
  "pollIntervalSeconds": 5
}
```

## 3. 查询短信

建议按 `pollIntervalSeconds` 轮询。

```http
POST /api/v1/session/check
Authorization: Bearer <API_KEY>
Content-Type: application/json
```

请求：

```json
{
  "sessionId": "sess_xxx",
  "sessionToken": "tok_xxx"
}
```

等待中：

```json
{
  "success": 1,
  "sessionId": "sess_xxx",
  "phone": "+1234567890",
  "status": "waiting",
  "received": false,
  "expiresAt": "2026-05-25T10:05:00.000Z",
  "canChangeAt": "2026-05-25T10:02:00.000Z",
  "canChange": false
}
```

收到短信：

```json
{
  "success": 1,
  "sessionId": "sess_xxx",
  "phone": "+1234567890",
  "status": "received",
  "received": true,
  "message": "Your verification code is 123456",
  "code": "123456",
  "receivedAt": "2026-05-25T10:01:20.000Z",
  "billing": {
    "charged": true,
    "alreadyCharged": true,
    "amount": 1,
    "balance": 99,
    "billingId": "bill_xxx"
  }
}
```

超时：

```json
{
  "success": 1,
  "sessionId": "sess_xxx",
  "status": "timeout",
  "received": false,
  "canChange": false
}
```

## 4. 更换号码

2 分钟未收到短信后可以更换号码。

```http
POST /api/v1/session/change-number
Authorization: Bearer <API_KEY>
Content-Type: application/json
```

请求：

```json
{
  "sessionId": "sess_xxx",
  "sessionToken": "tok_xxx"
}
```

响应同“获取号码”。

## 错误响应

```json
{
  "success": 0,
  "code": "INSUFFICIENT_BALANCE",
  "message": "余额不足"
}
```

常见错误码：

- `INVALID_AUTH`：API Key 错误或缺失
- `CLIENT_DISABLED`：客户已禁用
- `INSUFFICIENT_BALANCE`：余额不足
- `SESSION_NOT_FOUND`：会话不存在
- `SESSION_FORBIDDEN`：sessionToken 错误
- `CHANGE_TOO_EARLY`：未满 2 分钟不能更换
- `SMS_RECEIVED_CANNOT_CHANGE`：已收到短信，不能更换

## curl 示例

```bash
API_KEY="gptsms_live_xxx"
BASE="https://your-domain.com"

curl -s "$BASE/api/v1/balance" \
  -H "Authorization: Bearer $API_KEY"

curl -s -X POST "$BASE/api/v1/number" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"externalId":"order_10001"}'

curl -s -X POST "$BASE/api/v1/session/check" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"sess_xxx","sessionToken":"tok_xxx"}'
```
