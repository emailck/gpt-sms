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
  "externalId": "your_order_10001",
  "phone": "+1234567890"
}
```

`externalId` 可选。传入后具有幂等效果：同一个客户、同一个 `externalId`，如果已有 `waiting` 或 `received` 会话，会直接返回已有会话和可用于查码的 `sessionToken`，避免重复占号。

`phone` 可选。传入后表示指定手机号接码，调用方不需要知道号码来自哪种号码池。指定手机号时默认 `forceUse=true`，即只要系统里存在该手机号，就会尝试使用该号码接码，不会因为冷却、禁用、已达使用次数或当前状态不可用而自动换成其他号码：

- 如果该号码是自有号码池号码，系统会直接分配该号码，并通过该号码的 `smsUrl` 查询短信。
- 如果该号码是 SMSPool 历史号码，系统会自动调用上游 `resend`，然后等待新短信。
- 如果不传 `phone`，系统按后台配置的号码池优先级自动分配号码。

也可以传 `accountId` 精确指定内部号码记录；第三方通常只需要传 `phone`。

如果需要恢复严格可用性检查，可显式传：

```json
{
  "phone": "+1234567890",
  "forceUse": false
}
```

响应：

```json
{
  "success": 1,
  "sessionId": "sess_xxx",
  "sessionToken": "tok_xxx",
  "phone": "+1234567890",
  "poolType": "manual_pool",
  "numberSource": "manual_pool",
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

## 5. 指定手机号继续接码

如果第三方已经知道要继续使用的手机号，可以直接调用：

```http
POST /api/v1/number/continue
Authorization: Bearer <API_KEY>
Content-Type: application/json
```

请求：

```json
{
  "phone": "+1234567890",
  "externalId": "your_order_10002"
}
```

响应同“获取号码”。系统会自动判断号码池类型：

- `poolType: "manual_pool"`：自有号码池。
- `poolType: "smspool"`：SMSPool 历史号码，通过上游 resend 继续接码。

指定手机号时默认强制使用该号码；如果上游 SMSPool 拒绝 resend，接口会返回上游错误，不会自动换成其他号码。

## 6. 搜索可用号码

```http
GET /api/v1/numbers/search?phone=7890
Authorization: Bearer <API_KEY>
```

响应：

```json
{
  "success": 1,
  "numbers": [
    {
      "id": "acct_xxx",
      "phone": "+1234567890",
      "poolType": "manual_pool",
      "source": "manual_pool",
      "status": "available",
      "available": true
    }
  ]
}
```

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
