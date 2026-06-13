# Suppress a finding

Gateways, proxies, or custom middleware protect endpoints without triggering the static analyzer. Suppress false EXPOSED or UNKNOWN flags directly in code.

## 1. Syntax

Add comment on the same line or line immediately preceding the endpoint declaration.
Format required: `authmap:ignore reason=<justification>`

## 2. Examples

**Node.js / JavaScript:**
```js
// authmap:ignore reason=auth enforced by AWS API Gateway policy
app.get("/api/internal/metrics", (req, res) => {
    res.json({ status: "ok" });
});
```

**PHP:**
```php
# authmap:ignore reason=admin route protected by internal VPN
$app->get('/admin/stats', function ($request, $response) {
    return $response;
});
```

## 3. Verify

```bash
authmap --project .
```
Suppressed endpoints bypass the `--fail-on` threshold. They remain visible in JSON/SARIF output marked as `suppressed: true` for audit logs.
