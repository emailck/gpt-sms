# 服务端部署文档 / Server Deployment Guide

本文档用于说明 GPTSMS 项目在 Ubuntu 服务器上的生产部署、更新、回滚和安全注意事项。

当前推荐部署方式：

```text
Git 拉取代码 + npm install --omit=dev + systemd 托管 Node.js + Caddy HTTPS 反代
```

---

## 1. 当前生产架构

```text
Client Browser
    |
    | HTTPS
    v
Caddy :443
    |
    | reverse_proxy 127.0.0.1:17843
    v
Node.js / Express /opt/gptsms/server.js
    |
    v
/opt/gptsms/data/app.json
```

生产访问地址：

```text
https://sms.oai-gpt.com
```

管理后台路径：

```text
https://sms.oai-gpt.com/coco
```

Node.js 只监听本机：

```text
127.0.0.1:17843
```

不要让 Node.js 直接监听公网地址。

---

## 2. 服务器目录

项目目录：

```bash
/opt/gptsms
```

关键文件：

```text
/opt/gptsms/.env              # 生产环境变量，不能提交 Git
/opt/gptsms/data/app.json     # 业务数据，不能提交 Git
/opt/gptsms/server.js         # Node 服务入口
/opt/gptsms/public/           # 前台静态资源
/opt/gptsms/private/          # 后台页面资源，不作为公开静态目录暴露
/opt/gptsms/src/              # 服务端模块
```

权限建议：

```bash
sudo chown -R ubuntu:ubuntu /opt/gptsms
chmod 600 /opt/gptsms/.env
chmod 700 /opt/gptsms/data
chmod 600 /opt/gptsms/data/app.json
chmod 700 /opt/gptsms/private
chmod 755 /opt/gptsms/public
```

---

## 3. 是否推荐用 git pull 更新？

推荐。

优点：

- 不容易漏文件。
- 不会误把本地临时文件传到服务器。
- 可以通过 commit hash 明确当前线上版本。
- 可以快速回滚到上一个 commit。
- `.env`、`data/`、日志等敏感文件由 `.gitignore` 排除，不会被覆盖。

注意：

- 服务器上的 `/opt/gptsms/.env` 和 `/opt/gptsms/data/` 必须保留在服务器本地。
- 不要在服务器上修改业务代码；代码修改应在本地提交后推送，再由服务器 `git pull`。
- 如果服务器上已经有手工改动，先 `git status` 检查，避免 pull 冲突。

---

## 4. 首次部署流程

### 4.1 安装基础环境

```bash
sudo apt update
sudo apt install -y git curl ca-certificates
```

安装 Node.js，建议使用 Node.js 20 LTS 或更新 LTS 版本。

检查：

```bash
node -v
npm -v
```

### 4.2 拉取项目

```bash
sudo mkdir -p /opt/gptsms
sudo chown -R ubuntu:ubuntu /opt/gptsms
cd /opt/gptsms

git clone git@github.com:emailck/gpt-sms.git .
```

如果服务器没有 GitHub SSH key，也可以使用 HTTPS 仓库地址，但私有仓库需要配置 token 或 deploy key。

### 4.3 创建生产 .env

```bash
cd /opt/gptsms
cp .env.example .env
chmod 600 .env
```

生产必须设置强随机值：

```env
NODE_ENV=production
PORT=17843
HOST=127.0.0.1
TRUST_PROXY=1
ADMIN_PATH=/coco
MOCK_SMSPOOL=false
TIMEOUT_SECONDS=300
RESEND_COOLDOWN_SECONDS=300
ADMIN_TOKEN=请使用强随机字符串
APP_SECRET=请使用另一个强随机字符串
```

生成随机值示例：

```bash
openssl rand -hex 32
```

注意：

- `ADMIN_TOKEN` 和 `APP_SECRET` 不能相同。
- 不要把真实 `.env` 提交到 Git。
- 上游 API Key 可以写在 `.env`，也可以登录后台配置。

### 4.4 安装依赖

```bash
cd /opt/gptsms
npm install --omit=dev
```

### 4.5 创建 systemd 服务

```bash
sudo tee /etc/systemd/system/gptsms.service >/dev/null <<'EOF'
[Unit]
Description=GPTSMS CDK SMS service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/gptsms
EnvironmentFile=/opt/gptsms/.env
ExecStart=/usr/bin/node /opt/gptsms/server.js
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/opt/gptsms/data

[Install]
WantedBy=multi-user.target
EOF
```

启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable gptsms
sudo systemctl start gptsms
sudo systemctl status gptsms
```

检查监听：

```bash
ss -ltnp | grep 17843
```

期望看到：

```text
127.0.0.1:17843
```

---

## 5. Caddy 反代配置

Caddy 配置文件：

```bash
/etc/caddy/Caddyfile
```

示例站点配置：

```caddy
sms.oai-gpt.com {
    encode gzip

    header {
        X-Frame-Options DENY
        X-Content-Type-Options nosniff
        Referrer-Policy no-referrer
    }

    reverse_proxy 127.0.0.1:17843
}
```

重要：如果服务器已经有其他站点，**不要覆盖整个 Caddyfile**，只追加或合并当前站点配置。

修改后验证并重载：

```bash
sudo caddy fmt --overwrite /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

---

## 6. 日常更新流程，推荐

本地开发完成后：

```bash
git status
git add .
git commit -m "Your change"
git push
```

服务器更新：

```bash
cd /opt/gptsms

git status
# 确认没有未提交的服务器本地代码改动

git pull --ff-only origin main
npm install --omit=dev
node --check server.js
sudo systemctl restart gptsms
sudo systemctl status gptsms --no-pager
```

验证：

```bash
curl -fsS https://sms.oai-gpt.com/api/health
curl -I https://sms.oai-gpt.com/.env
curl -I https://sms.oai-gpt.com/data/app.json
curl -I https://sms.oai-gpt.com/private/admin.js
```

敏感路径应返回 404 或不可访问。

---

## 7. 推荐更新脚本

可以在服务器创建：

```bash
/opt/gptsms/deploy.sh
```

内容：

```bash
#!/usr/bin/env bash
set -euo pipefail

cd /opt/gptsms

echo "==> Checking local git status"
git status --short

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Refusing to deploy: tracked files have local changes."
  exit 1
fi

echo "==> Pulling latest code"
git pull --ff-only origin main

echo "==> Installing production dependencies"
npm install --omit=dev

echo "==> Syntax check"
node --check server.js
node --check src/db.js
node --check src/smspool.js
node --check src/crypto.js
node --check public/app.js
node --check private/admin.js

echo "==> Fixing permissions"
chmod 600 .env || true
chmod 700 data private || true
chmod 600 data/app.json || true
chmod 755 public || true

echo "==> Restarting service"
sudo systemctl restart gptsms
sleep 1
systemctl is-active gptsms

echo "==> Health check"
curl -fsS https://sms.oai-gpt.com/api/health

echo
echo "Deploy complete."
```

授权：

```bash
chmod +x /opt/gptsms/deploy.sh
```

之后更新只需要：

```bash
/opt/gptsms/deploy.sh
```

---

## 8. 回滚流程

查看最近提交：

```bash
cd /opt/gptsms
git log --oneline -10
```

临时回滚到指定提交：

```bash
git checkout <commit-hash>
npm install --omit=dev
sudo systemctl restart gptsms
```

确认无误后，如果需要长期回滚，应在本地仓库创建 revert commit，再推送：

```bash
git revert <bad-commit>
git push
```

服务器再执行：

```bash
git checkout main
git pull --ff-only origin main
sudo systemctl restart gptsms
```

---

## 9. 日志和排查

服务状态：

```bash
sudo systemctl status gptsms --no-pager
```

服务日志：

```bash
journalctl -u gptsms -n 100 --no-pager
journalctl -u gptsms -f
```

Caddy 状态：

```bash
sudo systemctl status caddy --no-pager
```

Caddy 日志：

```bash
journalctl -u caddy -n 100 --no-pager
```

监听端口：

```bash
ss -ltnp | grep -E '(:80|:443|:17843)'
```

---

## 10. 安全检查清单

每次部署后建议检查：

```bash
curl -I https://sms.oai-gpt.com/.env
curl -I https://sms.oai-gpt.com/data/app.json
curl -I https://sms.oai-gpt.com/private/admin.js
curl -I https://sms.oai-gpt.com/admin.js
curl -i https://sms.oai-gpt.com/api/admin/overview
```

预期：

- `.env` 不可访问
- `data/app.json` 不可访问
- `private/admin.js` 不可访问
- `/admin.js` 不可访问
- 未登录访问后台 API 返回 401

检查 Node 是否只监听本机：

```bash
ss -ltnp | grep 17843
```

预期：

```text
127.0.0.1:17843
```

Git 提交前检查敏感文件：

```bash
git status --short --ignored
git check-ignore -v .env data/app.json server.log key.pem 2>/dev/null
```

不要提交：

- `.env`
- `data/`
- 日志文件
- `.pem` / `.key`
- 真实 API Key
- 管理员 Token
- 数据库备份

---

## 11. 当前线上维护建议

- 后续优先使用 `git pull --ff-only origin main` 更新。
- 不要再用覆盖整个目录的方式部署，除非明确保留 `.env` 和 `data/`。
- 修改 Caddy 时只合并站点块，不要覆盖已有站点。
- 如果上线前改了依赖，必须执行 `npm install --omit=dev`。
- 如果修改了 `.env`，需要重启 `gptsms`。
- 如果只修改 Caddyfile，通常只需要 `sudo systemctl reload caddy`。