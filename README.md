# IKUUU 自动签到程序

自动登录并签到 IKUUU 的 Python 脚本，支持域名自动发现与更新。

## 功能特性

- **免费过 Geetest**：Playwright 无头浏览器点击「点我开始验证」，账号密码即可签到
- 显示账户信息（流量、会员状态等）
- **域名自动发现**：从导航页自动解析最新可用域名
- **域名缓存**：可用域名保存到 `domain.txt`
- **GitHub Actions**：定时运行，域名变更后自动提交

## 技术方案

登录页使用 **Geetest V4**（`captcha_type=ai` 自适应一键验证）。服务端会校验 `captcha_result`，空 token / 伪造 token 无法登录。

本项目采用的路径：

```
1. 解析可用域名
2. Playwright 打开登录页
3. 点击 Geetest「点我开始验证」→ 拿到合法 captcha_result
4. 提交邮箱 + 密码登录 → 获取会话 Cookie
5. POST /user/checkin 签到，并拉取账户信息
```

> 真实浏览器点击雷达按钮后，Geetest 通常直接 `verify success`，因此默认不依赖第三方打码服务。  
> 代码中仍保留「打码 API / 手工 Cookie」作为可选实现分支（浏览器环境不可用时的技术兜底），日常使用只需邮箱和密码。

## 安装依赖

```bash
pip install -r requirements.txt
# 首次需要浏览器内核（任选其一）
playwright install chromium
# 或使用本机已安装的 Chrome / Edge（代码会自动尝试 channel=chrome/msedge）
```

## 配置说明

**环境变量 > 本地变量 > 默认值**

| 配置项 | 说明 | 必需 |
|--------|------|------|
| `IKUUU_EMAIL` | 邮箱 | ✅ |
| `IKUUU_PASSWORD` | 密码 | ✅ |
| `IKUUU_DOMAIN` | 自定义域名 | 否（自动发现） |
| `IKUUU_USE_BROWSER_LOGIN` | `1`/`0`，默认开启浏览器过验证码 | 否 |
| `IKUUU_COOKIE` | 已有会话 Cookie | 否（兜底） |

### 本地运行

在 `main.py` 中修改（仅用于本地测试）：

```python
LOCAL_EMAIL = "your_email@example.com"
LOCAL_PASSWORD = "your_password"
LOCAL_DOMAIN = ""  # 可选，留空则自动发现
LOCAL_USE_BROWSER_LOGIN = True
```

或使用环境变量：

```bash
export IKUUU_EMAIL="your_email@example.com"
export IKUUU_PASSWORD="your_password"
python main.py
```

## 域名自动发现

1. 读取 `domain.txt` 缓存并测试
2. 不可用则依次测试环境变量、本地变量、默认域名
3. 全部失败则访问导航页自动解析最新域名
4. 找到可用域名后写入 `domain.txt`

判定规则：

- **真实服务**：GET `/` → 302 → `/auth/login`
- **导航页**：GET `/` → 200

## GitHub Actions 配置

1. **Fork 此仓库**
2. **配置 Secrets**（`Settings` → `Secrets and variables` → `Actions`）

   | Secret 名称 | 说明 | 必需 |
   |------------|------|------|
   | `IKUUU_EMAIL` | 邮箱 | ✅ |
   | `IKUUU_PASSWORD` | 密码 | ✅ |
   | `IKUUU_DOMAIN` | 自定义域名 | 否 |
   | `IKUUU_COOKIE` | 会话 Cookie | 否 |

3. **启用 Actions** 并手动触发一次测试

### 运行时间

- 自动：每天北京时间 9:00（UTC 1:00）
- 手动：Actions 页面可随时运行

Workflow 会自动执行 `playwright install --with-deps chromium`。

## 常见问题

### 登录失败

- 确认邮箱密码正确
- 确认已安装浏览器：`playwright install chromium`，或系统装有 Chrome/Edge
- 域名可能已更换，程序会自动发现；也可手动设置 `IKUUU_DOMAIN`
- 无浏览器环境时，可改用有效的 `IKUUU_COOKIE` 兜底

### GitHub Actions 失败

- 确认 Secrets 无多余空格
- 查看日志中 Playwright / Chromium 是否安装成功
- 网络问题可稍后手动重试

### 缺少依赖

```bash
pip install -r requirements.txt
playwright install chromium
```

## 注意事项

1. 请妥善保管账户信息，不要把密码提交到公开仓库
2. 建议每天运行一次，避免频繁请求
3. 域名更换无需手动干预
4. 浏览器自动化依赖 Playwright；CI 已配置自动安装 Chromium

## 许可证

MIT License
