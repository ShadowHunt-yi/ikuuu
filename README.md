# IKUUU 自动签到程序

自动登录并签到 IKUUU 的 Python 脚本，支持域名自动发现与更新。

## 功能特性

- 自动登录 IKUUU 账户并执行每日签到
- 显示账户信息（流量、会员状态等）
- **域名自动发现**：从导航页自动解析最新可用域名，无需手动更换
- **域名缓存**：可用域名保存到 `domain.txt`，避免每次重新发现
- **GitHub Actions 自动提交**：域名变更后自动提交到仓库，下次运行直接使用
- 支持 GitHub Actions 定时运行

## 安装依赖

```bash
pip install -r requirements.txt
```

或手动安装：

```bash
pip install requests beautifulsoup4 brotli urllib3
```

## 配置说明

### 配置优先级

**环境变量 > 本地变量 > 默认值**

### 本地运行

在 `main.py` 中修改（仅用于本地测试）：

```python
LOCAL_EMAIL = "your_email@example.com"
LOCAL_PASSWORD = "your_password"
LOCAL_DOMAIN = ""  # 可选，留空则自动发现
```

或使用环境变量：

```bash
# Linux/macOS
export IKUUU_EMAIL="your_email@example.com"
export IKUUU_PASSWORD="your_password"

# Windows PowerShell
$env:IKUUU_EMAIL = "your_email@example.com"
$env:IKUUU_PASSWORD = "your_password"
```

然后运行：

```bash
python main.py
```

## 域名自动发现

IKUUU 经常更换域名，本程序实现了自动发现机制：

### 工作流程

1. 读取 `domain.txt` 缓存的域名，测试是否可用
2. 不可用则依次测试环境变量、本地变量、默认域名
3. 全部失败则访问导航页（如 `ikuuu.ch`），自动解析最新域名
4. 找到可用域名后保存到 `domain.txt`

### 域名判定规则

- **真实服务**：GET 根路径返回 302 跳转到 `/auth/login`
- **导航页**：GET 根路径返回 200（HTML页面）

### 导航页解析策略

导航页的域名信息嵌入在混淆的 JavaScript 中，程序使用多种策略提取：

1. HTML 标签解析（`<h3>`、`<a>` 标签）
2. JS 字符串拼接模式匹配（如 `'ikuuu'+'.nl'`）
3. 混淆 JS 字符串数组解码（自定义 base64 字母表）

## GitHub Actions 配置

### 设置步骤

1. **Fork 此仓库**

2. **配置 Secrets**：`Settings` -> `Secrets and variables` -> `Actions`

   | Secret 名称 | 说明 | 必需 |
   |------------|------|------|
   | `IKUUU_EMAIL` | 邮箱 | 是 |
   | `IKUUU_PASSWORD` | 密码 | 是 |
   | `IKUUU_DOMAIN` | 自定义域名 | 否（自动发现） |

3. **启用 Actions** 并手动触发一次测试

### 运行时间

- **自动运行**：每天北京时间 9:00（UTC 1:00）
- **手动触发**：Actions 页面随时可运行

### 域名缓存自动提交

签到成功后，如果 `domain.txt` 有变化，GitHub Actions 会自动提交更新，下次运行直接使用缓存的域名。

### 修改运行时间

编辑 `.github/workflows/ikuuu-checkin.yml`：

```yaml
schedule:
  - cron: '0 1 * * *'  # UTC 1:00 = 北京时间 9:00
```

## 常见问题

### 登录失败

- 检查邮箱密码是否正确
- 域名可能已更换，程序会自动尝试发现新域名
- 如果自动发现也失败，可手动设置 `IKUUU_DOMAIN`

### GitHub Actions 运行失败

- 确认已正确添加 Secrets（无多余空格）
- 查看 Actions 运行日志定位问题
- 网络问题可稍后手动重试

### 缺少 brotli 库

```bash
pip install brotli
```

## 注意事项

1. 请妥善保管账户信息，不要提交密码到公开仓库
2. 建议每天运行一次，避免频繁请求
3. 域名更换无需手动干预，程序会自动发现并更新

## 许可证

MIT License
