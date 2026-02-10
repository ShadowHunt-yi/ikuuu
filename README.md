# IKUUU 自动签到程序

自动登录并签到 IKUUU (ikuuu.org) 的 Python 脚本。

## 功能特性

- ✅ 自动登录 IKUUU 账户
- ✅ 自动执行每日签到
- ✅ 显示账户信息（流量、会员状态等）
- ✅ 支持多域名配置
- ✅ 完整的错误处理和调试日志
- ✅ 支持 GitHub Actions 定时运行

## 安装依赖

### 方法一：使用 requirements.txt（推荐）

```bash
pip install -r requirements.txt
```

### 方法二：使用 pip 直接安装

```bash
pip install requests beautifulsoup4 brotli urllib3
```

## 配置说明

### 配置优先级

配置的优先级顺序为：**环境变量 > 本地变量 > 默认值**

这意味着：
- 🥇 环境变量（如 GitHub Secrets）优先级最高
- 🥈 代码中的本地变量次之
- 🥉 默认值最低

这样设计的好处是：
- ✅ 在 GitHub Actions 中运行时，使用 Secrets 配置
- ✅ 本地开发测试时，可以在代码中临时设置
- ✅ 本地变量不会覆盖云端的环境变量

### 本地运行配置

在 `main.py` 文件中修改以下变量（仅用于本地测试）：

```python
# 账户配置（本地测试用）
LOCAL_EMAIL = "your_email@example.com"      # 你的邮箱
LOCAL_PASSWORD = "your_password"             # 你的密码

# 域名配置（本地测试用，可选）
LOCAL_DOMAIN = "ikuuu.org"                   # 当前可用域名
```

⚠️ **注意**: 如果设置了环境变量，环境变量会覆盖这里的本地配置。

### 使用环境变量（推荐）

在系统中设置环境变量：

**Windows (PowerShell)**:
```powershell
$env:IKUUU_EMAIL = "your_email@example.com"
$env:IKUUU_PASSWORD = "your_password"
$env:IKUUU_DOMAIN = "ikuuu.org"  # 可选
```

**Linux/macOS**:
```bash
export IKUUU_EMAIL="your_email@example.com"
export IKUUU_PASSWORD="your_password"
export IKUUU_DOMAIN="ikuuu.org"  # 可选
```

## GitHub Actions 配置

### 设置步骤

1. **Fork 此仓库**
   - 点击右上角的 Fork 按钮

2. **配置 Secrets**
   - 进入你 Fork 的仓库
   - 点击 `Settings` -> `Secrets and variables` -> `Actions`
   - 点击 `New repository secret` 添加以下 Secrets：

   | Secret 名称 | 说明 | 必需 |
   |------------|------|------|
   | `IKUUU_EMAIL` | 你的 IKUUU 邮箱 | ✅ 是 |
   | `IKUUU_PASSWORD` | 你的 IKUUU 密码 | ✅ 是 |
   | `IKUUU_DOMAIN` | 自定义域名（如 ikuuu.org） | ⭕ 否（默认 ikuuu.ch） |

3. **启用 GitHub Actions**
   - 进入 `Actions` 标签页
   - 如果看到提示，点击 `I understand my workflows, go ahead and enable them`

4. **测试运行**
   - 在 `Actions` 标签页
   - 选择 `IKUUU 自动签到` workflow
   - 点击 `Run workflow` -> `Run workflow` 手动触发一次测试

### 运行时间

- **自动运行**: 每天北京时间 9:00（UTC 1:00）
- **手动触发**: 随时可以在 Actions 页面手动运行

### 查看运行日志

1. 进入仓库的 `Actions` 标签页
2. 点击最近的运行记录
3. 查看 `执行签到` 步骤的详细日志

### 修改运行时间

编辑 `.github/workflows/ikuuu-checkin.yml` 文件中的 cron 表达式：

```yaml
schedule:
  # 每天北京时间 9:00 执行（UTC 1:00）
  - cron: '0 1 * * *'
```

Cron 表达式格式：`分钟 小时 日 月 星期`
- `0 1 * * *` = 每天 UTC 1:00（北京时间 9:00）
- `0 */12 * * *` = 每 12 小时一次
- `30 2 * * *` = 每天 UTC 2:30（北京时间 10:30）

⚠️ **注意**: GitHub Actions 使用 UTC 时间，北京时间 = UTC + 8

## 使用方法

### 本地运行

```bash
python main.py
```

### 定时运行

程序会自动：
1. 登录你的 IKUUU 账户
2. 执行每日签到
3. 显示账户信息（剩余流量、会员状态等）

## 依赖说明

- **requests**: HTTP 请求库
- **beautifulsoup4**: HTML 解析库
- **brotli**: Brotli 压缩支持（必需）
- **urllib3**: HTTP 客户端库

⚠️ **重要**: `brotli` 库是必需的，因为 IKUUU 使用 Brotli 压缩响应数据。

## 常见问题

### 1. 签到失败，提示无法解析响应

**错误信息**: `无法解析签到响应: Expecting value: line 1 column 1 (char 0)`

**原因**: 缺少 Brotli 压缩库

**解决方法**:
```bash
pip install brotli
```

或者重新安装所有依赖：
```bash
pip install -r requirements.txt
```

### 2. 登录失败

**可能的原因**:
- ❌ 邮箱或密码错误
- ❌ 域名已更换
- ❌ 网络连接问题
- ❌ 账户被封禁

**解决方法**:
1. 检查账户信息是否正确
2. 尝试在浏览器中手动登录，确认账户状态
3. 更新域名配置（查看 IKUUU 官方最新域名）
4. 检查网络连接

### 3. GitHub Actions 运行失败

**检查清单**:
- ✅ 确认已正确添加 Secrets（IKUUU_EMAIL、IKUUU_PASSWORD）
- ✅ 确认 Secrets 值没有多余的空格
- ✅ 查看 Actions 运行日志，找到具体错误信息
- ✅ 如果是网络问题，可以稍后手动重试

### 4. 如何查看调试信息

程序会自动显示详细的调试日志：

| 级别 | 说明 | 示例 |
|------|------|------|
| 🔍 DEBUG | 详细的请求和响应信息 | 用于排查问题 |
| ℹ️ INFO | 一般流程信息 | 程序运行步骤 |
| ⚠️ WARNING | 警告信息 | 可能的问题 |
| ❌ ERROR | 错误信息 | 失败原因 |
| ✅ SUCCESS | 成功信息 | 操作成功 |

### 5. 域名经常变化怎么办？

IKUUU 的域名可能会定期更换。如遇访问问题：

1. **查看官方公告**: 访问 IKUUU 官方渠道获取最新域名
2. **更新配置**:
   - 本地运行：修改 `main.py` 中的 `LOCAL_DOMAIN`
   - GitHub Actions：更新 `IKUUU_DOMAIN` Secret
3. **常见域名**: ikuuu.org, ikuuu.ch, ikuuu.pw 等

### 6. 如何禁用调试日志？

如果不想看到详细的 DEBUG 日志，可以修改代码中打印 DEBUG 级别日志的部分，或者在调用时过滤输出。

## 注意事项

1. **账户安全**: 请妥善保管你的账户信息，不要将包含密码的代码提交到公开仓库
2. **频率限制**: 建议每天运行一次，避免频繁请求
3. **域名更新**: IKUUU 可能会更换域名，如遇访问问题请更新域名配置

## 许可证

MIT License
