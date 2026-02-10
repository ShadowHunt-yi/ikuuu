import requests
from bs4 import BeautifulSoup
import os
from datetime import datetime
import re
import base64
import time
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 检查必需的库
def check_dependencies():
    """检查并提示安装必需的依赖"""
    missing = []
    try:
        import brotli
    except ImportError:
        try:
            import brotlicffi
        except ImportError:
            missing.append("brotli")
    
    if missing:
        print("⚠️  检测到缺少必需的依赖库:")
        for lib in missing:
            print(f"   - {lib}")
        print("\n请运行以下命令安装:")
        print("   pip install brotli")
        print("\n或者安装所有依赖:")
        print("   pip install -r requirements.txt")
        print("")
        return False
    return True

# 域名配置
LOCAL_DOMAIN = ""                     # 本地测试时可填入域名，如：ikuuu.org
DEFAULT_DOMAIN = "ikuuu.ch"           # 默认域名

# 初始值，会被 resolve_domain() 覆盖
BASE_DOMAIN = DEFAULT_DOMAIN
BASE_URL = f"https://{BASE_DOMAIN}"

# 域名自动发现配置
DOMAIN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "domain.txt")
NAVIGATION_URLS = [
    "https://ikuuu.ch",
]
DOMAIN_TEST_TIMEOUT = 5

# 本地测试变量，本地测试时可以在这里设置，环境变量优先级更高
LOCAL_EMAIL = ""     # 本地测试时填入邮箱
LOCAL_PASSWORD = ""  # 本地测试时填入密码

def print_with_time(message, level="INFO"):
    """带时间戳和级别的打印"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level_emoji = {
        "INFO": "ℹ️",
        "SUCCESS": "✅", 
        "WARNING": "⚠️",
        "ERROR": "❌",
        "DEBUG": "🔍"
    }
    emoji = level_emoji.get(level, "ℹ️")
    print(f"[{current_time}] {emoji} {message}")

def print_separator(char="=", length=60):
    """打印分隔线"""
    print(char * length)

def read_domain_from_file():
    """从 domain.txt 读取缓存的域名"""
    try:
        if os.path.exists(DOMAIN_FILE):
            with open(DOMAIN_FILE, 'r', encoding='utf-8') as f:
                domain = f.readline().strip()
            if domain and '.' in domain and ' ' not in domain:
                domain = domain.replace('https://', '').replace('http://', '').rstrip('/')
                print_with_time(f"从缓存文件读取域名: {domain}", "DEBUG")
                return domain
            else:
                print_with_time(f"缓存文件中的域名无效: '{domain}'", "WARNING")
    except Exception as e:
        print_with_time(f"读取域名缓存文件失败: {str(e)}", "WARNING")
    return None

def save_domain_to_file(domain):
    """将可用域名保存到 domain.txt"""
    try:
        with open(DOMAIN_FILE, 'w', encoding='utf-8') as f:
            f.write(domain.strip() + '\n')
        print_with_time(f"已保存域名到缓存文件: {domain}", "SUCCESS")
        return True
    except Exception as e:
        print_with_time(f"保存域名缓存文件失败: {str(e)}", "WARNING")
        return False

def parse_json_response(response, context="响应"):
    """安全地解析JSON响应"""
    import json
    try:
        return response.json()
    except Exception:
        # requests 已自动处理 gzip/brotli 解压，只需清理文本
        text = response.text.lstrip('\ufeff')
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise ValueError(f"{context}响应不含有效JSON")

def create_session():
    """创建配置完整的会话对象"""
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    
    # 设置适配器，避免连接池问题
    adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    return session

def test_domain(domain):
    """快速测试域名是否为可用的 ikuuu 服务（非导航页）

    判断逻辑：GET 根路径，真实服务会 302 跳转到 /auth/login，导航页返回 200
    """
    test_url = f"https://{domain}/"
    try:
        session = create_session()
        response = session.get(test_url, timeout=DOMAIN_TEST_TIMEOUT, verify=False, allow_redirects=False)
        session.close()

        # 真实服务：根路径 302 跳转到 /auth/login
        if response.status_code == 302:
            location = response.headers.get('Location', '')
            if '/auth/login' in location:
                print_with_time(f"域名 {domain} 可用（302 -> /auth/login）", "SUCCESS")
                return True
            else:
                print_with_time(f"域名 {domain} 302跳转到 {location}，非服务页面", "DEBUG")
                return False

        # 导航页：返回 200 的 HTML 页面
        if response.status_code == 200:
            print_with_time(f"域名 {domain} 返回200，可能是导航页", "DEBUG")
            return False

        print_with_time(f"域名 {domain} 返回状态码 {response.status_code}", "WARNING")
        return False
    except Exception as e:
        print_with_time(f"域名 {domain} 不可用: {str(e)}", "DEBUG")
        return False

def _decode_obfuscated_strings(html_text):
    """从导航页的混淆JS中解码字符串数组"""
    # 自定义 base64 字母表（小写在前，大写在后）
    custom = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
    standard = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    table = str.maketrans(custom, standard)

    decoded = []
    # 提取编码字符串数组
    arrays = re.findall(r"\[(?:'[^']*',?\s*){5,}\]", html_text)
    for arr in arrays:
        items = re.findall(r"'([^']*)'", arr)
        for s in items:
            try:
                translated = s.translate(table)
                padding = 4 - len(translated) % 4
                if padding != 4:
                    translated += '=' * padding
                raw = base64.b64decode(translated)
                decoded.append(raw.decode('utf-8', errors='ignore'))
            except Exception:
                pass
    return decoded

def discover_domains():
    """从导航页自动发现当前可用域名列表"""
    print_with_time("开始自动发现域名...", "INFO")
    discovered = []

    for nav_url in NAVIGATION_URLS:
        try:
            print_with_time(f"尝试从 {nav_url} 获取域名列表...", "DEBUG")
            session = create_session()
            response = session.get(nav_url, timeout=DOMAIN_TEST_TIMEOUT + 5, verify=False, allow_redirects=True)
            session.close()

            if response.status_code != 200:
                continue

            html_text = response.text

            # 策略1：从 h3 标签提取域名（适用于非JS渲染的导航页）
            soup = BeautifulSoup(html_text, 'html.parser')
            for h3 in soup.find_all('h3'):
                text = h3.get_text(strip=True)
                if re.match(r'^ikuuu\.\w{2,}$', text, re.IGNORECASE):
                    discovered.append(text.lower())

            # 策略2：从 a 标签 href 提取域名
            for a in soup.find_all('a', href=True):
                match = re.search(r'https?://(ikuuu\.\w{2,})/?', a['href'], re.IGNORECASE)
                if match:
                    domain = match.group(1).lower()
                    if domain not in discovered:
                        discovered.append(domain)

            # 策略3：从字符串拼接模式提取（如 'ikuuu'+'.nl'）
            for m in re.finditer(r"'ikuuu'\+'\.(\w{2,})'", html_text):
                domain = f"ikuuu.{m.group(1).lower()}"
                if domain not in discovered:
                    discovered.append(domain)

            # 策略4：解码混淆JS字符串数组，查找 TLD 片段（如 .fyi, .nl）
            for s in _decode_obfuscated_strings(html_text):
                if re.match(r'^\.\w{2,4}$', s):
                    domain = f"ikuuu{s}".lower()
                    if domain not in discovered:
                        discovered.append(domain)

            if discovered:
                # 过滤掉导航页自身的域名
                nav_domain = nav_url.replace('https://', '').replace('http://', '').rstrip('/')
                discovered = [d for d in discovered if d != nav_domain]
                print_with_time(f"发现 {len(discovered)} 个域名: {', '.join(discovered)}", "SUCCESS")
                break

        except Exception as e:
            print_with_time(f"从 {nav_url} 获取域名失败: {str(e)}", "DEBUG")
            continue

    if not discovered:
        print_with_time("自动域名发现未找到任何域名", "WARNING")

    return discovered

def _set_domain(domain):
    """设置当前使用的域名"""
    global BASE_DOMAIN, BASE_URL
    BASE_DOMAIN = domain
    BASE_URL = f"https://{BASE_DOMAIN}"

def resolve_domain():
    """按优先级解析可用域名：缓存文件 > 环境变量 > 本地变量 > 默认值 > 自动发现"""
    print_with_time("开始域名解析...", "INFO")

    # 构建候选列表（有序去重）
    candidates = []
    for domain in [read_domain_from_file(), os.getenv('IKUUU_DOMAIN'), LOCAL_DOMAIN, DEFAULT_DOMAIN]:
        if domain and domain not in candidates:
            candidates.append(domain)

    # 逐个测试
    for domain in candidates:
        if test_domain(domain):
            _set_domain(domain)
            save_domain_to_file(domain)
            print_with_time(f"使用域名: {domain}", "SUCCESS")
            return domain

    # 候选域名均不可用，自动发现
    print_with_time("候选域名不可用，尝试自动发现...", "WARNING")
    for domain in discover_domains():
        if domain not in candidates and test_domain(domain):
            _set_domain(domain)
            save_domain_to_file(domain)
            print_with_time(f"使用自动发现的域名: {domain}", "SUCCESS")
            return domain

    print_with_time(f"所有域名均不可用，使用默认域名: {DEFAULT_DOMAIN}", "ERROR")
    _set_domain(DEFAULT_DOMAIN)

def safe_request(method, url, **kwargs):
    """安全的网络请求，包含重试"""
    kwargs.setdefault('timeout', 8)
    kwargs['verify'] = False

    for attempt in range(2):
        try:
            if attempt > 0:
                time.sleep(attempt * 2)
                print_with_time(f"第 {attempt + 1} 次重试...", "WARNING")
            session = create_session()
            response = session.request(method, url, **kwargs)
            session.close()
            return response
        except KeyboardInterrupt:
            raise
        except Exception as e:
            if attempt == 1:
                print_with_time(f"请求失败: {str(e)}", "ERROR")
    return None

def login_and_get_cookie():
    """登录 SSPanel 并获取 Cookie"""
    email = os.getenv('IKUUU_EMAIL') or LOCAL_EMAIL
    password = os.getenv('IKUUU_PASSWORD') or LOCAL_PASSWORD

    if not email or not password:
        print_with_time("请设置账户信息（环境变量 IKUUU_EMAIL/IKUUU_PASSWORD 或代码中 LOCAL_EMAIL/LOCAL_PASSWORD）", "ERROR")
        return None

    masked_email = f"{email[:3]}***{email.split('@')[1]}"
    print_with_time(f"账号: {masked_email}，域名: {BASE_DOMAIN}", "INFO")

    session = create_session()
    try:
        # 获取登录页面（取CSRF token）
        login_page_url = f"{BASE_URL}/auth/login"
        try:
            response = session.get(login_page_url, timeout=8, verify=False)
        except Exception as e:
            print_with_time(f"获取登录页面失败: {str(e)}", "ERROR")
            return None

        if response.status_code != 200:
            print_with_time(f"无法访问登录页面，状态码: {response.status_code}", "ERROR")
            return None

        # 查找 CSRF token
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_input = soup.find('input', {'name': '_token'})

        login_data = {'email': email, 'passwd': password}
        if csrf_input:
            login_data['_token'] = csrf_input.get('value')

        # 发送登录请求
        print_with_time("正在登录...", "INFO")
        headers = {
            'Origin': BASE_URL,
            'Referer': login_page_url,
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        try:
            response = session.post(login_page_url, data=login_data, headers=headers,
                                    timeout=8, verify=False, allow_redirects=False)
        except Exception as e:
            print_with_time(f"登录请求失败: {str(e)}", "ERROR")
            return None

        cookie_string = '; '.join([f"{c.name}={c.value}" for c in session.cookies])

        # 检查登录结果
        if response.status_code == 302 and '/user' in response.headers.get('Location', ''):
            print_with_time("登录成功", "SUCCESS")
            return cookie_string or None

        if response.status_code == 200:
            try:
                result = parse_json_response(response, "登录")
                if result.get('ret') == 1:
                    print_with_time("登录成功", "SUCCESS")
                    return cookie_string or None
                else:
                    print_with_time(f"登录失败: {result.get('msg', '未知错误')}", "ERROR")
                    return None
            except Exception:
                # JSON解析失败，用Cookie判断
                if cookie_string:
                    print_with_time("登录成功（Cookie检测）", "SUCCESS")
                    return cookie_string

        print_with_time(f"登录失败，状态码: {response.status_code}", "ERROR")
        return None
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print_with_time(f"登录错误: {str(e)}", "ERROR")
        return None
    finally:
        session.close()

def checkin(cookie):
    """执行签到操作"""
    print_with_time("开始执行签到...", "INFO")
    headers = {
        'Origin': BASE_URL, 'Referer': f"{BASE_URL}/user",
        'Cookie': cookie, 'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    try:
        response = safe_request('POST', f"{BASE_URL}/user/checkin", headers=headers)
        if not response:
            print_with_time("签到请求失败", "ERROR")
            return False

        data = parse_json_response(response, "签到")
        msg = data.get('msg', '')
        if data.get('ret') == 1:
            print_with_time(f"签到成功: {msg}", "SUCCESS")
            return True
        elif "已经签到" in msg:
            print_with_time(f"今日已签到: {msg}", "WARNING")
            return True
        else:
            print_with_time(f"签到失败: {msg or '未知错误'}", "ERROR")
            return False
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print_with_time(f"签到失败: {str(e)}", "ERROR")
        return False

def extract_account_info(soup):
    """从解析的HTML中提取账户信息"""
    # 关键词 -> 显示标签映射
    label_map = [
        (['会员时长', '时长', '到期'], '会员状态'),
        (['剩余流量', '流量', '可用'], '剩余流量'),
        (['在线设备', '设备', '连接'], '在线设备'),
        (['钱包', '余额', '积分'], '账户余额'),
    ]

    stat_cards = (soup.find_all('div', class_='card-statistic-2')
                  or soup.find_all('div', class_='card-statistic')
                  or soup.find_all('div', class_='card'))

    info_found = False
    for card in stat_cards:
        header = card.find('h4') or card.find('h3') or card.find('h5')
        if not header:
            continue
        title = header.get_text(strip=True)
        body = card.find('div', class_='card-body') or card.find('div', class_='card-content')
        if not body:
            continue

        value = re.sub(r'\s+', ' ', body.get_text(strip=True))
        label = None
        for keywords, lbl in label_map:
            if any(k in title for k in keywords):
                label = lbl
                break

        if label:
            print(f"  {label}: {value}")
            info_found = True
        elif value and len(value) > 3:
            print(f"  {title.rstrip(':')}: {value}")
            info_found = True

    return info_found

def get_user_info(cookie):
    """获取用户信息和流量数据"""
    print_separator("─", 50)
    print_with_time("正在获取账户信息...", "INFO")
    
    headers = {
        'Cookie': cookie
    }
    url = f"{BASE_URL}/user"
    
    try:
        response = safe_request('GET', url, headers=headers)
        
        if not response:
            print_with_time("获取账户信息失败", "ERROR")
            return False
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 检查页面标题确认登录状态
        page_title = soup.find('title')
        if page_title:
            title_text = page_title.get_text(strip=True)
            if any(keyword in title_text.lower() for keyword in ['login', '登录']):
                print_with_time("登录状态已失效，请检查账户信息", "ERROR")
                return False
        
        # 检查是否有Base64编码的内容
        decoded_html = None
        for script in soup.find_all('script'):
            script_content = script.get_text()
            if 'originBody' in script_content and 'decodeBase64' in script_content:
                match = re.search(r'var originBody = "([^"]+)"', script_content)
                if match:
                    try:
                        decoded_html = base64.b64decode(match.group(1)).decode('utf-8')
                    except Exception:
                        pass
                    break

        target_soup = BeautifulSoup(decoded_html, 'html.parser') if decoded_html else soup
        info_extracted = extract_account_info(target_soup)

        if not info_extracted:
            print_with_time("未能提取到详细账户信息", "WARNING")
            all_text = decoded_html or soup.get_text()
            numbers = re.findall(r'(\d+(?:\.\d+)?)\s*(GB|MB|天|个|USD|CNY)', all_text)
            if numbers:
                for value, unit in set(numbers):
                    print(f"  {value} {unit}")
        
        print_separator("─", 50)
        return True
        
    except KeyboardInterrupt:
        print_with_time("用户中断信息获取操作", "WARNING")
        raise
    except Exception as e:
        print_with_time(f"获取用户信息失败: {str(e)}", "ERROR")
        return False

def main():
    """主程序入口"""
    print_separator("=", 60)
    print_with_time("自动签到程序启动", "INFO")
    print_separator("=", 60)

    if not check_dependencies():
        return False

    resolve_domain()

    start_time = time.time()

    # 登录
    cookie_data = login_and_get_cookie()
    if not cookie_data:
        # 登录失败，尝试其他域名
        print_with_time("登录失败，尝试切换域名...", "WARNING")
        original = BASE_DOMAIN
        for domain in discover_domains():
            if domain != original and test_domain(domain):
                _set_domain(domain)
                save_domain_to_file(domain)
                print_with_time(f"切换到 {domain}，重试登录...", "INFO")
                cookie_data = login_and_get_cookie()
                if cookie_data:
                    break

    if not cookie_data:
        print_with_time("所有域名均无法登录", "ERROR")
        return False

    time.sleep(1)
    checkin_result = checkin(cookie_data)
    time.sleep(1)
    get_user_info(cookie_data)

    elapsed = round(time.time() - start_time, 2)
    print_separator("=", 60)
    print_with_time(f"执行完成，耗时 {elapsed} 秒", "SUCCESS" if checkin_result else "ERROR")
    print_separator("=", 60)
    return checkin_result

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)