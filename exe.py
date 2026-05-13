# -*- coding: utf-8 -*-
"""
TZC晚点签到系统 - 完整版
支持手动输入账号密码，记住账号密码功能
"""

import tkinter as tk
from tkinter import ttk
import threading
import requests
import re
import json
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ==================== 配置区域 ====================
BASE_SSO = "https://sso.tzc.edu.cn"
BASE_XGFW = "https://xgfw.tzc.edu.cn"
SVC = BASE_XGFW + "/xsfw/sys/swmzncqapp/*default/index.do"


# 配置文件路径（保存在程序同目录）
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.dat")

# 预设位置（可选）
LOCATIONS = {
    "6号宿舍楼": {
        "address": "浙江省台州市椒江区市府大道1139号",
        "longitude": 121.39567931605,
        "latitude": 28.655850491041
    },
    "图书馆": {
        "address": "浙江省台州市椒江区市府大道1139号台州学院图书馆",
        "longitude": 121.396200,
        "latitude": 28.656100
    },
    "教学楼": {
        "address": "浙江省台州市椒江区市府大道1139号台州学院教学楼",
        "longitude": 121.395900,
        "latitude": 28.655900
    }
}

# 默认使用6号宿舍楼
DEFAULT_LOCATION = "6号宿舍楼"


# ==================== 配置文件操作 ====================
def save_config(username, password, remember):
    """保存配置到文件"""
    if remember:
        # 简单加密（Base64）
        data = {
            "username": base64.b64encode(username.encode()).decode(),
            "password": base64.b64encode(password.encode()).decode(),
            "remember": True
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f)
    else:
        # 不记住密码，删除配置文件
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)


def load_config():
    """从文件加载配置"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
            return {
                "username": base64.b64decode(data["username"]).decode(),
                "password": base64.b64decode(data["password"]).decode(),
                "remember": data.get("remember", False)
            }
        except:
            return None
    return None


# ==================== 加密流程详解 ====================
"""
加密算法: AES-ECB模式
加密流程:
    1. 从登录页面获取密钥(login-croypto字段，Base64编码)
    2. 将密钥进行Base64解码得到原始密钥(bytes)
    3. 将明文密码进行UTF-8编码
    4. 使用PKCS7填充到16字节对齐
    5. 使用AES-ECB模式加密
    6. 将密文进行Base64编码得到最终加密字符串

密钥来源: GET https://sso.tzc.edu.cn/login 页面中的
         <input id="login-croypto" value="xxx"> 字段
"""


def enc(text, key):
    """
    AES-ECB加密函数
    """
    c = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(c.encrypt(pad(text.encode(), 16))).decode()


def parse_fields(html):
    """解析登录页面中的隐藏字段"""
    d = {}
    for k in ["login-croypto", "login-page-flowkey", "captchaId", "targetSystem"]:
        m = re.search(rf'id="{k}">(.*?)<', html)
        d[k] = m.group(1) if m and m.group(1) else ""
    return d


def sso_login(username, password):
    """
    SSO单点登录函数
    
    参数:
        username: 学号
        password: 密码
    """
    # 步骤1: 创建Session
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9",
    })
    
    # 步骤2: GET登录页面
    login_url = BASE_SSO + "/login?service=" + requests.utils.quote(SVC, safe="")
    r = session.get(login_url, timeout=15)
    
    # 步骤3: 解析页面字段
    fields = parse_fields(r.text)
    
    # 步骤4: 获取加密密钥并加密密码
    ck = base64.b64decode(fields["login-croypto"])
    
    # 步骤5: 构建登录表单数据
    data = [
        ("username", username),
        ("type", "UsernamePassword"),
        ("_eventId", "submit"),
        ("geolocation", ""),
        ("execution", fields["login-page-flowkey"]),
        ("captcha_code", ""),
        ("croypto", fields["login-croypto"]),
        ("password", enc(password, ck)),
        ("captcha_payload", enc("{}", ck)),
    ]
    
    # 步骤6: POST登录请求
    r = session.post(
        BASE_SSO + "/login", 
        data=data, 
        allow_redirects=False,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": BASE_SSO,
            "Referer": login_url
        }, 
        timeout=15
    )
    
    # 步骤7: 提取Ticket
    loc = r.headers.get("Location", "")
    if "ticket=" not in loc:
        raise Exception("SSO登录失败: 账号或密码错误")
    ticket = re.search(r"ticket=([^&\s]+)", loc).group(1)
    
    # 步骤8: 使用Ticket访问目标系统
    r = session.get(SVC + "?ticket=" + ticket, allow_redirects=True, timeout=15)
    
    # 步骤9: 提取关键Cookie
    weu_list, jsessionid = [], None
    for resp_obj in r.history + [r]:
        for c in resp_obj.headers.get("Set-Cookie", "").split(","):
            m = re.search(r"_WEU=([^;]+)", c)
            if m:
                weu_list.append(m.group(1))
            m = re.search(r"JSESSIONID=([^;]+)", c)
            if m:
                jsessionid = m.group(1)
    
    if len(weu_list) < 2:
        raise Exception("_WEU获取失败")
    if not jsessionid:
        raise Exception("JSESSIONID获取失败")
    
    session._WEU = weu_list[-1]
    session._JSESSIONID = jsessionid
    
    return session


def api_headers(session):
    """构建API请求头"""
    return {
        "Host": "xgfw.tzc.edu.cn",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": BASE_XGFW,
        "Referer": SVC,
        "Cookie": f"_WEU={session._WEU};EMAP_LANG=zh; JSESSIONID={session._JSESSIONID}",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    }


session_cache = None


def get_current_location():
    """获取当前选择的位置信息"""
    selected = location_var.get()
    if selected == "自定义":
        try:
            return {
                "address": address_var.get(),
                "longitude": float(longitude_var.get()),
                "latitude": float(latitude_var.get())
            }
        except ValueError:
            update("经纬度格式错误!")
            return None
    return LOCATIONS.get(selected, LOCATIONS[DEFAULT_LOCATION])


def do_login():
    """执行登录"""
    global session_cache
    
    username = username_var.get().strip()
    password = password_var.get().strip()
    
    if not username or not password:
        update("请输入账号和密码!")
        return
    
    try:
        # 保存配置
        save_config(username, password, remember_var.get())
        
        # SSO登录
        update("SSO登录中...")
        session_cache = sso_login(username, password)
        
        # 设置应用角色
        r = requests.post(
            BASE_XGFW + "/xsfw/sys/swpubapp/NewMobileAPIController/setAppRole.do",
            headers=api_headers(session_cache),
            data='data=%7B%22APPID%22%3A%225405362541914944%22%2C%22APPNAME%22%3A%22swmzncqapp%22%2C%22ROLEID%22%3A%22ba0a0ba727fe4fa7947338a0b346a1dd%22%7D',
            timeout=15
        )
        
        # 更新_WEU Cookie
        for c in r.headers.get("Set-Cookie", "").split(","):
            m = re.search(r"_WEU=([^;]+)", c)
            if m:
                session_cache._WEU = m.group(1)
        
        # 获取签到信息
        info = requests.post(
            BASE_XGFW + "/xsfw/sys/swmzncqapp/kqController/getKqInfo.do",
            headers=api_headers(session_cache),
            data='data=%7B%7D',
            timeout=15
        ).json()
        
        # 提取用户信息
        ssl = info.get("data", {}).get("SSL_INFO", {})
        xm = ssl.get("XM", "?")
        bjdm = ssl.get("BJDM_DISPLAY", "?")
        
        update(f"{xm}\n{bjdm}\n可以签到")
        btn_sign.config(state="normal")
        # 登录成功后禁用输入
        username_entry.config(state="disabled")
        password_entry.config(state="disabled")
        btn_login.config(state="disabled")
            
    except Exception as e:
        update(f"错误: {e}")


def do_sign():
    """执行签到"""
    if not session_cache:
        return
    
    location = get_current_location()
    if not location:
        return
    
    try:
        update("签到中...")
        
        sign_data = {
            "KQWZXX": location["address"],
            "JDZB": location["longitude"],
            "WDZB": location["latitude"]
        }
        encoded_data = requests.utils.quote(json.dumps(sign_data, ensure_ascii=False), safe='')
        
        r = requests.post(
            BASE_XGFW + "/xsfw/sys/swmzncqapp/kqController/addKqInfo.do",
            headers=api_headers(session_cache),
            data=f"data={encoded_data}",
            timeout=15
        )
        update(r.text)
        
    except Exception as e:
        update(f"错误: {e}")


def update(msg):
    """更新界面标签"""
    label.config(text=msg)
    root.update()


def task_login():
    """异步执行登录"""
    threading.Thread(target=do_login, daemon=True).start()


def task_sign():
    """异步执行签到"""
    threading.Thread(target=do_sign, daemon=True).start()


def on_location_change(event=None):
    """位置选择改变时的回调"""
    selected = location_var.get()
    if selected == "自定义":
        address_entry.config(state="normal")
        longitude_entry.config(state="normal")
        latitude_entry.config(state="normal")
    else:
        loc = LOCATIONS.get(selected, LOCATIONS[DEFAULT_LOCATION])
        address_var.set(loc["address"])
        longitude_var.set(str(loc["longitude"]))
        latitude_var.set(str(loc["latitude"]))
        address_entry.config(state="disabled")
        longitude_entry.config(state="disabled")
        latitude_entry.config(state="disabled")


# ==================== GUI界面 ====================
root = tk.Tk()
root.title("晚点签到")
root.geometry("400x550")
root.resizable(False, False)

# 居中显示
root.update_idletasks()
sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
root.geometry(f"+{(sw-400)//2}+{(sh-550)//2}")

# 加载保存的配置
config = load_config()

# 状态标签
label = tk.Label(root, text="请输入账号密码", font=("Microsoft YaHei", 11), justify="left")
label.pack(pady=10, padx=15)

# 登录框架
login_frame = tk.LabelFrame(root, text="账号登录", font=("Microsoft YaHei", 10), padx=10, pady=10)
login_frame.pack(pady=10, padx=15, fill="x")

# 账号
username_var = tk.StringVar(value=config["username"] if config else "")
tk.Label(login_frame, text="学号:").grid(row=0, column=0, sticky="w")
username_entry = tk.Entry(login_frame, textvariable=username_var, width=25)
username_entry.grid(row=0, column=1, columnspan=2, pady=5)

# 密码
password_var = tk.StringVar(value=config["password"] if config else "")
tk.Label(login_frame, text="密码:").grid(row=1, column=0, sticky="w")
password_entry = tk.Entry(login_frame, textvariable=password_var, show="*", width=25)
password_entry.grid(row=1, column=1, columnspan=2, pady=5)

# 记住密码
remember_var = tk.BooleanVar(value=config["remember"] if config else False)
remember_check = tk.Checkbutton(login_frame, text="记住账号密码", variable=remember_var)
remember_check.grid(row=2, column=0, columnspan=3, pady=5)

# 登录按钮
btn_login = tk.Button(login_frame, text="登录", command=task_login, width=15, font=("Microsoft YaHei", 10))
btn_login.grid(row=3, column=0, columnspan=3, pady=10)

# 位置选择框架
location_frame = tk.LabelFrame(root, text="签到位置", font=("Microsoft YaHei", 10), padx=10, pady=10)
location_frame.pack(pady=10, padx=15, fill="x")

# 位置选择
location_var = tk.StringVar(value=DEFAULT_LOCATION)
tk.Label(location_frame, text="选择位置:").grid(row=0, column=0, sticky="w")
location_combo = ttk.Combobox(location_frame, textvariable=location_var, values=list(LOCATIONS.keys()) + ["自定义"], state="readonly", width=25)
location_combo.grid(row=0, column=1, columnspan=2, pady=5)
location_combo.bind("<<ComboboxSelected>>", on_location_change)

# 地址
address_var = tk.StringVar(value=LOCATIONS[DEFAULT_LOCATION]["address"])
tk.Label(location_frame, text="地址:").grid(row=1, column=0, sticky="w")
address_entry = tk.Entry(location_frame, textvariable=address_var, width=30, state="disabled")
address_entry.grid(row=1, column=1, columnspan=2, pady=5)

# 经度
longitude_var = tk.StringVar(value=str(LOCATIONS[DEFAULT_LOCATION]["longitude"]))
tk.Label(location_frame, text="经度:").grid(row=2, column=0, sticky="w")
longitude_entry = tk.Entry(location_frame, textvariable=longitude_var, width=30, state="disabled")
longitude_entry.grid(row=2, column=1, columnspan=2, pady=5)

# 纬度
latitude_var = tk.StringVar(value=str(LOCATIONS[DEFAULT_LOCATION]["latitude"]))
tk.Label(location_frame, text="纬度:").grid(row=3, column=0, sticky="w")
latitude_entry = tk.Entry(location_frame, textvariable=latitude_var, width=30, state="disabled")
latitude_entry.grid(row=3, column=1, columnspan=2, pady=5)

# 按钮框架
btn_frame = tk.Frame(root)
btn_frame.pack(pady=15)

# 签到按钮
btn_sign = tk.Button(btn_frame, text="签到", command=task_sign, width=12, font=("Microsoft YaHei", 10), state="disabled")
btn_sign.grid(row=0, column=0, padx=10)

# 退出按钮
tk.Button(btn_frame, text="退出", command=root.destroy, width=12, font=("Microsoft YaHei", 10)).grid(row=0, column=1, padx=10)

root.mainloop()
