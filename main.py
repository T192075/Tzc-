# -*- coding: utf-8 -*-
"""
TZC晚点签到系统 - 完整版
基于1.py代码整合，包含详细加密流程注释
"""

import tkinter as tk
from tkinter import ttk
import threading
import requests
import re
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ==================== 配置区域 ====================
USERNAME = "你的学号"      # 替换为你的学号
PASSWORD = "你的密码"      # 替换为你的密码

BASE_SSO = "https://sso.tzc.edu.cn"
BASE_XGFW = "https://xgfw.tzc.edu.cn"
SVC = BASE_XGFW + "/xsfw/sys/swmzncqapp/*default/index.do"
TARGET_CLASSES = ("23智能制造1", "23智能制造2")

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
    
    参数:
        text: 明文字符串(密码)
        key: 密钥(bytes类型，从页面Base64解码获得)
    
    返回:
        Base64编码的密文字符串
    
    详细流程:
        1. AES.new(key, AES.MODE_ECB) - 创建AES加密器，ECB模式
        2. text.encode() - 将明文转为bytes
        3. pad(..., 16) - PKCS7填充到16字节对齐
        4. cipher.encrypt(...) - 执行AES加密
        5. base64.b64encode(...) - 将密文转为Base64字符串
    """
    c = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(c.encrypt(pad(text.encode(), 16))).decode()


def parse_fields(html):
    """
    解析登录页面中的隐藏字段
    
    参数:
        html: 登录页面HTML内容
    
    返回:
        字典，包含以下字段:
        - login-croypto: 加密密钥(Base64编码)
        - login-page-flowkey: 页面流程标识
        - captchaId: 验证码ID
        - targetSystem: 目标系统
    
    解析方式:
        使用正则表达式匹配 id="xxx">value< 格式的标签
    """
    d = {}
    for k in ["login-croypto", "login-page-flowkey", "captchaId", "targetSystem"]:
        m = re.search(rf'id="{k}">(.*?)<', html)
        d[k] = m.group(1) if m and m.group(1) else ""
    return d


def sso_login():
    """
    SSO单点登录函数
    
    完整流程:
        1. 创建Session，设置请求头
        2. GET登录页面，获取加密密钥和流程标识
        3. 使用AES-ECB加密密码
        4. POST登录请求，获取重定向URL中的Ticket
        5. 使用Ticket访问目标系统
        6. 从响应中提取Cookie(_WEU和JSESSIONID)
    
    返回:
        带有_WEU和_JSESSIONID属性的Session对象
    
    异常:
        登录失败时抛出Exception
    """
    # 步骤1: 创建Session
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9",
    })
    
    # 步骤2: GET登录页面
    # 构建登录URL，service参数是目标系统地址(URL编码)
    login_url = BASE_SSO + "/login?service=" + requests.utils.quote(SVC, safe="")
    r = session.get(login_url, timeout=15)
    
    # 步骤3: 解析页面字段
    fields = parse_fields(r.text)
    
    # 步骤4: 获取加密密钥并加密密码
    # login-croypto是Base64编码的密钥，需要解码为bytes
    ck = base64.b64decode(fields["login-croypto"])
    
    # 步骤5: 构建登录表单数据
    data = [
        ("username", USERNAME),                                    # 学号
        ("type", "UsernamePassword"),                              # 登录类型
        ("_eventId", "submit"),                                    # 事件标识
        ("geolocation", ""),                                       # 地理位置(空)
        ("execution", fields["login-page-flowkey"]),              # 页面流程标识
        ("captcha_code", ""),                                      # 验证码(空)
        ("croypto", fields["login-croypto"]),                     # 加密密钥(原始Base64)
        ("password", enc(PASSWORD, ck)),                          # ★ 加密后的密码 ★
        ("captcha_payload", enc("{}", ck)),                       # 加密后的验证码数据
    ]
    
    # 步骤6: POST登录请求
    # allow_redirects=False 禁止自动重定向，以便获取重定向URL
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
    # 登录成功后，服务器返回302重定向，Location中包含ticket
    loc = r.headers.get("Location", "")
    if "ticket=" not in loc:
        raise Exception("SSO登录失败: 未获取到Ticket")
    ticket = re.search(r"ticket=([^&\s]+)", loc).group(1)
    
    # 步骤8: 使用Ticket访问目标系统
    # 这一步会触发多次重定向，最终获取到系统Cookie
    r = session.get(SVC + "?ticket=" + ticket, allow_redirects=True, timeout=15)
    
    # 步骤9: 提取关键Cookie
    # _WEU: 系统会话标识(需要获取最新的)
    # JSESSIONID: Java会话ID
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
    
    # 将Cookie存储到session对象中
    session._WEU = weu_list[-1]      # 使用最新的_WEU
    session._JSESSIONID = jsessionid
    
    return session


def api_headers(session):
    """
    构建API请求头
    
    参数:
        session: 带有_WEU和_JSESSIONID的session对象
    
    返回:
        包含Cookie的请求头字典
    
    说明:
        后续所有API请求都需要使用这个请求头
        Cookie格式: _WEU=xxx;EMAP_LANG=zh; JSESSIONID=xxx
    """
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


def do_query():
    """
    查询签到信息
    
    流程:
        1. SSO登录获取session
        2. 设置应用角色(setAppRole.do)
        3. 获取签到信息(getKqInfo.do)
        4. 检查是否在允许的班级中
    """
    global session_cache
    try:
        # 步骤1: SSO登录
        update("SSO登录中...")
        session_cache = sso_login()
        
        # 步骤2: 设置应用角色
        # 这是必须的步骤，用于激活签到功能
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
        
        # 步骤3: 获取签到信息
        info = requests.post(
            BASE_XGFW + "/xsfw/sys/swmzncqapp/kqController/getKqInfo.do",
            headers=api_headers(session_cache),
            data='data=%7B%7D',
            timeout=15
        ).json()
        
        # 提取用户信息
        ssl = info.get("data", {}).get("SSL_INFO", {})
        xm = ssl.get("XM", "?")           # 姓名
        bjdm = ssl.get("BJDM_DISPLAY", "?")  # 班级
        
        # 步骤4: 检查班级
        if bjdm not in TARGET_CLASSES:
            update(f"{xm}\n{bjdm}\n非本班级,不签到")
            btn_sign.config(state="disabled")
        else:
            update(f"{xm}\n{bjdm}\n可以签到")
            btn_sign.config(state="normal")
            
    except Exception as e:
        update(f"错误: {e}")


def do_sign():
    """
    执行签到
    
    流程:
        1. 检查session是否有效
        2. 获取当前位置信息
        3. POST提交签到(addKqInfo.do)
    
    签到数据:
        - KQWZXX: 签到位置信息(地址)
        - JDZB: 经度坐标
        - WDZB: 纬度坐标
    """
    if not session_cache:
        return
    
    # 获取位置信息
    location = get_current_location()
    if not location:
        return
    
    try:
        update("签到中...")
        
        # 构建签到数据并URL编码
        sign_data = {
            "KQWZXX": location["address"],
            "JDZB": location["longitude"],
            "WDZB": location["latitude"]
        }
        encoded_data = requests.utils.quote(json.dumps(sign_data, ensure_ascii=False), safe='')
        
        # 提交签到
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


def task_query():
    """异步执行查询"""
    threading.Thread(target=do_query, daemon=True).start()


def task_sign():
    """异步执行签到"""
    threading.Thread(target=do_sign, daemon=True).start()


def on_location_change(event=None):
    """位置选择改变时的回调"""
    selected = location_var.get()
    if selected == "自定义":
        # 自定义模式：启用输入框
        address_entry.config(state="normal")
        longitude_entry.config(state="normal")
        latitude_entry.config(state="normal")
    else:
        # 预设模式：禁用输入框，自动填充
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
root.geometry("400x450")
root.resizable(False, False)

# 居中显示
root.update_idletasks()
sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
root.geometry(f"+{(sw-400)//2}+{(sh-450)//2}")

# 状态标签
label = tk.Label(root, text="正在登录...", font=("Microsoft YaHei", 11), justify="left")
label.pack(pady=10, padx=15)

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

# 启动时自动查询
root.after(200, task_query)

root.mainloop()
