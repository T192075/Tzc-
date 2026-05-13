# TZC晚点签到系统

完整版，包含详细加密流程注释。tzxy官网账号密码登录，需使用校园网签到

## 文件结构

```
main.py           # 完整程序（所有代码整合）
exe.py            # 窗口版
晚点签到.exe          # windows执行文件，双击可运行
README.md
index.html    # 技术分析文档
```

## 使用方法

1. 安装依赖：
```bash
pip install requests pycryptodome
```

2. 修改 `main.py` 中的账号密码：
```python
USERNAME = "你的学号"
PASSWORD = "你的密码"
```

3. 运行程序：
```bash
python main.py
```

## 加密流程

```
明文密码 → UTF-8编码 → PKCS7填充(16字节) → AES-ECB加密 → Base64编码 → 密文
```

- 密钥来源：登录页面 `login-croypto` 字段（Base64解码）
- 加密模式：AES-ECB
- 填充方式：PKCS7

## 免责声明

本项目仅供学习交流使用。
