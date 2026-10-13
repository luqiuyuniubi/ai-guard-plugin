import re

INJECTION = re.compile(
    r"ignore\s+(all\s+)?(previous|prior|system)|忽略.{0,12}(指令|规则|提示)|"
    r"(泄露|输出|打印).{0,12}(密钥|系统提示词)|system\s*prompt|"
    r"你现在是.{0,8}管理员|绕过.{0,8}(权限|审核)", re.I)
SECRET = re.compile(r"DEMO_SECRET_[A-Z0-9_]+|\bsk-demo-[A-Za-z0-9_-]+\b")
PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")


def redact(text):
    return PHONE.sub("[手机号已脱敏]", SECRET.sub("[密钥已脱敏]", text))
