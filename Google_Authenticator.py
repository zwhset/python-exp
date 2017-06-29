#coding:utf8

'''
google authenticator 两步认证
原理：
    基于hotp算法，按照时间同样一个字符串与时间相结合在不同服务器上会算出相同的数
    利用这相同的数去验证，服务器上只要保存明文即可。
'''
import hmac, base64, struct, hashlib, time
import random

def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = ord(h[19]) & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h

def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no=int(time.time())//30)

def shutff_str(): #生成随机字符串大字16位
    src = "abcdefghijklmnopqrstuvwxyz".upper()
    secret= "".join(random.sample(src,16)).replace(' ','')
    return secret

secret = shutff_str()

print(secret) # goole authenticator手机上 输入进行比对
for i in range(1,100):
    print(get_totp_token(secret))
    time.sleep(3)
