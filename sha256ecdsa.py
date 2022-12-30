# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

import hashlib
import random

x = "x"
y = "y"

'''
    curve parameter - 1.3.132.0.33
    p: 椭圆的域
    a: 椭圆的参数
    b: 椭圆的参数
    G：椭圆的基点
    n: 椭圆的阶数
    website: https://neuromancer.sk/std/secg/secp224r1
'''
curve_p = 0xffffffffffffffffffffffffffffffff000000000000000000000001
curve_a = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe
curve_b = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4
curve_G = {x: 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
           y: 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34}
curve_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D  
curve_h = 0x1

'''
    用辗转相除法求最大公约数，用于减少分子分母的量级
'''
def gcd(v1, v2):
    if v2 == 0:
        return v1
    else:
        return gcd(v2, v1 % v2)


'''
    求A的逆元，仅在p为素数时有效
'''
def pinv(A, n):
    return pow(A, n-2, n)
    

'''
    倍加，计算A+B
'''
def padd(A, B, p):
    global curve_a, curve_b
    
    flag = 1    #默认为正值，如果最后k值计算出来是负值，需要取其负元
    if(A[x] == B[x] and A[y] == B[y]):
        numerator = (3*pow(A[x],2) + curve_a) % p
        denominator = (2*A[y]) % p
    else:
        numerator = (A[y] - B[y]) % p
        denominator = (A[x] - B[x]) % p
    
    if((numerator > 0 and denominator < 0) or (numerator < 0 and denominator > 0)):
        flag = -1
        numerator = abs(numerator)
        denominator = abs(denominator)
    
    #约分减少运算量
    factor = gcd(numerator, denominator)
    numerator = numerator // factor
    denominator = denominator // factor
    
    #求分母逆元
    denominator_inv = pinv(denominator, p)
    
    #求斜率k
    k = (numerator * denominator_inv)
    if(flag < 0):
        k = -k
    k = k % p
    
    rx = (pow(k, 2) - A[x] - B[x]) % p
    ry = (k*(A[x] - rx) - A[y]) % p
    
    return {x:rx, y:ry}

'''
    倍乘，计算kA
'''
def pmul(k, A, p):
    ret = {x:0, y:0}
    r = A
    while(k != 0):
        if((k & 1) != 0):
            if(ret[x] == 0 and ret[y] == 0):
                ret = r
            else:
                ret = padd(ret, r, p)
        r = padd(r, r, p)
        k >>= 1
        
    return ret
    
'''
    该函数用证书信息来验证消息是否被修改
    h: 消息的哈希值，由客户端自行计算
    r：签名值，由证书或服务器提供
    s: 签名值，由证书或服务器提供
    Q：公钥，由证书或服务器提供
    eRG: 期待的签名值
'''
def sha256ecdsa(h, r, s, Q, erG, log=False):
    global curve_n, curve_p

    #先求s的逆元
    s_inv = pinv(s, curve_n)
    
    k1 = h * s_inv % curve_n
    k2 = r * s_inv % curve_n

    
    k1G = pmul(k1, curve_G, curve_p)
    k2Q = pmul(k2, Q, curve_p)
    rG = padd(k1G, k2Q, curve_p)
    
    if(log):
        print("Signature Check Parameter")
        print("   s_inv: %X" % s_inv)
        print("   k1: %X" % k1)
        print("   k2: %X" % k2)
        print("   k1G: (%X, %X)" % (k1G[x], k1G[y]))
        print("   k2Q: (%X, %X)" % (k2Q[x], k2Q[y]))
        print("   rG: (%X, %X)" % (rG[x], rG[y]))
        
    if(rG[x] == erG):
        if(log):
            print("sha256ecdsa ok")
        return True
    else:
        if(log):
            print("sha256ecdsa failed")
        return False

def signature(m, d, log=False):
    global curve_p, curve_G, curve_n

    #(a+b)%n = (a%n + b%n)%n
    #(a-b)%n = (a%n - b%n)%n
    #(a*b)%n = (a%n * b%n)%n
    #(a^b)%n = ((a%n)^b)%n
    
    Q = pmul(d, curve_G, curve_p)
    h = int.from_bytes(hashlib.sha256(m).digest(), "big") >> 32 #ignore low 32bits
    r = random.randint(1, curve_n-1)
    rG = pmul(r, curve_G, curve_p)
    
    r_inv = pinv(r, curve_n)
    s = ((h + d * rG[x]) * r_inv) % curve_n
    
    if(log):
        print("Signature Generate Parameter")
        print("   Q: (%X, %X)" % (Q[x], Q[y]))
        print("   h: %X" % h)
        print("   r: %X" % r)
        print("   rG: (%X, %X)" % (rG[x], rG[y]))
        print("   r_inv: %X" % r_inv)
        print("   s: %X" % s)
    
    return {"pubkey": Q, "signR":rG[x], "signS":s}

def check_QdG(d, Q):  
    ret = pmul(d, curve_G, curve_p)
    # print("r = (%X, %X)" % (ret[x], ret[y]))
    # print("Q = (%X, %X)" % (Q[x], Q[y]))
    if(ret[x] == Q[x] and ret[y] == Q[y]):
        return True
    else:
        return False
 
def main():
    # fd = open("root.der", "rb")
    # data = fd.read()
    # fd.close()
    
    # d = 0x3932B7D94599F5B1BAF108E9A6AA8C8471E362E3DF92BBA0B4284DFD
    # Q = {x:0x1B8C308B37940EEDFD45B98A57CCC6844D3A38AB04EE82304E3ECB39,
         # y:0xF089F3FEE7D69C6CC16020A3B09C815C191B598538ECC0C1C9FCB452}        
    d = 0x4065b8b4fa7af639bef49232e1202f62890d090249a04737c3fbb854
    Q = {x:0xC9A0616D3E50ACBFC6808D488F22DA45A61C21ABC594717201D34606,
         y:0x4B1786BCD0A28B4DA8E979757C6E81F03E777B55A405C7216DFF4EBA}   
    check_QdG(d, Q)
    
    # sign = generate_certificate(data, 0x3932B7D94599F5B1BAF108E9A6AA8C8471E362E3DF92BBA0B4284DFD, True)
    # h = int.from_bytes(hashlib.sha256(data).digest(), "big") >> 32 #ignore low 32bits
    
    # sign = {"signR": 0x779B041D03CC103D60C9531BF1649A064D1D4F55987D3CF0EC809744,
            # "signS": 0x654B4DC684C9BE91B9B3AFE22C5811E901F629A33CB21BA85B814925,
            # "pubkey": {x:0x471B71C9C51C66BAA2A07551D3D281CB18B72D2D552B688C267C9D7C, y:0x1582D96D0BA41680010A6CDA982DCC7A2E8C935C51610D73D22FF44D} }
    # sha256ecdsa(h, sign["signR"], sign["signS"], sign["pubkey"], sign["signR"], True)

        
if __name__ == '__main__':
	main()