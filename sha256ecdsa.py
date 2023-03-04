# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

import random
import struct

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
    h = int.from_bytes(SHA256(m).final(), "big") >> 32 #ignore low 32bits
    # r = random.randint(1, curve_n-1)
    r = 0x9BF9E817E50BEAAB442AD1F956D56B9D1C3F8A7D273F6DC9DF1B80F4
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

'''
    稍微有点特殊的sha256
    若只有一次final，则与hashlib.sha256没有区别
    若有多次final时，与与hashlib.sha256有区别
    这是由于wibu软授权框架下的sha256算法有问题
'''
class SHA256:
    def __init__(self, message=None):
        #64个常量Kt
        self.constants = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
        #迭代初始值，h0,h1,...,h7
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
            
        self.block_len = 0
        self.total_len = 0
        self.W = b""
        
        if(message != None):
            self.update(message)

    #x循环右移b个bit
    #rightrotate b bit
    def rightrotate(self, x, b):
        return ((x >> b) | (x << (32 - b))) & ((2**32)-1)

    def Compress(self, Wt, Kt, A, B, C, D, E, F, G, H):
        return ((H + (self.rightrotate(E, 6) ^ self.rightrotate(E, 11) ^ self.rightrotate(E, 25)) + (
                    (E & F) ^ (~E & G)) + Wt + Kt) + (
                            self.rightrotate(A, 2) ^ self.rightrotate(A, 13) ^ self.rightrotate(A, 22)) + (
                            (A & B) ^ (A & C) ^ (B & C))) & ((2**32)-1), A, B, C, (D + (
                    H + (self.rightrotate(E, 6) ^ self.rightrotate(E, 11) ^ self.rightrotate(E, 25)) + (
                        (E & F) ^ (~E & G)) + Wt + Kt)) & ((2**32)-1), E, F, G

    def extend(self):
        state = [0] * 64
    
        for i in range(16):
            state[i] = struct.unpack("I", self.W[i*4:i*4+4])[0]
            
        #构造64个word
        for j in range(16, 64):
            state[j] = (state[j - 16] + (
                        self.rightrotate(state[j - 15], 7) ^ self.rightrotate(state[j - 15], 18) ^ (state[j - 15] >> 3)) + state[
                        j - 7] + (self.rightrotate(state[j - 2], 17) ^ self.rightrotate(state[j - 2], 19) ^ (
                        state[j - 2] >> 10))) & ((2**32)-1)
        
        return state

    def round(self):
        state = self.extend()
    
        A, B, C, D, E, F, G, H = list(self.h)
        for j in range(64):
            A, B, C, D, E, F, G, H = self.Compress(state[j], self.constants[j], A, B, C, D, E, F, G, H)   
        self.h[0] = (self.h[0] + A) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + B) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + C) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + D) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + E) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + F) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + G) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + H) & 0xFFFFFFFF
        
    def update(self, message):
        # print("update: %s(%d)" % (message.hex(), len(message)))
        left_len = 64 - self.block_len
    
        self.total_len += len(message)
        if(left_len > len(message)):
            self.W += message
            self.block_len += len(message)
        else:
            self.W += message[0:left_len]
            self.block_len += left_len
            message = message[left_len:]
            
            while(self.block_len == 64):
                w_rev = b""
                for i in range(16):
                    w_rev += struct.pack("I", struct.unpack(">I", self.W[i*4:i*4+4])[0])
                self.W = w_rev
                self.round()
                
                if(len(message) < 64):
                    self.W = message
                    self.block_len = len(message)
                else:
                    self.W = message[0:64]
                    self.block_len = 64
                    message = message[64:]
                    
    def final(self):
        # print("block_len: %d before: %s" % (self.block_len, self.W.hex()))
        self.W += b'\x80'
        self.block_len += 1
        
        if(self.block_len <= 56):
            self.W += b"\x00" * (56 - self.block_len)
   
            w_rev = b""
            for i in range(14):
                w_rev += struct.pack("I", struct.unpack(">I", self.W[i*4:i*4+4])[0])
            self.W = w_rev
            
        else:
            self.W += b"\x00" * (64 - self.block_len)
            w_rev = b""
            for i in range(16):
                w_rev += struct.pack("I", struct.unpack(">I", self.W[i*4:i*4+4])[0])
            self.W = w_rev
            self.round()
            self.W = b"\x00" * 56
        
        self.total_len *= 8
        self.W += struct.pack("I", (self.total_len>>32))
        self.W += struct.pack("I", self.total_len)
        
        self.round()
        self.W = self.W[0:self.block_len]
        # print("block_len: %d after: %s" % (self.block_len, self.W.hex()))    
        return struct.pack(">IIIIIIII", self.h[0], self.h[1], self.h[2], self.h[3], self.h[4], self.h[5], self.h[6], self.h[7])
    
def sha256_test():
    h = SHA256()
    h.update(struct.pack("I", 5003))
    h.update(b"UUID=044527ca-a319-491b-a27f-6a25a97a44ea")
    part1 = h.final()
    h.update(part1)
    part2 = h.final()
    
    # should be B960BC22180606FF1FDC651947CAAB6DF0F9ADC4076B4CFE07FC1EE5393C4EDF D7F1CE8F432CF2BEB099E6F4262CB64506EEC8EAA360B38E40E0856B353F2B65
    print("%s %s" % (part1.hex().upper(), part2.hex().upper()))

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
    # h = int.from_bytes(SHA256(m).final(), "big") >> 32 #ignore low 32bits
    
    # sign = {"signR": 0x779B041D03CC103D60C9531BF1649A064D1D4F55987D3CF0EC809744,
            # "signS": 0x654B4DC684C9BE91B9B3AFE22C5811E901F629A33CB21BA85B814925,
            # "pubkey": {x:0x471B71C9C51C66BAA2A07551D3D281CB18B72D2D552B688C267C9D7C, y:0x1582D96D0BA41680010A6CDA982DCC7A2E8C935C51610D73D22FF44D} }
    # sha256ecdsa(h, sign["signR"], sign["signS"], sign["pubkey"], sign["signR"], True)

        
if __name__ == '__main__':
	main()