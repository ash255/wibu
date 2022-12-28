# !/usr/bin/env python3
# -*- coding:utf-8 -*- 
import struct

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
            
def main():
    h = SHA256()
    h.update(struct.pack("I", 5003))
    h.update(b"UUID=044527ca-a319-491b-a27f-6a25a97a44ea")
    part1 = h.final()
    h.update(part1)
    part2 = h.final()
    
    # should be B960BC22180606FF1FDC651947CAAB6DF0F9ADC4076B4CFE07FC1EE5393C4EDF D7F1CE8F432CF2BEB099E6F4262CB64506EEC8EAA360B38E40E0856B353F2B65
    print("%s %s" % (part1.hex().upper(), part2.hex().upper()))

if __name__ == "__main__":
    main()


