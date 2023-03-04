# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

import datetime, os, struct
from sha256ecdsa import SHA256

def read_file(file, mode="r"):
    try:
        fd = open(file, mode)
        data = fd.read()
        fd.close()
    except:
        return None
    return data
    
def write_file(file, data, mode="w"):
    try:
        fd = open(file, mode)
        fd.write(data)
        fd.close()
    except:
        return False
    return True

"""
    wibu实现的sha256算法有bug
    当一个上下文中执行两次final，第二次final输入与第一次final输入反转
"""
def wibu_sha256(code, feature):
    h = SHA256()
    h.update(struct.pack("I", code))
    h.update(feature)
    part1 = h.final()
    h.update(part1)
    part2 = h.final()
    
    # print("%s %s" % (part1.hex().upper(), part2.hex().upper()))
    return part1 + part2
    
def fstab():
    data = read_file("/etc/fstab")
    if(data != None):
        ret = []
        for line in data.split("\n"):
            if(line == "" or len(line) == 0):
                continue
            if(line.startswith("#")):
                continue
                
            while(line.find("  ") != -1):
                line = line.replace("  ", " ")
            elements = line.split(" ")
            ret.append(tuple(elements))
        return ret
    return data

def cpuinfo():
    data = read_file("/proc/cpuinfo")
    if(data != None):
        ret = {}
        for line in data.split("\n"):
            if(line == "" or len(line) == 0):
                continue
            pos = line.find(":")
            if(pos != -1):
                key = line[0:pos].strip()
                value = line[pos+1:].strip()
                ret[key] = value
        return ret
    return data

"""
    组比特的过程好SB呀，特别是it_len不是8的倍数时，不是用h256的前it_len个比特
"""
def wibu_get_bits(h256, length):
    mask = 1
    ret = ""
    for i in range(length):
        if((h256[i//8] & mask) != 0):
            ret += "1"
        else:
            ret += "0"
        mask *= 2
        if(mask == 0x100):
            mask = 1
    return ret

#type of serial_number is bytes
def short_serial_number(serial_number):
    part1 = int.from_bytes(serial_number[0:2], "little")
    part2 = int.from_bytes(SHA256(serial_number).final()[0:4], "little")
    # print("Short Serial number: %d-%d" % (part1, part2))
    return "%d-%d" % (part1, part2)
    
def main():
    print(short_serial_number(b"\x82\x00\x34\xd3\xa3\xfa\x6e\x51\xce\x48\xf1\x1c\x54\xf3\xe4\x7b\x9c\x56\x9e\x6d"))
    
if __name__ == "__main__":
	main()