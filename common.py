# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

import datetime
import SHA256
import struct
import copy

g_asn1_cb_done = 1          #不继续调用回调函数链后的函数
g_asn1_cb_continue = 0      #继续调用回调函数链后的函数
g_asn1_cb_interrupt = -1    #终止遍历

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
    
def write_line(fd, level, line):
    if(line != ""):
        if(level < 0):
            level = 0
        if(fd == None):
            print(" "*level + line, end="")
        else:
            fd.write(" "*level + line)

def asn1_value(data, path, new_value=None):
    if(len(path) == 0):
        return None
        
    if(type(data) == tuple):
        key = data[0]
        val = data[1]
        
        if(type(key) == str):
            if(path[0] == key):
                if(len(path) == 1):
                    if(new_value != None):
                        data = (key, new_value)
                    return val
                return asn1_value(val, path[1:], new_value)
        else:
            if(len(path) == 1):
                if(new_value != None):
                    data = (new_value, len(new_value)*8)
                return key
    elif(type(data) == dict):
        if(path[0] in data):
            key = path[0]
            val = data[key]
            if(len(path) == 1):
                if(new_value != None):
                    data[key] = new_value
                return val
            return asn1_value(val, path[1:], new_value)
    elif(type(data) == list):
        idx = int(path[0])
        if(idx < len(data)):
            if(len(path) == 1):
                if(new_value != None):
                    data[idx] = new_value
                return data[idx]
            return asn1_value(data[idx], path[1:], new_value)
    return None
    
"""
def print_asn1_data(data, fd=None, level=0):
    if(type(data) == tuple):
        key = data[0]
        val = data[1]
        
        if(type(key) == bytes or type(key) == bytearray):
            print_asn1_data(key, fd, level+2)
        else:
            if(type(val) == dict or (type(val) == tuple and type(val[0]) == str) or type(val) == list):
                write_line(fd, level, "<%s>\n" % key)
            else:
                write_line(fd, level, "<%s> " % key)
            print_asn1_data(val, fd, level+2)
            if(type(val) == dict or (type(val) == tuple and type(val[0]) == str) or type(val) == list):
                write_line(fd, level, "</%s>\n" % key)
            else:
                write_line(fd, 0, " </%s>\n" % key) 
    elif(type(data) == dict):
        for key, val in data.items():
            if(type(val) == dict or (type(val) == tuple and type(val[0]) == str) or type(val) == list):
                write_line(fd, level, "<%s>\n" % key)
            else:
                write_line(fd, level, "<%s> " % key)
            print_asn1_data(val, fd, level+2)
            if(type(val) == dict or (type(val) == tuple and type(val[0]) == str) or type(val) == list):
                write_line(fd, level, "</%s>\n" % key)
            else:
                write_line(fd, 0, " </%s>\n" % key) 
    elif(type(data) == list):
        cnt = 0
        for val in data:
            if(type(val) == dict or (type(val) == tuple and type(val[0]) == str) or type(val) == list):
                write_line(fd, level, "<%d>\n" % cnt)
            else:
                write_line(fd, level, "<%d> " % cnt)
            print_asn1_data(val, fd, level+2)
            if(type(val) == dict or (type(val) == tuple and type(val[0]) == str) or type(val) == list):
                write_line(fd, level, "</%d>\n" % cnt)
            else:
                write_line(fd, 0, " </%d>\n" % cnt)
            cnt += 1
    elif(type(data) == str):
        write_line(fd, 0, "%s" % data)
    elif(type(data) == int):
        write_line(fd, 0, "%d" % data)
    elif(type(data) == bytearray or type(data) == bytes):
        output = ""
        for b in data:
            output += "%02X " % b
        output = output.strip()
        write_line(fd, 0, output)
    elif(type(data) == bool):
        write_line(fd, 0, "%s" % data)
    elif(type(data) == datetime.datetime):
        write_line(fd, 0, "%s" % data)
    elif(data == None):
        write_line(fd, 0, "NULL")
    else:
        raise(Exception("type: %s" % type(data)))
"""

def asn1_call_cb(cbs, path, val):
    ret = g_asn1_cb_done
    for cb in cbs:
        ret = cb(path, val)
        if(ret == g_asn1_cb_done or ret == g_asn1_cb_interrupt):
            break
    return ret
    
def asn1_traverse(asn1_data, cbs_before=[], cbs_after=[], path=[]):
    if(type(asn1_data) == tuple):
        key = asn1_data[0]
        val = asn1_data[1]
        cur_path = copy.deepcopy(path)
        cur_path.append(key)
        if(asn1_call_cb(cbs_before, cur_path, val) == g_asn1_cb_interrupt):
            return g_asn1_cb_interrupt
        if(type(val) == dict or (type(val) == tuple and type(val[0]) == str) or type(val) == list):
            if(asn1_traverse(val, cbs_before, cbs_after, cur_path) == g_asn1_cb_interrupt):
                return g_asn1_cb_interrupt
        if(asn1_call_cb(cbs_after, cur_path, val) == g_asn1_cb_interrupt):
            return g_asn1_cb_interrupt
    elif(type(asn1_data) == dict):
        for key, val in asn1_data.items():
            cur_path = copy.deepcopy(path)
            cur_path.append(key)
            if(asn1_call_cb(cbs_before, cur_path, val) == g_asn1_cb_interrupt):
                return g_asn1_cb_interrupt
            if(type(val) == dict or (type(val) == tuple and type(val[0]) == str) or type(val) == list):
                if(asn1_traverse(val, cbs_before, cbs_after, cur_path) == g_asn1_cb_interrupt):
                    return g_asn1_cb_interrupt
            if(asn1_call_cb(cbs_after, cur_path, val) == g_asn1_cb_interrupt):
                return g_asn1_cb_interrupt
    elif(type(asn1_data) == list):
        cnt = 0
        for val in asn1_data:
            key = "%d" % cnt
            cur_path = copy.deepcopy(path)
            cur_path.append(key)
            if(asn1_call_cb(cbs_before, cur_path, val) == g_asn1_cb_interrupt):
                return g_asn1_cb_interrupt
            if(type(val) == dict or (type(val) == tuple and type(val[0]) == str) or type(val) == list):
                if(asn1_traverse(val, cbs_before, cbs_after, cur_path) == g_asn1_cb_interrupt):
                    return g_asn1_cb_interrupt
            if(asn1_call_cb(cbs_after, cur_path, val) == g_asn1_cb_interrupt):
                return g_asn1_cb_interrupt
            cnt += 1
    else:
        raise(Exception("type: %s" % type(asn1_data)))

"""
    wibu实现的sha256算法有bug
    当一个上下文中执行两次final，第二次final输入与第一次final输入反转
"""
def wibu_sha256(code, feature):
    h = SHA256.SHA256()
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

def print_asn1_data_cb(path, val, end, fd=None):
    key = path[-1]
    level = (len(path)-1) * 2
    if(end):
        if(type(val) == tuple or type(val) == dict or type(val) == list):
            if(type(val) == tuple and type(val[0]) != str):
                print_asn1_data2(key, val[0], level, end, fd=None)
            else:
                write_line(fd, level, "</%s>\n" % key)
    else:
        if(type(val) == tuple or type(val) == dict or type(val) == list):
            if(type(val) == tuple and type(val[0]) != str):
                print_asn1_data2(key, val[0], level, end, fd=None)
            else:
                write_line(fd, level, "<%s>\n" % key)
        elif(type(val) == str or type(val) == bool or type(val) == datetime.datetime):
            write_line(fd, level, "<%s> %s </%s>\n" % (key, val, key))
        elif(type(val) == int):
            write_line(fd, level, "<%s> %s </%s>\n" % (key, val, key))
        elif(type(val) == bytearray or type(val) == bytes):
            output = ""
            for b in val:
                output += "%02X " % b
            output = output.strip()
            write_line(fd, level, "<%s> %s </%s>\n" % (key, output, key))
        elif(val == None):
            write_line(fd, level, "<%s> NULL </%s>\n" % (key, key))
        else:
            raise(Exception("type: %s" % type(asn1_data)))
            
    return g_asn1_cb_continue
 
def print_asn1_data(data, fd=None):
    asn1_traverse(data, cbs_before=[lambda path,val: print_asn1_data_cb(path, val, False, fd)],cbs_after=[lambda path,val: print_asn1_data_cb(path, val, True, fd)])

def main():
    import wibu_asn1
    wibu_asn1.asn1_init("asn1/", None)
    asn1_data = wibu_asn1.asn1_def.decode("Wibu-File", read_file("dji_lif.bin", "rb"))
    asn1_traverse(asn1_data, cbs_before=[lambda path,val: print_asn1_data_cb(path, val, False)],cbs_after=[lambda path,val: print_asn1_data_cb(path, val, True)])
    
if __name__ == "__main__":
	main()