# -*- coding: utf-8 -*-
'''
    提供asn1相关的帮助函数
    
'''
import os
import asn1tools
from Crypto.Cipher import AES
from datetime import datetime
from copy import deepcopy

'''
【关于asn1帮助函数的设计】
下表为部分asn1类型对应的python类型
|-----------------------------------------|
| ASN1 Type         |  Python Type        |
|-----------------------------------------|
| BOOLEAN           |  bool               |
| INTEGER           |  int                |
| BIT-STRING        |  tuple(bytes,int)   |
| OCTET-STRING      |  bytes              |
| NULL              |  None               |
| OBJECT-IDENTIFIER |  str                |
| ObjectDescripion  |  str                |
| EXTERNAL          |  str                |
| REAL              |  float              |
| ENUMERATED        |  str                |
| EMBEDDED PDV      |  str                |
| UTF8String        |  str                |
| RELATIVE-OI       |  str                |
| SEQUENCE          |  dict               |
| SEQUENCE OF       |  list               |
| SET               |  dict               |
| SET OF            |  list               |
| CHOICE            |  tuple(key,val)     |
| NumericString     |  str                |
| PrintableString   |  str                |
| TeletexString     |  str                |
| VideotexString    |  str                |
| IA5String         |  str                |
| UTCTime           |  datetime           |
| GeneralizedTime   |  datetime           |
| GraphicString     |  str                |
| VisibleString     |  str                |
| GeneralString     |  str                |
| UniversalString   |  str                |
| CHARACTER STRING  |  str                |
| BMPString         |  str                |

1. SEQUENCE和SET为dict，带有key
2. CHOICE为tuple，带有key，key为第一项，value为第二项
3. SEQUENCE OF和SET OF为list，以序号作为key，从0开始
4. BIT-STRING是比较特殊的tuple，需要特别对待

以上前三者均可以相互包含，构成迭代递归的结构
值得注意的是，python的函数参数无法指定传值还是传引用
当参数为list和dict时为传引用，str、bytes、tuple时为传值
在编写递归函数时，注意直接对tuple进行修改无法反馈到原始数据中
'''

g_asn1_cb_done = 1          #return code, 不继续调用回调函数链后的函数
g_asn1_cb_continue = 0      #return code, 继续调用回调函数链后的函数
g_asn1_cb_interrupt = -1    #return code, 终止遍历

class AsnHelpErr(Exception):
    pass

class AsnInfoErr(AsnHelpErr):
    pass

'''
    todo: 当前问题，无法处理连续tuple嵌套的结构，如("a", ("b", 456))
'''
def asn1_value(data, path, new_value=None, parent=None, parent_key=None):
    if(len(path) == 0):
        return None
        
    if(type(data) == tuple):
        key = data[0]
        val = data[1]
        
        if(type(key) == str):
            if(path[0] == key):
                if(len(path) == 1):
                    if(new_value != None and parent != None and parent_key != None):
                        parent[parent_key] = (key, new_value)
                    return val
                return asn1_value(val, path[1:], new_value)
        else:
            if(len(path) == 1):
                if(new_value != None and parent != None and parent_key != None):
                    parent[parent_key] = (new_value, len(new_value)*8)
                return key
            return asn1_value(key, path[1:], new_value)
    elif(type(data) == dict):
        if(path[0] in data):
            key = path[0]
            val = data[key]
            if(len(path) == 1):
                if(new_value != None):
                    data[key] = new_value
                return val
            return asn1_value(val, path[1:], new_value, data, key)
    elif(type(data) == list):
        idx = int(path[0])
        val = data[idx]
        if(idx < len(data)):
            if(len(path) == 1):
                if(new_value != None):
                    data[idx] = new_value
                return val
            return asn1_value(val, path[1:], new_value, data, idx)
    return None
   
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
        cur_path = deepcopy(path)
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
            cur_path = deepcopy(path)
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
            # key = "%d" % cnt
            key = cnt
            cur_path = deepcopy(path)
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
        raise AsnHelpErr("type: %s" % type(asn1_data))

def write_line(fd, level, line):
    if(line != ""):
        if(level < 0):
            level = 0
        if(fd == None):
            print(" "*level + line, end="")
        else:
            fd.write(" "*level + line)

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
        elif(type(val) == str or type(val) == bool or type(val) == datetime):
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
            raise AsnHelpErr("type: %s" % type(asn1_data))
            
    return g_asn1_cb_continue
 
def print_asn1_data(data, fd=None):
    asn1_traverse(data, cbs_before=[lambda path,val: print_asn1_data_cb(path, val, False, fd)],cbs_after=[lambda path,val: print_asn1_data_cb(path, val, True, fd)])

def asn1_init(asn1_dir):
    asn1_files = []
    for root,dirs,files in os.walk(asn1_dir):
        for name in files:
            if(name.endswith("asn1")):
                asn1_files.append("%s/%s" % (root, name))
    t_asn1_def = asn1tools.compile_files(asn1_files, "der")
    return t_asn1_def

def asn1_to_str(val):
    ret = ""
    if isinstance(val, str):
        ret = val
    elif isinstance(val, (bool, datetime)):    #isinstance(True, int)=True, 所以要放到isinstance(val, int)前
        ret = "%s" % str(val)
    elif isinstance(val, int):
        ret = "%d" % val
    elif isinstance(val, (bytes, bytearray)):
        output = ""
        for b in val:
            output += "%02X " % b
        output = output.strip(" ")
        ret = output
    elif isinstance(val, tuple):
        output = ""
        for b in val[0]:
            output += "%02X " % b
        output = output.strip(" ")
        ret = output
    elif(val == None):
        ret = "NULL"
    else:
        raise AsnHelpErr("unknown type: %s" % type(val))
    return ret

def str_to_asn1(val_type, val_str):
    val = None
    if(val_type == str):
        val = val_str
    elif(val_type == bool):
        val = (val_str.lower() != "false")
    elif(val_type == datetime):
        val = datetime.strptime(val_str,"%Y-%m-%d %H:%M:%S")
    elif(val_type == int):
        if(val_str.startswith("0x")):
            val = int(val_str, 16)
        else:
            val = int(val_str, 10)
    elif(val_type == bytearray or val_type == bytes):
        val = bytes.fromhex(val_str.replace(" ", ""))
    elif(val_type == None):
        val = None
    elif(val_type == tuple):
        tmp = bytes.fromhex(val_str.replace(" ", ""))
        val = (tmp, len(tmp)*8)
    else:
        raise AsnHelpErr("unknown type: %s" % val_type)
    return val

'''
    AsnInfo用于处理asn1数据
    可以当成字典使用，如wpi_asn1["asn1_type"] = "WPI-CONTENT"
'''
class AsnInfo(object):
    '''
        args包含以下成员,带*号的为必须被初始化
            *name       -   string         -  实例的名称
            *asn1_def   -                  -  asn1定义的集合
            *asn1_type  -   string         -  asn1类型
            *bin_data   -   bytes          -  二进制数据
            asn1_data   -                  -  解析后的asn1结构
            *is_enc     -   bool           -  是否加密
            enc_data    -   bytes          -  加密后的数据（密文），若有加密则与bin_data相同，在encode或decode函数中同步
            dec_data    -   bytes          -  加密前的数据（明文），若无加密则与bin_data相同，在encode或decode函数中同步
            pri_key     -   int            -  证书的私钥
            aes_key     -   int            -  加密密钥
            *childs     -   list(tuple)    -  [(path, AsnInfo)]
            widget      -   QAsnTreeWidget -  用于关联的组件
    '''
    def __init__(self, **args):
        self.info = {}
        self.info["name"] = ""
        self.info["asn1_def"] = None
        self.info["asn1_type"] = ""
        self.info["bin_data"] = b""
        self.info["is_enc"] = False
        self.info["childs"] = []
        for key, val in args.items():
            self.info[key] = val
            
    def __getitem__(self, key):
        if key in self.info:
            return self.info[key]
        else:
            return None
    
    def __setitem__(self, key, val):
        self.info[key] = val
        
        
    def __iter__(self):
        for key in self.info:
            yield key
            
    def __repr__(self):
        ret = ""
        for key, val in self.info.items():
            if(isinstance(val, int)):
                ret += "%s: 0x%X (%d)\n" % (key, val, val)
            elif(isinstance(val, (bytes, bytearray))):
                ret += "%s: %s\n" % (key, val.hex())
            else:
                ret += "%s: %s\n" % (key, str(val))
        return ret.strip("\n")
    
    def contain_child(self, path):
        for child_path, child in self.info["childs"]:
            if(child_path == path):
                return True
        return False
        
    def get_child(self, path):
        for child_path, child in self.info["childs"]:
            if(child_path == path):
                return child
        return None
    
    def set_child(self, path, child):
        if(self.contain_child((path, child))):
            idx = self.info["childs"].index(path)
            self.info["childs"][idx] = (path, child)
        else:
            self.info["childs"].append((path, child))
    
    def __str__(self):
        return repr(self)
        
    def check(self, need_keys):
        for key in need_keys: 
            if(key not in self.info):
                raise AsnInfoErr("no %s\n%s" % (key, repr(self)))

    def __decrypt_data(self, data, aes_key):
        aes_key_bytes = aes_key.to_bytes(16, "big")
        aes128 = AES.new(aes_key_bytes, AES.MODE_CBC, b"\x00"*16)
        decrypt_data = aes128.decrypt(data)
        #这里采用了特殊的填充方式，Crypto.Util.Padding仅支持pkcs7、iso7816、x923，需要自定义实现unpad
        #todo: 去完padding后可能还存在hash_val，先不考虑这种情况，一旦出现该情况，编码和解码不一致
        end = -1
        for i in range(len(decrypt_data)-1,0,-1):
            if(decrypt_data[i] != 0 and decrypt_data[i] == 1):
                end = i
                break
        return decrypt_data[0:end]
        
    def __encrypt_data(self, data, aes_key):
        aes_key_bytes = aes_key.to_bytes(16, "big")
        aes128 = AES.new(aes_key_bytes, AES.MODE_CBC, b"\x00"*16)
        #这里采用了特殊的填充方式，Crypto.Util.Padding仅支持pkcs7、iso7816、x923，需要自定义实现pad
        #先填充一个1，再填充多个0。强制填充，故至少有一个1和一个0
        data += b"\x01\x00"
        if((len(data) % 16) != 0):
            padding = 16 - (len(data) % 16)
            data += b"\x00" * padding
        encrypt_data = aes128.encrypt(data)
        return encrypt_data

    def decode(self):
        self.check(["asn1_def", "asn1_type", "bin_data", "is_enc"])
        
        if(self.info["is_enc"]):
            #aes解密
            self.check(["aes_key"])
            self.info["enc_data"] = self.info["bin_data"]
            try:
                self.info["dec_data"] = self.__decrypt_data(self.info["enc_data"], self.info["aes_key"])
            except Exception as e:
                raise AsnInfoErr("decrypt failed\n%s\n%s" % (repr(self), repr(e)))
        else:
            self.info["dec_data"] = self.info["bin_data"]
            
        try:
            self.info["asn1_data"] = self.info["asn1_def"].decode(self.info["asn1_type"], self.info["dec_data"])
        except Exception as e:
            raise AsnInfoErr("decode failed\n%s\n%s" % (repr(self), repr(e)))
        return self.info["asn1_data"]

    def encode(self):
        self.check(["asn1_def", "asn1_type", "asn1_data", "is_enc"])
        
        try:
            self.info["dec_data"] = self.info["asn1_def"].encode(self.info["asn1_type"], self.info["asn1_data"])
        except Exception as e:
            raise AsnInfoErr("encode failed\n%s\n%s" % (repr(self), repr(e)))
            
        if(self.info["is_enc"]):
            #aes加密
            self.check(["aes_key"])
            try:
                self.info["enc_data"] = self.__encrypt_data(self.info["dec_data"], self.info["aes_key"])
            except Exception as e:
                raise AsnInfoErr("encrypt failed\n%s\n%s" % (repr(self), repr(e)))
            self.info["bin_data"] = self.info["enc_data"]
        else:
            self.info["bin_data"] = self.info["dec_data"]
        
        return self.info["bin_data"]

if __name__ == "__main__":
    asn1_def = asn1_init("../asn1/")
    a = AsnInfo(asn1_type="Content-FI-Dynamic", is_enc=True, asn1_def=asn1_def)
    a["bin_data"] = bytes.fromhex("FB 34 5E C4 6C 3C 7E CE D4 C3 04 E9 C2 FC 60 E1 A4 38 A8 20 50 AD 2F 14 66 39 B3 6B 23 50 20 3B DD 67 45 9D 60 14 23 74 0A E4 19 39 3A EF 43 0C 3B A8 95 2E 3D E2 5E 98 46 60 F0 78 39 F0 ED 47 66 E1 BD 03 52 FC 6D CF C0 47 58 31 38 F1 9C C5 87 D1 39 0E E5 1B 15 B6 DB CD B3 CF 75 A2 2E 70")
    a["aes_key"] = 0x3C4DF0690DCF721A58247EDCD190C90
    c = a.decode()
    print_asn1_data(c)
    be = a["bin_data"]
    af = a.encode()
    print(be.hex())
    print(af.hex())
    if(be != af):
        print("{}".format(a))
    
    # asn1_def = asn1_init("asn1/")
    # asn1_data = asn1_def.decode("Wibu-File", read_file("*.bin", "rb"))
    # asn1_traverse(asn1_data, cbs_before=[lambda path,val: print_asn1_data_cb(path, val, False)],cbs_after=[lambda path,val: print_asn1_data_cb(path, val, True)])
    
    