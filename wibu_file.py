# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

'''
    仅支持后缀为WibuCmLIF，WibuCmRaC，WibuCmRaU的格式
'''

import struct
import common
import base64

class WibuFileErr(Exception):
    pass

class WibuFile:
    def __init__(self, file):
        self.file = file
        self.data = common.read_file(file)
        if(self.data == None):
            raise WibuFileErr("%s not found" % file)
        
        self.info = {}
        cur_key = ""
        for line in self.data.split('\n'):
            if(len(line) == 0):
                continue
            if(line.startswith('[')):
                key = line[1:-1]    #skip[]
                self.info[key] = {}
                cur_key = key
                continue
            else:
                pos = line.find("=")
                if(pos != -1):
                    key = line[0:pos]
                    value = line[pos+1:]
                    self.info[cur_key][key] = value
                else:
                    if(type(self.info[cur_key]) == dict):
                        self.info[cur_key] = ""
                    self.info[cur_key] += line
                    
        # for k,v in self.info.items():
            # print("%s=%s" % (k,v))
        
        self.asn1_data = {}
        for k,v in self.info.items():
            if(type(v) != dict):
                base64_dec_data = base64.b64decode(v.ljust((len(v)+3)//4*4, "="))        
                self.asn1_data[k] = self.asn1_dec(base64_dec_data, int(self.info["Info"]["TimeStamp"], 10))
                
    def asn1_enc(self, data, timestamp):
        return self.asn1_dec(data, timestamp)
        
    def asn1_dec(self, data, timestamp):
        ret = b''
        for i in range(0, len(data)//4):
            ret += struct.pack("I", struct.unpack("I", data[i*4:i*4+4])[0] ^ timestamp)
            timestamp = (0x5917 * timestamp + 0x4A6B) % 0x100000000

        if((len(data) % 4) != 0):
            ret += data[-(len(data) % 4):]
        
        return ret  
    
    '''
        return a dict contian asn1 data
    '''
    def get_asn1_data(self):
        return self.asn1_data
    
    def set_asn1_data(self, data):
        self.asn1_data = data
        for k,v in self.get_asn1_data().items():
            self.info["Info"][k+"Size"] = len(v)
    
    def save(self, file=None):
        if(file == None):
            file = self.file
        
        fd = open(file, "w", newline="")
        for key,val in self.info.items():
            fd.write("[%s]\n" % key)
            if(type(val) == dict):
                for k,v in val.items():
                    fd.write("%s=%s\n" % (k,v))
            else:
                asn1_enc_data = self.asn1_enc(self.asn1_data[key], int(self.info["Info"]["TimeStamp"], 10))
                base64_enc_data = base64.b64encode(asn1_enc_data).decode().strip("=")
                for i in range(0, len(base64_enc_data), 100):
                    fd.write("%s\n" % base64_enc_data[i:i+100])
            fd.write("\n")
            
        fd.close()

def main():
    f = wibu_file("testcase/dji_aeroscope_pro.WibuCmLIF")
    for k,v in f.get_asn1_data().items():
        print("%s=%s" % (k,v.hex().upper()))
        
if __name__ == '__main__':
	main()
    