# !/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
    读取wibu授权信息，生成给wibu_reader使用的配置
'''
import os
import itertools
import common
import sha256ecdsa
from asn_help import *
from wibu_control import WbcFile
from wibu_cert import WibuCert

default_path = "/var/lib/CodeMeter/CmAct"

class WibuCfg(object):
    def __init__(self, file, asn1_path):
        self.fd = open(file, "w")
        self.asn1_def = asn1_init(asn1_path)
        self.wbc_keys = []
        self.cmact_asn1 = None
        self.info = {}
    
    def __del__(self):
        self.fd.close()
       
    def get_firmcode(self):
        pass

    def proc_wbc(self, file):
        wbc = WbcFile(file)
        if(wbc.check()):
            for cf in itertools.product([True, False], repeat=4):
                self.wbc_keys.append(int.from_bytes(wbc.get_private_key(cf), "big"))
        
    def proc_WibuCmActLic(self, file):
        data = common.read_file(file, "rb")
        lic_asn1 = self.asn1_def.decode("Wibu-File", data)
        lic_content = asn1_value(lic_asn1, ["signed", "content", "contentInfo", "content"])
        lic_content_asn1 = self.asn1_def.decode("License-Content", lic_content)
        lif = asn1_value(lic_content_asn1, ["lif"])
        lif_asn1 = self.asn1_def.decode("Wibu-File", lif)
        lif_content = asn1_value(lif_asn1, ["signed", "content", "contentInfo", "content"])
        lif_content_asn1 = self.asn1_def.decode("LIF-Content", lif_content)
        cmact = asn1_value(lic_asn1, ["signed", "content", "certificates", "0"])
        self.cmact_asn1 = self.asn1_def.decode("Certificate", cmact)
        
        self.info["SerialNumber"] = asn1_value(lic_content_asn1, ["cmact-serial-id"])
        self.info["FirmCode"] = str(int.from_bytes(asn1_value(lif_content_asn1, ["license-description", "firm-code"]), "big"))
        
    def save(self):
        self.info["CmActId"] = asn1_value(self.cmact_asn1,["tbsCertificate","subjectUniqueID"])[0]
        pub_key = asn1_value(self.cmact_asn1,["tbsCertificate","subjectPublicKeyInfo","subjectPublicKey"])[0]
        qx = int.from_bytes(pub_key[1:29], "big")
        qy = int.from_bytes(pub_key[29:57], "big")
        for pri_key in self.wbc_keys:
            if(sha256ecdsa.check_QdG(pri_key, {"x":qx, "y":qy})):
                self.info["PrivateKey"] = "0x%X" % pri_key
                break
    
        #[General]
        self.fd.write("[General]\n")
        for key in ["FirmCode", "SerialNumber", "PrivateKey", "CmActId"]:
            if(key not in self.info):
                self.fd.write(";%s=\n" % key)
            else:
                self.fd.write("%s=%s\n" % (key, asn1_to_str(self.info[key])))
        self.fd.write("\n")
        
        #[Replace]
        self.fd.write(";[Replace]\n")
        self.fd.write(";Number=1\n")
        self.fd.write("\n")
        
        self.fd.write(";[Replace_0]\n")
        self.fd.write(";AsnType=Content-PI-P\n")
        self.fd.write(";Path=product-item,pi-expirationtime,time\n")
        self.fd.write(";Type=bytes;bytes,int,str,bool\n")
        self.fd.write(";Value=0058000000\n")
        self.fd.write("\n")
    
def main():
    cfgs = {}
    if(os.path.exists("cfg") == False):
        os.makedirs("cfg")
    for root,dirs,files in os.walk(default_path):
        for file in files:
            if(file.endswith((".wbc", ".WibuCmActLic"))):
                file_name = os.path.splitext(os.path.basename(file))[0]
                serial_number = bytes.fromhex((file_name.split("_")[1]))
                short_name = common.short_serial_number(serial_number)
                cfg_name =  "cfg/context-%s.cfg" % short_name
                if(cfg_name in cfgs):
                    cfg = cfgs[cfg_name]
                else:
                    cfg = WibuCfg(cfg_name, "asn1")
                    cfgs[cfg_name] = cfg
                    
                if(file.endswith(".wbc")):
                    cfg.proc_wbc(os.path.join(root, file))
                elif(file.endswith(".WibuCmActLic")):
                    cfg.proc_WibuCmActLic(os.path.join(root, file))
                    
    for cfg in cfgs.values():
        cfg.save()
        
if __name__ == "__main__":
    main()
    