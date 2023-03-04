# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from wibu_file import WibuFile
from asn_help import *
import sha256ecdsa
import common

defalut_private_key = 0xd9352ca798fde876a6c093e60bb39870ddb10e722276ab78eea3cc40

class WibuCert(object):
    def __init__(self, asn1_def, setting=None):
        self.asn1_def = asn1_def
        self.setting = setting

    def check_cert(self, cert, pub_key):
        cert_asn1 = self.asn1_def.decode("Certificate", cert)
        sign = asn1_value(cert_asn1,["signature"])[0]
        sign_asn1 = self.asn1_def.decode("SignerSignature", sign)
        r = asn1_value(sign_asn1,["r"])
        s = asn1_value(sign_asn1,["s"])
        
        qx = int.from_bytes(pub_key[1:29], "big")
        qy = int.from_bytes(pub_key[29:57], "big")
        
        hash_data_asn1 = asn1_value(cert_asn1, ["tbsCertificate"])
        hash_data = asn1_def.encode("TBSCertificate", hash_data_asn1)
        h = int.from_bytes(sha256ecdsa.sha256(hash_data).final(), "big") >> 32 #ignore low 32bits
        
        return sha256ecdsa.sha256ecdsa(h, r, s, {"x":qx, "y":qy}, r)

    '''
        更换证书的公-私钥对信息、签名信息
        参数：
            cert: 证书的asn1数据
            sign_key: 用于签名的私钥
        返回值：
            被更换证书的asn1数据
    '''
    def patch_cert_key(self, asn_cert, sign_key=defalut_private_key):
        pub_key = asn1_value(asn_cert,["tbsCertificate","subjectPublicKeyInfo","subjectPublicKey"])[0]

        qx = int.from_bytes(pub_key[1:29], "big")
        qy = int.from_bytes(pub_key[29:57], "big")
        
        # 先算公钥
        sign = sha256ecdsa.signature(b"", sign_key)
        
        pub_key = b"\x04" + sign["pubkey"]["x"].to_bytes(28, "big") + sign["pubkey"]["y"].to_bytes(28, "big") 
        asn1_value(asn_cert,["tbsCertificate","subjectPublicKeyInfo","subjectPublicKey"], (pub_key, len(pub_key)*8))
        
        # 再算rs
        asn_hash_data = asn1_value(asn_cert, ["tbsCertificate"])
        hash_data = self.asn1_def.encode("TBSCertificate", asn_hash_data)
        sign = sha256ecdsa.signature(hash_data, sign_key)

        # print("original public key: (0x%X, 0x%X)" % (qx, qy))
        # print("new private key: 0x%X" % sign_key)
        # print("new public key: (0x%X, 0x%X)" % (sign["pubkey"]["x"], sign["pubkey"]["y"]))
        # print("new rs: (0x%X, 0x%X)" % (sign["signR"], sign["signS"]))

        sign_data = self.asn1_def.encode("SignerSignature", {"r":sign["signR"], "s":sign["signS"]})
        asn1_value(asn_cert,["signature"], (sign_data, len(sign_data)*8))
        return asn_cert
    
    '''
        更换证书的特定信息，不同的证书修复的地方不同
        参数：
            cert: 证书的asn1数据
        返回值：
            被更换证书的asn1数据
    '''
    def patch_cert_data(self, asn_cert):
        if(self.setting != None and self.setting.contains("FirmCode") and self.setting.contains("SerialNumber")):
            o  = asn1_value(asn_cert,["tbsCertificate","subject","rdnSequence","0","0","value"])
            CN = asn1_value(asn_cert,["tbsCertificate","subject","rdnSequence","1","0","value"])

            firm_code = self.setting.value("FirmCode")
            serial_num = self.setting.value("SerialNumber")
            if(CN == "Wibu-Production"):
                pass
            elif(CN == "LPK"):
                asn1_value(asn_cert,["tbsCertificate","subject","rdnSequence","0","0","value"], "%d" % firm_code)
                ext_lpk = asn1_value(asn_cert,["tbsCertificate","extensions","2", "extnValue"]) #extnID=1.3.6.1.4.1.44485.3.1
                asn_ext_lpk = self.asn1_def.decode("Ext-LPK", ext_lpk)
                asn1_value(asn_ext_lpk,["firm-code"], firm_code)
                ext_lpk = self.asn1_def.encode("Ext-LPK", asn_ext_lpk)
                asn1_value(asn_cert,["tbsCertificate","extensions","2", "extnValue"], ext_lpk)
            elif(CN == "LTK"):
                asn1_value(asn_cert,["tbsCertificate","subject","rdnSequence","0","0","value"], "%d" % firm_code)
                ext_ltk = asn1_value(asn_cert,["tbsCertificate","extensions","2", "extnValue"]) #extnID=1.3.6.1.4.1.44485.3.2
                asn_ext_ltk = self.asn1_def.decode("Ext-LTK", ext_ltk)
                asn1_value(asn_ext_ltk,["firm-code"], firm_code)
                ext_ltk = self.asn1_def.encode("Ext-LTK", asn_ext_ltk)
                asn1_value(asn_cert,["tbsCertificate","extensions","2", "extnValue"], ext_ltk)
            elif(CN == "CmActKey"):
                short_serial = common.short_serial_number(serial_num)
                asn1_value(asn_cert,["tbsCertificate","subject","rdnSequence","0","0","value"], short_serial)
                asn1_value(asn_cert,["tbsCertificate","issuer", "rdnSequence","0","0","value"], short_serial)
                ext_cmact = asn1_value(asn_cert,["tbsCertificate","extensions","1", "extnValue"]) #extnID=1.3.6.1.4.1.44485.3.3
                asn_ext_cmact = self.asn1_def.decode("Ext-CmAct-Key", ext_cmact)
                asn1_value(asn_ext_cmact,["cmact-serial-number"], serial_num)
                ext_cmact = self.asn1_def.encode("Ext-CmAct-Key", asn_ext_cmact)
                asn1_value(asn_cert,["tbsCertificate","extensions","1", "extnValue"], ext_cmact)
                
                # 若CmActKey证书的ID指定了，则变更为指定ID
                if(self.setting.contains("CmActId")):
                    cmact_id = self.setting.value("CmActId")
                    asn1_value(asn_cert,["tbsCertificate","issuerUniqueID"], (cmact_id, 8*len(cmact_id)))
                    asn1_value(asn_cert,["tbsCertificate","subjectUniqueID"], (cmact_id, 8*len(cmact_id)))
                
                # CmActKey证书的私钥是通过系统特征计算的
                # 若有指定的私钥，则更换为指定的私钥；若无，则保持原来的私钥。
                if(self.setting.contains("PrivateKey")):
                    pri_key = self.setting.value("PrivateKey")
                    return self.patch_cert_key(asn_cert, pri_key)
                else:
                    return asn_cert
        return self.patch_cert_key(asn_cert)
        
    '''
        修复证书对内容的签名信息，包括证书自身的修复
        参数：
            asn_wibu_file: wibu-file signed格式的asn1数据
        返回值：
            被修复的wibu-file数据
    '''
    def patch_sign_data(self, asn_wibu_file):
        global defalut_private_key
        
        subject_id = asn1_value(asn_wibu_file, ["signed","content","signerInfos","0","signerIdentifier", "subjectKeyIdentifier"])
        content = asn1_value(asn_wibu_file, ["signed","content","contentInfo","content"])
        certs = asn1_value(asn_wibu_file, ["signed","content","certificates"])

        new_certs = []
        for cert in certs:
            asn_cert = self.asn1_def.decode("Certificate", cert)
            asn_cert = self.patch_cert_data(asn_cert)
            subject_uid = asn1_value(asn_cert,["tbsCertificate","subjectUniqueID"])[0]
            if(subject_uid == subject_id):
                sign = sha256ecdsa.signature(content, defalut_private_key)
                # print("new rs: (0x%X, 0x%X)" % (sign["signR"], sign["signS"]))
                sign_data = self.asn1_def.encode("SignerSignature", {"r":sign["signR"], "s":sign["signS"]})
                asn1_value(asn_wibu_file, ["signed","content","signerInfos","0","encryptedDigest"], sign_data)
            
            new_certs.append(self.asn1_def.encode("Certificate", asn_cert))

        asn1_value(asn_wibu_file, ["signed","content","certificates"], new_certs)
        return asn_wibu_file

       
def patch_codemeterlin(src, dst, cert):
    root_data = common.read_file(cert, "rb")
    src_data = common.read_file(src, "rb")
    
    pos = src_data.find(b"\x30\x82\x01\x6E\x30\x82\x01\x1D\xA0\x03\x02\x01\x02\x02\x04\xB2")
    if(pos == -1):
        # print("can"t not find root cert")
        return False
        
    dst_data = src_data[0:pos] + root_data + src_data[pos+len(root_data):]
    common.write_file(dst, dst_data, "wb")
    return True

# 尝试修正lif，使其允许在vm中运行    
def test_change_lif(wibu_cert, asn_wibu_file):  
    content = asn1_value(asn_wibu_file, ["signed","content","contentInfo","content"])
    asn_content_res = wibu_cert.asn1_def.decode("LIF-Content", content)
    asn1_value(asn_content_res, ["cmact-options", "allow-vm"], True)
    new_content = wibu_cert.asn1_def.encode("LIF-Content", asn_content_res)
    asn1_value(asn_wibu_file, ["signed","content","contentInfo","content"], new_content)
    return asn_wibu_file

def patch_lif(src, dst):
    f = WibuFile(src)
    asn1_data = f.get_asn1_data()
    
    wibu_cert = WibuCert(asn1_init("../asn1"), None)
    asn_wibu_file = wibu_cert.asn1_def.decode("Wibu-File", asn1_data["LicenseInformation"])
    asn_wibu_file = test_change_lif(wibu_cert, asn_wibu_file)
    asn_wibu_file = wibu_cert.patch_sign_data(asn_wibu_file)
    patch_data = wibu_cert.asn1_def.encode("Wibu-File", asn_wibu_file)
    
    f.set_asn1_data({"LicenseInformation":patch_data})
    f.save(dst)

def patch_root_der(src, dst):
    wibu_cert = WibuCert(asn1_init("../asn1"), None)
    asn_cert = wibu_cert.asn1_def.decode("Certificate", common.read_file(src, "rb")) 
    asn_cert = wibu_cert.patch_cert_key(asn_cert)
    common.write_file(dst, "wb", wibu_cert.asn1_def.encode("Certificate", asn_cert))

def main():
    # patch_codemeterlin("../ida/CodeMeterLin", "tmp/CodeMeterLin(root)", "testcase/root_new.der")
    # patch_der("testcase/root.der", "tmp/root_new.der")
    patch_lif("testcase/Terra2314.WibuCmLIF", "tmp/Terra2314.WibuCmLIF")
    
if __name__ == "__main__":
	main()