# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

import asn1tools
import wibu_file
import common
import sha256ecdsa
import wibu_asn1
import hashlib

defalut_private_key = 0xd9352ca798fde876a6c093e60bb39870ddb10e722276ab78eea3cc40

def cert_data_fix(cert, sign_key=None):
    global defalut_private_key

    asn_cert_res = wibu_asn1.asn1_def.decode("Certificate", cert, True)
    pub_key = common.asn1_value(asn_cert_res,["tbsCertificate","subjectPublicKeyInfo","subjectPublicKey"])

    qx = int.from_bytes(pub_key[0][1:29], "big")
    qy = int.from_bytes(pub_key[0][29:57], "big")
    # 固定的私钥
    d = defalut_private_key

    if(sign_key == None):
        sign_key = d
    
    # 先算公钥
    sign = sha256ecdsa.signature(b'', sign_key)
    
    pub_key = b'\x04' + sign["pubkey"]["x"].to_bytes(28, "big") + sign["pubkey"]["y"].to_bytes(28, "big") 
    common.asn1_value(asn_cert_res,["tbsCertificate","subjectPublicKeyInfo","subjectPublicKey"], (pub_key, len(pub_key)*8))
    
    # 再算rs
    asn_hash_data = common.asn1_value(asn_cert_res, ["tbsCertificate"])
    hash_data = wibu_asn1.asn1_def.encode("TBSCertificate", asn_hash_data)
    sign = sha256ecdsa.signature(hash_data, sign_key)

    # print("original public key: (0x%X, 0x%X)" % (qx, qy))
    # print("new private key: 0x%X" % d)
    # print("new public key: (0x%X, 0x%X)" % (sign["pubkey"]["x"], sign["pubkey"]["y"]))
    # print("new rs: (0x%X, 0x%X)" % (sign["signR"], sign["signS"]))

    sign_data = wibu_asn1.asn1_def.encode("SignerSignature", {"r":sign["signR"], "s":sign["signS"]}, True)
    common.asn1_value(asn_cert_res,["signature"], (sign_data, len(sign_data)*8))
    return wibu_asn1.asn1_def.encode("Certificate", asn_cert_res, True)
     
def cert_file_fix(src, dst):
    data = common.read_file(src, "rb")
    new_cert = cert_data_fix(data)
    print("new cert len: %d" % len(new_cert))
    common.write_file(dst, new_cert, "wb")
    
def patch_codemeterlin(src, dst):
    root_data = common.read_file("tmp/root_new.der", "rb")
    src_data = common.read_file(src, "rb")
    
    pos = src_data.find(b"\x30\x82\x01\x6E\x30\x82\x01\x1D\xA0\x03\x02\x01\x02\x02\x04\xB2")
    if(pos == -1):
        print("can't not find root cer")
        return
        
    dst_data = src_data[0:pos] + root_data + src_data[pos+len(root_data):]
    common.write_file(dst, dst_data, "wb")

def patch_sign_data(sign_data):
    global defalut_private_key
    
    asn_wibu_f_res = wibu_asn1.asn1_def.decode("Wibu-File", sign_data, True)
    subject_id = common.asn1_value(asn_wibu_f_res, ["signed","content","signerInfos","0","signerIdentifier", "subjectKeyIdentifier"])
    content = common.asn1_value(asn_wibu_f_res, ["signed","content","contentInfo","content"])
    certs = common.asn1_value(asn_wibu_f_res, ["signed","content","certificates"])

    new_certs = []
    for cert in certs:
        asn_cert_res = wibu_asn1.asn1_def.decode("Certificate", cert, True)
        CN = common.asn1_value(asn_cert_res,["tbsCertificate","subject","rdnSequence","1","0","value"])
        if(CN == "CmActKey"):
            # 跳过CmActKey证书的替换，因为该证书的私钥是通过系统特征计算的
            new_certs.append(cert)
            continue
        
        new_cert = cert_data_fix(cert, defalut_private_key)
        new_certs.append(new_cert)
        asn_cert_res = wibu_asn1.asn1_def.decode("Certificate", new_cert, True)
        subject_uid = common.asn1_value(asn_cert_res,["tbsCertificate","subjectUniqueID"])[0]
        if(subject_uid == subject_id):
            sign = sha256ecdsa.signature(content, defalut_private_key)
            sign_data = wibu_asn1.asn1_def.encode("SignerSignature", {"r":sign["signR"], "s":sign["signS"]}, True)
            common.asn1_value(asn_wibu_f_res, ["signed","content","signerInfos","0","encryptedDigest"], sign_data)

    common.asn1_value(asn_wibu_f_res, ["signed","content","certificates"], new_certs)
    return wibu_asn1.asn1_def.encode("Wibu-File", asn_wibu_f_res, True)

# 尝试修正lif，使其允许在vm中运行    
def test_change_lif(lif_data):
    asn_wibu_f_res = wibu_asn1.asn1_def.decode("Wibu-File", lif_data, True)
    content = common.asn1_value(asn_wibu_f_res, ["signed","content","contentInfo","content"])
    asn_content_res = wibu_asn1.asn1_def.decode("LIF-Content", content, True)
    common.asn1_value(asn_content_res, ["cmact-options", "allow-vm"], True)
    new_content = wibu_asn1.asn1_def.encode("LIF-Content", asn_content_res, True)
    common.asn1_value(asn_wibu_f_res, ["signed","content","contentInfo","content"], new_content)
    return wibu_asn1.asn1_def.encode("Wibu-File", asn_wibu_f_res, True)

def patch_lif(src, dst):
    f = wibu_file.wibu_file(src)
    asn1_data = f.get_asn1_data()
    patch_data = patch_sign_data(test_change_lif(asn1_data["LicenseInformation"]))
    f.set_asn1_data({"LicenseInformation":patch_data})
    f.save(dst)

def main():
    wibu_asn1.asn1_init("asn1/", "testcase/root.der")
    
    # cert_file_fix("testcase/root.der", "tmp/root_new.der")
    # patch_codemeterlin("../ida/CodeMeterLin", "tmp/CodeMeterLin(root)")
    patch_lif("testcase/dji_aeroscope_pro.WibuCmLIF", "tmp/dji_aeroscope_pro.WibuCmLIF")
    
    
if __name__ == '__main__':
	main()