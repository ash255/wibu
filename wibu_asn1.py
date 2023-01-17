# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

import asn1tools
import wibu_file
import common
import sha256ecdsa
import hashlib
import os
import struct
from Crypto.Cipher import AES

asn1_def = None
certs_chain = {}

def certs_chain_add(certs_chain, cert):
    asn_cert_res = asn1_def.decode("Certificate", cert, True)
    o = common.asn1_value(asn_cert_res,["tbsCertificate","subject","rdnSequence","0","0","value"])
    CN = common.asn1_value(asn_cert_res,["tbsCertificate","subject","rdnSequence","1","0","value"])
    key = "%s:%s" % (o, CN)
    if(key not in certs_chain):
        certs_chain[key] = asn_cert_res
        # fd = open("tmp/%s_%s.xml" % (o, CN), "w")
        # common.print_asn1_data(asn_cert_res, fd)
        # fd.close()
        # print("cert: %s" % key)
        # common.print_asn1_data(asn_cert_res)
        if(CN == "LPK"):
            asn_ext_lpk = common.asn1_value(asn_cert_res,["tbsCertificate","extensions","2","extnValue"])
            asn_ext_lpk_res = asn1_def.decode("Ext-LPK", asn_ext_lpk, True)
            # common.print_asn1_data(asn_ext_lpk_res)
        elif(CN == "LTK"):
            asn_ext_ltk = common.asn1_value(asn_cert_res,["tbsCertificate","extensions","2","extnValue"])
            asn_ext_ltk_res = asn1_def.decode("Ext-LTK", asn_ext_ltk, True)
            # common.print_asn1_data(asn_ext_ltk_res)
    return key

def certs_chain_check(certs_chain):
    for key, value in certs_chain.items():
        o = common.asn1_value(value,["tbsCertificate","issuer","rdnSequence","0","0","value"])
        CN = common.asn1_value(value,["tbsCertificate","issuer","rdnSequence","1","0","value"])
        parent_key = "%s:%s" % (o, CN)
        if(parent_key not in certs_chain):
            raise(Exception("mo cert[%s] when check cert[%s]" % (parent_key, key)))
            
        sign = common.asn1_value(value,["signature"])[0]
        asn_sign_res = asn1_def.decode("SignerSignature", sign, True)
        r = common.asn1_value(asn_sign_res,["r"])
        s = common.asn1_value(asn_sign_res,["s"])
        parent_value = certs_chain[parent_key]
        pub_key = common.asn1_value(parent_value,["tbsCertificate","subjectPublicKeyInfo","subjectPublicKey"])[0]
        
        qx = int.from_bytes(pub_key[1:29], "big")
        qy = int.from_bytes(pub_key[29:57], "big")
        
        asn_hash_data = common.asn1_value(value,["tbsCertificate"])
        hash_data = asn1_def.encode("TBSCertificate", asn_hash_data)
        h = int.from_bytes(hashlib.sha256(hash_data).digest(), "big") >> 32 #ignore low 32bits
        
        if(sha256ecdsa.sha256ecdsa(h, r, s, {"x":qx, "y":qy}, r) == False):
            raise(Exception("Check cert[%s] failed" % (key)))
            
    return True

def check_wibu_file_content_valid(asn_wibu_f_res):
    content = common.asn1_value(asn_wibu_f_res, ["signed","content","contentInfo","content"])

    ### check content valid
    digest = common.asn1_value(asn_wibu_f_res, ["signed","content","signerInfos","0","encryptedDigest"])
    subject_id = common.asn1_value(asn_wibu_f_res, ["signed","content","signerInfos","0","signerIdentifier", "subjectKeyIdentifier"])
    asn_sign_res = asn1_def.decode("SignerSignature", digest, True)
    # common.print_asn1_data(asn_sign_res)
    h = int.from_bytes(hashlib.sha256(content).digest(), "big") >> 32 #ignore low 32bits
    r = common.asn1_value(asn_sign_res,["r"])
    s = common.asn1_value(asn_sign_res,["s"])

    ### check all certs valid
    certs = common.asn1_value(asn_wibu_f_res, ["signed","content","certificates"])
    content_check = False
    for cert in reversed(certs):
        cert_name = certs_chain_add(certs_chain, cert)          

        subject_uid = common.asn1_value(certs_chain[cert_name],["tbsCertificate","subjectUniqueID"])[0]
        if(subject_uid == subject_id):
            pub_key = common.asn1_value(certs_chain[cert_name],["tbsCertificate","subjectPublicKeyInfo","subjectPublicKey"])[0]
            qx = int.from_bytes(pub_key[1:29], "big")
            qy = int.from_bytes(pub_key[29:57], "big")
            
            # print("Q:{x:0x%X, y:0x%X} r=0x%X s=0x%X" % (qx, qy, r, s))
            if(sha256ecdsa.sha256ecdsa(h, r, s, {"x":qx, "y":qy}, r)):
                content_check = True
    
    certs_chain_check(certs_chain)
    
    if(content_check == False):
        raise(Exception("Check content failed")) 
  
def wibu_file_sign_proc_content(asn_wibu_f_res):
    content_type = common.asn1_value(asn_wibu_f_res, ["signed","content","contentInfo","contentType"])
    asn_type = ""
    if(content_type == "1.3.6.1.4.1.44485.2.1"):
        asn_type = "LIF-Content"
    elif(content_type == "1.3.6.1.4.1.44485.2.2"):
        asn_type = "Remote-Context-Content"
    elif(content_type == "1.3.6.1.4.1.44485.2.3"):
        asn_type = "Remote-Update-Content"
    elif(content_type == "1.3.6.1.4.1.44485.2.4"):
        asn_type = "Receipt-Content"
    elif(content_type == "1.3.6.1.4.1.44485.2.5"):
        asn_type = "License-Content"
    elif(content_type == "1.3.6.1.4.1.44485.2.6"):
        pass
    elif(content_type == "1.3.6.1.4.1.44485.2.7"):
        pass
    elif(content_type == "1.3.6.1.4.1.44485.2.8"):
        pass
    elif(content_type == "1.3.6.1.4.1.44485.2.9"):
        asn_type = "Content-FI-T"
    elif(content_type == "1.3.6.1.4.1.44485.2.10"):
        asn_type = "Content-FI-P"
    elif(content_type == "1.3.6.1.4.1.44485.2.11"):
        pass
    elif(content_type == "1.3.6.1.4.1.44485.2.12"):
        pass   
    elif(content_type == "1.3.6.1.4.1.44485.2.13"):
        asn_type = "Content-PI-T"
    elif(content_type == "1.3.6.1.4.1.44485.2.14"):
        asn_type = "Content-PI-P"
    elif(content_type == "1.3.6.1.4.1.44485.2.15"):
        asn_type = "Content-PI-Merge"
    elif(content_type == "1.3.6.1.4.1.44485.2.16"):
        asn_type = "Content-PI-Delete"
    elif(content_type == "1.3.6.1.4.1.44485.2.17"):
        pass   
    elif(content_type == "1.3.6.1.4.1.44485.2.18"):
        asn_type = "Content-FI-Delete"
    else:
        raise(Exception("unknown content type %s\n" % content_type))
        
    if(asn_type == ""):
        raise(Exception("unknown content type %s\n" % content_type))

    content = common.asn1_value(asn_wibu_f_res, ["signed","content","contentInfo","content"])
    asn_content_res = asn1_def.decode(asn_type, content, True)
    # common.print_asn1_data(asn_content_res)
    
    if(asn_type == "LIF-Content"):
        fix_str = common.asn1_value(asn_content_res, ["license-description","license-description"])
        common.asn1_value(asn_content_res, ["license-description","license-description"], fix_str.decode("utf-16")) 
        
    return asn_content_res

def wibu_file_sign_proc(wibu_file_data):
    asn_wibu_f_res = asn1_def.decode("Wibu-File", wibu_file_data, True)
    # common.print_asn1_data(asn_wibu_f_res)
    check_wibu_file_content_valid(asn_wibu_f_res)
    
    return wibu_file_sign_proc_content(asn_wibu_f_res)

def lif_proc(lif_file):
    f = wibu_file.wibu_file(lif_file)
    asn1_data = f.get_asn1_data()
    
    asn_lif_res = wibu_file_sign_proc(asn1_data["LicenseInformation"])
    # common.print_asn1_data(asn_lif_res)
    
def rac_proc(rac_file):
    f = wibu_file.wibu_file(rac_file)
    asn1_data = f.get_asn1_data()
    
    asn_rac_res = wibu_file_sign_proc(asn1_data["Context"])
    # common.print_asn1_data(asn_rac_res)
    
    if(common.asn1_value(asn_rac_res, ["content-id"]) == "1.3.6.1.4.1.44485.2.2.3"):
        prog_content = common.asn1_value(asn_rac_res, ["content-val"])
        asn_prog_res = asn1_def.decode("Prog-Context",  prog_content, True)   
        # common.print_asn1_data(asn_prog_res)
    
        ### same as LicenseInformation
        lif = common.asn1_value(asn_prog_res, ["container-type-specific","cmact","lif"])
        asn_lif_res = wibu_file_sign_proc(lif)
        # common.print_asn1_data(asn_lif_res)

def wibu_file_envelope_proc(envelope_data, d, asn_envelope_res=None):
    if(asn_envelope_res == None):
        asn_envelope_res = asn1_def.decode("Wibu-File",  envelope_data, True)        
    # common.print_asn1_data(asn_envelope_res)
    
    encrypt_key = common.asn1_value(asn_envelope_res, ["envelope","content","recipientInfos","0","encryptedKey"])
    # common.print_asn1_data(encrypt_key)
    
    encrypt_data = common.asn1_value(asn_envelope_res, ["envelope","content","encryptedContentInfo","encryptedContent"])
    encrypt_data_type = common.asn1_value(asn_envelope_res, ["envelope","content","encryptedContentInfo","contentType"])
    
    aes_key = int.from_bytes(encrypt_key[0:16], "big")
    tmp_Q = {"x": int.from_bytes(encrypt_key[16:44], "big"), "y": int.from_bytes(encrypt_key[48:76], "big")}
    # print("%X %X" % (tmp_Q["x"], tmp_Q["y"]))
    
    res = sha256ecdsa.pmul(d, tmp_Q, sha256ecdsa.curve_p)
    # print(res)

    sha = hashlib.sha256()
    sha.update(b"\x04")
    sha.update(encrypt_key[16:44] + encrypt_key[48:76])
    sha.update(res["x"].to_bytes(28, "big"))
    sha.update(b"\x00\x00\x00\x01")
    xor_strem = sha.digest()
    
    aes_key ^= int.from_bytes(xor_strem[0:16], "big")
    # print("aes_key: %X" % aes_key)
    aes_key_bytes = aes_key.to_bytes(16, "big")

    aes128 = AES.new(aes_key_bytes, AES.MODE_CBC, b"\x00"*16)
    decrypt_data = aes128.decrypt(encrypt_data)
    # print("encrypt len:%d data=%s" % (len(encrypt_data), encrypt_data.hex()))
    # print("decrypt len:%d data=%s" % (len(decrypt_data), decrypt_data.hex()))
    
    return decrypt_data, encrypt_data_type
  
def update_proc(asn1_data, d):
    asn_ruc_res = wibu_file_sign_proc(asn1_data) 
    # common.print_asn1_data(asn_ruc_res)
    
    content_id = common.asn1_value(asn_ruc_res, ["content-id"])
    if(content_id == "1.3.6.1.4.1.44485.2.3.4"):
        prog_update = common.asn1_value(asn_ruc_res, ["content-val"])
        asn_prog_res = asn1_def.decode("Prog-Update",  prog_update, True)   
        # common.print_asn1_data(asn_prog_res)
        
        if(common.asn1_value(asn_prog_res, ["fi"]) != None):
            fi_p = common.asn1_value(asn_prog_res, ["fi", "fi-p"])
            asn_fi_p_content_res = wibu_file_sign_proc(fi_p) 
            # print("<!-- fi-p -->")
            # common.print_asn1_data(asn_fi_p_content_res) 
            
            hashing_salt = common.asn1_value(asn_fi_p_content_res, ["hashing-salt"])
            fi_dynamic_hash = common.asn1_value(asn_fi_p_content_res, ["fi-dynamic-hash"])
            
            fi_dynamic = common.asn1_value(asn_prog_res, ["fi", "fi-dynamic"]) 
            decrypt_data, decrypt_data_type = wibu_file_envelope_proc(fi_dynamic, d)
            decrypt_data = decrypt_data.rstrip(b"\x00")
            decrypt_data = decrypt_data[0:-1]
            print(decrypt_data.hex())
            
            if(decrypt_data_type == "1.3.6.1.4.1.44485.2.7"):
                asn_fi_dyn_res = asn1_def.decode("Content-FI-Dynamic", decrypt_data, True)
                # print("<!-- fi-dynamic -->")
                # common.print_asn1_data(asn_fi_dyn_res)
            else:
                raise(Exception("unknown decrypt data type %s" % decrypt_data_type))
                
            # check fi-dynamic is Unmodified
            # from sub_781ED0 sub_77BF00 sub_781890
            h1 = hashlib.sha256(hashing_salt + decrypt_data).digest()
            for i in range(0,0xFFFF):
                h2 = hashlib.sha256(hashing_salt + struct.pack(">H", i) + h1).digest()
                if(h2[0:16] == fi_dynamic_hash):
                    print("i=%d" % i)
                
            # h2 = hashlib.sha256(hashing_salt + b"\x01" + h1).digest()
            # print(hashing_salt.hex())
            # print(h2.hex())
            # print(fi_dynamic_hash.hex())
        elif(common.asn1_value(asn_prog_res, ["pi"]) != None):
            pi_list = common.asn1_value(asn_prog_res, ["pi"])
            for pi in pi_list:
                # common.print_asn1_data(pi)
                pi_p = common.asn1_value(pi, ["pi-p"])
                pi_dynamic = common.asn1_value(pi, ["pi-dynamic"])
                
                asn_pi_p_content_res = wibu_file_sign_proc(pi_p)
                # print("<!-- pi-p -->")
                # common.print_asn1_data(asn_pi_p_content_res)
                h1 = hashlib.sha256(pi_dynamic).digest()
                print("pi-p h1: %s" % h1.hex())
                
                decrypt_data, decrypt_data_type = wibu_file_envelope_proc(pi_dynamic, d)
                # common.write_file("pi-p.dat", decrypt_data, "wb")
                if(decrypt_data_type == "1.3.6.1.4.1.44485.2.11"):
                    asn_pi_dyn_res = asn1_def.decode("Content-PI-Dynamic", decrypt_data, True)
                    # print("<!-- pi-dynamic -->")
                    # common.print_asn1_data(asn_pi_dyn_res)
                else:
                    raise(Exception("unknown decrypt data type %s" % decrypt_data_type))
     
                hashing_salt = common.asn1_value(asn_pi_p_content_res, ["hashing-salt"])
                pi_dynamic_hash = common.asn1_value(asn_pi_p_content_res, ["pi-dynamic-hash"])
                # h1 = hashlib.sha256(hashing_salt + decrypt_data).digest()
                # h1 = hashlib.sha256(hashing_salt + pi_dynamic).digest()
                # h2 = hashlib.sha256(hashing_salt + h1).digest()
                # h2 = hashlib.sha256(hashing_salt + struct.pack(">H", i) + h1).digest()
 
                # h2 = hashlib.sha256(hashing_salt + b"\x01" + h1).digest()
                # print(h2.hex())
                # print(pi_dynamic_hash.hex())
        else:
            common.print_asn1_data(asn_prog_res)
            raise(Exception("cant parser Prog-Update"))
    else:
        raise(Exception("unknown content type %s" % content_id))
    
def rau_proc(rau_file, d):
    f = wibu_file.wibu_file(rau_file)
    asn1_data = f.get_asn1_data()
    
    for key, value in asn1_data.items():
        # common.write_file("%s.dat" % key, value, "wb")
    
        if(key.startswith("LicenseInformation")):
            wibu_file_sign_proc(value)
        elif(key.startswith("Update")):
            update_proc(value, d)
        else:
            raise(Exception("unknown data type %s" % key))
            
def asn1_init(asn1_dir, root_der=None):
    global asn1_def, certs_chain
    
    asn1_files = []
    for root,dirs,files in os.walk(asn1_dir):
        for name in files:
            if(name.endswith("asn1")):
                asn1_files.append("%s/%s" % (root, name))
    
    asn1_def = asn1tools.compile_files(asn1_files, "der")
    if(root_der != None):
        certs_chain_add(certs_chain, common.read_file(root_der, "rb"))

def check_CmAct_key(d):
    for key, value in certs_chain.items():
        if(key.find("CmActKey") != -1):
            pub_key = common.asn1_value(value,["tbsCertificate","subjectPublicKeyInfo","subjectPublicKey"])[0]
            
            qx = int.from_bytes(pub_key[1:29], "big")
            qy = int.from_bytes(pub_key[29:57], "big")
            
            ret = sha256ecdsa.check_QdG(d, {"x":qx, "y":qy})
            if(ret):
                print("CmAct key check ok")
            else:
                print("CmAct key check failed")
            return ret
    return False
    
def dyn_proc(file, d):
    data = common.read_file(file, "rb")
    decrypt_data, decrypt_data_type = wibu_file_envelope_proc(data, d)

    if(decrypt_data_type == "1.3.6.1.4.1.44485.2.6"):
        decrypt_data = decrypt_data.rstrip(b"\x00")

        asn1_raw_data = decrypt_data[0:-33]
        sha_val = decrypt_data[-33:-1]
        print("%X:%s" % (len(asn1_raw_data), asn1_raw_data.hex()))
        print("%X:%s" % (len(sha_val), sha_val.hex()))
    
        asn_dyn_res = asn1_def.decode("DynData-Content", asn1_raw_data, True)
        # common.print_asn1_data(asn_dyn_res)
        # common.write_file("fi_dyn.dat", decrypt_data, "wb")
        
        salt = bytes.fromhex("1F1670679E24FB107705D4C89CD73C9C")    #check where it from
        
        h1 = hashlib.sha256(asn1_raw_data).digest()
        h2 = hashlib.sha256(salt+h1).digest()
        print(h1.hex())
        print(h2.hex())
        # print(sha_val.hex())
    else:
        raise(Exception("unknown decrypt data type %s" % decrypt_data_type))

def main():
    asn1_init("asn1/", "testcase/root.der")
    
    lif_proc("testcase/dji_aeroscope_pro.WibuCmLIF")
    # lif_proc("testcase/Terra2314.WibuCmLIF")
    # rac_proc("testcase/context-130-2326785491.WibuCmRaC")
    # rac_proc("testcase/update-130-1021612743.WibuCmRaC")
    # check_CmAct_key(0xd9352ca798fde876a6c093e60bb39870ddb10e722276ab78eea3cc40)
    # rau_proc("testcase/32b9e930-fc3a-419e-9bd1-59cf6ec375f8_556_1659322984.WibuCmRaU", 0x0)
    
    # dyn_proc("testcase/CmAct/6000316_8200e6ce5636541cb1f68f530b883a916de609b0.WibuCmActDyn", 0x4065b8b4fa7af639bef49232e1202f62890d090249a04737c3fbb854)
    # dyn_proc("testcase/CmAct/6000316_82004bd37fef2aeaf4b7964b85e65d3d6e9011b6.WibuCmActDyn", 0xd9352ca798fde876a6c093e60bb39870ddb10e722276ab78eea3cc40)
    # dyn_proc("testcase/new/4/CmAct/6000107_8200f5a6520fcf8bc74e6f45f88883264bf1361e.WibuCmActDyn", 0xaa3887d8d0d468bbbc79afc0e89921f0f9be8f25b86aed15480e9e56)
    # dyn_proc("testcase/update/CmAct/6000316_8200c900fc2e46151f3647f20204e79ea3e302f7.WibuCmActDyn", 0xf4e3892b60dfdf1e88b21f1848e8ccbef32bd3abe53763c8a3321955)
    # rau_proc("testcase/new/3/context-130-4191928771.WibuCmRaU", 0xaa3887d8d0d468bbbc79afc0e89921f0f9be8f25b86aed15480e9e56)
    rau_proc("testcase/new/4/context-130-4191928771-2.WibuCmRaU", 0xaa3887d8d0d468bbbc79afc0e89921f0f9be8f25b86aed15480e9e56)
    
    # data = common.read_file("testcase/CmAct/6000316_8200e6ce5636541cb1f68f530b883a916de609b0.WibuCmActLic", "rb")
    # res = wibu_file_sign_proc(data)
    # common.print_asn1_data(res)
    # lif = common.asn1_value(res, ["lif"])
    # lif_res = wibu_file_sign_proc(lif)
    # common.print_asn1_data(lif_res)
    
if __name__ == "__main__":
	main()