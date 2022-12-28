# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from SHA256 import SHA256
from wbc import wbc_file
import struct

def main():
    # out = wibu_sha256(5001, b'mjs')
    # out = wibu_sha256(5003, b'UUID=044527ca-a319-491b-a27f-6a25a97a44ea')
    # nonce = bytes.fromhex("5A953B8DE30C80383851A1C4A0DCB4C08B5EA6DB5B57503C9F766B7EE75303B6")
    # item_id = SHA256(nonce + out).final()
    # print("%s" % item_id.hex())
    
    
    wbc = wbc_file("6000316_820064b5af57b09a70db832e589ab841a6a268c6.wbc")
    # wbc = wbc_file("6000316_82008ff8913699c1f694201c4769955c19c3e154.wbc")
    if(wbc.check()):
        k = wbc.get_private_key()
        print("private_key: %s" % k.hex())

if __name__ == '__main__':
	main()