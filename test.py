# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

from wbc import wbc_file
import sha256ecdsa

def main(): 
    wbc = wbc_file("testcase\CmAct\6000316_82004bd37fef2aeaf4b7964b85e65d3d6e9011b6.wbc")
    if(wbc.check()):
        k = wbc.get_private_key()
        print("private_key: %s" % k.hex())
        

if __name__ == '__main__':
	main()