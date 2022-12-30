# !/usr/bin/env python3
# -*- coding:utf-8 -*- 

import common
import configparser
from SHA256 import SHA256
import sys, os, uuid, struct

class wbc_file:
    def __init__(self, wbc_path=None):
        if(wbc_path != None):
            cf = configparser.ConfigParser()
            
            wbc_content = common.read_file(wbc_path).replace("\x00", "")
            cf.read_string(wbc_content)

            if(not cf.has_section("WIBU-SYSTEMS Control File")):
                raise(Exception("No WIBU-SYSTEMS Control File Section"))
            
            if(not cf.has_section("Inventory")):
                raise(Exception("No Inventory"))
        
            self.config = cf
            self.guid = cf.get("WIBU-SYSTEMS Control File", "guid")
            self.nonce = bytes.fromhex(cf.get("Inventory","nonce"))
            self.redundancy_data = cf.get("Inventory","redundancydata")
            self.item_count = cf.getint("Inventory","itemcount")
            self.part1 = ''
            self.part2 = self.get_part2()
            self.part3 = self.get_part3(wbc_path)
            
            self.items = []
            for item_idx in range(self.item_count):
                it_id = 0
                it_pos = 0
                it_len = 0
                it_param = 0
                it = cf.items("Item_%d" % item_idx)
                for name, value in it:
                    # print("%s = %s" % (name, value))
                    if(name == "id"):
                        it_id = int(value, 16)
                    elif(name == "position"):
                        it_pos = int(value, 10)
                    elif(name == "length"):
                        it_len = int(value, 10)
                    elif(name == "params"):
                        it_param = int(value, 16)
                    else:
                        print("unknown item field")
                # idx id pos len param
                self.items += [(item_idx, it_id, it_pos, it_len, it_param)]
            
            if(cf.has_section("IdList")):
                list_count = cf.getint("IdList", "ItemCount")
                for i in range(list_count):
                    it_id = int(cf.get("IdList", "ID_%d" % i), 16)
                    self.items += [(i+self.item_count, it_id, 0, 0, 0)]
                self.item_count += list_count
            
    def get_part2(self):
        cf = self.config
    
        h = SHA256()
        h.update(bytes.fromhex("17051401040C14020402134414021346"))
        h.update(bytes.fromhex(cf.get("Inventory","nonce")))
        h.update(bytes.fromhex(cf.get("Inventory","redundancydata"))[0:33])
        h.update(struct.pack("I", int(cf.get("Inventory","version0"), 10)))
        h.update(struct.pack("I", int(cf.get("Inventory","version1"), 10)))
        h.update(struct.pack("I", int(cf.get("Inventory","version2"), 10)))
        h.update(struct.pack("I", int(cf.get("Inventory","version3"), 10)))
        h.update(struct.pack("I", int(cf.get("Inventory","Heuristic"), 10)))
        h.update(struct.pack("I", int(cf.get("Inventory","flags"), 10)))
        
        for i in range(cf.getint("Inventory","itemcount")):
            item_name = "Item_%d" % i
            h.update(bytes.fromhex(cf.get(item_name,"id")))
            h.update(struct.pack("I", int(cf.get(item_name,"position"), 10)))
            h.update(struct.pack("I", int(cf.get(item_name,"length"), 10)))
            h.update(bytes.fromhex(cf.get(item_name,"params")))
            
        h.update(struct.pack("I", int(cf.get("Inventory","itemcount"), 10)))
        part2 = ''
        for i in h.final():
            part2 += "%x" % i
        # print("part2: %s" % part2)
        return part2
    
    def get_part3(self, wbc_path):
        wbc_name_hash = SHA256(os.path.basename(wbc_path).encode()).final()
        # print("wbc_name_hash: %s" % wbc_name_hash.hex())
        for root,dirs,files in os.walk("/var/spool/ctmp"):
            for name in files:
                data = common.read_file("%s/%s" % (root, name), "rb")
                # print("file: %s/%s" % (root, name))
                if(data != None and len(data) >= 53):
                    name_hash = data[0:32]
                    # print("name_hash: %s" % name_hash.hex())
                    if(name_hash == wbc_name_hash):
                        part3 = ""
                        part3_bin = data[32:49]
                        for i in part3_bin:
                            part3 += "%x" % i
                        # print("part3: %s" % part3)
                        return part3
                    
    
    def check_item(self, code, feature):
        pass
    
    def get_feature_dict(self):
        # codes = [5001,5002,5003,6001,6101,6102,6103,6104,6105,6106,6107,6108,6109,6110,7001,7002,7003,8001,8002,8003,8004,8005,200001,200002,200003]
        codes = [5001,5002,5003,6001,6101,6103,6104,6105,6106,6107,6108,6109,6110,7001,7002,7003,8001,8002,8003,8004,8005,200001,200002,200003]
        
        '''
        return {5001: b'king-ThinkCentre-M920t-N000',
                5003: b'UUID=474e99e3-6399-4537-bcde-527cf4c5cd5d',
                6001: b'e0:be:03:1d:2f:9b',
                6101: b'10SMS0SL00',
                # 6102: b'ThinkCentre M920t-N000',
                6103: b'LENOVO',
                6104: b'SDK0L77769 WIN 3423602108383',
                6105: b'LENOVO',
                6106: b'3133',
                6107: b'09/21/2020',
                6108: b'LENOVO',
                6109: b'M1UKT5CA',
                6110: b'M70GW9G9',
                8001: b'(69d69)(69d69)(69d69)(69d69)',
                8005: b'16384|Kingston|9905625-004.A03LF   |643E01DE'}
        '''
        
        feature_dist = {}
        for code in codes:
            feature = self.get_feature(code, feature_dist)
            if(feature != None):
                if(type(feature) == str):
                    # print("%d: %s" % (code, feature))
                    feature = feature.encode()
                if(type(feature) == bytes):
                    # print("%d: %s" % (code, feature,hex()))
                    pass
                feature_dist[code] = feature
                
        return feature_dist
    
    def check(self):
        # only support linux
        if(not sys.platform.startswith("linux")):
            raise(Exception("please run in linxu platform"))

        feature_dist = self.get_feature_dict()
   
        feature_check_ok_cnt = 0
        feature_check_ok_h256 = []
        for code, feature in feature_dist.items():
            h256 = common.wibu_sha256(code, feature)
            item_id = int.from_bytes(SHA256(self.nonce + h256).final(), "big")
            # print("h256: %s" % h256.hex())
            # print("id: %X" % item_id)
            
            check = False
            check_idx = 0
            for it_idx, it_id, it_pos, it_len, it_param in self.items:
                if(it_id == item_id):
                    check_idx = it_idx
                    feature_check_ok_h256 += [(it_idx, it_pos, it_len, h256)]
                    check = True
                    break
            if(check):
                print("code_%d check ok, match item_%d" % (code, check_idx))
                feature_check_ok_cnt += 1
            else:
                print("code_%d check faild, not match any item" % code)
                pass
        
        print("wbc id count: %d" % self.item_count)     
        print("system featue count: %d" % len(feature_dist))
        print("system featue ok: %d" % feature_check_ok_cnt)
        
        if(feature_check_ok_cnt >= self.item_count):
            print("all wbc item check ok")

            feature_check_ok_h256 = sorted(feature_check_ok_h256, key=lambda feature: feature[0])
            part1_bin = ''
            for it_idx, it_pos, it_len, h256 in feature_check_ok_h256:
                if(it_len > 0):
                    part1_bin += common.wibu_get_bits(h256, it_len)
            
            
            if(len(part1_bin) != 512):
                raise(Exception("part1_bin len %d is not 512" % len(part1_bin)))
            self.part1 = ''
            # 每8个比特反转一下后输出
            for i in range(0, len(part1_bin), 8):
                self.part1 += "%x" % int(part1_bin[i:i+8][::-1], 2)
            return True
        else:
            print("wbc item check failed")
            return False

    def get_private_key(self):
        if(len(self.part1) == 0):
            raise(Exception("can't get part1, please run check function first"))
            
        print("part1: %s" % self.part1)
        print("part2: %s" % self.part2)
        print("part3: %s" % self.part3)
        
        # data = "[%s-%s]{%s}" % (self.part1, self.part2, self.part3)
        data = "[%s-%s]" % (self.part1, self.part2)
        h = SHA256()
        h.update(data.encode())
        h.update(struct.pack("I", 0x04000000)) #todo: check it how to get
        if(False):
            h.update(b"{1F4C32E0-34BB-414F-B1D6-C8D59E4B8004}\x00")
        else:
            # another sequence is below
            h.update(b"{EE6E8A94-0B9A-4F58-8C8F-C9DCD01E51A4}\x00")
        
        if(False):
            # if running in virtual machine, add it
            h.update(struct.pack("I", 0xAAC0FFEE))
            
        out = h.final()
        out += SHA256(out).final()[0:8]
        
        # this time, out is 32+8=40 bytes
        # print("%s" % out.hex())
        
        h = SHA256()
        h.update(out)
        if(True):
            h.update(bytes.fromhex("C3649C300C6444438AB4DFDE047D25E1"))
        else:
            # another sequence is below
            h.update(bytes.fromhex("122031AE01E743C19EB602076FF482CB"))
        k = h.final()
        # print("k: %s" % k.hex())
        
        return k[0:28]

    def combine_feature(self, code, features, code_list):
        h = SHA256()
        for code in code_list:
            if(code in features):
                val = features[code]
                h.update(struct.pack("I", code))
                if(type(val) == str):
                    val = val.encode()
                h.update(common.wibu_sha256(code, val))
        
        part1 = h.final()
        h.update(part1)
        part2 = h.final()
        return part1 + part2
        
    def get_feature(self, code, features=None):
        if(code == 5001):
            data = common.read_file("/proc/sys/kernel/hostname")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data
        elif(code == 5002):
            data = common.read_file("/sys/bus/i2c/drivers/i2c_adapter/module/srcversion")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data
        elif(code == 5003):
            # 寻找根目录所在设备名称
            fs = common.fstab()
            if(fs != None):
                for fs_info in fs:
                    if(fs_info[1] == '/'):
                        # print("%d: %s" % (code, fs_info[0]))
                        return fs_info[0]
            return fs
        elif(code == 6001):
            #获取mac, 如08:00:27:78:8a:d7
            #todo: 多网卡情况下可能有误
            mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
            mac_str = ":".join(mac[i:i+2] for i in range(0,11,2))
            # print("%d: %s" % (code, mac_str))
            return mac_str
        elif(code == 6101):
            data = common.read_file("/sys/class/dmi/id/product_name")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data
        elif(code == 6102):
            data = common.read_file("/sys/class/dmi/id/product_version")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data
        elif(code == 6103):
            data = common.read_file("/sys/class/dmi/id/sys_vendor")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data        
        elif(code == 6104):
            data = common.read_file("/sys/class/dmi/id/board_version")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data          
        elif(code == 6105):
            data = common.read_file("/sys/class/dmi/id/board_vendor")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data   
        elif(code == 6106):
            data = common.read_file("/sys/class/dmi/id/board_name")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data         
        elif(code == 6107):
            data = common.read_file("/sys/class/dmi/id/bios_date")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data          
        elif(code == 6108):
            data = common.read_file("/sys/class/dmi/id/bios_vendor")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data  
        elif(code == 6109):
            data = common.read_file("/sys/class/dmi/id/bios_version")
            if(data != None):
                data = data.strip()
                # print("%d: %s" % (code, data))
            return data  
        elif(code == 6110):
            #运行以下三个命令中的一个
            #/usr/bin/codemeter-info -Z d6c11a123ca6b9e6290e1b85542d9a7ebf15a1f8c17e455ebc3ca734292b15e6 (/sys/class/dmi/id/product_serial)
            #/usr/bin/codemeter-info -Z 83f924b2cba312b3383aeaebd16d16af704a35ba0e8a83d8de1244b4c20e9de6 (/usr/sbin/dmidecode -s system-serial-number)
            #/usr/bin/codemeter-info -Z 825fabfb0a32da7981a7e3a4a0469c59c99d49b974ebc443e94fa9f5a96467b6 (/usr/sbin/dmidecode -s system-serial-number)
            ret = os.popen("/usr/bin/codemeter-info -Z d6c11a123ca6b9e6290e1b85542d9a7ebf15a1f8c17e455ebc3ca734292b15e6").read().strip()
            if(ret == ""):
                return None
            return ret
        elif(code == 7001 or code == 7002 or code == 7003):
            dev_name = self.get_feature(5003)
            if(dev_name != None):
                if(dev_name.startswith("hd")):
                    if(code == 7003 and os.path.exist("/proc/ide/%s/model" % dev_name)):
                        return common.read_file("/proc/ide/%s/model" % dev_name)
                    return None
                elif(dev_name.startswith("sd")):
                    for root,dirs,files in os.walk("/sys/bus/scsi/drivers/sd"):
                        for name in dirs:
                            if(os.path.exist("%s/%s/block/%s" % (root, name, dev_name))):
                                rev = common.read_file("%s/%s/rev" % (root, name))
                                vendor = common.read_file("%s/%s/vendor" % (root, name))
                                model = common.read_file("%s/%s/model" % (root, name))
                                if(code == 7001):
                                    return vendor
                                elif(code == 7002):
                                    return rev
                                elif(code == 7003):
                                    return model
                    return None
                else:
                    return None
            return dev_name
        elif(code == 8001):
            cpu = common.cpuinfo()
            ret = int(cpu["cpu family"], 10) * 0xFFFF + int(cpu["model"],10) * 0xFF + int(cpu["stepping"],10)
            return ("(%x)" % ret)*4
        elif(code == 8002):
            path = "/sys/class/power_supply"
            for root,dirs,files in os.walk(path):
                for d in dirs:
                    if(root == path and d.startswith("BAT")):
                        manufacturer = common.read_file("%s/%s/%s" % (root, d, "manufacturer"))
                        model_name = common.read_file("%s/%s/%s" % (root, d, "model_name"))
                        serial_number = common.read_file("%s/%s/%s" % (root, d, "serial_number"))
                        if(manufacturer != None and model_name != None and serial_number != None):
                            return "%s|%s|%s" % (manufacturer, model_name, serial_number)
            return None
        elif(code == 8003):
            path = "/sys/class/drm"
            for root,dirs,files in os.walk(path):
                for d in dirs:
                    if(root == path and d.startswith("card") and d.find("LVDS") != -1):
                        edid = common.read_file("%s/%s/%s" % (root, d, "edid"), "rb")
                        ret = ""
                        for b in edid:
                            ret += "%02x" % b
                        return ret
            return None
        elif(code == 8004):
            path = "/sys/bus/usb/devices"
            for root,dirs,files in os.walk(path):
                for d in dirs:
                    if(root == path and d.startswith("usb") == False):
                        idVendor = common.read_file("%s/%s/%s" % (root, d, "idVendor"))
                        idProduct = common.read_file("%s/%s/%s" % (root, d, "idProduct"))
                        manufacturer = common.read_file("%s/%s/%s" % (root, d, "manufacturer"))
                        product = common.read_file("%s/%s/%s" % (root, d, "product"))
                        serial = common.read_file("%s/%s/%s" % (root, d, "serial"))
                        removable = common.read_file("%s/%s/%s" % (root, d, "removable"))
                        
                        if(idVendor != None and idProduct != None and manufacturer != None and \
                           product != None and serial != None and removable != None):
                        
                            ret = "%s%s%s" % (idVendor, idProduct, serial)
                            if(removable == "fixed"):
                                return ret
                            
                            product_low = product.lower()
                            if(product_low.find("integrated") != -1 or
                               product_low.find("internal") != -1 or
                               product_low.find("built-in") != -1 or
                               product.find("Card Reader") != -1 or
                               product.find("Bluetooth") != -1 or
                               product.find("IR Receiver") != -1):
                                return ret
                            
                            if(manufacturer.find("Apple") != -1):
                                return ret
                        
            return None
        elif(code == 8005):
            #运行以下其中一个命令
            #/usr/bin/codemeter-info -Z efe29c248ac07cdb68fe09cc0f2913366406e5b4a47a9e6bda3eda14cc471f69 (/usr/sbin/dmidecode -t 17)
            #/usr/bin/codemeter-info -Z 9b0855c03c8977a941be48d9422fef6aa9821d7481e94ffe2d9d3737470a604e (/usr/sbin/dmidecode -t 17)
            ret = os.popen("/usr/bin/codemeter-info -Z 9b0855c03c8977a941be48d9422fef6aa9821d7481e94ffe2d9d3737470a604e").read().strip()
            if(ret == ""):
                return None
            return ret
        #20000X的为整合feature
        elif(code == 200001):
            return self.combine_feature(200001, features, [4002,4003,4005,10002,5002,6110])
        elif(code == 200002):
            return self.combine_feature(200002, features, [4002,4003,4005,10002,5002,1001,8001,13001,6110])
        elif(code == 200003):
            #200003与代码list顺序有关系
            return self.combine_feature(200003, features, [5001,5002,5003,7001,7003,8001,6101,6103,6104,6105,6106,6107,6108,6109,6110,6001,8002,8003,8004,8005])


def main():
    print(wbc_file().get_feature(8002))
    print(wbc_file().get_feature(8003))
    print(wbc_file().get_feature(8004))
    # os.system("cp /var/lib/CodeMeter/CmAct/ . -r")
    # os.system("cp /var/spool/ctmp/ . -r")
    
    # for code, feature in wbc_file().get_feature_dict().items():
        # print("%d: %s" % (code, feature))

if __name__ == '__main__':
	main()