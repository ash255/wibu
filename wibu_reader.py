import os
import common
import wibu_file
import wibu_asn1
import wibu_cert
import tkinter
import datetime
import copy
import sha256ecdsa
import hashlib
import SHA256
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import simpledialog
from tkinter import Scrollbar
from tkinter import messagebox

g_unmodified_color = "green"
g_modified_color = "red"
g_fixed_color = "blue"

def asn1_to_str(val):
    ret = ""
    if(type(val) == str):
        ret = val
    elif(type(val) == int):
        ret = "%d" % val
    elif(type(val) == bytearray or type(val) == bytes):
        output = ""
        for b in val:
            output += "%02X " % b
        output = output.strip()
        ret = output
    elif(type(val) == bool):
        ret = "%s" % val
    elif(type(val) == datetime.datetime):
        ret = "%s" % val
    elif(type(val) == tuple):
        output = ""
        for b in val[0]:
            output += "%02X " % b
        output = output.strip()
        ret = output
    elif(val == None):
        ret = "NULL"
    else:
        raise(Exception("unknown type: %s" % type(val)))
    return ret

def str_to_asn1(val_type, val_str):
    val = None
    if(val_type == str):
        val = val_str
    elif(val_type == bool):
        val = (val_str != "0")
    elif(val_type == datetime.datetime):
        val = datetime.datetime.strptime(val_str,"%Y-%m-%d %H:%M:%S")
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
        raise(Exception("unknown type: %s" % val_type))
    return val

class asn1_reader(tkinter.Tk):
    def __init__(self, parent=None, file=None):
        super().__init__()
        self.parent = parent    #不用master的原因：双击窗口时触发的事件全都跑到最初创建的窗口里
        self.create_widgets()
        self.reset()
        if(file != None):
            self.load_file(file)

    def reset(self):
        self.config(background = g_unmodified_color)
        self.geometry("800x600")
        self.title("asn1 reader")
        self.combobox["values"] = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.asn1_raw_dict = {}     #每一项asn数据构建字典，类似WibuCmLIF可能存在多个asn数据
        self.asn1_data_dict = {} 
        self.asn1_type = ""
        self.cur_asn1_data = None
        self.f = None
        self.d = None               #私钥
        self.file = ""
        self.asn1_path = []         #sub_reader可以通过该值修改parent的asn1变量
        self.tree_item_dict = {}    #sub_reader可以通过该值更新parent的显示, 记录了每个asn1节点所对应的tree item
    
    def oid_to_type(self, oid):
        asn_type = ""
        if(oid == "1.3.6.1.4.1.44485.2.1"):
            asn_type = "LIF-Content"
        elif(oid == "1.3.6.1.4.1.44485.2.2"):
            asn_type = "Remote-Context-Content"
        elif(oid == "1.3.6.1.4.1.44485.2.2.3"):
            asn_type = "Prog-Context"
        elif(oid == "1.3.6.1.4.1.44485.2.3"):
            asn_type = "Remote-Update-Content"
        elif(oid == "1.3.6.1.4.1.44485.2.3.4"):
            asn_type = "Prog-Update"  
        elif(oid == "1.3.6.1.4.1.44485.2.4"):
            asn_type = "Receipt-Content"
        elif(oid == "1.3.6.1.4.1.44485.2.5"):
            asn_type = "License-Content"
        elif(oid == "1.3.6.1.4.1.44485.2.6"):
            asn_type = "DynData-Content"
        elif(oid == "1.3.6.1.4.1.44485.2.7"):
            asn_type = "Content-FI-Dynamic"
        elif(oid == "1.3.6.1.4.1.44485.2.8"):
            pass
        elif(oid == "1.3.6.1.4.1.44485.2.9"):
            asn_type = "Content-FI-T"
        elif(oid == "1.3.6.1.4.1.44485.2.10"):
            asn_type = "Content-FI-P"
        elif(oid == "1.3.6.1.4.1.44485.2.11"):
            asn_type = "Content-PI-Dynamic"
        elif(oid == "1.3.6.1.4.1.44485.2.12"):
            pass   
        elif(oid == "1.3.6.1.4.1.44485.2.13"):
            asn_type = "Content-PI-T"
        elif(oid == "1.3.6.1.4.1.44485.2.14"):
            asn_type = "Content-PI-P"
        elif(oid == "1.3.6.1.4.1.44485.2.15"):
            asn_type = "Content-PI-Merge"
        elif(oid == "1.3.6.1.4.1.44485.2.16"):
            asn_type = "Content-PI-Delete"
        elif(oid == "1.3.6.1.4.1.44485.2.17"):
            pass   
        elif(oid == "1.3.6.1.4.1.44485.2.18"):
            asn_type = "Content-FI-Delete"
        elif(oid == "1.3.6.1.4.1.44485.3.1"):
            asn_type = "Ext-LPK"
        elif(oid == "1.3.6.1.4.1.44485.3.2"):
            asn_type = "Ext-LTK"
        elif(oid == "1.3.6.1.4.1.44485.3.3"):
            asn_type = "Ext-CmAct-Key"
        elif(oid == "1.3.6.1.4.1.44485.3.4"):
            asn_type = "Ext-RaCKey"
        else:
            raise(Exception("unknown content type %s\n" % oid))
        return asn_type
        
    def guess_asn1_type(self, path):
        last_node_name = ""
        idx = -1
        while(type(path[idx]) != str):
            idx -= 1
        last_node_name = path[idx]
        
        if(last_node_name == "certificates"):
            return "Certificate"
        elif(last_node_name == "encryptedDigest"):
            return "SignerSignature"
        elif(last_node_name == "content"):
            type_path = path[0:idx] + ["contentType"]
            type_oid = common.asn1_value(self.cur_asn1_data, type_path)
            if(type_oid != None):
                return self.oid_to_type(type_oid)
        elif(last_node_name == "content-val"):
            type_path = path[0:idx] + ["content-id"]
            type_oid = common.asn1_value(self.cur_asn1_data, type_path)
            if(type_oid != None):
                return self.oid_to_type(type_oid)
        elif(last_node_name == "lif"):
            return "Wibu-File"
        elif(last_node_name == "extnValue"):
            type_path = path[0:idx] + ["extnID"]
            type_oid = common.asn1_value(self.cur_asn1_data, type_path)
            if(type_oid != None):
                return self.oid_to_type(type_oid)
        elif(last_node_name == "fi-p"):
            return "Wibu-File"
        elif(last_node_name == "fi-dynamic"):
            return "Wibu-File"  
        elif(last_node_name == "pi-p"):
            return "Wibu-File"
        elif(last_node_name == "pi-dynamic"):
            return "Wibu-File"  
        elif(last_node_name == "encryptedContent"):
            type_path = path[0:idx] + ["contentType"]
            type_oid = common.asn1_value(self.cur_asn1_data, type_path)
            if(type_oid != None):
                return self.oid_to_type(type_oid)
        return ""
    
    def get_aes_key(self, pri_key):
        encrypt_key = common.asn1_value(self.cur_asn1_data, ["envelope","content","recipientInfos","0","encryptedKey"])
        if(encrypt_key == None):
            return None
        
        aes_key = int.from_bytes(encrypt_key[0:16], "big")
        tmp_Q = {"x": int.from_bytes(encrypt_key[16:44], "big"), "y": int.from_bytes(encrypt_key[48:76], "big")}
        
        res = sha256ecdsa.pmul(pri_key, tmp_Q, sha256ecdsa.curve_p)

        sha = hashlib.sha256()
        sha.update(b"\x04")
        sha.update(encrypt_key[16:44] + encrypt_key[48:76])
        sha.update(res["x"].to_bytes(28, "big"))
        sha.update(b"\x00\x00\x00\x01")
        xor_strem = sha.digest()
        
        aes_key ^= int.from_bytes(xor_strem[0:16], "big")
        aes_key_bytes = aes_key.to_bytes(16, "big")
       
        return aes_key_bytes
    
    def aes_decrypt_data(self, data, pri_key):
        aes_key = self.get_aes_key(pri_key)
        aes128 = AES.new(aes_key, AES.MODE_CBC, b"\x00"*16)
        decrypt_data = aes128.decrypt(data)
        common.write_file("dyn_conten.bin", decrypt_data, "wb")
        return decrypt_data
        
    def aes_encrypt_data(self, data, pri_key):
        aes_key = self.get_aes_key(pri_key)
        aes128 = AES.new(aes_key, AES.MODE_CBC, b"\x00"*16)
        data = pad(data, 16)
        encrypt_data = aes128.encrypt(data)
        return encrypt_data
    
    def create_sub_reader(self, path, data, asn1_type, encrypted):
        d = None
        if(encrypted):
            init_val = ""
            if(self.d != None):
                init_val = hex(self.d)
            
            input_val = simpledialog.askstring("请输入私钥", "私钥（16进制）", parent=self, initialvalue=init_val)
            if(input_val != None):
                d = int(input_val, 16)
            else:
                return
            data = self.aes_decrypt_data(data, d)
            if(data == None):
                messagebox.showinfo("Information","解密数据失败")
                return
            self.d = d #之后可以不用重复输入 

        reader = asn1_reader(self)
        reader.d = d
        reader.title(asn1_type)
        reader.menu_file.entryconfig("打开", state="disabled")    #禁用打开按钮，防止在sub_reader中加载别的数据
        reader.asn1_raw_dict = {"default": data}
        reader.combobox["values"] = list(reader.asn1_raw_dict)
        reader.combobox.current(0)
        reader.load_data(reader.asn1_raw_dict, asn1_type)
        reader.asn1_path = path
        self.attributes("-disabled", 1)
        reader.mainloop()
    
    def tree_double_click(self, event):
        sel_id = self.tree.selection()
        mouse_id = self.tree.identify("item", event.x, event.y)
        if(sel_id != () and sel_id[0] == mouse_id): #排除在选中项外的地方触发的事件
            sel_item = self.tree.item(sel_id[0])
            if(sel_item["values"] != ""): #无具体内容的节点无路径，此处可以排除掉
                val = common.asn1_value(self.cur_asn1_data, sel_item["values"])
                if(val != None):
                    input_val = simpledialog.askstring(sel_item["values"][-1], "%s" % type(val), initialvalue=asn1_to_str(val), parent=self)
                    if(input_val != None and asn1_to_str(val) != input_val):
                        self.tree.item(sel_id[0], text="%s: %s" % (sel_item["values"][-1], input_val))
                        common.asn1_value(self.cur_asn1_data, sel_item["values"], str_to_asn1(type(val), input_val))
                        self.config(background = g_modified_color)
                        
    def tree_right_click(self, event):
        sel_id = self.tree.selection()
        mouse_id = self.tree.identify("item", event.x, event.y)
        if(sel_id != () and sel_id[0] == mouse_id): #排除在选中项外的地方触发的事件
            sel_item = self.tree.item(sel_id[0])
            if(sel_item["values"] != ""): #无具体内容的节点无路径，此处可以排除掉
                # create popup menu
                menu_popup = Menu(self, tearoff=0)
                
                val = common.asn1_value(self.cur_asn1_data, sel_item["values"])
                if(val != None):
                    if(type(val) == bytearray or type(val) == bytes):
                        asn1_type = self.guess_asn1_type(sel_item["values"])
                        if(asn1_type != ""):
                            if(asn1_type == "DynData-Content" or asn1_type == "Content-PI-Dynamic" or asn1_type == "Content-FI-Dynamic"):
                                menu_popup.add_command(label=asn1_type, command=lambda :self.create_sub_reader(sel_item["values"], val, asn1_type, True))
                            else:
                                menu_popup.add_command(label=asn1_type, command=lambda :self.create_sub_reader(sel_item["values"], val, asn1_type, False))
            
                menu_popup.add_command(label="编辑", command=lambda :self.tree_double_click(event))
                menu_popup.post(event.x_root, event.y_root)

    def save_file(self):
        if("default" in self.asn1_data_dict):
            # 二进制模式
            self.asn1_raw_dict["default"] = wibu_asn1.asn1_def.encode(self.asn1_type, self.asn1_data_dict["default"])
            suffix = ".bin"
            dir = None
            if(self.file != ""):
                suffix = os.path.splitext(self.file)[-1]
            file_path = filedialog.asksaveasfilename(defaultextension=suffix, filetypes=[(suffix,suffix)], initialdir=dir, parent=self, title="请选择保存的文件")
            if(file_path != ""):
                common.write_file(file_path, self.asn1_raw_dict["default"], "wb")
        elif(len(self.asn1_data_dict) > 0):
            # 文本模式
            for key,val in self.asn1_raw_dict.items():
                self.asn1_raw_dict[key] = wibu_asn1.asn1_def.encode(self.asn1_type, self.asn1_data_dict[key])
                
            suffix = os.path.splitext(self.file)[-1]
            dir = os.path.dirname(self.file)
            file_path = filedialog.asksaveasfilename(defaultextension=suffix, filetypes=[(suffix,suffix), ("bin", ".bin")], initialdir=dir, parent=self, title="请选择保存的文件")
            if(file_path != ""):
                if(file_path.endswith(".bin")):
                    tmp = wibu_asn1.asn1_def.encode(self.asn1_type, self.cur_asn1_data)
                    common.write_file(file_path, tmp, "wb")
                else:          
                    self.f.set_asn1_data(self.asn1_raw_dict)
                    self.f.save(file_path)
    
    def open_file(self):
        file_path = filedialog.askopenfilename(parent=self, title="请选择打开的文件",
                                               filetypes=[("WibuCm文件", "*.WibuCm*"), ("所有文件", "*.*")])
        if(file_path != ""):
            self.reset()
            self.load_file(file_path)
    
    def fix_pi_fi(self, salt):
        pi_map = {
            "pi-featuremap": 0x25, 
            "pi-text": 0x26,
            "pi-userdata": 0x27,
            "pi-unitcounter": 0x28,
            "pi-usageperiod": 0x29,
            "pi-activationtime": 0x2A,
            "pi-expirationtime": 0x2B,
            "pi-protdata": 0x2C,
            "pi-maintenanceperiod": 0x2F,
            "pi-licensequantity": 0x37,
            "pi-status": 0x46}

        sha1 = SHA256.SHA256(salt)
        sha2 = SHA256.SHA256(salt)
        
        pisk = common.asn1_value(self.cur_asn1_data, ["pi-dynamic","pi-pisk"])
        sha1.update(pisk)
        h1 = sha1.final()
        sha2.update(b"\x23" + h1)
        
        for key, val in pi_map.items():
            if(common.asn1_value(self.cur_asn1_data, ["pi-dynamic", key]) != None):
                attr = common.asn1_value(self.cur_asn1_data, ["pi-dynamic", key, "dependencies", "attribute"])
                if(attr == None or (attr & 4) == 0):
                    sha2.update(struct.pack("B", val))
                    # print("%s add sha data 0x%02X" % (key, val))
          
        list_pi_secretdata = common.asn1_value(self.cur_asn1_data, ["pi-dynamic", "list-pi-secretdata"])
        for pi_secretdata in list_pi_secretdata:
            attr = common.asn1_value(pi_secretdata, ["dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", val))
                # print("pi_secretdata[%d] add sha data 0x%02X" % (list_pi_secretdata.index(pi_secretdata), 0x52))
            
        list_pi_hiddendata = common.asn1_value(self.cur_asn1_data, ["pi-dynamic", "list-pi-hiddendata"])
        for pi_hiddendata in list_pi_hiddendata:
            attr = common.asn1_value(pi_hiddendata, ["dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", 0x52))
                # print("list_pi_hiddendata[%d] add sha data 0x%02X" % (list_pi_hiddendata.index(pi_hiddendata), 0x53))
        
        list_pi_extprotdata = common.asn1_value(self.cur_asn1_data, ["pi-dynamic", "list-pi-extprotdata"])
        for pi_extprotdata in list_pi_extprotdata:
            attr = common.asn1_value(pi_extprotdata, ["dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", val))
                # print("list_pi_extprotdata[%d] add sha data 0x%02X" % (list_pi_extprotdata.index(pi_extprotdata), 0x5B))
        
        if(common.asn1_value(self.cur_asn1_data, ["pi-dynamic", "pi-delay"]) != None):
            attr = common.asn1_value(self.cur_asn1_data, ["pi-dynamic", "pi-delay", "dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", 0xA2))
                # print("%s add sha data 0x%02X" % ("pi-delay", 0xA2))
            
        if(common.asn1_value(self.cur_asn1_data, ["pi-dynamic", "pi-password"]) != None):
            attr = common.asn1_value(self.cur_asn1_data, ["pi-dynamic", "pi-password", "dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", 0xA3))
                print("%s add sha data 0x%02X" % ("pi-password", 0xA3))
                if(attr == None or (attr & 1) == 0):
                    password_hash = common.asn1_value(self.cur_asn1_data, ["pi-dynamic", "pi-password", "password-hash"])
                    sha1.update(password_hash)
                    h1 = sha1.final()
                    sha2.update(h1)
                    # print("%s add sha data %s" % ("pi-password", h1.hex()))

        # common.asn1_value(self.cur_asn1_data, ["pi-dynamic", "pi-password", "dependencies", "attribute"])

        print(sha2.final().hex())
    
    def fix(self):
        if(self.asn1_type == ""):
            return True
        elif(self.asn1_type == "Wibu-File"):
            certs = common.asn1_value(self.cur_asn1_data, ["signed", "content", "certificates"])
            if(certs == None):
                # fix envelope
                # 用新密钥来重新加密content
                # self.aes_encrypt_data()
                pass
            else:
                # fix signed cert
                new_certs = []
                for cert in certs:
                    new_certs.append(wibu_cert.cert_data_fix(cert))
                common.asn1_value(self.cur_asn1_data, ["signed", "content", "certificates"], new_certs)
                return True  
        elif(self.asn1_type == "fi-dynamic"):
            pass
        return True
           
    def window_double_click(self, event):
        # if use self.master, sub_reader cant pass "event.widget == self", so i use self.parent
        if(event.widget == self):   #排除不在自己区域内触发的双击事件
            if(self.cget("background") == g_modified_color):
                if(self.fix()):
                    self.config(background = g_fixed_color)
                    messagebox.showinfo("Information","fix done")
    
    def window_on_close(self):
        try:    #保证能正确关闭窗口
            if(self.parent != None):
                # 若有修改，关闭前将asn1数据传递给父窗口
                # 只能是二进制模式
                if(self.cget("background") == g_fixed_color):
                    if("default" in self.asn1_data_dict):
                        self.asn1_raw_dict["default"] = wibu_asn1.asn1_def.encode(self.asn1_type, self.asn1_data_dict["default"])
                        data = self.asn1_raw_dict["default"]
                        if(self.asn1_path != []):
                            item_key = "".join(str(node)+"_" for node in self.asn1_path).strip("_")
                            if(item_key in self.parent.tree_item_dict):
                                if(self.d != None):
                                    data = self.parent.aes_encrypt_data(data, self.d)
                                self.parent.tree.item(self.parent.tree_item_dict[item_key], text="%s: %s" % (self.asn1_path[-1], asn1_to_str(data)))
                                common.asn1_value(self.parent.cur_asn1_data, self.asn1_path, data)
                                self.parent.config(background = g_modified_color)
        finally:
            if(self.parent != None):
                self.parent.attributes("-disabled", 0)
            self.destroy()
    
    def combobox_selected(self, event):
        cur_selected = self.combobox.get()
        if(cur_selected in self.asn1_raw_dict):
            # 需要做部分reset操作
            self.asn1_path = [] 
            self.tree_item_dict = {}
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.load_data({cur_selected: self.asn1_raw_dict[cur_selected]}, self.asn1_type)
    
    def create_widgets(self):
        self.bind("<Double-Button-1>", lambda event:self.window_double_click(event))
        self.protocol("WM_DELETE_WINDOW", self.window_on_close)
    
        # create combobox
        self.combobox = tkinter.ttk.Combobox(self, state="readonly")
        self.combobox.bind("<<ComboboxSelected>>", lambda event:self.combobox_selected(event))
        self.combobox.pack()
        
        # create treeview
        self.tree = ttk.Treeview(self, selectmode = "browse", show = "tree")
        self.tree.bind("<Double-Button-1>", lambda event:self.tree_double_click(event))
        self.tree.pack(expand=True, fill="both")
        
        # create treeview scrollbar
        self.menu_bar_y = Scrollbar(self.tree, orient=VERTICAL, command=self.tree.yview)
        self.menu_bar_y.pack(side=RIGHT, fill=Y)
        self.menu_bar_x = Scrollbar(self.tree, orient=HORIZONTAL, command=self.tree.xview)
        self.menu_bar_x.pack(side=BOTTOM, fill=X)
        self.tree.config(xscrollcommand=self.menu_bar_x.set, yscrollcommand = self.menu_bar_y.set)
        
        # create menu
        self.menu_file = Menu(self, tearoff=0)
        self.menu_file.add_command(label="打开", command=self.open_file)
        self.menu_file.add_command(label="保存", command=self.save_file)
        self.menu_file.add_command(label="退出", command=self.quit)
        self.menu_top = Menu(self)
        self.menu_top.add_cascade(label="文件", menu=self.menu_file)
        self.config(menu=self.menu_top) 
        
        # popup menu event
        self.tree.bind("<Button-3>", lambda event:self.tree_right_click(event))   

    def tree_insert_end(self, node, show_text, usr_data):
        if(usr_data != None):
            return self.tree.insert(node, len(self.tree.get_children(node)), text=show_text, open=True, values=usr_data)
        else:
            return self.tree.insert(node, len(self.tree.get_children(node)), text=show_text, open=True)

    def tree_add_asn1_cb(self, path, val):
        key = path[-1]
        parent_key = "".join(str(node)+"_" for node in path[0:-1]).strip("_")
        if(type(val) == tuple or type(val) == dict or type(val) == list):
            if(type(val) == tuple and type(val[0]) != str):
                self.tree_add_asn1_cb(path, val[0])
            else:
                parent = ""
                if(parent_key in self.tree_item_dict):
                    parent = self.tree_item_dict[parent_key]
                show_text = "%s" % key
                item = self.tree_insert_end(parent, show_text, None) #无具体内容的节点就别添加路径，反正它不能修改，只能用于索引
                item_key = "".join(str(node)+"_" for node in path).strip("_")
                if(item_key not in self.tree_item_dict):
                    self.tree_item_dict[item_key] = item
        else:
            parent = ""
            if(parent_key in self.tree_item_dict):
                parent = self.tree_item_dict[parent_key]
            val_str = asn1_to_str(val)
            show_text = "%s: %s" % (key, val_str)
            item = self.tree_insert_end(parent, show_text, path) #有具体内容的节点就添加路径，修改时需要该路径
            item_key = "".join(str(node)+"_" for node in path).strip("_")
            if(item_key not in self.tree_item_dict):
                self.tree_item_dict[item_key] = item 
        return 1
            
    def tree_add_asn1_2(self, asn1_data):
        common.asn1_traverse(asn1_data, cbs_before=[lambda path,val: self.tree_add_asn1_cb(path, val)])

    def load_data(self, asn1_raw_data, asn1_type):
        key = list(asn1_raw_data)[0]
        val = asn1_raw_data[key]
        self.asn1_raw_dict[key] = val
        
        self.asn1_type = asn1_type
        self.cur_asn1_data = wibu_asn1.asn1_def.decode(asn1_type, val, True)
        self.asn1_data_dict[key] = self.cur_asn1_data
        
        # treeview
        self.tree_add_asn1_2(self.cur_asn1_data)

    def load_file(self, file):        
        if(os.path.exists(file) == False):
            raise(Exception("file %s not exist" % file))
        
        self.file=file
        suffix = os.path.splitext(file)[-1]
        if(suffix == ".WibuCmLIF" or suffix == ".WibuCmRaC" or suffix == ".WibuCmRaU"):
            asn1_type = "Wibu-File"
            self.f = wibu_file.wibu_file(file)
            self.asn1_raw_dict = self.f.get_asn1_data()
        elif(suffix == ".WibuCmActDyn" or suffix == ".WibuCmActLic"):
            asn1_type = "Wibu-File"
            self.asn1_raw_dict = { "default":common.read_file(file, "rb")}
        else:
            raise(Exception("unknown suffix %s" % suffix))
         
        if(asn1_type == None or self.asn1_raw_dict == None):
            raise(Exception("asn1_type or asn1_raw_dictNone"))
                
        # main window
        self.title(os.path.basename(file))

        # combobox
        self.combobox["values"] = list(self.asn1_raw_dict)
        self.combobox.current(0)

        for key, val in self.asn1_raw_dict.items():
            self.asn1_data_dict[key] = wibu_asn1.asn1_def.decode(asn1_type, val, True)
        
        first_key = list(self.asn1_raw_dict)[0]
        self.load_data({first_key:self.asn1_raw_dict[first_key]}, asn1_type)
        
def main():
    wibu_asn1.asn1_init("asn1/", None)
    # reader = asn1_reader(file="testcase/dji_aeroscope_pro.WibuCmLIF")
    # reader = asn1_reader(file="testcase/context-130-142953036.WibuCmRaC")
    # reader = asn1_reader(file="testcase/32b9e930-fc3a-419e-9bd1-59cf6ec375f8_556_1659322984.WibuCmRaU")
    # reader = asn1_reader(file="testcase/new/4/context-130-4191928771-2.WibuCmRaU")
    # reader = asn1_reader(file="testcase/new/3/context-130-4191928771.WibuCmRaU")
    # reader = asn1_reader(file="testcase/new/4/CmAct/6000107_8200f5a6520fcf8bc74e6f45f88883264bf1361e.WibuCmActDyn")
    reader = asn1_reader(file="testcase/new/4/context-130-4191928771-2.WibuCmRaU")
    
    # fd = open("testcase/new/4/content-pi-dynamic.bin","rb")
    # data = fd.read()
    # fd.close()
    # reader = asn1_reader()  #file="testcase/new/4/content-pi-dynamic.bin"
    # reader.load_data({"default":data}, "Content-PI-Dynamic")
    # reader.fix_pi_fi(b"\xA4\x45\x4D\xAB")
    # reader = asn1_reader()
    
    reader.mainloop()
    # new_reader(None, "testcase/32b9e930-fc3a-419e-9bd1-59cf6ec375f8_556_1659322984.WibuCmRaU")
    
if __name__ == "__main__":
	main()