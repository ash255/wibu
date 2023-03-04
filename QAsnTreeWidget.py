# -*- coding: utf-8 -*-
from PyQt5 import QtCore, QtGui, QtWidgets
from asn_help import *
import sha256ecdsa
import traceback

_translate = QtCore.QCoreApplication.translate

class QAsnTreeWidgetErr(Exception):
    pass

def oid_to_type(oid):
    asn_type = ""
    if(oid == "1.3.6.1.4.1.44485.2.1"):
        asn_type = "LIF-Content"
    elif(oid == "1.3.6.1.4.1.44485.2.2"):
        asn_type = "Remote-Context-Content"
    elif(oid == "1.3.6.1.4.1.44485.2.2.3"):
        asn_type = "Prog-Context"
    elif(oid == "1.3.6.1.4.1.44485.2.3"):
        asn_type = "Remote-Update-Content"
    elif(oid == "1.3.6.1.4.1.44485.2.3.1"):
        asn_type = "Push-Update"
    elif(oid == "1.3.6.1.4.1.44485.2.3.2"):
        asn_type = "Return-Update"
    elif(oid == "1.3.6.1.4.1.44485.2.3.3"):
        asn_type = "Pull-Update"
    elif(oid == "1.3.6.1.4.1.44485.2.3.4"):
        asn_type = "Prog-Update"
    elif(oid == "1.3.6.1.4.1.44485.2.3.5"):
        asn_type = "Update-Update"
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
    
    if(asn_type == ""):
        # raise QAsnTreeWidgetErr("unknown content type %s\n" % oid)
        print("unknown content type %s" % oid)
    return asn_type
  
def guess_asn1_type(path, asn1_data):
    last_node_name = ""
    idx = -1
    while(type(path[idx]) != str):
        idx -= 1
    last_node_name = path[idx]
    
    if(last_node_name in ["certificates"]):
        return "Certificate"
    elif(last_node_name in ["encryptedDigest", "signature"]):
        return "SignerSignature"
    elif(last_node_name in ["lif", "fi-p", "fi-dynamic", "pi-p", "pi-dynamic", "pkcs7-elements"]):
        return "Wibu-File"
    elif(last_node_name == "content"):
        type_path = path[0:idx] + ["contentType"]
        type_oid = asn1_value(asn1_data, type_path)
        if(type_oid != None):
            return oid_to_type(type_oid)
    elif(last_node_name == "content-val"):
        type_path = path[0:idx] + ["content-id"]
        type_oid = asn1_value(asn1_data, type_path)
        if(type_oid != None):
            return oid_to_type(type_oid)
    elif(last_node_name == "extnValue"):
        type_path = path[0:idx] + ["extnID"]
        type_oid = asn1_value(asn1_data, type_path)
        if(type_oid != None):
            return oid_to_type(type_oid)
    elif(last_node_name == "encryptedContent"):
        type_path = path[0:idx] + ["contentType"]
        type_oid = asn1_value(asn1_data, type_path)
        if(type_oid != None):
            return oid_to_type(type_oid)
    return ""

def get_short_name(path):
    name = ""
    idx = -1
    while(type(path[idx]) != str):
        name = "[%s]%s" % (str(path[idx]), name)
        idx -= 1
    
    name = path[idx] + name
    return name 

def getAesKey(asn1_data, pri_key):  
    encrypt_key = asn1_value(asn1_data, ["envelope","content","recipientInfos","0","encryptedKey"])
    if(encrypt_key == None):
        return 0
    
    aes_key = int.from_bytes(encrypt_key[0:16], "big")
    tmp_Q = {"x": int.from_bytes(encrypt_key[16:44], "big"), "y": int.from_bytes(encrypt_key[48:76], "big")}
    res = sha256ecdsa.pmul(pri_key, tmp_Q, sha256ecdsa.curve_p)
    
    sha = sha256ecdsa.SHA256()
    sha.update(b"\x04")
    sha.update(encrypt_key[16:44] + encrypt_key[48:76])
    sha.update(res["x"].to_bytes(28, "big"))
    sha.update(b"\x00\x00\x00\x01")
    xor_strem = sha.final()
    aes_key ^= int.from_bytes(xor_strem[0:16], "big")

    # print("getAesKey: 0x%X" % aes_key)
    return aes_key

def genAesKey(pri_key):
    # 实在不行就用sha256ecdsa的curve_G？
    # 解密AES密钥使用的默认Q点
    curve_x = 0xD15081C8538C7EDEC13293B8B42B1F055EF0CEE5BBEB0F1D26DB0AC8
    curve_y = 0x35670209D870D8319624D2C2726584AC5DDBDB908466BE4F0D613FCE
    
    aes_key = 0x3C4DF0690DCF721A58247EDCD190C90
    tmp_Q = {"x": curve_x, "y": curve_y}
    
    res = sha256ecdsa.pmul(pri_key, tmp_Q, sha256ecdsa.curve_p)
    
    sha = sha256ecdsa.SHA256()
    sha.update(b"\x04")
    sha.update(curve_x.to_bytes(28, "big") + curve_y.to_bytes(28, "big"))
    sha.update(res["x"].to_bytes(28, "big"))
    sha.update(b"\x00\x00\x00\x01")
    xor_strem = sha.final()
    aes_key_enc = aes_key ^ int.from_bytes(xor_strem[0:16], "big")
    
    encryptedKey = aes_key_enc.to_bytes(16, "big") + curve_x.to_bytes(28, "big").ljust(32,b"\x00") + curve_y.to_bytes(28, "big").ljust(32,b"\x00")
    
    # print("genAesKey: 0x%X" % aes_key)
    return (aes_key, encryptedKey)

def messageBox(parent, title, content):
    return QtWidgets.QMessageBox.information(parent, _translate("QAsnTreeWidget", title), _translate("QAsnTreeWidget", content), QtWidgets.QMessageBox.Ok)

'''
    用于显示ASN1数据的树状图
    如何使用？
        在构造时需要传入一个AsnInfo实例，推荐初始化asn1_type和bin_data
    自定义信号
        subWidgetCreated(QAsnTreeWidget) - 子组件被创建，由接收者决定如何显示
'''
class QAsnTreeWidget(QtWidgets.QTreeWidget):
    subWidgetCreated = QtCore.pyqtSignal(object)
    
    def __init__(self, parent=None, asn1_info=None, setting=None):
        super().__init__(parent)
        
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.headerItem().setText(0, _translate("AsnTreeWidget", "节点"))
        self.headerItem().setText(1, _translate("AsnTreeWidget", "值"))
        self.itemDoubleClicked['QTreeWidgetItem*','int'].connect(self.treeWidgetDoubleClick)
        self.itemChanged['QTreeWidgetItem*','int'].connect(self.treeWidgetChanged)
        self.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.treeWidgetPopMenu)
        
        self.sub_widgets = {} #sub_widgets[str(path)] = QAsnTreeWidget
        self.items_path = {}  #items_path[str[path]] = QTreeWidgetItem
        self.asn1_info = asn1_info
        self.setting = setting
        if(asn1_info != None):
            asn1_info["widget"] = self
            self.updateView()
            
    def __ASN1Callback(self, path, val):
        if(isinstance(val, (tuple, list, dict))):
            if(isinstance(val, tuple) and isinstance(val[0], (bytes, bytearray))):
                self.__ASN1Callback(path, val[0])
            else:
                if(str(path) not in self.items_path):
                    parent = self
                    if(str(path[0:-1]) in self.items_path):
                        parent = self.items_path[str(path[0:-1])]
                    item = QtWidgets.QTreeWidgetItem(parent, [str(path[-1])])
                    item.setFlags(item.flags() | QtCore.Qt.ItemIsEditable)
                    self.items_path[str(path)] = item
        else:
            if(str(path) in self.items_path):
                item = self.items_path[str(path)]
                item.setText(1, asn1_to_str(val))
            else:
                parent = self
                if(str(path[0:-1]) in self.items_path):
                    parent = self.items_path[str(path[0:-1])]
                item = QtWidgets.QTreeWidgetItem(parent, [str(path[-1]), asn1_to_str(val)])
                item.setFlags(item.flags() | QtCore.Qt.ItemIsEditable)
                item.setData(2, 2, path)
                self.items_path[str(path)] = item 
            
        return 1
  
    def updateView(self, clear_cache=False):
        if("asn1_data" not in self.asn1_info):
            self.asn1_info.check(["asn1_type", "bin_data"])
            self.asn1_info.decode()
        self.asn1_info.check(["asn1_data"])
        if(clear_cache):
            self.clear()
            self.items_path = {}
        asn1_traverse(self.asn1_info["asn1_data"], cbs_before=[self.__ASN1Callback])
        self.expandAll()

    def treeWidgetDoubleClick(self, item, col):
        if(col == 1):
            path = item.data(2, 2)
            if(path != None):
                self.editItem(item, 1)
    
    def treeWidgetChanged(self, item, col):
        if(col == 1):
            path = item.data(2, 2)
            if(path != None):
                self.asn1_info.check(["asn1_data"])
                val = asn1_value(self.asn1_info["asn1_data"], path)
                new_val = item.text(1)
                asn1_value(self.asn1_info["asn1_data"], path, str_to_asn1(type(val), new_val))
                item.setBackground(1, QtGui.QBrush(QtCore.Qt.red))
                
    def treeWidgetPopMenu(self, pos):
        item = self.itemAt(pos)
        if(item != None):
            path = item.data(2, 2)
            if(path != None):
                self.asn1_info.check(["asn1_data"])
                val = asn1_value(self.asn1_info["asn1_data"], path)
                if(isinstance(val, (bytes, bytearray))):
                    right_menu = QtWidgets.QMenu(self)
                    asn1_type = guess_asn1_type(path, self.asn1_info["asn1_data"])
                    if(asn1_type != ""):
                        action = QtWidgets.QAction(asn1_type, right_menu)
                        action.triggered.connect(lambda :self.subWidgetCreate(path, asn1_type))
                        right_menu.addAction(action)
                        
                    action = QtWidgets.QAction(_translate("AsnTreeWidget", "UTF-16编辑"), right_menu) #因为asn1tools无法将BMPString正确地解析为utf16字符串
                    action.triggered.connect(lambda :self.utf16Edit(path))
                    right_menu.addAction(action)
                    right_menu.exec_(QtGui.QCursor.pos())

    def utf16Edit(self, path):
        self.asn1_info.check(["asn1_data"])
        val = asn1_value(self.asn1_info["asn1_data"], path)
        val_uft16 = ""
        try:
            val_uft16 = val.decode("utf-16")
        except Exception as e:
            #无法decode就当无事发生，因为所有的bytes类型都可以尝试decode
            return
        
        if(len(val_uft16) == 0):
            return 
            
        text, ok = QtWidgets.QInputDialog.getText(self, 
            _translate("AsnTreeWidget", "UTF-16编辑"), 
            _translate("AsnTreeWidget", val_uft16), 
            QtWidgets.QLineEdit.Normal,
            val_uft16)
            
        if(ok and text != val_uft16):
            asn1_value(self.asn1_info["asn1_data"], path, text.encode("utf-16"))
            self.items_path[str(path)].setText(1, asn1_to_str(text.encode("utf-16")))
           
    def subWidgetCreate(self, path, asn1_type):
        if(str(path) not in self.sub_widgets):
            if(self.asn1_info.contain_child(path) == False):
                self.asn1_info.check(["name", "childs", "asn1_data"])
                is_enc = False
                key_count = 0
                key_list = []
                if(asn1_type in ["DynData-Content", "Content-PI-Dynamic", "Content-FI-Dynamic"]):
                    pri_key = 0
                    if(self.setting != None and self.setting.contains("usrPriKey")):
                        pri_key = self.setting.value("usrPriKey")
                        text = "0x%X" % pri_key
                    else:
                        text, ok = QtWidgets.QInputDialog.getMultiLineText(self, 
                            _translate("AsnTreeWidget", "请输入私钥"), 
                            _translate("AsnTreeWidget", "多条私钥以\\n分割"), 
                            "0x%X" % pri_key)
                        if(text == ""):
                            return
                    
                    text = text.replace("\r", "")
                    key_list = text.split("\n")
                    key_count = len(key_list)
                    is_enc = True
                
                bin_data = asn1_value(self.asn1_info["asn1_data"], path)
                if(isinstance(bin_data, (bytes, bytearray)) == False):
                    raise QAsnTreeWidgetErr("%s path %s is not bytes, type is %s" % (self.asn1_info["name"], str(path), type(bin_data)))
                sub_asn1_info = AsnInfo(name = get_short_name(path),
                                        asn1_def = self.asn1_info["asn1_def"],
                                        asn1_type = asn1_type,
                                        bin_data = bin_data,
                                        is_enc = is_enc)
                
                success = False
                if(key_count > 0):
                    for key in key_list:
                        pri_key = int(key, 16)
                        aes_key = getAesKey(self.asn1_info["asn1_data"], pri_key)
                        try:
                            sub_asn1_info["aes_key"] = aes_key
                            sub_asn1_info["pri_key"] = pri_key
                            sub_asn1_info.decode()
                        except Exception as e:
                            # traceback.print_exc()
                            pass
                        else:
                            if(key_count > 1):
                                print("pri_key: 0x%X" % pri_key)
                            if(self.setting != None):
                                self.setting.setValue("usrPriKey", pri_key)
                                self.setting.sync()
                            self.asn1_info["pri_key"] = pri_key
                            success = True
                            break
                else:
                    try:
                        sub_asn1_info.decode()
                    except Exception as e:
                        pass
                    else:
                        success = True
                    
                if(success == False):
                    messageBox(self, "错误", "解码失败")
                    return
                    
                self.asn1_info.set_child(path, sub_asn1_info)
            else:
                sub_asn1_info = self.asn1_info.get_child(path)
            sub_widget = QAsnTreeWidget(self, sub_asn1_info, self.setting)
            sub_widget.itemChanged['QTreeWidgetItem*','int'].connect(lambda :self.subWidgetChanged(path, sub_asn1_info))
            self.sub_widgets[str(path)] = sub_widget
        else:
            sub_widget = self.sub_widgets[str(path)]
        
        self.subWidgetCreated.emit(sub_widget)
        
    def subWidgetChanged(self, path, sub_asn1_info):
        bin_data = sub_asn1_info.encode()
        self.asn1_info.check(["asn1_data"])
        asn1_value(self.asn1_info["asn1_data"], path, bin_data)
        # self.items_path[str(path)].setBackground(1, QtGui.QBrush(QtCore.Qt.red))
        self.updateView()