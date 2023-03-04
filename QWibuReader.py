# -*- coding: utf-8 -*-
import sys, os, struct, itertools, traceback
import common
from asn_help import *
from sha256ecdsa import *
from wibu_cert import *
from wibu_file import WibuFile
from wibu_control import WbcFile
from wibu_reader_ui import Ui_WibuReader
from PyQt5 import QtCore, QtGui, QtWidgets
from QAboutDialog import QAboutDialog
from QAsnTreeWidget import *
from QSettingDialog import QSettingDialog

_translate = QtCore.QCoreApplication.translate

def messageBox(parent, title, content):
    return QtWidgets.QMessageBox.information(parent, _translate("QWibuReader", title), _translate("QWibuReader", content), QtWidgets.QMessageBox.Ok)

class WibuReaderErr(Exception):
    pass
  
class QWibuReader(QtWidgets.QMainWindow, Ui_WibuReader):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        
        #状态条UI代码
        self.status_asn1_type = QtWidgets.QLabel(self)
        self.status_text = QtWidgets.QLabel(self)
        self.statusbar.addPermanentWidget(self.status_asn1_type, 6)
        self.statusbar.addPermanentWidget(self.status_text, 1)
        self.setAcceptDrops(True)
        
        self.runtime = QtCore.QSettings("WIBU", "QWibuReader")
        self.setting = QtCore.QSettings("config.ini", QtCore.QSettings.IniFormat)
        self.setting.setIniCodec("UTF-8")
        if(self.setting.contains("asn1_dir") == False):
            messageBox("错误", "没有找到ASN1定义目录")
            self.close()
            return
        asn1_dir = self.setting.value("asn1_dir")
        self.asn1_def = asn1_init(asn1_dir)
        self.wibu_cert = WibuCert(self.asn1_def, self.runtime)
        
        self.init()
   
    def init(self):   
        self.comboBox.clear()
        self.tabWidget.clear()
        self.status_asn1_type.setText("")
        self.status_text.setText("")
        
        self.runtime.clear()
        self.file = ""
        self.file_type = -1     #0: WibuCm文件  1: bin文件
    
    def showAbout(self):
        diag = QAboutDialog(self.setting, self)
        diag.show()
        diag.exec_()

    def reloadFile(self, file):
        self.init()
        asn1_dict = {}
        if(file != ""):
            self.file = file
            self.setWindowTitle(os.path.basename(file))
            suffix = os.path.splitext(file)[-1].lower()
            if(suffix in [".wibucmlif", ".wibucmrac", ".wibucmrau"]):
                self.file_type = 0
                wibu_file = WibuFile(file)
                self.runtime.setValue("wibu_file", wibu_file)
                asn1_type = "Wibu-File"
                asn1_dict = wibu_file.get_asn1_data()
                
            elif(suffix in [".wibucmactdyn", ".wibucmactlic", ".###", ".+++"]):
                self.file_type = 1
                asn1_type = "Wibu-File"
                asn1_dict["default"] = common.read_file(file, "rb")
                if(len(asn1_dict["default"]) == 0):
                    messageBox(self, "错误", "文件为空")
                    return
            else:
                messageBox(self, "错误", "不支持该格式")
                return
                
            if(len(asn1_dict) == 0):
                raise WibuReaderErr("asn1_dict empty")
                
            for key, val in asn1_dict.items():
                asn_widget = self.asnTreeWidgetCreate(key, asn1_type, val)
                self.comboBox.addItem(key, asn_widget)
                
            asn_widget = self.comboBox.itemData(0)
            self.tabWidget.addTab(asn_widget, asn_widget.asn1_info["name"])
            self.comboBox.setCurrentIndex(0)
            self.status_text.setText(_translate("QWibuReader", "未修复"))
            
            # 尝试加载修复配置
            expect_cfg_path = "%s.cfg" % os.path.splitext(file)[0]
            if(os.path.exists(expect_cfg_path)):
                diag = QSettingDialog(self, self.runtime)
                diag.loadConfig(expect_cfg_path)
                diag.show()
                diag.exec_()
                
    def openFile(self):
        file, filetype = QtWidgets.QFileDialog.getOpenFileName(filter="WibuCm文件 (*.WibuCm* *.### *.+++);;所有文件 (*.*)")
        if(file != ""):
            self.reloadFile(file)

    def saveFile(self):        
        if(self.file_type == 0):
            if(self.runtime.contains("wibu_file") == False):
                messageBox(self, "错误", "操作失败")
                return
            wibu_file = self.runtime.value("wibu_file")
            
            suffix = os.path.splitext(self.file)[-1].lower()
            if(suffix == ".wibucmlif" or suffix == ".wibucmrac" or suffix == ".wibucmrau"):
                file, filetype = QtWidgets.QFileDialog.getSaveFileName(filter="WibuCm文件 (*%s)" % suffix, directory=self.file) 
                if(file != ""):
                    wibu_file_dict = {}
                    for i in range(self.comboBox.count()):
                        asn_widget = self.comboBox.itemData(i)
                        asn1_info = asn_widget.asn1_info
                        wibu_file_dict[self.comboBox.itemText(i)] = asn1_info.encode()
                    wibu_file.set_asn1_data(wibu_file_dict)
                    wibu_file.save(file)
                    messageBox(self, "提示", "操作成功")
        elif(self.file_type == 1):
            asn_widget = self.comboBox.currentData()
            if(asn_widget != None):
                self.tabWidget.setCurrentIndex(self.tabWidget.indexOf(asn_widget))
                self.saveAsBinFile()
        
    def saveAsBinFile(self):
        asn_widget = self.tabWidget.currentWidget()
        if(asn_widget != None):
            file, filetype = QtWidgets.QFileDialog.getSaveFileName(filter="bin文件 (*.bin)") 
            if(file != ""):
                asn1_info = asn_widget.asn1_info
                common.write_file(file, asn1_info.encode(), "wb")
                messageBox(self, "提示", "操作成功")
            
    def saveAsXmlFile(self):
        asn_widget = self.tabWidget.currentWidget()
        if(asn_widget != None):
            file, filetype = QtWidgets.QFileDialog.getSaveFileName(filter="xml文件 (*.xml)") 
            if(file != ""):
                asn1_info = asn_widget.asn1_info
                fd = open(file, "w")
                print_asn1_data(asn1_info["asn1_data"], fd)
                fd.close()
                messageBox(self, "提示", "操作成功")    
    
    def calcPiHash(self, p_content, dyn_content, salt, sha1=None, sha2=None):
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
        
        if(sha1 == None):
            sha1 = SHA256(salt)
        if(sha2 == None):
            sha2 = SHA256(salt)
        
        pisk = asn1_value(dyn_content, ["pi-dynamic","pi-pisk"])
        sha1.update(pisk)
        h1 = sha1.final()
        sha2.update(b"\x23" + h1)
        
        for key, val in pi_map.items():
            if(asn1_value(dyn_content, ["pi-dynamic", key]) != None):
                attr = asn1_value(dyn_content, ["pi-dynamic", key, "dependencies", "attribute"])
                if(attr == None or (attr & 4) == 0):
                    sha2.update(struct.pack("B", val))
                    # print("%s add sha data 0x%02X" % (key, val))
          
        list_pi_secretdata = asn1_value(dyn_content, ["pi-dynamic", "list-pi-secretdata"])
        for pi_secretdata in list_pi_secretdata:
            attr = asn1_value(pi_secretdata, ["dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", val))
                # print("pi_secretdata[%d] add sha data 0x%02X" % (list_pi_secretdata.index(pi_secretdata), 0x52))
            
        list_pi_hiddendata = asn1_value(dyn_content, ["pi-dynamic", "list-pi-hiddendata"])
        for pi_hiddendata in list_pi_hiddendata:
            attr = asn1_value(pi_hiddendata, ["dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", 0x52))
                # print("list_pi_hiddendata[%d] add sha data 0x%02X" % (list_pi_hiddendata.index(pi_hiddendata), 0x53))
        
        list_pi_extprotdata = asn1_value(dyn_content, ["pi-dynamic", "list-pi-extprotdata"])
        for pi_extprotdata in list_pi_extprotdata:
            attr = asn1_value(pi_extprotdata, ["dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", val))
                # print("list_pi_extprotdata[%d] add sha data 0x%02X" % (list_pi_extprotdata.index(pi_extprotdata), 0x5B))
        
        if(asn1_value(dyn_content, ["pi-dynamic", "pi-delay"]) != None):
            attr = asn1_value(dyn_content, ["pi-dynamic", "pi-delay", "dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", 0xA2))
                # print("%s add sha data 0x%02X" % ("pi-delay", 0xA2))
            
        if(asn1_value(dyn_content, ["pi-dynamic", "pi-password"]) != None):
            attr = asn1_value(dyn_content, ["pi-dynamic", "pi-password", "dependencies", "attribute"])
            if(attr == None or (attr & 4) == 0):
                sha2.update(struct.pack("B", 0xA3))
                # print("%s add sha data 0x%02X" % ("pi-password", 0xA3))
                if(attr == None or (attr & 1) == 0):
                    password_hash = asn1_value(dyn_content, ["pi-dynamic", "pi-password", "password-hash"])
                    sha1.update(password_hash)
                    h1 = sha1.final()
                    sha2.update(h1)
                    # print("%s add sha data %s" % ("pi-password", h1.hex()))

        
        #每一个product_item对应一个pi_dynamic
        pi_moduleitems = asn1_value(p_content, ["product-item", "pi-moduleitems"])
        pi_dynamics_for_moduleitems = asn1_value(dyn_content, ["pi-dynamic", "pi-dynamics-for-moduleitems"])
        if(pi_moduleitems != None and pi_dynamics_for_moduleitems != None):
            if(len(pi_moduleitems) != len(pi_dynamics_for_moduleitems)):
                print("len(pi_moduleitems) != len(pi_dynamics_for_moduleitems)")
                return b""
                
            for i in range(len(pi_moduleitems)):
                self.calcPiHash(pi_moduleitems[i], pi_dynamics_for_moduleitems[i], None, sha1, sha2)
        
        #递归调用时，salt为None
        if(salt != None):
            return sha2.final()[0:16]
    
    def calcFiHash(self, p_content, dyn_content, salt):
        sha1 = SHA256(salt)
        sha2 = SHA256(salt)
        sha1.update(asn1_value(dyn_content, ["fi-firm-key"]))
        sha2.update(b"\x01")
        sha2.update(sha1.final())
        return sha2.final()[0:16]
    
    def fixHash(self, p_info, d_info):
        #修复FI或PI的哈希校验  
        salt = asn1_value(p_info["asn1_data"], ["hashing-salt"])
        if(d_info["asn1_type"] == "Content-PI-Dynamic"):
            dyn_hash = asn1_value(p_info["asn1_data"], ["pi-dynamic-hash"])
            new_hash = self.calcPiHash(p_info["asn1_data"], d_info["asn1_data"], salt)
            asn1_value(p_info["asn1_data"], ["pi-dynamic-hash"], new_hash)
            # print("old pi hash: %s" % dyn_hash.hex())
            # print("new pi hash: %s" % new_hash.hex())
        elif(d_info["asn1_type"] == "Content-FI-Dynamic"):
            dyn_hash = asn1_value(p_info["asn1_data"], ["fi-dynamic-hash"])
            new_hash = self.calcFiHash(p_info["asn1_data"], d_info["asn1_data"], salt)
            asn1_value(p_info["asn1_data"], ["fi-dynamic-hash"], new_hash)
            # print("old fi hash: %s" % dyn_hash.hex())
            # print("new fi hash: %s" % new_hash.hex())
        else:
            messageBox(self, "错误", "未支持的dynamic类型: %s" % d_info["asn1_type"])
            return False
        
        return True
        
    def fixData(self, asn1_info):
        asn1_type = asn1_info["asn1_type"]
        asn1_data = asn1_info["asn1_data"]
        # print("fixData: %s %s" % (asn1_info["name"], asn1_info["asn1_type"]))
        
        # 固定需要修复的字段
        if(asn1_type == "Prog-Update"):
            # fix fi
            if(asn1_value(asn1_data, ["fi"]) != None):
                if(asn1_info.contain_child(["fi", "fi-p"]) and asn1_info.contain_child(["fi", "fi-dynamic"])):
                    fi_p_info = asn1_info.get_child(["fi", "fi-p"])
                    fi_dynamic_info = asn1_info.get_child(["fi", "fi-dynamic"])
                    if(fi_p_info.contain_child(["signed", "content", "contentInfo", "content"]) and 
                       fi_dynamic_info.contain_child(["envelope", "content", "encryptedContentInfo", "encryptedContent"])):
                        fi_p = fi_p_info.get_child(["signed", "content", "contentInfo", "content"])
                        fi_dynamic = fi_dynamic_info.get_child(["envelope", "content", "encryptedContentInfo", "encryptedContent"])
                        if(self.fixHash(fi_p, fi_dynamic) == False):
                            return False
            
            # fix pi
            pi_list = asn1_value(asn1_data, ["pi"])
            cnt = 0
            for pi in pi_list:
                if(asn1_info.contain_child(["pi", cnt, "pi-p"]) and asn1_info.contain_child(["pi", cnt, "pi-dynamic"])):
                    pi_p_info = asn1_info.get_child(["pi", cnt, "pi-p"])
                    pi_dynamic_info = asn1_info.get_child(["pi", cnt, "pi-dynamic"])
                    if(pi_p_info.contain_child(["signed", "content", "contentInfo", "content"]) and 
                       pi_dynamic_info.contain_child(["envelope", "content", "encryptedContentInfo", "encryptedContent"])):
                        pi_p = pi_p_info.get_child(["signed", "content", "contentInfo", "content"])
                        pi_dynamic = pi_dynamic_info.get_child(["envelope", "content", "encryptedContentInfo", "encryptedContent"])
                        if(self.fixHash(pi_p, pi_dynamic) == False):
                            return False
                cnt += 1
        elif(asn1_type == "Content-FI-P"):
            #serial-number and firm-code
            if(asn1_value(asn1_data, ["hardware-id", "cmact-machine-id"]) != None and self.runtime.contains("SerialNumber")):
                asn1_value(asn1_data, ["hardware-id", "cmact-machine-id"], self.runtime.value("SerialNumber"))
            if(self.runtime.contains("FirmCode")):
                asn1_value(asn1_data, ["firm-code"], self.runtime.value("FirmCode").to_bytes(5, "big"))
        elif(asn1_type == "LIF-Content"):
            #firm-code
            if(asn1_value(asn1_data, ["license-description", "firm-code"]) != None and self.runtime.contains("FirmCode")):
                asn1_value(asn1_data, ["license-description", "firm-code"], self.runtime.value("FirmCode").to_bytes(5, "big"))
        
        #根据用户配置修复指定字段
        if(self.runtime.contains("Replace/Number")):
            for i in range(self.runtime.value("Replace/Number")):
                asn_type = self.runtime.value("Replace_%d/AsnType" % i)
                if(asn_type == asn1_type):
                    path = self.runtime.value("Replace_%d/Path" % i)
                    value = self.runtime.value("Replace_%d/Value" % i)
                    if(asn1_value(asn1_data, path) != None):
                        asn1_value(asn1_data, path, value)
        
        for path, child_info in asn1_info["childs"]:
            self.fixData(child_info)
            asn1_value(asn1_data, path, child_info.encode())

        #最后修复证书的摘要
        if(asn1_type == "Wibu-File"):
            if(asn1_value(asn1_data, ["signed"]) == None):
                # fix envelope
                # 若CmActKey证书的ID指定了，则变更为指定ID
                if(self.runtime.contains("CmActId")):
                    asn1_value(asn1_data,["envelope", "content", "recipientInfos", 0, "signerIdentifier"], ("subjectKeyIdentifier", self.runtime.value("CmActId")))
  
                # CmActKey证书的私钥是通过系统特征计算的
                # 若有指定的私钥，则更换为指定的私钥；若无，则保持原来的私钥。
                if(self.runtime.contains("PrivateKey")):
                    if(asn1_info.contain_child(["envelope", "content", "encryptedContentInfo", "encryptedContent"])):
                        ase_key, encryptedKey = genAesKey(self.runtime.value("PrivateKey"))
                        asn1_value(asn1_data, ["envelope","content","recipientInfos","0","encryptedKey"], encryptedKey)
                        content_info = asn1_info.get_child(["envelope", "content", "encryptedContentInfo", "encryptedContent"])
                        content_info["aes_key"] = ase_key
                        asn1_value(asn1_data, ["envelope","content","encryptedContentInfo","encryptedContent"], content_info.encode())
            else:
                # fix signed
                # 1. fix certs
                # 2. fix signature of content by new certs
                asn1_info["asn1_data"] = self.wibu_cert.patch_sign_data(asn1_data)
  
        if("widget" in asn1_info):
            asn1_info["widget"].updateView()
        
        return True
        
    def fixFile(self):
        #只有展开的tab才会被修复
        if(self.file == ""):
            return
        try:
            for i in range(self.comboBox.count()):
                asn_widget = self.comboBox.itemData(i)
                if(self.fixData(asn_widget.asn1_info) == False):
                    messageBox(self, "错误", "修复失败")
                    return
            self.status_text.setText(_translate("QWibuReader", "已修复"))
            messageBox(self, "提示", "修复成功")
        except Exception as e:
            traceback.print_exc()
            messageBox(self, "错误", "修复失败")
    
    def fixRau(self):
        #先尽可能自动展开content   
        if(self.file == ""):
            return
        for i in range(self.comboBox.count()):
            asn_widget = self.comboBox.itemData(i)
            if(self.unfoldContent(asn_widget.asn1_info) == False):
                print("unfoldContent false!!")
                return
        self.fixFile()
    
    def unfoldContent(self, asn1_info):
        asn1_type = asn1_info["asn1_type"]
        asn1_data = asn1_info["asn1_data"]
        # print("unfoldContent %s %s" % (asn1_info["name"], asn1_info["asn1_type"]))
        
        paths = []
        is_enc = False
        aes_key = 0
        if(asn1_type == "Wibu-File"):
            if(asn1_value(asn1_data, ["signed"]) == None):
                path = ["envelope","content","encryptedContentInfo","encryptedContent"]
                paths.append(path)
                is_enc = True
                if(self.runtime.contains("usrPriKey") == False):
                    text, ok = QtWidgets.QInputDialog.getText(self, 
                        _translate("AsnTreeWidget", "请输入私钥"),
                        _translate("AsnTreeWidget", "16进制私钥"))
                    if(text == ""):
                        return False
                    self.runtime.setValue("usrPriKey", int(text, 16))
                aes_key = getAesKey(asn1_data, self.runtime.value("usrPriKey"))
            else:
                path = ["signed","content","contentInfo","content"]
                paths.append(path)
        elif(asn1_type == "Remote-Update-Content"):
            path = ["content-val"]
            paths.append(path)
        elif(asn1_type == "Prog-Update"):
            if(asn1_value(asn1_data, ["fi"]) != None):
                paths.append(["fi", "fi-p"])
                paths.append(["fi", "fi-dynamic"])
            pi_list = asn1_value(asn1_data, ["pi"])
            cnt = 0
            for pi in pi_list:
                paths.append(["pi", cnt, "pi-p"]) 
                paths.append(["pi", cnt, "pi-dynamic"])
                cnt += 1

        if(len(paths) > 0):
            for path in paths:
                if(asn1_info.contain_child(path) == False):
                    bin_data = asn1_value(asn1_data, path)
                    sub_type = guess_asn1_type(path, asn1_data)
                    sub_info = AsnInfo(name = get_short_name(path),
                                        asn1_def = self.asn1_def,
                                        asn1_type = sub_type,
                                        bin_data = bin_data,
                                        is_enc = is_enc,
                                        aes_key = aes_key)
                    sub_info.decode()
                    asn1_info.set_child(path, sub_info)
                if(self.unfoldContent(asn1_info.get_child(path)) == False):
                    return False
        return True
    
    def asnTreeWidgetCreate(self, name, asn1_type, bin_data):
        asn1_info = AsnInfo(name = name,
                            asn1_def = self.asn1_def,
                            asn1_type = asn1_type,
                            bin_data = bin_data,
                            is_enc = False)
                             
        asn1_info.decode()
        asn_widget = QAsnTreeWidget(self, asn1_info, self.runtime)
        asn_widget.subWidgetCreated.connect(self.asnTreeWidgetShow)
        return asn_widget
    
    def asnTreeWidgetShow(self, asn_widget):
        if(self.tabWidget.indexOf(asn_widget) == -1):
            asn_widget.subWidgetCreated.connect(self.asnTreeWidgetShow)
            self.tabWidget.addTab(asn_widget, asn_widget.asn1_info["name"])
        
        self.tabWidget.setCurrentIndex(self.tabWidget.indexOf(asn_widget))
    
    def tabWidgetChanged(self, index):
        asn_widget = self.tabWidget.widget(index)
        if(asn_widget != None):
            self.status_asn1_type.setText(_translate("QWibuReader", asn_widget.asn1_info["asn1_type"]))
    
    def comboboxSelected(self):
        asn_widget = self.comboBox.currentData()
        if(asn_widget != None):
            self.asnTreeWidgetShow(asn_widget)

    def authSettingClick(self):
        diag = QSettingDialog(self, self.runtime)
        diag.show()
        diag.exec_()
        
    def wbcKeyClick(self):
        if(not sys.platform.startswith("linux")):
            messageBox(self, "错误", "仅支持linux平台")
            return
            
        file, filetype = QtWidgets.QFileDialog.getOpenFileName(filter="wbc文件 (*.wbc)")
        if(file == ""):
            return
        wbc = WbcFile(file)
        if(wbc.check()):
            k_list = ""
            for cf in itertools.product([True, False], repeat=4):
                k = wbc.get_private_key(cf)
                if(k_list.find(k.hex()) == -1):
                    k_list += k.hex() + "\n"
            
            QtWidgets.QInputDialog.getMultiLineText(self, _translate("QWibuReader", "wbc私钥"), _translate("QWibuReader", "wbc私钥"), k_list)
    
    def codeMeterLinPatchClick(self):
        if(self.setting.value("cert") == None):
            messageBox(self, "错误", "未在配置文件中找到cert")
            return
        
        cert = self.setting.value("cert")
        if(os.path.exists(cert) == False):
            messageBox(self, "错误", "cert: %s不存在" % cert)
            return
        input_file = ""
        if(os.path.exists("/usr/sbin/CodeMeterLin")):
            button = QtWidgets.QMessageBox.information(
                self, 
                _translate("QWibuReader", "提示"), 
                _translate("QWibuReader", "在/usr/sbin/找到CodeMeterLin，是否对其打补丁"), 
                QtWidgets.QMessageBox.Yes, QtWidgets.QMessageBox.No)
            if(button == QtWidgets.QMessageBox.Yes):
                input_file = "/usr/sbin/CodeMeterLin"
        
        
        if(input_file == ""):
            file, filetype = QtWidgets.QFileDialog.getOpenFileName(filter="所有文件 (*.*)")
            if(file == ""):
                return
            
            input_file = file
        
        #先备份文件
        backup_file = "%s.bak" % input_file
        common.write_file(backup_file, common.read_file(input_file, "rb"), "wb")
        if(wibu_cert.patch_codemeterlin(backup_file, input_file, cert)):
            messageBox(self, "提示", "打补丁成功")
        else:
            messageBox(self, "错误", "打补丁失败")

    def dragEnterEvent(self, e):
        e.accept()
    
    def dropEvent(self, e):
        self.reloadFile(e.mimeData().text().lstrip("file:///"))

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    wibu_reader = QWibuReader()
    wibu_reader.show()
    sys.exit(app.exec_())
