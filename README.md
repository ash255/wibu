# Wibu Reader
本程序用于读取和修改Wibu软授权过程的文件。

**仅用于学习交流，严禁用作商业用途，造成任何法律问题本人概不承担。**

# 适用平台

* linux

* python3

# 依赖项

* asn1tools
* PyQt5

## 如何安装

```
pip install -r requirements.txt
```

# 如何使用

## QWibuReader

```
python QWibuReader.py
```

### 功能

常规功能：

* 打开，保存，保存为其他类型，拖入

特殊功能：

* 对CodeMeterLin打补丁，工具-CodeMeterLin补丁
* 计算CmAct证书的私钥，工具-wbc私钥
* 根据cfg文件修复RAU文件，工具-授权设置，工具栏-RAU按钮
* 常规修复，工具栏-Fix按钮

## wibu_cfg

```
python wibu_cfg.py
ls cfg/* -l
```

### 功能

该文件会自动扫描`/var/lib/CodeMeter/CmAct`目录获取所有授权信息，并在cfg目录下生成对应的信息。

* `FirmCode`是软件号。

* `serialNmber`是唯一的授权识别号。

* `PrivateKey`是wbc文件计算出来的CmAct证书所用的私钥，该证书是一份自签证书。

* `CmActId`是CmAct证书的唯一识别号。

* `Replace`字段用于自定义替换规则，可由用户进行填写。

```
[General]
FirmCode=6000xxx
SerialNumber=82 00 xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
PrivateKey=0xAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFF
CmActId=AB CD EF 01 23 45 67

;[Replace]
;Number=1

;[Replace_0]
;AsnType=Content-PI-P
;Path=product-item,pi-expirationtime,time
;Type=bytes;bytes,int,str,bool
;Value=0058000000
```

