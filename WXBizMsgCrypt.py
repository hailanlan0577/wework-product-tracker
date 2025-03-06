#!/usr/bin/env python
# -*- encoding:utf-8 -*-

""" 
企业微信消息加解密处理
"""

import base64
import string
import random
import hashlib
import time
import struct
from Crypto.Cipher import AES
import xml.etree.cElementTree as ET
import socket

class FormatException(Exception):
    pass

def throw_exception(message, exception_class=FormatException):
    """my define raise exception function"""
    raise exception_class(message)

class SHA1:
    """计算企业微信的消息签名接口"""
   
    @staticmethod
    def getSHA1(token, timestamp, nonce, encrypt):
        """用SHA1算法生成安全签名
        @param token:  票据
        @param timestamp: 时间戳
        @param nonce: 随机字符串
        @param encrypt: 密文
        @return: 安全签名
        """
        try:
            sortlist = [token, timestamp, nonce, encrypt]
            sortlist.sort()
            sha = hashlib.sha1()
            sha.update("".join(sortlist).encode())
            return  sha.hexdigest()
        except Exception as e:
            print(e)
            throw_exception("[SHA1] SHA1 Error")

class XMLParse:
    """提供提取消息格式中的密文及生成回复消息格式的接口"""

    # xml消息模板
    AES_TEXT_RESPONSE_TEMPLATE = """<xml>
<Encrypt><![CDATA[%(msg_encrypt)s]]></Encrypt>
<MsgSignature><![CDATA[%(msg_signaturet)s]]></MsgSignature>
<TimeStamp>%(timestamp)s</TimeStamp>
<Nonce><![CDATA[%(nonce)s]]></Nonce>
</xml>"""

    @staticmethod
    def extract(xmltext):
        """提取出xml数据包中的加密消息
        @param xmltext: 待提取的xml字符串
        @return: 提取出的加密消息字符串
        """
        try:
            xml_tree = ET.fromstring(xmltext)
            encrypt  = xml_tree.find("Encrypt")
            return  encrypt.text
        except Exception as e:
            print(e)
            throw_exception("[XML_Parse] Extract encrypt text error.")

    @staticmethod
    def generate(encrypt, signature, timestamp, nonce):
        """生成xml消息
        @param encrypt: 加密后的消息密文
        @param signature: 安全签名
        @param timestamp: 时间戳
        @param nonce: 随机字符串
        @return: 生成的xml字符串
        """
        resp_dict = {
                    'msg_encrypt' : encrypt,
                    'msg_signaturet': signature,
                    'timestamp': timestamp,
                    'nonce': nonce,
                     }
        resp_xml = XMLParse.AES_TEXT_RESPONSE_TEMPLATE % resp_dict
        return resp_xml   

class PKCS7Encoder():
    """提供基于PKCS7算法的加解密接口"""

    block_size = 32
    @classmethod
    def encode(cls, text):
        """ 对需要加密的明文进行填充补位
        @param text: 需要进行填充补位操作的明文
        @return: 补齐明文字符串
        """
        text_length = len(text)
        # 计算需要填充的位数
        amount_to_pad = cls.block_size - (text_length % cls.block_size)
        if amount_to_pad == 0:
            amount_to_pad = cls.block_size
        # 获得补位所用的字符
        pad = chr(amount_to_pad)
        return text + (pad * amount_to_pad).encode()
    
    @classmethod
    def decode(cls, decrypted):
        """删除解密后明文的补位字符
        @param decrypted: 解密后的明文
        @return: 删除补位字符后的明文
        """
        pad = ord(decrypted[-1])
        if pad < 1 or pad > 32:
            pad = 0
        return decrypted[:-pad]

class Prpcrypt(object):
    """提供接收和推送给企业微信消息的加解密接口"""

    def __init__(self, key):
        #self.key = base64.b64decode(key+"=")
        self.key = key
        # 设置加解密模式为AES的CBC模式
        self.mode = AES.MODE_CBC

    def encrypt(self, text, receiveId):
        """对明文进行加密
        @param text: 需要加密的明文
        @return: 加密得到的字符串
        """
        # 16位随机字符串添加到明文开头
        len_str = struct.pack("I", socket.htonl(len(text)))
        # 企业微信的ReceiveID
        text = (self.get_random_str() + len_str + text.encode() + receiveId.encode()).decode('latin-1')
        # 使用自定义的填充方式对明文进行补位填充
        text = PKCS7Encoder.encode(text.encode())
        # 加密
        aes = AES.new(self.key, self.mode, self.key[:16].encode())
        encrypt_text = aes.encrypt(text)
        # 使用BASE64对加密后的字符串进行编码
        return base64.b64encode(encrypt_text)

    def decrypt(self, text, receiveId):
        """对解密后的明文进行补位删除
        @param text: 密文 
        @return: 删除填充补位后的明文
        """
        try:
            # 使用BASE64对密文进行解码
            text = base64.b64decode(text)
            # 使用AES算法解密密文
            aes = AES.new(self.key, self.mode, self.key[:16].encode())
            decrypt_text = aes.decrypt(text)
            # 去除补位字符
            result = PKCS7Encoder.decode(decrypt_text)
            # 去除16位随机字符串
            content = result[16:]
            xml_len = socket.ntohl(struct.unpack("I", content[: 4])[0])
            xml_content = content[4: xml_len + 4]
            from_receiveId = content[xml_len + 4:].decode()
        except Exception as e:
            print(e)
            throw_exception("[Prpcrypt] Decrypt Error")
        if from_receiveId != receiveId:
            throw_exception("[Prpcrypt] ValidateCorpid Error")
        return xml_content.decode()

    def get_random_str(self):
        """ 随机生成16位字符串
        @return: 16位字符串
        """
        rule = string.ascii_letters + string.digits
        str = random.sample(rule, 16)
        return "".join(str)

class WXBizMsgCrypt(object):
    # 构造函数
    def __init__(self, token, encodingAesKey, corpId):
        """
        token: 企业微信后台，开发者设置的token
        encodingAesKey: 企业微信后台，开发者设置的EncodingAESKey
        corpId: 企业ID
        """
        try:
            self.token = token
            self.encodingAesKey = encodingAesKey
            self.corpId = corpId
            self.key = base64.b64decode(self.encodingAesKey + '=')
            self.pc = Prpcrypt(self.key)
        except Exception as e:
            print(e)
            throw_exception("[WXBizMsgCrypt] Init error")

    def VerifyURL(self, sMsgSignature, sTimeStamp, sNonce, sEchoStr):
        """验证URL
        @param sMsgSignature: 签名串，对应URL参数的msg_signature
        @param sTimeStamp: 时间戳，对应URL参数的timestamp
        @param sNonce: 随机串，对应URL参数的nonce
        @param sEchoStr: 随机串，对应URL参数的echostr
        @return: 解密之后的echostr
        """
        try:
            signature = SHA1.getSHA1(self.token, sTimeStamp, sNonce, sEchoStr)
            if signature != sMsgSignature:
                throw_exception("[WXBizMsgCrypt] VerifyURL Signature Error")
            result = self.pc.decrypt(sEchoStr, self.corpId)
            return result
        except Exception as e:
            print(e)
            throw_exception("[WXBizMsgCrypt] VerifyURL Error")

    def EncryptMsg(self, sReplyMsg, sNonce, timestamp = None):
        """将企业微信回复用户的消息加密打包
        @param sReplyMsg: 企业微信待回复用户的消息，xml格式的字符串
        @param sTimeStamp: 时间戳，可以自己生成，也可以用URL参数的timestamp
        @param sNonce: 随机串，可以自己生成，也可以用URL参数的nonce
        @return: 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串
        """
        try:
            if timestamp is None:
                timestamp = str(int(time.time()))
            encrypt = self.pc.encrypt(sReplyMsg, self.corpId)
            signature = SHA1.getSHA1(self.token, timestamp, sNonce, encrypt)
            result = XMLParse.generate(encrypt, signature, timestamp, sNonce)
            return result
        except Exception as e:
            print(e)
            throw_exception("[WXBizMsgCrypt] EncryptMsg Error")

    def DecryptMsg(self, sPostData, sMsgSignature, sTimeStamp, sNonce):
        """检验消息的真实性，并且获取解密后的明文
        @param sMsgSignature: 签名串，对应URL参数的msg_signature
        @param sTimeStamp: 时间戳，对应URL参数的timestamp
        @param sNonce: 随机串，对应URL参数的nonce
        @param sPostData: 密文，对应POST请求的数据
        @return: 解密后的原文
        """
        try:
            encrypt = XMLParse.extract(sPostData)
            signature = SHA1.getSHA1(self.token, sTimeStamp, sNonce, encrypt)
            if signature != sMsgSignature:
                throw_exception("[WXBizMsgCrypt] DecryptMsg Signature Error")
            result = self.pc.decrypt(encrypt, self.corpId)
            return 0, result
        except Exception as e:
            print(e)
            throw_exception("[WXBizMsgCrypt] DecryptMsg Error")
