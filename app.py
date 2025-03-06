#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import time
import logging
import requests
from flask import Flask, request, jsonify
from WXBizMsgCrypt import WXBizMsgCrypt
import xml.etree.ElementTree as ET

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__)

# 从环境变量获取配置
CORP_ID = os.environ.get('CORP_ID')
CORP_SECRET = os.environ.get('CORP_SECRET')
TOKEN = os.environ.get('TOKEN')
ENCODING_AES_KEY = os.environ.get('ENCODING_AES_KEY')
AGENT_ID = os.environ.get('AGENT_ID')
SPREADSHEET_ID = os.environ.get('SPREADSHEET_ID')
ADMIN_USERID = os.environ.get('ADMIN_USERID')

# 用于存储临时消息数据的字典
message_data = {}

# 验证配置是否完整
@app.before_first_request
def check_config():
    required_vars = ['CORP_ID', 'CORP_SECRET', 'TOKEN', 'ENCODING_AES_KEY', 'AGENT_ID', 'SPREADSHEET_ID', 'ADMIN_USERID']
    missing_vars = [var for var in required_vars if not globals()[var]]
    
    if missing_vars:
        logger.error(f"缺少必要的环境变量: {', '.join(missing_vars)}")
    else:
        logger.info("所有必要的环境变量已配置")

# 获取企业微信访问令牌
def get_access_token():
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CORP_ID}&corpsecret={CORP_SECRET}"
    response = requests.get(url)
    data = response.json()
    
    if data.get('errcode') == 0:
        return data.get('access_token')
    else:
        logger.error(f"获取access_token失败: {data}")
        return None

# 向智能表格添加一行数据
def add_spreadsheet_row(image_url, price):
    access_token = get_access_token()
    if not access_token:
        return False, "获取访问令牌失败"
    
    url = f"https://qyapi.weixin.qq.com/cgi-bin/wedoc/spreadsheet/append_row?access_token={access_token}"
    
    data = {
        "spreadsheet_id": SPREADSHEET_ID,
        "values": [
            [price, "", image_url]  # 价格, 编码(留空), 图片URL
        ]
    }
    
    response = requests.post(url, json=data)
    result = response.json()
    
    if result.get('errcode') == 0:
        return True, "数据已成功添加到表格"
    else:
        error_msg = f"添加数据失败: {result.get('errmsg')}"
        logger.error(error_msg)
        return False, error_msg

# 向企业微信群发送消息
def send_group_message(chat_id, content):
    access_token = get_access_token()
    if not access_token:
        return False
    
    url = f"https://qyapi.weixin.qq.com/cgi-bin/appchat/send?access_token={access_token}"
    
    data = {
        "chatid": chat_id,
        "msgtype": "text",
        "text": {
            "content": content
        },
        "safe": 0
    }
    
    response = requests.post(url, json=data)
    result = response.json()
    
    if result.get('errcode') == 0:
        return True
    else:
        logger.error(f"发送群消息失败: {result}")
        return False

# 企业微信回调路由
@app.route('/wechat/callback', methods=['GET', 'POST'])
def wechat_callback():
    # 处理企业微信验证请求
    if request.method == 'GET':
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        echostr = request.args.get('echostr')
        
        wxcpt = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORP_ID)
        ret, sEchoStr = wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)
        
        if ret == 0:
            return sEchoStr
        else:
            return "验证失败", 403
    
    # 处理接收到的消息
    elif request.method == 'POST':
        try:
            msg_signature = request.args.get('msg_signature')
            timestamp = request.args.get('timestamp')
            nonce = request.args.get('nonce')
            
            wxcpt = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORP_ID)
            ret, sMsg = wxcpt.DecryptMsg(request.data, msg_signature, timestamp, nonce)
            
            if ret != 0:
                logger.error(f"消息解密失败，错误码: {ret}")
                return "OK"
            
            # 解析XML消息
            xml_tree = ET.fromstring(sMsg)
            msg_type = xml_tree.find('MsgType').text
            from_username = xml_tree.find('FromUserName').text
            chat_id = xml_tree.find('ChatId').text if xml_tree.find('ChatId') is not None else None
            
            # 只处理群聊消息
            if not chat_id:
                return "OK"
            
            # 初始化群聊消息数据存储
            if chat_id not in message_data:
                message_data[chat_id] = {
                    'images': [],
                    'prices': [],
                    'status': 'collecting'  # collecting, ready, processing
                }
            
            # 处理图片消息
            if msg_type == 'image':
                pic_url = xml_tree.find('PicUrl').text
                message_data[chat_id]['images'].append(pic_url)
                logger.info(f"收到图片: {pic_url}")
            
            # 处理文本消息
            elif msg_type == 'text':
                content = xml_tree.find('Content').text
                
                # 处理价格信息（纯数字）
                if content.isdigit():
                    message_data[chat_id]['prices'].append(content)
                    logger.info(f"收到价格: {content}")
                
                # 处理结束标记
                elif content == '#':
                    message_data[chat_id]['status'] = 'ready'
                    logger.info("收到结束标记")
                
                # 处理@管理员触发
                elif f"@{ADMIN_USERID}" in content and message_data[chat_id]['status'] == 'ready':
                    # 修改状态为处理中，防止重复处理
                    message_data[chat_id]['status'] = 'processing'
                    
                    # 确保有足够的数据进行处理
                    if len(message_data[chat_id]['images']) > 0 and len(message_data[chat_id]['prices']) > 0:
                        # 匹配图片和价格
                        success_count = 0
                        fail_count = 0
                        error_msgs = []
                        
                        # 以较短的列表长度为准
                        process_count = min(len(message_data[chat_id]['images']), len(message_data[chat_id]['prices']))
                        
                        for i in range(process_count):
                            image_url = message_data[chat_id]['images'][i]
                            price = message_data[chat_id]['prices'][i]
                            
                            success, msg = add_spreadsheet_row(image_url, price)
                            if success:
                                success_count += 1
                            else:
                                fail_count += 1
                                error_msgs.append(msg)
                        
                        # 发送处理结果消息
                        result_msg = f"处理完成: 成功 {success_count} 条, 失败 {fail_count} 条"
                        if error_msgs:
                            result_msg += f"\n错误信息: {', '.join(error_msgs[:3])}"
                            if len(error_msgs) > 3:
                                result_msg += "..."
                        
                        send_group_message(chat_id, result_msg)
                        
                        # 清空已处理的数据
                        message_data[chat_id] = {
                            'images': [],
                            'prices': [],
                            'status': 'collecting'
                        }
                        
                    else:
                        send_group_message(chat_id, "数据不完整，请确保发送了包包照片和价格")
                        message_data[chat_id]['status'] = 'collecting'
            
            return "OK"
            
        except Exception as e:
            logger.exception(f"处理消息时发生错误: {str(e)}")
            return "OK"

# 健康检查路由
@app.route('/')
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": time.time()
    })

if __name__ == '__main__':
    # 获取端口，如果没有设置则使用默认值5000
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
