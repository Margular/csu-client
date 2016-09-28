#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib.request
import urllib.parse
import argparse
import platform
import os
import re
import sys
import getpass

def RSAEncryption(n , d , m):   #n->Modulus , d->Public Exponent , m->Message
    message = ""
    for each in m:
        message = hex(ord(each)).split('0x')[1] + message
    message = int(message , 16)
    return hex(message**d % n).split('0x')[1]

def login():
    data = {'accountID' : username + "@zndx.inter" , 
            'password' : RSAEncryption(n , d , password) ,
            'brasAddress' : '59df7586' ,
            'userIntranetAddress' : ip}
    # 取得cookie
    response = urllib.request.urlopen('http://61.137.86.87:8080/portalNat444/AccessServices/bas.59df7586?wlanuserip=%s' % ip)
    cookie = response.headers.get('Set-Cookie')
    # 登录
    data_urlencode = urllib.parse.urlencode(data)
    req = urllib.request.Request('http://61.137.86.87:8080/portalNat444/AccessServices/login' , data_urlencode.encode() , headers = {'Referer' : 'http://61.137.86.87:8080/portalNat444/index.jsp' , 'Cookie' : cookie})
    data = eval(urllib.request.urlopen(req).read().decode())

    if data['resultCode'] == '0':
        print('登录成功!')
        # 取得帐号信息
        req = urllib.request.Request('http://61.137.86.87:8080/portalNat444/main2.jsp' , headers = {'Cookie' : cookie})
        html = urllib.request.urlopen(req).read().decode()
        print(re.findall(r'(尊敬的.+用户，您本月截止至.+为止，宽带业务使用情况如下:)' , html)[0])
        print(re.findall(r'(您的账户本月总流量\(公网\):.+MB)' , html)[0])
        print(re.findall(r'(您的账户本月已用流量\(公网\):.+MB)' , html)[0])
        print(re.findall(r'(您的账户本月剩余流量\(公网\):.+MB)' , html)[0])
        print(re.findall(r'(您的账户本月已用流量（校园网\):.+MB)' , html)[0])
        print(re.findall(r'(您宽带账户当前剩余金额:.+元)' , html)[0])
    elif data['resultCode'] == '1':
        if data['resultDescribe'] == None or data['resultDescribe'] == '':
            print('其他原因认证拒绝')
        else:
            print(data['resultDescribe'])
    elif data['resultCode'] == '2':
        print('用户连接已存在')
    elif data['resultCode'] == '3':
        print('接入服务器繁忙, 稍后重试')
    elif data['resultCode'] == '4':
        print('未知错误')
    elif data['resultCode'] == '6':
        print('认证响应超时')
    elif data['resultCode'] == '7':
        print('捕获用户网络地址错误')
    elif data['resultCode'] == '8':
        print('服务器网络连接异常')
    elif data['resultCode'] == '9':
        print('认证服务脚本执行异常')
    elif data['resultCode'] == '10':
        print('校验码错误')
    elif data['resultCode'] == '11':
        print('您的密码相对简单，帐号存在被盗风险，请及时修改成强度高的密码')
    elif data['resultCode'] == '12':
        print('无法获取您的网络地址,请输入任意其它网站从网关处导航至本认证页面')
    elif data['resultCode'] == '13':
        print('无法获取您接入点设备地址，请输入任意其它网站从网关处导航至本认证页面')
    elif data['resultCode'] == '14':
        print('无法获取您套餐信息')
    elif data['resultCode'] == '16':
        print('请输入任意其它网站导航至本认证页面,并按正常PORTAL正常流程认证')
    elif data['resultCode'] == '17':
        print('连接已失效，请输入任意其它网站从网关处导航至本认证页面')
    else:
        print('未知错误')

def logout():
    data = {'brasAddress' : '59df7586' ,
            'userIntranetAddress' : ip}
    data_urlencode = urllib.parse.urlencode(data)
    req = urllib.request.Request('http://61.137.86.87:8080/portalNat444/AccessServices/logout?' , data_urlencode.encode() , headers = {'Referer' : 'http://61.137.86.87:8080/portalNat444/main2.jsp'})
    data = eval(urllib.request.urlopen(req).read().decode())
    if data['resultCode'] == '0':
        print('下线成功')
    elif data['resultCode'] == '1':
        print('服务器拒绝请求')
    elif data['resultCode'] == '2':
        print('下线请求执行失败')
    elif data['resultCode'] == '3':
        print('您已经下线')
    elif data['resultCode'] == '4':
        print('服务器响应超时')
    elif data['resultCode'] == '5':
        print('后台网络连接异常')
    elif data['resultCode'] == '6':
        print('服务脚本执行异常')
    elif data['resultCode'] == '7':
        print('无法获取您的网络地址')
    elif data['resultCode'] == '8':
        print('无法获取您接入点设备地址')
    elif data['resultCode'] == '9':
        print('请输入任意其它网站导航至本认证页面,并按正常PORTAL正常流程认证')
    else:
        print('未知错误')

def get_ip_address():
    if 'Linux' in platform.system() or 'Mac' in platform.system():
        config = os.popen('ifconfig')
    elif 'Windows' in platform.system():
        config = os.popen('ipconfig')
    else:
        print('未知系统,请手动输入IP地址!')
        sys.exit(0)
    config = ''.join(config.readlines())
    if not config:
        print('获取IP失败!试试sudo执行?')
        sys.exit()
    ip = re.findall(r'(10\.96\.(?!127\.255)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9]))' , config)[0][0]
    return ip


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = '跨平台数字中南客户端')
    parser.add_argument('-o' , '--logout' , help = '注销' , action='store_true')
    parser.add_argument('-i' , '--ip' , help = '自定义IP')
    args = parser.parse_args()
    n = 0xa8a02b821d52d3d0ca90620c78474b78435423be99da83cc190ab5cb5b9b922a4c8ba6b251e78429757cf11cde119e1eacff46fa3bf3b43ef68ceb29897b7aa6b5b1359fef6f35f32b748dc109fd3d09f3443a2cc3b73e99579f3d0fe6a96ccf6a48bc40056a6cac327d309b93b1d61d6f6e8f4a42fc9540f34f1c4a2e053445
    d = 0x10001
    ip = args.ip if args.ip else get_ip_address()
    print('获取IP为 : %s' % ip)
    if args.logout:
        print('正在注销...')
        logout()
    else:
        username = input("username:")
        password = getpass.getpass("password:")
        print('正在登录...')
        login()
