#!/usr/bin/env python
#coding=utf-8

"""
This is a auto ssh-login script that also can store your password encryptly.
Usage:
./login.py [--add] [--ency] [--decy] [--mod] [--modkey]
  --add                添加帐号
  --ency               加密密码，配置文件密码为密文，回车后输入 all 或 tip name 列表
  --decy               解密密码，配置文件密码为明文，回车后输入 all 或 tip name 列表
  --mod                修改密码，回车后输入 all 或 tip name 列表
  --modkey             修改key，回车后输入 all 或 tip name 列表

Example:
1. 添加
./login.py --add
  > input new user@ip: root@10.121.123.123
  > input new password: 123
  > input new tip name: testtip
  > input new key: mykey
  > input new notice: test string
2. 登录
./login.py
  > input tip name: testtip
  > input key: mykey
3. 加密
./login.py --ency
  > input tip name: all  # 说明：这里 all 代表加密配置文件里的密码（自动排除已加密），或者 可以为 tip_name 列表
4. 解密
./login.py --decy
  > input tip name: testtip
  > input key: mykey
"""

import pexpect
import os
import termios
import struct
import fcntl
import sys
import getopt
import readline
import json
import base64
import re
import shutil
from Crypto.Cipher import AES
from datetime import datetime

g_LoginFileName = 'login.conf'
g_EncryptData = 'supercalifragilisticexpiadocious'


def exit_with_usage():
    print globals()['__doc__']
    os._exit(1)

def _getLoginInfoFromJson():
    data = {}
    if os.path.exists(g_LoginFileName) == False:
        return data
    with open(g_LoginFileName, 'r') as f:
        data = json.load(f)
    return data

def _storeLoginInfoToFile(data, isoverload=False):
    now = datetime.now()
    if os.path.exists(g_LoginFileName):
        shutil.copyfile(g_LoginFileName, g_LoginFileName + '.' + str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute))
    old_data = _getLoginInfoFromJson()
    with open(g_LoginFileName, 'w') as f:
        try:
            for i in old_data:
                if i in data.keys() and isoverload == True:
                    continue
                elif i not in data.keys():
                    data[i] = old_data[i]
            f.write(json.dumps(data, skipkeys=True, encoding = "utf-8", indent = 4))
        except Exception as e:
            f.write(json.dumps(old_data, skipkeys=True, encoding = "utf-8", indent = 4))
            print str(e)
     
def getLoginInfo():
    return _getLoginInfoFromJson()

def saveLoginInfo(data, isoverload=False):
    _storeLoginInfoToFile(data, isoverload)

def getLoginByMsg(msg='default'):
    data = getLoginInfo()
    info = {}
    info = data[msg]
    return info


def getAllDecryptLoginInfo():
    data = getLoginInfo()
    ret = {}
    for i in data:
        if 'HasEncrypt' in data[i].keys() and data[i]['HasEncrypt'].upper().startswith('T'):
            continue
        else:
            ret[i] = data[i]
    return ret

def getAllEncryptLoginInfo():
    data = getLoginInfo()
    ret = {}
    for i in data:
        if 'HasEncrypt' in data[i].keys() and data[i]['HasEncrypt'].upper().startswith('T'):
            ret[i] = data[i]
    return ret

def desEncrypt(key, passwd):
    length = 16
    count = passwd.count('')
    if count <= length:
        add = length - count + 1
    else:
        add = length - (count % length) + 1
    text = passwd + (' '*add)
    newkey = key.join(g_EncryptData)[0:32]
    mode=AES.MODE_CBC
    encryptor = AES.new(newkey, mode)
    ciphertext = encryptor.encrypt(text)
    return base64.b64encode(ciphertext)

def desDecrypt(key, passwd):
    mode=AES.MODE_CBC
    newkey = key.join(g_EncryptData)[0:32]
    text = base64.b64decode(passwd)
    decryptor = AES.new(newkey, mode)
    ciphertext = decryptor.decrypt(text)
    return ciphertext.strip()

def encryptPasswd(key, tip):
    login = {}
    if tip != 'all':
       login[tip] = getLoginByMsg(tip)
    else:
       login = getAllDecryptLoginInfo()
    for i in login:
       login[i]['Password'] = desEncrypt(key, login[i]['Password'])
       login[i]['HasEncrypt'] = 'True'
    return login

def decryptPasswd(key, tip):
   login = {}
   if tip != 'all':
       login[tip] = getLoginByMsg(tip)
   else:
       login = getAllEncryptLoginInfo()
   for i in login:
       login[i]['Password'] = desDecrypt(key, login[i]['Password'])
       login[i]['HasEncrypt'] = 'False'
   return login

def completer(text, state):
    data = getLoginInfo()
    options = [x for x in data if x.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None

def getwinsize():
    """This returns the window size of the child tty.
    The return value is a tuple of (rows, cols).
    """
    if 'TIOCGWINSZ' in dir(termios):
        TIOCGWINSZ = termios.TIOCGWINSZ
    else:
        TIOCGWINSZ = 1074295912L # Assume
    s = struct.pack('HHHH', 0, 0, 0, 0)
    x = fcntl.ioctl(sys.stdout.fileno(), TIOCGWINSZ, s)
    return struct.unpack('HHHH', x)[0:2]

def ssh_login(hostname, password):
    try:
        ssh = pexpect.spawn('ssh %s' % (hostname))
        winsize = getwinsize();
        ssh.setwinsize(winsize[0],winsize[1])
        i = ssh.expect(['[pP]assword', 'continue connecting (yes/no)?'], timeout=3)
        if i == 0:
            ssh.sendline(password)
        elif i == 1:
            ssh.sendline('yes')
            ssh.sendline(password)
        print 'connect success!'
        print '======================'
        ssh.interact()
    except pexpect.EOF:
        print "pexpect EOF error"
    except pexpect.TIMEOUT:
        print 'connection TIMEOUT'
    except Exception as e:
        pass
    finally:
        ssh.close()

def input(msg):
    while(True):
        try:
            res = raw_input(msg)
            if res:
                break
        except Exception as e:
            continue
    return res

def inputTipNameWithCheck(data): 
    while(True):
       try:
           tiplist = raw_input("> input tip name: ")
           if tiplist == 'all':
               tips = getLoginInfo().keys()
           else:
               tips = tiplist.split()
           tip_exist = [x for x in tips if data and x in data]
           tip_noexist = [x for x in tips if data and x not in data]
           if tip_exist and (tiplist == 'all' or not tip_noexist):
               break
           else:
               print 'Error: tip', tip_noexist,'not invalid!'
       except Exception as e:
           continue
    print 'Effect tip: ', tip_exist
    return tip_exist

def inputTipNameWithCheckExist():
    data = getLoginInfo()
    return inputTipNameWithCheck(data)
    
def inputTipNameWithCheckEncrypt():
    data = getAllEncryptLoginInfo()
    return inputTipNameWithCheck(data)

def inputTipNameWithCheckDecrypt():
    data = getAllDecryptLoginInfo()
    return inputTipNameWithCheck(data)

def inputTipName():
    while(True):
      try:
          tip = raw_input("> input tip name: ")
          if not tip:
              break
      except Exception as e:
          continue
    return tip

def ency(args):
    tips = inputTipNameWithCheckDecrypt()
    login = {}
    key = input('> input key: ')
    for i in range(len(tips)):
        login.update(encryptPasswd(key, tips[i]))
    saveLoginInfo(login)

def decy(args):
    tips = inputTipNameWithCheckEncrypt()
    key = input('> input key: ')
    login = {}
    for i in range(len(tips)):
        login.update(decryptPasswd(key, tips[i]))
    saveLoginInfo(login)

def add(args):
    host = input('> input new user@ip: ')
    passwd = input('> input new password: ')
    tip = input('> input new tip name: ')
    key = input('> input new key: ')
    notice = input('> input new notice: ')
    login = {}
    temp = {}

    temp['Password'] = desEncrypt(key, passwd)
    temp['Notice'] = notice
    temp['HasEncrypt'] = 'True' 
    temp['Hostname'] = host

    login[tip] = temp
    saveLoginInfo(login)
        

def modKey(args):
    old_key = input('> input old key: ')
    new_key = input('> input new key: ') 
    tips = inputTipNameWithCheckEncrypt()
    login = {}
    for i in range(len(tips)):
        tip = tips[i]
        login.update(decryptPasswd(old_key, tip))
        login[tip]['Password'] = desEncrypt(new_key, login[tip]['Password'])
        login[tip]['HasEncrypt'] = 'True'
    saveLoginInfo(login)

def modPasswd(args):
    key = input('> input key: ') 
    new_passwd = input('> input new password: ')
    tips = inputTipNameWithCheckExist()
    ency = getAllEncryptLoginInfo()
    tips_ency =  [x for x in tips if x in ency.keys()]
    tips_decy =  [x for x in tips if x not in ency.keys()]
    login = {}

    for i in range(len(tips_ency)):
        tip = tips_ency[i]
        login.update(decryptPasswd(key, tip))
        login[tip]['Password'] = desEncrypt(key, new_passwd)
        login[tip]['HasEncrypt'] = 'True'
    for i in range(len(tips_decy)):
        tip = tips_decy[i]
        login.update(getLoginInfoByMsg(tip))
        login[tip]['Password'] = new_passwd
    saveLoginInfo(login)

def loginCommand(args):
    tips = inputTipNameWithCheckExist()
    key = input('> input key: ')
    tip = tips[0]

    ency = getAllEncryptLoginInfo()
    if tip in ency.keys(): 
        login = decryptPasswd(key,tip)
    else:
        login = getAllDecryptLoginInfo()
 
    password = login[tip]['Password']
    hostname = login[tip]['Hostname'] 

    print 'ssh ' + hostname + '...' + password
 
    ssh_login(hostname, password)

    
command = {'--ency':ency, '--decy': decy, '--add': add, '--mod':modPasswd, '--modkey':modKey}

if __name__ == '__main__':
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")

    try:
        optlist, args = getopt.getopt(sys.argv[1:], '', ['ency','decy','add', 'mod','modkey'])
    except Exception, e:
        print str(e)
        exit_with_usage() 

    if (not optlist or optlist and '--add' not in optlist[0]) and os.path.exists(g_LoginFileName) == False:
        print 'ERROR: ' + g_LoginFileName + ' not exist. 请先使用 --add 新增帐号'
        exit_with_usage()

    if optlist:
        command[optlist[0][0]](args)
    else:
        loginCommand(args) 

