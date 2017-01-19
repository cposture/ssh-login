#!/usr/bin/env python
#coding=utf-8

"""
This is an auto ssh-login script that also can store your password encryptly.
Usage:
  ./login.py [--add] [--ency] [--decy] [--mod] [--modkey] [--show [ency|decy]]
  notice: you can hit tab or input 'tip name' or 'all' keyword to select user

  --add                add user
  --del                delete user
  --show [ency|decy]] show userinfo, when has ency option, show the userinfo but password is invisible
  --ency               encrypt password
  --decy               decrypt password
  --mod                modify password
  --modkey             modify key

Example:
1. Add user
  ./login.py --add
  > input new user@ip: root@10.121.123.123
  > input new password: 123
  > input new tip name: testtip
  > input new key: mykey
  > input new notice: test string
2. Login
  ./login.py
  > input tip name: testtip
  > input key: mykey
3. Encrypt password
  ./login.py --ency
  > input tip name: all  # notice: the keyword 'all' represent all the encrypted password in the configure file
4. Decrypt password
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
import traceback
import getpass
import pprint

__version__ = '1.1.0'

g_login_filename = 'login.conf'
g_encrypt_data = 'supercalifragilisticexpiadocious'
g_debug = False
STYLE = {
        'fore':
        {
            'black'    : 30,   #  black
            'red'      : 31,   #  red
            'green'    : 32,   #  green
            'yellow'   : 33,   #  yellow
            'blue'     : 34,   #  blue
            'purple'   : 35,   #  purple
            'cyan'     : 36,   #  cyan
            'white'    : 37,   #  white
        },

        'back' :
        {
            'black'     : 40,  #  black
            'red'       : 41,  #  red
            'green'     : 42,  #  green
            'yellow'    : 43,  #  yellow
            'blue'      : 44,  #  blue
            'purple'    : 45,  #  purple
            'cyan'      : 46,  #  cyan
            'white'     : 47,  #  white
        },

        'mode' :
        {
            'mormal'    : 0,   #  normal
            'bold'      : 1,   #  bold
            'underline' : 4,   #  underline
            'blink'     : 5,   #  blinking
            'invert'    : 7,   #  reverse
            'hide'      : 8,   #  invisible
        },

        'default' :
        {
            'end' : 0,
        },
}


def UseStyle(string, mode = '', fore = '', back = ''):
    mode  = '{0}'.format(STYLE['mode'][mode] if mode in STYLE['mode'] else '')
    fore  = '{0}'.format(STYLE['fore'][fore] if fore in STYLE['fore'] else '')
    back  = '{0}'.format(STYLE['back'][back] if back in STYLE['back'] else '')
    style = ';'.join([s for s in [mode, fore, back] if s])
    style = '\033[{0}m'.format(style if style else '')
    end   = '\033[{0}m'.format(STYLE['default']['end'] if style else '')
    return '{0}{1}{2}'.format(style, string, end)


def printWarn(text):
    print UseStyle(text, fore = 'yellow')


def printError(text):
    print UseStyle(text, fore = 'red')


def printInfo(text):
    print UseStyle(text, fore = 'green')

def printDebug(text):
    print UseStyle(text, fore = 'cyan')

class ConfError(Exception):
    '''
    raise when the Configure file not exists or format error
    '''
    pass


class TipError(Exception):
    '''
    raise when Tip name not exists
    '''
    pass


def exit_with_usage():
    print globals()['__doc__']
    os._exit(1)


def exit_with_conf_format():
    print '''
    {
        "tip_name":
        {
            "HasEncrypt": "False",
            "Notice": "cgi marchine",
            "Hostname": "root@101.15.0.13",
            "Password": "123456"
        }
    }
    '''
    os._exit(1)


def _getLoginInfoFromJson():
    '''
    raise IOError, ConfError
    '''
    data = {}
    try:
        with open(g_login_filename, 'r') as f:
           data = json.load(f)
    except ValueError:
        raise ConfError('Configure file is empty or format error')
    if not data:
        raise ConfError('Configure file is empty or format error')
    return data


def backupConfFile():
    now = datetime.now()
    shutil.copyfile(g_login_filename, g_login_filename + '.' + str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute))


def _incrementSaveLoginInfoToFile(data, isoverload=True):
    '''
    raise IOError
    Usage: incrementally save data to file
    params:
        data: dict type, the data want to store in file
        isoverload: when false, the key that contained by both data and file will not update to file
    '''
    old_data = {} 
    try:
        #backupConfFile()
        old_data = _getLoginInfoFromJson()
    except IOError:
        pass
    except ConfError:
        pass
    with open(g_login_filename, 'w') as f:
        json_str = ''
        try:
            for i in old_data:
                if i in data.keys() and isoverload == True:
                    continue
                elif i not in data.keys() or isoverload == False:
                    data[i] = old_data[i]
            json_str = json.dumps(data, skipkeys=True, encoding = "ascii", indent = 4)
        except UnicodeDecodeError as e:
            printError('Error: Save ' + g_login_filename + ' failed, maybe key error')
        if json_str:
            f.write(json_str)
        else:
            printError('Error: Save ' + g_login_filename + ' failed, maybe key error')


def _wholeSaveLoginInfoToFile(data, isoverload=True):
    '''
    raise IOError
    Usage: wholely save data to file
    params:
        data: dict type, the data want to store in file
        isoverload: when false, the key that contained by both data and file will not update to file
    '''
    old_data = {}
    try:
        #backupConfFile()
        old_data = _getLoginInfoFromJson()
    except IOError:
        pass
    except ConfError:
        pass
    with open(g_login_filename, 'w') as f:
        json_str = ''
        try:
            for i in data:
                if i in old_data.keys() and isoverload == False:
                    data[i] = old_data[i]
            json_str = json.dumps(data, skipkeys=True, encoding = "ascii", indent = 4)
        except UnicodeDecodeError as e:
            printError('Error: Save ' + g_login_filename + ' failed, maybe key error')
        if json_str:
            f.write(json_str)
        else:
            printError('Error: Save ' + g_login_filename + ' failed, maybe key error')


def wholeSaveLoginInfo(data, isoverload=True):
    _wholeSaveLoginInfoToFile(data, isoverload)


def incrementSaveLoginInfo(data, isoverload=True):
    _incrementSaveLoginInfoToFile(data, isoverload)


def getLoginInfo():
    '''
    return: all userinfo, the ret dict contains tip:userinfo key-value
    '''
    return _getLoginInfoFromJson()


def getLoginInfoByTipName(tipname):
    '''
    raise getLoginInfo, TipError
    return: userinfo dict specified by tip name
    notice: you can use ret['Password'] to get password, but the ret dict don't contain the key of tip name
    '''
    try:
        data = getLoginInfo()
        info = {}
        info = data[tipname]
    except KeyError:
        raise TipError('Tip not exists')
    return info


def getAllDecryptLoginInfo():
    '''
    raise getLoginInfo exception
    return: all decrypt userinfo, the ret dict contains tip:userinfo key-value
    '''
    data = getLoginInfo()
    ret = {}
    for i in data:
        try:
            if data[i]['HasEncrypt'].upper().startswith('T'):
                continue
            else:
                ret[i] = data[i]
        except KeyError as e:
            printWarn('WARNING: ' + str(e))
            continue
    return ret


def getAllEncryptLoginInfo():
    '''
    raise getLoginInfo exception
    return: all encrypt userinfo, the ret dict contains tip:userinfo key-value
    '''
    data = getLoginInfo()
    ret = {}
    for i in data:
        try:
            if data[i]['HasEncrypt'].upper().startswith('T'):
                ret[i] = data[i]
        except KeyError as e:
            printWarn( 'WARNING: ' + str(e))
            continue
    return ret


def desEncrypt(key, passwd):
    length = 16
    count = passwd.count('')
    if count <= length:
        add = length - count + 1
    else:
        add = length - (count % length) + 1
    text = passwd + (' '*add)
    newkey = key.join(g_encrypt_data)[0:32]
    mode=AES.MODE_CBC
    encryptor = AES.new(newkey, mode, b'0000000000000000')
    ciphertext = encryptor.encrypt(text)
    return base64.b64encode(ciphertext)


def desDecrypt(key, passwd):
    mode=AES.MODE_CBC
    newkey = key.join(g_encrypt_data)[0:32]
    text = base64.b64decode(passwd)
    decryptor = AES.new(newkey, mode, b'0000000000000000')
    ciphertext = decryptor.decrypt(text)
    return ciphertext.strip()


def encryptPasswd(key, tip):
    '''
    raise getLoginInfoByTipName, getAllDecryptLoginInfo Exception
    notice: it will check the given tip whether exists, and when the tip name is 'all' keyword, it will encrypt all unencrypted password
    '''
    login = {}
    if tip != 'all':
        login[tip] = getLoginInfoByTipName(tip)
    else:
        login = getAllDecryptLoginInfo()
    for i in login:
        try:
            login[i]['Password'] = desEncrypt(key, login[i]['Password'])
            login[i]['HasEncrypt'] = 'True'
        except KeyError as e:
            printWarn('WARNING: ' + str(e) + ' configure file format error')
            continue
    return login


def decryptPasswd(key, tip):
   '''
   raise getLoginInfoByTipName, getAllDecryptLoginInfo Exception
   notice: it will check the given tip whether exists, and when the tip name is 'all' keyword, it will decrypt all encrypted password
   '''
   login = {}
   if tip != 'all':
       login[tip] = getLoginInfoByTipName(tip)
   else:
       login = getAllEncryptLoginInfo()
   for i in login:
       try:
           login[i]['Password'] = desDecrypt(key, login[i]['Password'])
           login[i]['HasEncrypt'] = 'False'
       except KeyError as e:
            printWarn('WARNING: ' + str(e) + ' configure file format error')
            continue
   return login


def completer(text, state):
    '''
    raise getLoginInfo Exception
    '''
    data = getLoginInfo()
    options = [x for x in data if x.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None


def getwinsize():
    """
    This returns the window size of the child tty.
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
    """
            -------------------  first login   ---------------------     no      --------
            |  input user@ip  | -------------> | ask whether login | --------->  | quit |
            -------------------                ---------------------             --------
        timeeout/   |              success              | yes
     name not known |-----------------------------------|
                    v                                   v
                  --------     over limition   --------------------        ---------
                  | quit | <------------------ |  input password  | -----> | Login |
                  --------                     --------------------        ---------

    """
    try:
        ssh = pexpect.spawn('ssh {0}'.format(hostname))
        winsize = getwinsize();
        while True:
            i = ssh.expect(['(yes/no)', 'failed', '[pP]assword', '[#\$] ', 'not known'], timeout=3)
            if g_debug:
                printDebug(str(i) + ' ssh.before ' + ssh.before + ' ssh.after ' + ssh.after)
            if i == 0:
                ssh.sendline('yes')
            elif i == 2:
                ssh.sendline(password)
            elif i == 3:
                break
            else:
	        printError('connect fail, please check ' + hostname + '...' + password)
                os._exit(1)
        printInfo('connect success!')
        ssh.setwinsize(winsize[0],winsize[1])
        ssh.interact()
    except pexpect.EOF:
        printError( "pexpect EOF error")
    except pexpect.TIMEOUT:
        printError( 'connection TIMEOUT')
    except Exception as e:
        pass
    finally:
        ssh.close()


def inputWithPrompt(msg):
    '''
    a base method to prompt msg and get input string
    '''
    while(True):
        try:
            res = raw_input(msg)
            if res:
                break
        except Exception as e:
            continue
    return res


def inputTipNameWithCheck(data):
    '''
    the return value is the tip name list that exists in given data dict
    '''
    while(True):
       try:
           tiplist = raw_input("> input tip name: ")
           if tiplist == 'all':
               tips = data.keys()
           else:
               tips = tiplist.split()
           tip_exist = [x for x in tips if data and x in data]
           tip_noexist = [x for x in tips if data and x not in data]
           if tip_exist and (tiplist == 'all' or not tip_noexist):
               break
           else:
               printError('Error: tip ' +  str(tip_noexist) + ' not invalid!')
       except Exception as e:
           continue
    printInfo('Effect tip: ' + str(tip_exist))
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


def ency(args):
    try:
        tips = inputTipNameWithCheckDecrypt()
        login = {}
        key = getpass.getpass('> input key: ')
        for tip in enumerate(tips):
            try:
                login.update(encryptPasswd(key, tip[1]))
            except TipError as e:
                printWarn('WARNING: ' + str(e))
        incrementSaveLoginInfo(login)
    except ConfError:
        traceback.print_exc()
        exit_with_conf_format()
    except IOError as e:
        printError('ERROR: ' + str(e))
        traceback.print_exc()


def decy(args):
    try:
        tips = inputTipNameWithCheckEncrypt()
        key = getpass.getpass('> input key: ')
        login = {}
        for tip in enumerate(tips):
            try:
                login.update(decryptPasswd(key, tip[1]))
            except TipError as e:
                printWarn('WARNING: ' + str(e))
        incrementSaveLoginInfo(login)
    except ConfError:
        traceback.print_exc()
        exit_with_conf_format()
    except IOError as e:
        printError( 'ERROR: ' + str(e))
        traceback.print_exc()


def add(args):
    host = inputWithPrompt('> input new user@ip: ')
    passwd = getpass.getpass('> input new password: ')
    tip = inputWithPrompt('> input new tip name: ')
    key = getpass.getpass('> input new key: ')
    notice = inputWithPrompt('> input new notice: ')
    login = {}
    temp = {}
    temp['Password'] = desEncrypt(key, passwd)
    temp['Notice'] = notice
    temp['HasEncrypt'] = 'True'
    temp['Hostname'] = host
    login[tip] = temp
    try:
        incrementSaveLoginInfo(login)
    except IOError as e:
        printError('ERROR: ' + str(e))
        traceback.print_exc()


def modKey(args):
    tips = inputTipNameWithCheckEncrypt()
    old_key = getpass.getpass('> input old key: ')
    new_key = getpass.getpass('> input new key: ')
    login = {}
    try:
        for tip in enumerate(tips):
            try:
                login.update(decryptPasswd(old_key, tip[1]))
                login[tip]['Password'] = desEncrypt(new_key, login[tip]['Password'])
                login[tip]['HasEncrypt'] = 'True'
            except TipError as e:
                printWarn('WARNING: ' + str(e))
                continue
        incrementSaveLoginInfo(login)
    except IOError as e:
        printError('ERROR: ' + str(e))
        traceback.print_exc()
    except ConfError:
        exit_with_conf_format()
        traceback.print_exc()


def modPasswd(args):
    tips = inputTipNameWithCheckExist()
    key = getpass.getpass('> input key: ')
    new_passwd = getpass.getpass('> input new password: ')
    ency = getAllEncryptLoginInfo()
    tips_ency =  [x for x in tips if x in ency.keys()]
    tips_decy =  [x for x in tips if x not in ency.keys()]
    login = {}

    try:
        for i in enumerate(tips_ency):
            try:
                tip = i[1]
                login.update(decryptPasswd(key, tip))
                login[tip]['Password'] = desEncrypt(key, new_passwd)
                login[tip]['HasEncrypt'] = 'True'
            except TipError as e:
                printWarn('WARNING: ' + str(e))
        for tip in tips_decy:
            login[tip] = getLoginInfoByTipName(tip)
            print login
            login[tip]['Password'] = new_passwd
        incrementSaveLoginInfo(login)
    except IOError as e:
        printError('ERROR: ' + str(e))
        traceback.print_exc()
    except ConfError:
        traceback.print_exc()
        exit_with_conf_format()


def delUser(args):
    try:
        tips = inputTipNameWithCheckExist()
        login = getLoginInfo()
        for i in tips:
            try:
                del login[i]
            except TipError as e:
                printWarn('WARNING: ' + str(e))
        wholeSaveLoginInfo(login)
        printInfo('delete ' + str(tips) + 'success!')
    except ConfError:
        traceback.print_exc()
        exit_with_conf_format()
    except IOError as e:
        printError( 'ERROR: ' + str(e))
        traceback.print_exc()


def showUser(args):
    try:
        tips = inputTipNameWithCheckExist()
        login = getLoginInfo()
        for i in tips:
            try:
                printInfo(i+': ')
                if not args or 'ency' in args:
                    login[i]['Password'] = '******'
                elif 'decy' in args and login[i]['HasEncrypt'].upper().startswith('T'):
                    key = getpass.getpass('> input key: ')
                    login[i]['password'] = desDecrypt(key, login[i]['Password'])
                pprint.pprint(login[i], indent=4)
            except KeyError as e:
                printError('Error: ' + str(e))
    except ConfError:
        traceback.print_exc()
        exit_with_conf_format()
    except IOError as e:
        printError( 'ERROR: ' + str(e))
        traceback.print_exc()


def loginCommand(args):
    if 'debug' in args:
        g_debug = True
    tips = inputTipNameWithCheckExist()
    key = getpass.getpass('> input key: ')
    tip = tips[0]
    try:
        ency = getAllEncryptLoginInfo()
        if tip in ency.keys():
            login = decryptPasswd(key,tip)
        else:
            login = getAllDecryptLoginInfo()
        password = login[tip]['Password']
        hostname = login[tip]['Hostname']
        ssh_login(hostname, password)
    except TipError as e:
        printWarn('WARNING: ' + str(e))
    except IOError as e:
        printError('ERROR: ' + str(e))
        traceback.print_exc()
    except ConfError:
        exit_with_conf_format()


command = {'--ency':ency, '--decy': decy, '--add': add, '--mod':modPasswd, '--modkey':modKey, '--del': delUser, '--show': showUser}

if __name__ == '__main__':
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    try:
        # optlist contains (verb, value) key-value, and args contains the left args
        optlist, args = getopt.getopt(sys.argv[1:], '', ['ency','decy','add', 'mod','modkey', 'del', 'show', 'debug'])
    except getopt.GetoptError as e:
        printError('ERROR: ' + str(e))
        exit_with_usage()
    for key, value in optlist:
        # open debug option
        if '--debug' == key:
            g_debug = True
    # patch: when firtly use, the configure file don't exists, to prompt usage
    if (not optlist or optlist and '--add' not in optlist[0]) and os.path.exists(g_login_filename) == False:
        printError('ERROR: ' + g_login_filename + ' not exist. please use --add option to add new user')
        exit_with_usage()
    if optlist and '--debug' !=  optlist[0][0]:
        command[optlist[0][0]](args)
    else:
        loginCommand(args)
