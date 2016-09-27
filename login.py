#!/usr/bin/env python
#coding=utf-8

import pexpect
import os
import termios
import struct
import fcntl
import sys
import json


def getLoginByMsg(msg='default'):
    with open('login.conf', 'r') as f:
        data = json.load(f)
        info = {}
        info['Password'] = data[msg]['Password']
        info['Hostname'] = data[msg]['Hostname']
        return info

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
        ssh.sendline(password)
        ssh.setwinsize(winsize[0],winsize[1])
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

if __name__ == '__main__':
    tip = 'default'
    if len(sys.argv) > 1:
        tip = sys.argv[1]
    while(True):
        try:
            login = getLoginByMsg(tip)
            break
        except Exception as e:
            print 'Error: ' + str(e)
            tip = raw_input('continue...input new tip nmae or Ctrl+C to exit?')
            continue

    password = login['Password']
    hostname = login['Hostname']

    print 'ssh ' + hostname + '...'

    ssh_login(hostname, password)
