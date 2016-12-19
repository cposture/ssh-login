# 1. Feature

1. 管理多个帐号，一键 ssh 登录
2. 密码AES加密，密文存储密码，且只需要记住一个任意长 key，即可解密登录，所有帐号 key 可以相同
3. 随时添加新账号，修改 key、密码 只需要一条指令



# 2. Todo

1.

# 3. Finished

1.

# 4. Installation

## 4.1 依赖模块

```
1. python 2.6
2. Crypto 模块
3. pexpect 模块
```

```
chmod +x login.py
```

# 5. Configuration

> 概念：key 用于 AES 加密密码，初始化加密密码时生成，登录帐号时使用，任意长；tip_name：你帐号的简短小名，登录帐号时使用，任意长，自定义指定于配置文件中

### 5.1 配置文件

```
{
"tip_name": {
            "Hostname" : "root@xx.xx.xx.xx",
            "Password" : "abcd"
           }
}
```

# 6. Usage

特性：可以使用 tab 键进行 tip_name 补全

```
This is a auto ssh-login script that also can store your password encryptly.
Usage:
  ./login.py [--add] [--ency] [--decy] [--mod] [--modkey] [--show] [--del]
  notice: you can hit tab or input 'tip name' or 'all' keyword to select user

  --add                add user
  --del                delete user
  --show               show userinfo
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
```

## 6.1 Example

1. 添加

```
./login.py --add
> input new user@ip: root@10.121.123.123
> input new password: 123
> input new tip name: testtip
> input new key: mykey
> input new notice: test string
```

2. 登录

```
./login.py
> input tip name: testtip
> input key: mykey
```

3. 加密

```
./login.py --ency
> input tip name: all  # 说明：这里 all 代表加密配置文件里的密码（自动排除已加密），或者 可以为 tip_name 列表
```

4. 解密

```
./login.py --decy
> input tip name: testtip
> input key: mykey
```
