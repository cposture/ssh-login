# 1. Feature

1. 管理多个帐号，一键 ssh 登录
2. 密码加密，且只需要记住一个任意长 key，即可解密登录，所有帐号 key 可以相同
3. 随时添加新账号，修改 key 只需要一条指令

# 2. Todo

1. 密码 AES 加密逻辑
2. 配置文件密码加密

# 3. Finished

1. ssh 登录功能
2. 配置文件读取功能

# 4. Installation

```
chmod +x login.py
```

# 5. Configuration

> 概念：key 用于 AES 加密密码，初始化加密密码时生成，登录帐号时使用，任意长；tip_msg：你帐号的简短小名，登录帐号时使用，任意长，自定义指定于配置文件中

### 5.1 配置文件

```
{
"tip_msg": {
            "Hostname" : "root@xx.xx.xx.xx",
            "Password" : "abcd"
           }
}
```

### 5.2 初始化加密配置文件的密码


* 部分加密

```
// 使用 your_key 加密指定的 tip_msg_1 tip_msg_2 密码
./login.py init tip_msg_1 [tip_msg_2...] your_key
```

* 所有加密

```
// 使用 your_key 加密所有的 tip_msg 密码
./login.py inti your_key
```

### 5.3 修改指定帐号的key

```
./login.py mod tip_msg old_key new_key
```

# 6. Usage

### 6.1 新增帐号

在配置文件中，新增帐号，添加主机名和对应的登录密码

```
{
"tip_test": {
            "Hostname" : "root@192.168.1.1",
            "Password" : "abcdefg"
           }
}
```

### 6.2 加密密码

加密后，要记住自己的 key，所有帐号都可以用统一的key

```
./login.py init tip_test key_test
```

### 6.3 登录指定的帐号

```
./login.py tip_test key_test
```
