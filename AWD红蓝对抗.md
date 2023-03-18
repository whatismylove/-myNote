# AWD

## 一、防

备份网站文件
修改数据库默认密码
修改网页登陆端一切弱密码
查看是否留有后门文件及账户
关闭不必要端口，如远程登陆端口
使用命令匹配一句话特性
关注是否运行了“特殊”进程
权限高可以设置防火墙或者禁止他人修改本目录

### 1.备份

<img src="C:\Users\Treaveler\AppData\Roaming\Typora\typora-user-images\image-20221106202253351.png" alt="image-20221106202253351" style="zoom:80%;" />

### 2.基础防护

![image-20221106202609027](C:\Users\Treaveler\AppData\Roaming\Typora\typora-user-images\image-20221106202609027.png)

### 3.WAF

![image-20221106202923438](C:\Users\Treaveler\AppData\Roaming\Typora\typora-user-images\image-20221106202923438.png)

### 4.文件监控

> 自备文件监控脚本（python、shell、php)可以实时监控站点目录是否遭到可疑篡改，或者被挂马，若出现此种情况，立即恢复。  

## 二、攻

1.权限维持

拿到webshell后，当然是要维持权限啦!简单的Webshell一眼就看出来了好伐，在AWD中优先考虑种不死马、反弹shell等留后门方式维持权限，以便后续刷flag，再考虑提升权限。

一个不死马：

![image-20221106203457601](C:\Users\Treaveler\AppData\Roaming\Typora\typora-user-images\image-20221106203457601.png)