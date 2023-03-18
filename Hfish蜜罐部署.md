# Hfish蜜罐部署

HFish是一款基于 Golang 开发的跨平台多功能主动诱导型开源国产蜜罐框架系统，为了企业安全防护做出了精心的打造，全程记录黑客攻击手段，实现防护自主化。

## Hfish蜜罐的特点：

1. 多功能 不仅仅支持 HTTP(S) 蜜罐，还支持 SSH、SFTP、Redis、Mysql、FTP、Telnet、暗网 等；
2. 扩展性 提供 API 接口，使用者可以随意扩展蜜罐模块 ( WEB、PC、APP)
3. 便捷性 使用 Golang + SQLite 开发，使用者可以在 Win + Mac + Linux 上快速部署一套蜜罐平台。

## 部署

拉取镜像：

docker pull imdevops/hfish 

启动镜像：

docker run -d --name hfish -p 21:21 -p 22:22 -p 23:23 -p 69:69 -p 3306:3306 -p 5900:5900 -p 6379:6379 -p 8080:8080 -p 8081:8081 -p 8989:8989 -p 9000:9000 -p 9001:9001 -p 9200:9200 -p 11211:11211 --restart=always imdevops/hfish:latest



若端口报错：

netstat -tanlp

kill pid 关闭进程

192.168.43.243:9000 web地址

192.168.43.243:9001 后台地址账号密码admin



ssh蜜罐测试

ssh root@192.168.43.243

hydra -L username.txt -P passwd.txt -t 2 -vV -e ns 192.168.43.243 ssh（九头蛇）

ftp 蜜罐测试

ftp 192.168.43.243

mysql 蜜罐测试

mysql -u root -p -h 192.168.43.243

web蜜罐

192.168.43.243:9000





172.16.12.130