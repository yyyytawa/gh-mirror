# gh-mirror
一个软件,可以搭建 GitHub 镜像站,支持登录.基于 go 语言编写.

## 功能解析
- [x] 搭建 GitHub 镜像站  
- [x] 可以登录
- [x] 支持多种验证方式
- [x] 域前置(相当于可以拿国内机器搭建,需要 GitHub 源站 IP 没有被直接封禁/干扰)  
- [ ] ~~加速下载~~  

## 注意事项
**请务必认真阅读 `config.toml` 的内容和源码,搭建之后强烈推荐开启验证防止未经授权的访问以及 `Netcraft` 的钓鱼投诉.**  
**本项目不提供任何额外服务,纯个人使用.**  
**请不要在不可信的镜像站上登录,镜像站可以直接获取你和 GitHub 通讯的所有内容.**  
**本项目主要反代干扰最严重的几个域名, camo,objects,githubassets 并未反代.**  

## 已知问题且不会修复
Passkey 登录无法使用.  
下载速度慢.系运营商相关方面直接对相关 IP 限速,无解.  
无法直接下载源码的 ZIP 文件.(自己 git clone 去~)  
源码里面的 `https://github.com` 也会被替换为镜像站的域名  
不支持第三方登录  

## 构建
1. 搭建 GO 的环境  
2. 克隆本项目的源码  
3. 切换到项目目录并输入命令编译  
```bash
go mod tidy
CGO_ENABLED=0 go build
```
如果你想要交叉编译的话请手动指定 `GOOS` 和 `GOARCH`.例如  
```bash
# 构建 Linux ARM64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build
```
4. Enjoy it!  

## 配置
自己看注释吧.  

## 进程守护
### Systemd
```ini
[Unit]
Description=Github Proxy
After=network.target

[Service]
User=nobody # 不建议使用 root 运行,如果出现权限不够自行解决
WorkingDirectory=/opt/gh-proxy # 程序的工作路径
ExecStart=/opt/gh-proxy/github-proxy # 程序本体的路径
Restart=on-failure
Type=simple

[Install]
WantedBy=multi-user.target
```

重载配置: `sudo systemctl daemon-reload`  
启动服务: `sudo systemctl start github-proxy`  
停止服务: `sudo systemctl stop github-proxy`  
开机自启: `sudo systemctl enable github-proxy`  
取消自启: `sudo systemctl disable github-proxy`  

### NSSM
~~官网: [nssm.cc]~~ 不知道为啥我这边打开 503.
第三方替代: https://github.com/fightroad/nssm  
下载之后解压,找到主程序(这边示例为 nssm.exe,如果不是请自行更改).相关命令自带 GUI,按需填写相关信息即可.  
注册服务: `nssm.exe install`  
停止服务: `nssm.exe stop github-proxy`  
启动服务: `nssm.exe start github-proxy`  
移除服务: `nssm.exe remove github-proxy`

**WARNING: NSSM 注册的服务启动依赖于 NSSM 程序,注册服务之后请勿移动/删除 NSSM 程序,会导致 NSSM 注册的服务失效,需要重新注册.**  

其他的自行探究.  

## LICENSE
GPL 3.0