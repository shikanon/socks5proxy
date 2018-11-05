# Socks5 Proxy
------

用golang 实现了一个简单的socks5协议来实现代理转发，主要应用场景是給公司内部做VPN登陆，提供内网访问。
(声明：由于采用的是原始的socks5协议，并没有对协议做改造加工，并不一定能防范GFW的主动探测，请勿用于非法用途)

文件结构
```
cryptogram.go       `加密算法`
socks5.go           `socks5协议实现`
server.go           `服务端实现`
client.go           `客户端实现`
cmd/server/main.go  `服务端主启动程序`
cmd/client/main.go  `客户端主启动程`
```


- [SOCKS5协议介绍](./docs/socks5.md)
- [加密算法介绍](./docs/cryptogram.md)
- [软件下载及版本说明](./docs/release.md)



## TODO

* [ * ] 混淆加密
* [ * ] 客户端