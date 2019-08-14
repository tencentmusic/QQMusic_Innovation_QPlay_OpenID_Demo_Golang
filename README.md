该示例代码将演示《QQ音乐OpenID接入指南(暂用名)》中"5 异构设备接入"章节。

### 如何使用

进入到`src`目录，执行如下命令：

>$ go run main.go

运行成功后，将会在终端看到如下输出：

    Auth server

在浏览器里访问：`http://本机局域网或互联网IP:8080`，请注意，如果使用`localhost`或者`127.0.0.1`来替代
`本机局域网或互联网IP`，则会因为手机无法访问该Server，从而引起失败。

在页面打开后，点击"生成二维码"，即可看到二维码图片显示，同时会注意在终端有如下输出：

    response Body: { "msg": "ok", "ret": 0, "sdk_qr_code": "qqmusic:\/\/qq.com\/other\/openid?p=%7B%22appId%22%3A%221%22%2C%22cmd%22%3A%22qrcode%22%2C%22code%22%3A%221PPkDFZyNDakd9r7Dahj6vJStHt%22%7D", "sub_ret": 0 }