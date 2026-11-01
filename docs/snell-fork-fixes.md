# Snell UDP 与连接池修复分支

本分支基于 sing-box v1.14.4，通过 `go.mod` 的固定版本替换引用
`github.com/mofanxt/sing-snell` 提交 `8e985c41e9f58edf0d68e9280de8d5040adcc784`。
无需本地补丁目录或相邻源码目录即可构建。

## 包含的修复

- `aaf6998`：复用前检测底层连接，丢弃已断开的空闲会话；覆盖 v4/v6 和 obfs。
- `082b10f`：连接池优先复用最近归还的会话，减少取到老旧连接的机会。
- `8e985c4`：v4 客户端与 v5 服务端为 UDP 转发保留完整数据报的读取空间。
  原来的 1162/1402 字节提示会让转发层的缓冲区过小，造成静默截断。
  写入端原有记录长度检查继续生效，超限数据报返回错误；不改变协议格式或 TCP 帧处理。

读取空间采用 `buf.UDPBufferSize`，增加了受影响转发路径的单个包缓冲容量。
这不表示 Snell 能传输任意大小的 UDP 数据报；协议记录上限仍由写入端强制校验。

## 验证

```sh
go test -race github.com/sagernet/sing-snell/...
go test ./protocol/snell
go build -tags with_quic,with_clash_api ./cmd/sing-box
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags with_quic,with_clash_api ./cmd/sing-box
```

依赖中的回归覆盖正向 1000–2000 字节、反向 1200–2000 字节、18000 字节超限报错，以及
FIN/RST 空闲会话恢复和 LIFO。恢复旧 UDP 实现时，正向 1200 字节及反向 1403 字节用例失败。
原依赖版本和 sing-box 实际使用的 sing 版本均运行竞态检查。

本机隔离 sing-box 实例以 SOCKS → Snell v4 → Snell v5 → 阿里 DoH3 路径完成三次
证书验证、ALPN h3、HTTP 200 和 DNS 响应校验。该结果不替代生产环境部署后的验收。
