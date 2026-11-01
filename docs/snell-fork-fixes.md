# Snell 修复版（v1.14.4-mofanxt.1）

本分支基于 sing-box v1.14.4，只修改 `go.mod`/`go.sum`，用固定版本替换引用
`github.com/mofanxt/sing-snell` 的 main 分支提交 `88716887dc7a`，不改动 sing-box 本身的代码。
该提交合并了下列修复，每组都已向上游 SagerNet/sing-snell 提交独立 PR。

| 上游 PR | 修复 |
| --- | --- |
| [#9](https://github.com/SagerNet/sing-snell/pull/9) | 复用前探测空闲会话的底层连接，丢弃被 FIN/RST 的死会话；连接池改为优先复用最近归还的会话 |
| [#10](https://github.com/SagerNet/sing-snell/pull/10) | v4 客户端/v5 服务端 UDP：读缓冲不再截断超过 1162/1402 字节的数据报（QUIC/HTTP/3），低内存构建同样覆盖；UDP 包不再受 TCP 分帧窗口限制，空闲后的大包不会中断会话；批量写入在加密前校验整批长度 |
| [#11](https://github.com/SagerNet/sing-snell/pull/11) | 复用连接关闭后的迟到写入返回错误，不再写进已归还或被下一条连接使用的会话；修复 writer 数据竞争；阻塞写入时 `Close` 不再卡住 |
| [#12](https://github.com/SagerNet/sing-snell/pull/12) | v5/v6 服务端丢弃域名源地址的 UDP 回包，不再中断整个 UDP 会话 |
| [#13](https://github.com/SagerNet/sing-snell/pull/13) | 客户端 TCP 流未收到 zero chunk 即断开时报 `io.ErrUnexpectedEOF`，复用模式不再把死会话放回池；所有 reader 在记录中途断开时报异常 EOF |

写入端仍按协议上限拒绝超限 UDP 包；协议格式不变。UDP 复制路径的单包读缓冲变大（Linux 64 包批量约 2 MiB/方向），
与 sing 对未声明 MTU 的写入端的默认分配一致。

## 验证

```sh
go build -tags with_quic,with_clash_api ./cmd/sing-box
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags "$(cat release/DEFAULT_BUILD_TAGS),with_purego" ./cmd/sing-box
```

sing-snell 侧：新增回归测试在未修复的上游 main 上均失败；`make lint` 四平台 0 问题；Go 1.25/1.26/1.27 的 `-race`
测试通过（含 `with_low_memory`）；与官方 snell-server v6.0.0rc（amd64）及 v4.1.1、v5.0.1（linux-aarch64 官方构建）的
Docker 互通测试全部通过。两轮独立代码审查的最终结论为无需修复。
