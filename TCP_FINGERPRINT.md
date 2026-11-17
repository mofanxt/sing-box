# 实验性 TCP 指纹透传

开发基线为上游 testing 021950077be86ea2c3aa72f1256238f08e9b9944，即用户指定的最新开发主干，不是稳定版。默认关闭，需搭配支持私有扩展的 sing-snell。生产验收及逐机状态由部署方单独记录；本文件说明协议和实现边界。

## 配置入口

- 采集端：`experimental.tcp_fingerprint.capture_interfaces` 指定 Linux 接口列表。
- 两端 Snell v6：`tcp_fingerprint: true` 显式允许私有逐请求扩展；每个中转均需支持。
- 出口：`experimental.tcp_fingerprint` 设置 `rewrite: true`、独占 `queue`（默认19518；同一网络命名空间的其他实例须使用不同编号），最终 direct 出站设置 `tcp_fingerprint: true`。
- 透明 TCP 前端：direct 出站 `fingerprint_proxy_protocol: true` 在原始应用数据前写 PROXY v2 私有0xe0 TLV（v1:前缀+十六进制文本，避免HAProxy格式器截断NUL）；下游监听设置 `fingerprint_proxy_protocol: {"trusted_sources": ["127.0.0.1/32"]}`。仅适用于显式信任的内部跳点，不应公开接收伪造头。原版SS2022客户端不需要更改。

采集只读取 SYN，不解密 TLS；样本按源/目标四元组精确匹配，最多8192条、30秒。元数据最多256种模板，不按来源IP推断设备。现有HAProxy/DNAT链路需要单独完成原始四元组关联和配置生成器集成，不能只开启新字段就宣称接通。

## 内核出口

Linux需CAP_NET_RAW和CAP_NET_ADMIN以及nft工具。仅专用SO_MARK高16位为队列编号（默认0x4c3e）的IPv4 SYN进入独占NFQUEUE；不允许与冲突的routing mark、MPTCP或未经验证的多接口策略混用。保留本连接序列号、时间戳数值并重算校验和；MSS使用该出站内核原值，不继承入口隧道的较小MSS，也绝不超过出口内核值。

启动时用本机回环握手校准SO_RCVBUFFORCE与实际窗口缩放的关系，申请值上限16MiB（Linux内部缓冲计数可能加倍），不修改系统sysctl。找不到匹配缩放、模板容量已满、缺失样本时回退原生行为；实际SYN缩放再次校验，绝不只改报文数字。校准表只在启动时生成；运行中调整相关内核参数可能使样本跳过。

只支持IPv4、无IP选项/分片和受支持TCP选项。采集支持普通或RFC3168 ECN协商SYN；TFO选项及服务器专属cookie在采集阶段移除，保留其余选项。TFO早期数据只允许首部采集，不保存或传递负载；出口任何带负载的SYN都不改写。IPv6、QUIC/HTTP3、完整TCP行为、TLS/JA3/JA4、操作系统判定和风控效果不在承诺范围。本版本使用NFQUEUE，不是eBPF。

正常关闭删除自有nft表，队列fail-open。异常退出可能留下 `inet sbox_tcp_fingerprint_19518` 空闲表；服务再启动拒绝覆盖已有表，需先确认拥有者及残留来源再处理。不得删除其他实例的表或队列。

## 构建与验证

```
go test -race ./common/tcpfingerprint ./protocol/snell ./common/listener ./option
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags with_quic,with_utls,with_clash_api,with_gvisor ./cmd/sing-box
```

完整隔离三跳、SS2022桥接、无元数据回退和UDP回归脚本维护在 my-servers 项目的 scripts/proxy/tcp-fingerprint-lab.py。生产替换前仍须核对目标机完整配置、主备、DNS和独立自动回退。

兼容入口可显式设置 `fingerprint_proxy_protocol.optional: true`：只解析可信来源的PROXY头，不带头的旧连接继续按原协议处理。Linux通过MSG_PEEK检查签名，不提前消费TLS/SS数据；不可信来源提供的伪造头仍不会被信任。默认严格模式要求可信来源和合法转发头。
