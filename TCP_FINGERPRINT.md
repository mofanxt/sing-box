# 实验性 TCP 指纹透传

开发基线为上游 testing 021950077be86ea2c3aa72f1256238f08e9b9944，即用户指定的最新开发主干，不是稳定版。默认关闭，需搭配支持私有扩展的 sing-snell。生产验收及逐机状态由部署方单独记录；本文件说明协议和实现边界。

## 配置入口

- 采集端：`experimental.tcp_fingerprint.capture_interfaces` 指定 Linux 接口列表。
- 两端 Snell v6：`tcp_fingerprint: true` 显式允许私有逐请求扩展；每个中转均需支持。启用时须使用 default 或 unshaped 加密模式。
- 出口：`experimental.tcp_fingerprint` 设置 `rewrite: true`、独占 `queue`（默认19518；同一网络命名空间的其他实例须使用不同编号），最终 direct 出站设置 `tcp_fingerprint: true`。
- 透明 TCP 前端：direct 出站 `fingerprint_proxy_protocol: true` 在原始应用数据前写 PROXY v2 私有0xe0 TLV（v1:前缀+十六进制文本，避免HAProxy格式器截断NUL）；下游监听设置 `fingerprint_proxy_protocol: {"trusted_sources": ["127.0.0.1/32"]}`。仅适用于显式信任的内部跳点，不应公开接收伪造头。原版SS2022客户端不需要更改。

启用扩展的 Snell v6 入站只采用每条逻辑请求携带的样本。普通客户端也能连接该端口，缺少样本时使用原生出口。关闭扩展的客户端直连入口继续采用物理连接样本。内部 PROXY v2 支持同地址族的 IPv4 和 IPv6 端点，IPv6 仅透传地址和端口。

采集只读取 SYN，不解密 TLS；样本按源/目标四元组精确匹配，最多8192条、30秒。出口同时握手最多使用256种模板，相同模板共享引用，入口MSS不参与去重，拨号结束后释放槽位，不按来源IP推断设备。现有HAProxy/DNAT链路需要单独完成原始四元组关联和配置生成器集成，不能只开启新字段就宣称接通。

## 内核出口

Linux需CAP_NET_RAW和CAP_NET_ADMIN以及nft工具。仅专用SO_MARK高16位为队列编号（默认0x4c3e）的IPv4 SYN进入独占NFQUEUE；不允许与冲突的routing mark、MPTCP或未经验证的多接口策略混用。保留本连接序列号、时间戳数值并重算校验和；MSS使用该出站内核原值，不继承入口隧道的较小MSS，也绝不超过出口内核值。

出口保留内核接收缓冲自动调优。存在 WS 选项时，使用逐 socket 的 TCP_WINDOW_CLAMP 将通告窗口限制在该缩放能表示的最大值，保留 socket 上已有的更小限制。内核仍决定实际缩放。该 socket 设置会优先于 Linux 路由的 window 指标，需要依赖特定路由窗口限制的流量应使用普通 direct 出站。实际 SYN 缩放与样本不一致、模板已满或缺少样本时使用原生 SYN。路由规则为该 TCP 出站指定多接口策略时，拨号返回配置冲突。

只支持IPv4、无IP选项/分片和受支持TCP选项。采集支持普通或RFC3168 ECN协商SYN；TFO选项及服务器专属cookie在采集阶段移除，保留其余选项。TFO早期数据只允许首部采集，不保存或传递负载；出口任何带负载的SYN都不改写。IPv6、QUIC/HTTP3、完整TCP行为、TLS/JA3/JA4、操作系统判定和风控效果不在承诺范围。本版本使用NFQUEUE，不是eBPF。

正常关闭删除自有nft表，队列fail-open。异常退出后，新进程先独占同一 NFQUEUE，再核对残留表的完整规则。规则与受管布局一致时继续使用，出现额外对象或不同规则时停止。

## 构建与验证

```
go test -race ./common/tcpfingerprint ./protocol/snell ./common/listener ./option
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags with_quic,with_utls,with_clash_api,with_gvisor ./cmd/sing-box
```

完整隔离三跳、SS2022桥接、无元数据回退和UDP回归脚本维护在 my-servers 项目的 scripts/proxy/tcp-fingerprint-lab.py。生产替换前仍须核对目标机完整配置、主备、DNS和独立自动回退。

兼容入口可显式设置 `fingerprint_proxy_protocol.optional: true`：只解析可信来源的PROXY头，首字节等待三秒仍无数据时交给旧协议，已收到部分签名时另给三秒完成签名。Linux通过MSG_PEEK检查签名，不提前消费TLS/SS数据；不可信来源提供的伪造头仍不会被信任。默认严格模式要求可信来源和合法转发头。由 WebSocket 等 transport 自行接管 TCP 监听时，启动会拒绝配置这些依赖逐连接接收处理的选项。PROXY 转发出站只声明 TCP 能力。
