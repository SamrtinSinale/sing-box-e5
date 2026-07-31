---
icon: material/lan-connect
---

# eBPF

eBPF 入站通过 cgroup socket-address 程序拦截本机产生的 TCP 和 UDP 流量，
不使用 TUN、TProxy、TC、iptables 或 SOCKS 中间层。

此入站用于以 root 权限直接运行 Android 或 Linux 原生 sing-box 二进制的场景。
构建时必须启用 cgo 和 `with_ebpf` 构建标签。

## 结构

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",

  ... // 监听字段

  "network": "",
  "redirect_address": [
    "127.128.0.0/9",
    "fd53:696e:672d:626f::/64"
  ],
  "bypass_rule_set": [
    "geoip-cn"
  ],
  "include_uid": [],
  "include_uid_range": [],
  "exclude_uid": [],
  "exclude_uid_range": []
}
```

### 监听字段

参阅[监听字段](/zh/configuration/shared/listen/)了解可用字段。

eBPF 入站在内部使用从 `redirect_address` 中选取的地址。因此，`listen`
可以省略或设为未指定地址（`0.0.0.0` 或 `::`）。入站会根据
`redirect_address` 启用的地址族创建 IPv4 和/或 IPv6 通配 listener。

`listen_port` 默认为 `65532`。值为 `0` 时同样使用此默认值；不支持随机监听
端口，因为加载 eBPF 程序时会把重定向端口写入程序。

不支持 `proxy_protocol` 和 `proxy_protocol_accept_no_header`，因为被拦截的应用
连接不包含 Proxy Protocol 头。

不支持 `netns`。cgroup hook 和重定向路由作用于当前网络命名空间，无法限定到
监听字段指定的网络命名空间。

`bind_interface` 可以省略或设为 `lo`。不支持其他接口，因为重定向连接通过
loopback 接口交付。

配置的 `udp_timeout` 和 `detour` 会像其他 UDP 入站一样作用于被拦截的 UDP 会话。

### 字段

#### network

监听的网络协议，`tcp` `udp` 之一。

默认所有。

未被 `network` 选中的协议会绕过 eBPF 入站。

#### include_uid

需要拦截的进程 UID 列表。

当 `include_uid` 或 `include_uid_range` 非空时，未被这两个字段匹配的 UID
产生的流量会绕过 eBPF 入站。

#### include_uid_range

需要拦截的进程 UID 范围列表，格式为 `start:end`。

#### exclude_uid

需要绕过的进程 UID 列表。

exclude 规则的优先级高于 include 规则。

#### exclude_uid_range

需要绕过的进程 UID 范围列表，格式为 `start:end`。

UID 规则匹配执行 socket 操作的进程有效 UID。UID 范围会被压缩为 eBPF LPM
trie 条目，不会展开为逐 UID 条目。

#### bypass_rule_set

目标 IP CIDR 条目需要绕过 eBPF 入站的规则集列表。

启动时，sing-box 调用现有的规则集 CIDR 提取接口，将结果合并到 IPv4 和 IPv6
eBPF LPM trie map。目标地址命中任一 map 时，cgroup 程序保持原始目标不变；
应用 socket 直接使用内核网络栈，不会进入 eBPF listener、嗅探、普通路由规则
或出站。

此字段执行的是 CIDR 提取，并不执行完整规则集匹配。仅提取目标 `ip_cidr` 和
二进制 IP set 条目；eBPF 程序不会判断域名、端口、网络、进程、来源、逻辑分组
或反选条件。特别是，当 `ip_cidr` 与其他条件组合时，CIDR 仍会被单独提取，
其他条件不会保留。因此，此字段应只引用纯 CIDR 规则集。

多个规则集及其中提取出的所有 CIDR 按并集合并。选择 `direct` 出站的普通
路由规则不会自动下沉；只有此处显式列出的规则集会启用内核直连绕过。

引用的本地或远程规则集重新加载后，sing-box 会再次提取 CIDR 并原地更新 map，
无需重新加载或挂载 eBPF 程序。若更新无法应用，会记录错误并保留上一次成功
应用的策略。

此绕过只作用于经过 cgroup socket-address hook 的本机流量。Android 热点的
转发流量不经过这些 hook。

#### redirect_address

将被拦截连接重定向到 sing-box listener 时使用的内部地址前缀。

每个地址族最多配置一个前缀。配置 IPv4 前缀会启用 IPv4 拦截，配置 IPv6
前缀会启用原生 IPv6 拦截，同时配置两者则启用双栈拦截。IPv4-mapped IPv6
socket 按 IPv4 处理。

省略时使用 `127.128.0.0/9`，且仅启用 IPv4 拦截。目前 IPv4 前缀必须在
`/8` 到 `/10` 之间，IPv6 前缀必须为 `/64`。

这些前缀是流量令牌地址池，并不是 TUN 入站所使用的接口子网。无连接 UDP 根据
原始地址、端口和协议确定性生成稳定的主机令牌，发往同一目的地的后续数据包会
复用已有 map 条目。TCP 和已连接 UDP 还会把 socket `SO_COOKIE` 混入令牌，避免
发往同一目的地的并发 socket 错误共享生命周期状态。

redirect map 不会淘汰或覆盖已有条目。令牌冲突时最多执行四次确定性探测；map
容量耗尽时会拒绝新流量，而不会将其错误路由到其他目的地。较大的前缀可使热路径
通常只需一次探测。默认值使用 IPv4 回环范围中较少被显式使用的后半段，同时保留
23 位令牌空间；IPv6 示例使用 sing-box 专用的 ULA 前缀。自定义前缀不得与设备
需要访问的任何目的网络重叠。

redirect 条目会按照实际所有者回收。TCP listener 读取原始目的地址后立即删除对应
条目；无连接 UDP 条目在 sing-box UDP NAT 会话之间进行引用计数，并在最后一个
会话关闭时删除；已连接 UDP 以 socket cookie 保存 redirect 令牌，并在应用 socket
关闭时由 cgroup socket-release 程序删除 redirect、令牌和 peer cache 条目。UDP
socket 重新 connect 时，也会先删除此前的已连接映射再安装新映射。

sing-box 会在当前网络命名空间中，通过 loopback 接口为每个配置前缀自动添加
`RTN_LOCAL` 路由。若已有本地路由能够覆盖该前缀则直接复用；关闭时只删除由
当前入站创建的路由。

除 `bypass_rule_set` 外，配置不包含私网、网卡或 DNS 策略。sing-box 从
`/proc/self/mountinfo` 自动找到 cgroup2 根挂载点，并在该层拦截本机应用
流量；回环流量始终保持本地直连。

同一 cgroup 层级同时只能由一个 eBPF 入站管理。sing-box 会在入站生命周期内
独占锁定 cgroup2 根目录。只有成功取得该锁后，才会清理由异常退出遗留的
sing-box eBPF 程序，因此启动第二个实例不会卸载仍在运行的实例所挂载的程序。

sing-box 会把自身创建的 socket 的 `SO_COOKIE` 登记到 eBPF LRU map。cgroup
程序在重定向前查询此 map，从而避免 sing-box 的出站连接和 UDP listener
再次被捕获。

## 构建

继续使用现有的 `make build` 目标。构建时需要启用 cgo，并在平时使用的
构建标签中追加 `with_ebpf`。例如，在 Linux 上保留 sing-box 标准构建标签：

```sh
CGO_ENABLED=1 \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

为 Android 构建时，在同一个 `make build` 目标上指定目标架构和 Android NDK
编译器：

```sh
CGO_ENABLED=1 \
GOOS=android \
GOARCH=arm64 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang" \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

设备内核必须提供 cgroup2，以及配置的地址族和 `network` 所需的 cgroup
attach type：connect4/connect6；启用 UDP 时还需要 UDP4/UDP6 sendmsg、recvmsg
和 `BPF_CGROUP_INET_SOCK_RELEASE`。进程需要创建并挂载 BPF map/program 以及
管理本地路由的权限。

## 鸣谢

感谢 [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
项目提供了本入站所基于的原始 eBPF 流量拦截实现。
