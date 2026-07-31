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

#### redirect_address

将被拦截连接重定向到 sing-box listener 时使用的内部地址前缀。

每个地址族最多配置一个前缀。配置 IPv4 前缀会启用 IPv4 拦截，配置 IPv6
前缀会启用原生 IPv6 拦截，同时配置两者则启用双栈拦截。IPv4-mapped IPv6
socket 按 IPv4 处理。

省略时使用 `127.128.0.0/9`，且仅启用 IPv4 拦截。目前 IPv4 前缀必须在
`/8` 到 `/10` 之间，IPv6 前缀必须为 `/64`。

这些前缀是流量令牌地址池，并不是 TUN 入站所使用的接口子网。eBPF 程序会为
每个被拦截的流随机选择一个主机地址，并通过该地址还原原始目的地。因此地址池
必须足够大，以降低并发流量选中相同令牌的概率。默认值使用 IPv4 回环范围中较少
被显式使用的后半段，同时保留 23 位令牌空间；IPv6 示例使用 sing-box 专用的
ULA 前缀。自定义前缀不得与设备需要访问的任何目的网络重叠。

sing-box 会在 `netns` 选定的网络命名空间中，通过 loopback 接口为每个配置
前缀自动添加 `RTN_LOCAL` 路由。若已有本地路由能够覆盖该前缀则直接复用；
关闭时只删除由当前入站创建的路由。

配置不包含 CIDR、私网、网卡或 DNS 策略。sing-box 从
`/proc/self/mountinfo` 自动找到 cgroup2 根挂载点，并在该层拦截本机应用流量；
回环流量保持本地直连。

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
attach type：connect4/connect6；启用 UDP 时还需要 UDP4/UDP6 sendmsg 和
recvmsg。进程需要创建并挂载 BPF map/program 以及管理本地路由的权限。

## 鸣谢

感谢 [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
项目提供了本入站所基于的原始 eBPF 流量拦截实现。
