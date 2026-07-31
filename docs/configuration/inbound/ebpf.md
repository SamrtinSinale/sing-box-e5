---
icon: material/lan-connect
---

# eBPF

The eBPF inbound intercepts locally generated TCP and UDP traffic with cgroup
socket-address programs. It does not use a TUN device, TProxy, TC, iptables, or
a SOCKS bridge.

This inbound is intended for a rooted Android or Linux native sing-box binary.
It is included only in builds made with the `with_ebpf` build tag and cgo.

## Structure

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",

  ... // Listen Fields

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

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for available fields.

The eBPF inbound uses addresses selected from `redirect_address` internally.
Therefore, `listen` may be omitted or set to an unspecified address (`0.0.0.0`
or `::`). The inbound creates an IPv4 and/or IPv6 wildcard listener according
to the address families enabled by `redirect_address`.

`listen_port` defaults to `65532`. A value of `0` also selects this default;
random listener ports are not supported because the redirect port is embedded
in the eBPF programs when they are loaded.

`proxy_protocol` and `proxy_protocol_accept_no_header` are not supported. The
intercepted application connections do not contain Proxy Protocol headers.

The configured `udp_timeout` and `detour` apply to intercepted UDP sessions as
they do for other UDP inbounds.

### Fields

#### network

Listen network, one of `tcp` `udp`.

Both if empty.

Protocols not selected by `network` bypass the eBPF inbound.

#### include_uid

List of process UIDs to intercept.

When `include_uid` or `include_uid_range` is non-empty, traffic from UIDs not
matched by either field bypasses the eBPF inbound.

#### include_uid_range

List of process UID ranges to intercept, in `start:end` format.

#### exclude_uid

List of process UIDs to bypass.

Exclude rules take priority over include rules.

#### exclude_uid_range

List of process UID ranges to bypass, in `start:end` format.

UID rules match the effective UID of the process performing the socket
operation. Ranges are compiled into compressed eBPF LPM trie entries instead
of being expanded into individual UIDs.

#### redirect_address

Internal address prefixes used to redirect intercepted connections to the
sing-box listener.

One prefix may be configured for each address family. An IPv4 prefix enables
IPv4 interception, an IPv6 prefix enables native IPv6 interception, and
configuring both enables dual-stack interception. IPv4-mapped IPv6 sockets are
treated as IPv4.

If omitted, `127.128.0.0/9` is used and only IPv4 interception is enabled. IPv4
prefixes must currently be between `/8` and `/10`, and IPv6 prefixes must use
`/64`.

These prefixes are flow-token pools, not interface subnets like the addresses
used by a TUN inbound. The eBPF programs select a random host address for every
intercepted flow and use it to recover the original destination. Large prefixes
are therefore required to keep simultaneous flows from selecting the same
token. The default uses the less commonly used upper half of the IPv4 loopback
range while retaining 23 bits of token space. The IPv6 example is a sing-box
specific ULA prefix. A custom prefix must not overlap any destination network
that the device needs to reach.

sing-box automatically installs an `RTN_LOCAL` route for each configured
prefix through the loopback interface in the network namespace selected by
`netns`. An existing local route that covers the prefix is reused. On shutdown,
sing-box removes only routes created by this inbound.

There are no CIDR, private-network, interface, or DNS policy fields. The
programs attach to the root cgroup2 mount discovered from
`/proc/self/mountinfo`, so all local application sockets in that hierarchy are
intercepted. Loopback traffic is left local.

sing-box registers the `SO_COOKIE` value of each socket it creates in an eBPF
LRU map. The cgroup programs consult this map before redirecting traffic, which
prevents sing-box outbound connections and UDP listeners from being captured
again.

## Build

Use the existing `make build` target with cgo enabled and append `with_ebpf` to
the build tags you normally use. For example, to retain the standard sing-box
build tags on Linux:

```sh
CGO_ENABLED=1 \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

For Android, provide the target architecture and an Android NDK compiler while
using the same `make build` target:

```sh
CGO_ENABLED=1 \
GOOS=android \
GOARCH=arm64 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang" \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

The device kernel must provide cgroup2 and the cgroup attach types required by
the configured address families and `network`: connect4/connect6 and, for UDP,
UDP4/UDP6 sendmsg and recvmsg. The process needs permission to create and attach
BPF maps/programs and to manage local routes.

## Credits

Thanks to [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
for the original eBPF interception implementation on which this inbound is
based.
