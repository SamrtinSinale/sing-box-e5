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
  "bypass_rule_set": [
    "geoip-cn"
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

`netns` is not supported. The cgroup hooks and redirect routes operate in the
current network namespace and cannot be scoped to a listener network namespace.

`bind_interface` may be omitted or set to `lo`. Other interfaces are not
supported because redirected connections are delivered through the loopback
interface.

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

#### bypass_rule_set

List of rule-sets whose destination IP CIDR entries bypass the eBPF inbound.

At startup, sing-box calls the existing rule-set CIDR extractor and merges the
result into IPv4 and IPv6 eBPF LPM trie maps. When a destination matches either
map, the cgroup program leaves the original destination unchanged. The
application socket then uses the kernel network stack directly and does not
enter the eBPF listener, sniffing, normal route rules, or an outbound.

This field performs CIDR extraction, not complete rule-set matching. Only
destination `ip_cidr` and binary IP set entries are extracted. Domain, port,
network, process, source, logical grouping, and invert conditions are not
evaluated by the eBPF program. In particular, an `ip_cidr` combined with
another condition is still extracted without that condition. Use CIDR-only
rule-sets for this field.

Multiple referenced rule-sets and all extracted CIDRs are merged as a union.
Normal route rules that select a `direct` outbound are not automatically
offloaded; only rule-sets explicitly listed here enable kernel direct bypass.

When a referenced local or remote rule-set is reloaded, sing-box extracts the
CIDRs again and updates the maps in place without reloading or reattaching the
eBPF programs. If an update cannot be applied, the error is logged and the
previous successfully applied policy is retained.

This bypass applies only to locally generated traffic that reaches the cgroup
socket-address hooks. Forwarded Android hotspot traffic does not pass through
these hooks.

#### redirect_address

Internal address prefixes used to redirect intercepted connections to the
sing-box listener.

One prefix may be configured for each address family. An IPv4 prefix enables
IPv4 interception, an IPv6 prefix enables native IPv6 interception, and
configuring both enables dual-stack interception. IPv4-mapped IPv6 sockets are
treated as IPv4.

If omitted, `127.128.0.0/9` is used and only IPv4 interception is enabled. IPv4
prefixes must be within `127.0.0.0/8` and use a prefix between `/8` and `/10`.
IPv6 prefixes must be within the ULA range `fc00::/7` and use `/64`.

These prefixes are flow-token pools, not interface subnets like the addresses
used by a TUN inbound. Unconnected UDP derives a stable host token from the
original address, port, and protocol, so repeated packets to the same
destination reuse an existing map entry. TCP and connected UDP additionally
mix the socket `SO_COOKIE` into the token, preventing concurrent sockets to the
same destination from sharing lifecycle state.

TCP and UDP use separate redirect maps with 65536 entries each. The maps do not
evict or overwrite entries. A token collision uses up to four deterministic
probes, and a full map rejects the new flow instead of routing it to another
destination. Large prefixes keep this lookup path close to one probe. The
default uses the less commonly used upper half of the IPv4 loopback range while
retaining 23 bits of token space. The IPv6 example is a sing-box specific ULA
prefix. Before installing the local route, sing-box rejects a prefix that
overlaps a non-loopback interface address or a non-default route in the main
routing table.

Redirect entries are reclaimed according to their actual owners. A TCP entry
is removed immediately after the listener consumes its original destination.
Unconnected UDP entries are reference-counted across sing-box UDP NAT sessions
and removed when the last session closes. Connected UDP stores its redirect
token by socket cookie and removes the redirect, token, and peer-cache entries
from a cgroup socket-release program when the application socket closes. A UDP
socket reconnect also removes the previous connected mapping before installing
the replacement.

sing-box logs eBPF runtime metrics every five minutes when they change and once
when the inbound stops. The metrics include separate TCP and UDP map occupancy, token
collisions, map update failures, rejected redirects, and userspace original
destination lookup misses. Occupancy at or above 75 percent, rejected redirects,
and lookup misses are logged as warnings.

sing-box automatically installs an `RTN_LOCAL` route for each configured
prefix through the loopback interface in the current network namespace. An
existing local route that covers the prefix is reused. On shutdown, sing-box
removes only routes created by this inbound.

Except for `bypass_rule_set`, there are no private-network, interface, or DNS policy
fields. The programs attach to the root cgroup2 mount discovered from
`/proc/self/mountinfo`. Loopback traffic is always left local.

Only one eBPF inbound may own a cgroup hierarchy at a time. sing-box holds an
exclusive lock on the cgroup2 root directory for the inbound lifetime. Stale
sing-box eBPF programs left by an unclean exit are removed only after this lock
has been acquired, so starting another instance cannot detach a running one.

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
UDP4/UDP6 sendmsg and recvmsg plus `BPF_CGROUP_INET_SOCK_RELEASE`. The process
needs permission to create and attach BPF maps/programs and to manage local
routes.

## Credits

Thanks to [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
for the original eBPF interception implementation on which this inbound is
based.
