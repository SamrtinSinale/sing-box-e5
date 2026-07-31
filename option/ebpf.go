package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type EBPFInboundOptions struct {
	ListenOptions
	Network         NetworkList                      `json:"network,omitempty"`
	RedirectAddress badoption.Listable[netip.Prefix] `json:"redirect_address,omitempty" examples:"127.128.0.0/9,fd53:696e:672d:626f::/64"`
}
