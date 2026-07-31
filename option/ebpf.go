package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type EBPFInboundOptions struct {
	ListenOptions
	Network         NetworkList                      `json:"network,omitempty"`
	RedirectAddress badoption.Listable[netip.Prefix] `json:"redirect_address,omitempty" examples:"127.128.0.0/9,fd53:696e:672d:626f::/64"`
	BypassRuleSet   badoption.Listable[string]       `json:"bypass_rule_set,omitempty" reference:"rule_set"`
	IncludeUID      badoption.Listable[uint32]       `json:"include_uid,omitempty"`
	IncludeUIDRange badoption.Listable[string]       `json:"include_uid_range,omitempty"`
	ExcludeUID      badoption.Listable[uint32]       `json:"exclude_uid,omitempty"`
	ExcludeUIDRange badoption.Listable[string]       `json:"exclude_uid_range,omitempty"`
}
