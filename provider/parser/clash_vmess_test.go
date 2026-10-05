package parser

import (
	"context"
	"encoding/base64"
	"fmt"
	"runtime"
	"testing"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestParseClashVMessSecurity(t *testing.T) {
	autoSecurity := "chacha20-poly1305"
	switch runtime.GOARCH {
	case "amd64", "arm64", "s390x":
		autoSecurity = "aes-128-gcm"
	}
	for _, network := range []string{"tcp", "ws", "grpc"} {
		for _, tlsEnabled := range []bool{false, true} {
			for _, cipher := range []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero", ""} {
				t.Run(fmt.Sprintf("%s/tls=%t/cipher=%s", network, tlsEnabled, cipher), func(t *testing.T) {
					outbounds, endpoints, err := ParseClashSubscription(context.Background(), fmt.Sprintf(`
proxies:
  - name: vmess-out
    type: vmess
    server: example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: %q
    tls: %t
    network: %s
    grpc-opts:
      grpc-service-name: vmess
`, cipher, tlsEnabled, network))
					require.NoError(t, err)
					require.Empty(t, endpoints)
					require.Len(t, outbounds, 1)
					options := outbounds[0].Options.(*option.VMessOutboundOptions)
					expectedSecurity := cipher
					// Clash 省略 cipher 等同 auto：两者都要归一成 AEAD，
					// 否则 sing-box 在 TLS 下会把它当 zero，服务端拒绝。
					if cipher == "auto" || cipher == "" {
						expectedSecurity = autoSecurity
					}
					require.Equal(t, expectedSecurity, options.Security)
					if tlsEnabled {
						require.NotNil(t, options.TLS)
						require.True(t, options.TLS.Enabled)
					} else {
						require.True(t, options.TLS == nil || !options.TLS.Enabled)
					}
				})
			}
		}
	}
}

func TestParseVMessAutoSecurityOtherFormats(t *testing.T) {
	t.Run("sing-box JSON", func(t *testing.T) {
		registry := outbound.NewRegistry()
		outbound.Register[option.VMessOutboundOptions](registry, C.TypeVMess, nil)
		ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), registry)
		outbounds, _, err := ParseBoxSubscription(ctx, `{"outbounds":[{
			"type":"vmess","server":"example.com","server_port":443,
			"uuid":"11111111-1111-1111-1111-111111111111",
			"security":"auto","tls":{"enabled":true}
		}]}`)
		require.NoError(t, err)
		require.Len(t, outbounds, 1)
		require.Equal(t, "auto", outbounds[0].Options.(*option.VMessOutboundOptions).Security)
	})
	t.Run("VMess link", func(t *testing.T) {
		link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(`{
			"add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111",
			"scy":"auto","tls":"tls","net":"grpc","path":"vmess"
		}`))
		outbound, err := ParseSubscriptionLink(link)
		require.NoError(t, err)
		// 链接格式（mihomo / Xray）的 auto 要归一成 AEAD：sing-box 出站会把
		// auto + TLS 变成 zero，服务端按 AEAD 解会拒绝。
		require.Equal(t, expectedVMessAutoSecurity(), outbound.Options.(*option.VMessOutboundOptions).Security)
	})
}
