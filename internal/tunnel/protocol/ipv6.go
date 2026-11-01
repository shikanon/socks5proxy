package protocol

import (
	"errors"
	"net/netip"
)

// ValidateIPv6Parameters refuses unsupported, unsolicited or partial dual-stack
// negotiation before a client installs any OS network configuration.
func ValidateIPv6Parameters(m Message, requested bool) (client, server, dns netip.Addr, err error) {
	if !requested {
		if m.IPv6 || m.ClientIPv6 != "" || m.ServerIPv6 != "" || m.DNSIPv6 != "" {
			err = errors.New("server returned unsolicited IPv6 parameters")
		}
		return
	}
	if !m.IPv6 || m.MTU < 1280 || m.MTU > 1400 {
		err = errors.New("server does not support the requested IPv6 tunnel")
		return
	}
	client, err = parseIPv6(m.ClientIPv6)
	if err != nil {
		return
	}
	server, err = parseIPv6(m.ServerIPv6)
	if err != nil {
		return
	}
	if client == server {
		err = errors.New("IPv6 client and server addresses must differ")
		return
	}
	if m.DNSIPv6 != "" {
		dns, err = parseIPv6(m.DNSIPv6)
	}
	return
}

func parseIPv6(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is6() || addr.Is4In6() || !addr.IsGlobalUnicast() || addr.Zone() != "" {
		return netip.Addr{}, errors.New("invalid unicast IPv6 tunnel parameter")
	}
	return addr, nil
}

// MatchesLease excludes the invalid zero address when IPv6 is disabled.
func MatchesLease(addr, ipv4, ipv6 netip.Addr) bool {
	return addr.IsValid() && (addr == ipv4 || (ipv6.IsValid() && addr == ipv6))
}

func SameTunnelParameters(a, b Message) bool {
	return a.ClientIPv4 == b.ClientIPv4 && a.ServerIPv4 == b.ServerIPv4 &&
		a.DNSIPv4 == b.DNSIPv4 && a.MTU == b.MTU && a.Obfs == b.Obfs &&
		a.IPv6 == b.IPv6 && a.ClientIPv6 == b.ClientIPv6 &&
		a.ServerIPv6 == b.ServerIPv6 && a.DNSIPv6 == b.DNSIPv6
}
