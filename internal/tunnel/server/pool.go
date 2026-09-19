package server

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net/netip"
	"sort"
	"sync"
)

type AddressPool struct {
	mu        sync.Mutex
	prefix    netip.Prefix
	server    netip.Addr
	first     uint32
	last      uint32
	next      uint32
	byClient  map[string]netip.Addr
	allocated map[netip.Addr]string
}

func NewAddressPool(cidr string) (*AddressPool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return nil, errors.New("invalid IPv4 tunnel CIDR")
	}
	prefix = prefix.Masked()
	if prefix.Bits() > 30 {
		return nil, errors.New("tunnel CIDR has no client addresses")
	}
	base := addrUint32(prefix.Addr())
	hostBits := 32 - prefix.Bits()
	broadcast := base | uint32((uint64(1)<<hostBits)-1)
	serverAddr := uint32Addr(base + 1)
	first := base + 2
	last := broadcast - 1
	return &AddressPool{
		prefix:    prefix,
		server:    serverAddr,
		first:     first,
		last:      last,
		next:      first,
		byClient:  make(map[string]netip.Addr),
		allocated: make(map[netip.Addr]string),
	}, nil
}

func (p *AddressPool) Server() netip.Addr {
	return p.server
}

func (p *AddressPool) Prefix() netip.Prefix {
	return p.prefix
}

func (p *AddressPool) Acquire(clientID string) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if addr, ok := p.byClient[clientID]; ok {
		return addr, nil
	}
	capacity := uint64(p.last) - uint64(p.first) + 1
	for checked := uint64(0); checked < capacity; checked++ {
		candidate := uint32Addr(p.next)
		if p.next == p.last {
			p.next = p.first
		} else {
			p.next++
		}
		if _, exists := p.allocated[candidate]; exists {
			continue
		}
		p.byClient[clientID] = candidate
		p.allocated[candidate] = clientID
		return candidate, nil
	}
	return netip.Addr{}, errors.New("tunnel address pool exhausted")
}

func (p *AddressPool) Reserve(clientIDs []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := append([]string(nil), clientIDs...)
	sort.Strings(ids)
	capacity := uint64(p.last) - uint64(p.first) + 1
	if uint64(len(ids)) > capacity {
		return errors.New("tunnel address pool is smaller than the configured client set")
	}
	for _, clientID := range ids {
		if _, exists := p.byClient[clientID]; exists {
			continue
		}
		hasher := fnv.New32a()
		_, _ = hasher.Write([]byte(clientID))
		start := p.first + uint32(uint64(hasher.Sum32())%capacity)
		for offset := uint64(0); offset < capacity; offset++ {
			value := p.first + uint32((uint64(start-p.first)+offset)%capacity)
			candidate := uint32Addr(value)
			if _, exists := p.allocated[candidate]; exists {
				continue
			}
			p.byClient[clientID] = candidate
			p.allocated[candidate] = clientID
			break
		}
	}
	return nil
}

func addrUint32(addr netip.Addr) uint32 {
	value := addr.As4()
	return binary.BigEndian.Uint32(value[:])
}

func uint32Addr(value uint32) netip.Addr {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return netip.AddrFrom4(raw)
}
