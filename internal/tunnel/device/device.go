package device

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

type Device interface {
	Name() string
	MTU() int
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
	Close() error
}

// Reserve room for Linux's virtio header and macOS's address-family header.
const packetOffset = 16

type Native struct {
	dev       tun.Device
	name      string
	mtu       int
	readMu    sync.Mutex
	pending   [][]byte
	readBufs  [][]byte
	readSizes []int
}

func Create(name string, mtu int) (*Native, error) {
	if name == "" {
		switch runtime.GOOS {
		case "darwin":
			name = "utun"
		case "windows":
			name = "Socks5Proxy"
		default:
			name = "socks5tun0"
		}
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN device: %w", err)
	}
	actualName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("read TUN name: %w", err)
	}
	actualMTU, err := dev.MTU()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("read TUN MTU: %w", err)
	}
	return &Native{dev: dev, name: actualName, mtu: actualMTU}, nil
}

func (d *Native) Name() string {
	return d.name
}

func (d *Native) MTU() int {
	return d.mtu
}

func (d *Native) ReadPacket() ([]byte, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()

	if len(d.pending) > 0 {
		packet := d.pending[0]
		d.pending = d.pending[1:]
		return packet, nil
	}

	if d.readBufs == nil {
		batchSize := d.dev.BatchSize()
		if batchSize < 1 {
			batchSize = 1
		}
		d.readBufs = make([][]byte, batchSize)
		d.readSizes = make([]int, batchSize)
		for i := range d.readBufs {
			d.readBufs[i] = make([]byte, packetOffset+65535)
		}
	}
	// Native reads are serialized. Reuse the large batch workspace while
	// returning owned packet copies to asynchronous transport workers.
	bufs, sizes := d.readBufs, d.readSizes
	n, err := d.dev.Read(bufs, sizes, packetOffset)
	if err != nil {
		return nil, err
	}
	if n < 1 {
		return nil, io.ErrNoProgress
	}
	for i := 0; i < n; i++ {
		if sizes[i] <= 0 || sizes[i] > len(bufs[i])-packetOffset {
			continue
		}
		d.pending = append(d.pending, append([]byte(nil), bufs[i][packetOffset:packetOffset+sizes[i]]...))
	}
	if len(d.pending) == 0 {
		return nil, errors.New("TUN returned no valid packets")
	}
	packet := d.pending[0]
	d.pending = d.pending[1:]
	return packet, nil
}

func (d *Native) WritePacket(packet []byte) error {
	buf := make([]byte, packetOffset+len(packet))
	copy(buf[packetOffset:], packet)
	n, err := d.dev.Write([][]byte{buf}, packetOffset)
	if err != nil {
		return err
	}
	// The pinned Linux backend returns bytes (including any virtio header),
	// while macOS and Windows return the number of packets.
	if (runtime.GOOS == "linux" && n < len(packet)) || (runtime.GOOS != "linux" && n != 1) {
		return io.ErrShortWrite
	}
	return nil
}

func (d *Native) Close() error {
	return d.dev.Close()
}
