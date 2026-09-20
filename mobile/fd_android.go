package mobile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// AttachFD duplicates an Android VpnService descriptor. The caller retains
// ownership of the original. Close interrupts both native packet workers.
func (c *Client) AttachFD(fd int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != "ready" || c.closeFD != nil {
		return errors.New("AttachFD requires a ready client without an attached descriptor")
	}
	if c.control == nil {
		return errors.New("Android VPN requires a SocketProtector")
	}
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if err := unix.SetNonblock(dup, true); err != nil {
		_ = unix.Close(dup)
		return err
	}
	file := os.NewFile(uintptr(dup), "vpn-tun")
	c.closeFD = func() { _ = file.Close() }
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, err := file.Read(buffer)
			if err != nil {
				if c.ctx.Err() == nil {
					c.fail(err)
				}
				return
			}
			if err := c.WritePacket(buffer[:n]); err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			packet, err := c.ReadPacket()
			if err != nil {
				return
			}
			n, err := file.Write(packet)
			if err != nil || n != len(packet) {
				if err == nil {
					err = errors.New("short VPN packet write")
				}
				c.fail(err)
				return
			}
		}
	}()
	return nil
}
