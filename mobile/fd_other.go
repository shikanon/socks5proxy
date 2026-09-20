//go:build !android

package mobile

import "errors"

func (c *Client) AttachFD(fd int) error {
	return errors.New("AttachFD is Android-only; use ReadPacket and WritePacket on this platform")
}
