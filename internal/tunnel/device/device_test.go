package device

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

type batchDevice struct {
	calls int
	batch int
	read  func([][]byte, []int, int) (int, error)
}

func (d *batchDevice) File() *os.File                   { return nil }
func (d *batchDevice) MTU() (int, error)                { return 1150, nil }
func (d *batchDevice) Name() (string, error)            { return "test", nil }
func (d *batchDevice) Events() <-chan tun.Event         { return nil }
func (d *batchDevice) Close() error                     { return nil }
func (d *batchDevice) BatchSize() int                   { return d.batch }
func (d *batchDevice) Write([][]byte, int) (int, error) { return 0, io.ErrClosedPipe }
func (d *batchDevice) Read(b [][]byte, s []int, off int) (int, error) {
	d.calls++
	return d.read(b, s, off)
}

func TestNativeReadPacket(t *testing.T) {
	t.Run("batch_workspace_reuse_and_packet_ownership", func(t *testing.T) {
		raw := &batchDevice{batch: 2}
		var workspace *byte
		raw.read = func(bufs [][]byte, sizes []int, offset int) (int, error) {
			if workspace == nil {
				workspace = &bufs[0][0]
			} else if workspace != &bufs[0][0] {
				t.Fatal("large batch workspace was allocated again")
			}
			for i := range bufs {
				sizes[i] = 3
				copy(bufs[i][offset:], []byte{byte(raw.calls), byte(i), 0xa5})
			}
			return 2, nil
		}
		native := &Native{dev: raw}
		first, err := native.ReadPacket()
		if err != nil || !bytes.Equal(first, []byte{1, 0, 0xa5}) {
			t.Fatal("first batch packet incorrect", err)
		}
		second, err := native.ReadPacket()
		if err != nil || !bytes.Equal(second, []byte{1, 1, 0xa5}) || raw.calls != 1 {
			t.Fatal("pending packet incorrectly reread device", err)
		}
		third, err := native.ReadPacket()
		if err != nil || !bytes.Equal(third, []byte{2, 0, 0xa5}) || raw.calls != 2 {
			t.Fatal("second batch incorrect", err)
		}
		if !bytes.Equal(first, []byte{1, 0, 0xa5}) || !bytes.Equal(second, []byte{1, 1, 0xa5}) {
			t.Fatal("reused workspace overwrote returned packet")
		}
	})
	for _, scenario := range []string{"zero_batch_fallback", "read_error", "empty_read", "invalid_size"} {
		t.Run(scenario, func(t *testing.T) {
			raw := &batchDevice{}
			raw.read = func(bufs [][]byte, sizes []int, offset int) (int, error) {
				if len(bufs) != 1 || len(sizes) != 1 {
					t.Fatal("zero batch size fallback incorrect")
				}
				switch scenario {
				case "read_error":
					return 0, io.ErrClosedPipe
				case "empty_read":
					return 0, nil
				case "invalid_size":
					sizes[0] = len(bufs[0]) + 1
				default:
					sizes[0] = 1
					bufs[0][offset] = 0xa5
				}
				return 1, nil
			}
			native := &Native{dev: raw}
			packet, err := native.ReadPacket()
			if scenario == "zero_batch_fallback" {
				if err != nil || !bytes.Equal(packet, []byte{0xa5}) {
					t.Fatal("valid fallback packet rejected", err)
				}
			} else if err == nil {
				t.Fatal("invalid native read accepted")
			}
		})
	}
}
