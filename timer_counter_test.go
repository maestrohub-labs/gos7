package gos7

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// fakeS7 answers the COTP connection, the PDU negotiation and one read-var
// request, replying with data as the item's payload. It returns the read
// request it received.
func fakeS7(t *testing.T, data []byte) (addr string, request <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		readTPKT := func() []byte {
			h := make([]byte, 4)
			if _, err := io.ReadFull(conn, h); err != nil {
				return nil
			}
			rest := make([]byte, int(binary.BigEndian.Uint16(h[2:]))-4)
			if _, err := io.ReadFull(conn, rest); err != nil {
				return nil
			}
			return append(h, rest...)
		}
		// COTP connection confirm.
		if readTPKT() == nil {
			return
		}
		conn.Write([]byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02})
		// Setup communication: ack with PDU 240.
		if readTPKT() == nil {
			return
		}
		conn.Write([]byte{0x03, 0x00, 0x00, 0x1B, 0x02, 0xF0, 0x80, 0x32, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0})
		req := readTPKT()
		if req == nil {
			return
		}
		got <- req
		// Read-var ack: one item, return code FF, transport size 09 (octets), length in bytes.
		body := []byte{0x32, 0x03, 0x00, 0x00, req[11], req[12], 0x00, 0x02, 0x00, byte(4 + len(data)), 0x00, 0x00, 0x04, 0x01, 0xFF, 0x09, 0x00, byte(len(data))}
		body = append(body, data...)
		msg := append([]byte{0x03, 0x00, 0x00, 0x00, 0x02, 0xF0, 0x80}, body...)
		binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)))
		conn.Write(msg)
	}()
	return ln.Addr().String(), got
}

func connectFake(t *testing.T, addr string) Client {
	t.Helper()
	h := NewTCPClientHandler(addr, 0, 2)
	h.Timeout = 2 * time.Second
	if err := h.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return NewClient(h)
}

// A timer is its whole 2-byte word, as the CPU sends it: the time base and
// the hundreds digit live in the high byte (S5TIME 2#10 base, BCD 123 =
// 0x2123). The request asks for timers by number, with the timer transport.
func TestAGReadTM_KeepsTheWholeWord(t *testing.T) {
	addr, req := fakeS7(t, []byte{0x21, 0x23, 0x00, 0x05})
	c := connectFake(t, addr)
	buf := make([]byte, 4)
	if err := c.AGReadTM(7, 2, buf); err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x21, 0x23, 0x00, 0x05}; string(buf) != string(want) {
		t.Errorf("timers = % X, want % X", buf, want)
	}
	r := <-req
	if r[27] != 0x1D || r[22] != 0x1D { // area timers, transport timer
		t.Errorf("area/transport = %02X/%02X, want 1D/1D", r[27], r[22])
	}
	if n, start := binary.BigEndian.Uint16(r[23:]), int(r[28])<<16|int(r[29])<<8|int(r[30]); n != 2 || start != 7 {
		t.Errorf("amount %d from %d, want 2 from 7", n, start)
	}
}

func TestAGReadCT_KeepsTheWholeWord(t *testing.T) {
	addr, req := fakeS7(t, []byte{0x09, 0x99})
	c := connectFake(t, addr)
	buf := make([]byte, 2)
	if err := c.AGReadCT(3, 1, buf); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x09 || buf[1] != 0x99 {
		t.Errorf("counter = % X, want 09 99", buf)
	}
	if r := <-req; r[27] != 0x1C || r[22] != 0x1C {
		t.Errorf("area/transport = %02X/%02X, want 1C/1C", r[27], r[22])
	}
}

// A buffer too small for 2 bytes per element is refused, not overrun.
func TestTimerCounterBufferTooSmall(t *testing.T) {
	c := NewClient(NewTCPClientHandler("127.0.0.1:1", 0, 2))
	if err := c.AGReadTM(0, 2, make([]byte, 3)); err == nil {
		t.Error("AGReadTM with 3 bytes for 2 timers: want an error")
	}
	if err := c.AGWriteCT(0, 1, make([]byte, 1)); err == nil {
		t.Error("AGWriteCT with 1 byte for a counter: want an error")
	}
}
