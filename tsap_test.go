package gos7

import (
	"io"
	"net"
	"testing"
	"time"
)

// The COTP connection request carries the TSAPs a caller gives, unchanged:
// parameter C1 (calling TSAP) at bytes 16-17 and C2 (called TSAP) at 20-21.
func TestNewTCPClientHandlerWithTSAP_ConnectionRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		cr := make([]byte, len(isoConnectionRequestTelegram))
		if _, err := io.ReadFull(conn, cr); err == nil {
			got <- cr
		}
	}()

	h := NewTCPClientHandlerWithTSAP(ln.Addr().String(), 0x1000, 0x0200)
	h.Timeout = 2 * time.Second
	_ = h.Connect() // the peer hangs up after the request; only the request matters

	select {
	case cr := <-got:
		if cr[15] != 0x02 || cr[16] != 0x10 || cr[17] != 0x00 {
			t.Errorf("calling TSAP: got % X, want C1 02 10 00", cr[14:18])
		}
		if cr[19] != 0x02 || cr[20] != 0x02 || cr[21] != 0x00 {
			t.Errorf("called TSAP: got % X, want C2 02 02 00", cr[18:22])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no connection request received")
	}
}

// An address without a port gets the ISO-on-TCP port, as with rack/slot.
func TestNewTCPClientHandlerWithTSAP_DefaultPort(t *testing.T) {
	h := NewTCPClientHandlerWithTSAP("192.0.2.10", 0x0100, 0x0200)
	if h.Address != "192.0.2.10:102" {
		t.Errorf("address = %q, want 192.0.2.10:102", h.Address)
	}
}
