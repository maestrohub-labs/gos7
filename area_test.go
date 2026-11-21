package gos7

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedS7 accepts one connection, confirms the COTP connection and the
// PDU negotiation (PDU 240), then answers each request with reply(request).
// A nil reply sends nothing. It records every request after the setup.
type scriptedS7 struct {
	addr string
	mu   sync.Mutex
	reqs [][]byte
}

func (s *scriptedS7) requests() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.reqs...)
}

func newScriptedS7(t *testing.T, reply func(req []byte) []byte) *scriptedS7 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &scriptedS7{addr: ln.Addr().String()}
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
		if readTPKT() == nil {
			return
		}
		conn.Write([]byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x02, 0x00, 0xC2, 0x02, 0x01, 0x02})
		if readTPKT() == nil {
			return
		}
		conn.Write([]byte{0x03, 0x00, 0x00, 0x1B, 0x02, 0xF0, 0x80, 0x32, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0})
		for {
			req := readTPKT()
			if req == nil {
				return
			}
			s.mu.Lock()
			s.reqs = append(s.reqs, req)
			s.mu.Unlock()
			if out := reply(req); out != nil {
				conn.Write(out)
			}
		}
	}()
	return s
}

// ackData frames an Ack_Data answering req with the given parameter and
// data sections.
func ackData(req, param, data []byte) []byte {
	body := []byte{0x32, 0x03, 0x00, 0x00, req[11], req[12], 0, 0, 0, 0, 0x00, 0x00}
	binary.BigEndian.PutUint16(body[6:], uint16(len(param)))
	binary.BigEndian.PutUint16(body[8:], uint16(len(data)))
	msg := append([]byte{0x03, 0x00, 0x00, 0x00, 0x02, 0xF0, 0x80}, body...)
	msg = append(append(msg, param...), data...)
	binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)))
	return msg
}

// readItem answers a read with one item: return code, transport, length
// field, then the value.
func readItem(req []byte, code, transport byte, length int, value []byte) []byte {
	data := []byte{code, transport, byte(length >> 8), byte(length)}
	return ackData(req, []byte{0x04, 0x01}, append(data, value...))
}

func writeAck(req []byte, code byte) []byte {
	return ackData(req, []byte{0x05, 0x01}, []byte{code})
}

func connectTo(t *testing.T, addr string) Client {
	t.Helper()
	h := NewTCPClientHandlerWithTSAP(addr, 0x0200, 0x0102)
	h.Timeout = 2 * time.Second
	if err := h.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return NewClient(h)
}

// item returns the S7ANY item of a read or write request: transport,
// count, DB, area and the 24-bit address.
func item(r []byte) (transport byte, count, db int, area byte, address int) {
	return r[22], int(binary.BigEndian.Uint16(r[23:])), int(binary.BigEndian.Uint16(r[25:])), r[27], int(r[28])<<16 | int(r[29])<<8 | int(r[30])
}

// The 200 family's system flags (SM) are bytes addressed in bits, like M:
// SMB28 is area 0x05, transport BYTE, address 28*8.
func TestAGReadArea_SystemFlags(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte { return readItem(r, 0xFF, 0x04, 16, []byte{0x12, 0x34}) })
	c := connectTo(t, s.addr)
	buf := make([]byte, 2)
	if err := c.AGReadArea(AreaSM, 0, 28, 2, WLByte, buf); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x12 || buf[1] != 0x34 {
		t.Errorf("SMB28-29 = % X, want 12 34", buf)
	}
	ts, n, db, area, addr := item(s.requests()[0])
	if ts != 0x02 || n != 2 || db != 0 || area != 0x05 || addr != 28*8 {
		t.Errorf("item = transport %02X count %d db %d area %02X address %d; want 02 2 0 05 %d", ts, n, db, area, addr, 28*8)
	}
}

// An IEC counter of the 200 family is asked for by number, with the area
// code as its transport size, and is answered as a 3-byte octet string: a
// status byte and the 16-bit count (libnodave's daveCounter200 asks the same
// way).
func TestAGReadArea_IECCounter(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte { return readItem(r, 0xFF, 0x09, 3, []byte{0x01, 0x00, 0x2A}) })
	c := connectTo(t, s.addr)
	buf := make([]byte, 3)
	if err := c.AGReadArea(AreaIECCounter, 0, 12, 1, WLByte, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "\x01\x00\x2A" {
		t.Errorf("C12 = % X, want 01 00 2A", buf)
	}
	ts, n, _, area, addr := item(s.requests()[0])
	if ts != 0x1E || n != 1 || area != 0x1E || addr != 12 {
		t.Errorf("item = transport %02X count %d area %02X address %d; want 1E 1 1E 12", ts, n, area, addr)
	}
}

// An IEC timer: a status byte and a 32-bit value, 5 bytes.
func TestAGReadArea_IECTimer(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte {
		return readItem(r, 0xFF, 0x09, 5, []byte{0x00, 0x00, 0x00, 0x30, 0x39})
	})
	c := connectTo(t, s.addr)
	buf := make([]byte, 5)
	if err := c.AGReadArea(AreaIECTimer, 0, 255, 1, WLIECTimer, buf); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(buf[1:]) != 12345 {
		t.Errorf("T255 = % X, want 00 00 00 30 39", buf)
	}
	ts, n, _, area, addr := item(s.requests()[0])
	if ts != 0x1F || n != 1 || area != 0x1F || addr != 255 {
		t.Errorf("item = transport %02X count %d area %02X address %d; want 1F 1 1F 255", ts, n, area, addr)
	}
}

// A bit is written as a bit: transport BIT, the bit address, and a data
// item of transport 03 with length 1. Nothing else in its byte is touched.
func TestAGWriteArea_Bit(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte { return writeAck(r, 0xFF) })
	c := connectTo(t, s.addr)
	if err := c.AGWriteArea(AreaMK, 0, 10*8+3, 1, WLBit, []byte{1}); err != nil {
		t.Fatal(err)
	}
	r := s.requests()[0]
	ts, n, _, area, addr := item(r)
	if r[17] != 0x05 || ts != 0x01 || n != 1 || area != 0x83 || addr != 83 {
		t.Errorf("item = function %02X transport %02X count %d area %02X address %d; want 05 01 1 83 83", r[17], ts, n, area, addr)
	}
	if data := r[31:]; len(data) != 5 || data[1] != 0x03 || binary.BigEndian.Uint16(data[2:]) != 1 || data[4] != 1 {
		t.Errorf("data item = % X, want 00 03 00 01 01", data)
	}
}

// A DB word is written as bytes addressed in bits, as AGWriteDB writes it.
func TestAGWriteArea_DBBytes(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte { return writeAck(r, 0xFF) })
	c := connectTo(t, s.addr)
	if err := c.AGWriteArea(AreaDB, 7, 100, 2, WLByte, []byte{0xBE, 0xEF}); err != nil {
		t.Fatal(err)
	}
	r := s.requests()[0]
	ts, n, db, area, addr := item(r)
	if ts != 0x02 || n != 2 || db != 7 || area != 0x84 || addr != 800 {
		t.Errorf("item = transport %02X count %d db %d area %02X address %d; want 02 2 7 84 800", ts, n, db, area, addr)
	}
	if data := r[31:]; len(data) != 6 || data[1] != 0x04 || binary.BigEndian.Uint16(data[2:]) != 16 || data[4] != 0xBE || data[5] != 0xEF {
		t.Errorf("data item = % X, want 00 04 00 10 BE EF", data)
	}
}

// A refused item is an *ItemError carrying the CPU's return code, with the
// text this package has always given it.
func TestAGArea_RefusalIsAnItemError(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte {
		if r[17] == 0x05 {
			return writeAck(r, 0x03)
		}
		return readItem(r, 0x05, 0x00, 0, nil)
	})
	c := connectTo(t, s.addr)
	err := c.AGReadArea(AreaDB, 9, 0, 1, WLByte, make([]byte, 1))
	var ie *ItemError
	if !errors.As(err, &ie) || ie.Code != 0x05 {
		t.Fatalf("read: got %v, want an ItemError with code 05", err)
	}
	if err.Error() != ErrorText(errCliAddressOutOfRange) {
		t.Errorf("read text = %q, want %q", err.Error(), ErrorText(errCliAddressOutOfRange))
	}
	err = c.AGWriteArea(AreaMK, 0, 0, 1, WLByte, []byte{1})
	if !errors.As(err, &ie) || ie.Code != 0x03 {
		t.Fatalf("write: got %v, want an ItemError with code 03", err)
	}
	// The AG functions report a refusal the same way.
	err = c.AGReadDB(9, 0, 1, make([]byte, 1))
	if !errors.As(err, &ie) {
		t.Errorf("AGReadDB: got %v, want an ItemError", err)
	}
}

// An answer that carries fewer bytes than were asked for is refused; it
// used to be copied past its end.
func TestAGReadArea_ShortAnswerIsRefused(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte { return readItem(r, 0xFF, 0x04, 8, []byte{0x01}) })
	c := connectTo(t, s.addr)
	err := c.AGReadDB(1, 0, 4, make([]byte, 4))
	if err == nil || !strings.Contains(err.Error(), "want 29") {
		t.Fatalf("got %v, want a refusal of the short answer", err)
	}
}

// Requests the buffer cannot hold, a bit amount other than 1 and an IEC
// write are refused before anything is sent.
func TestAGArea_RefusedBeforeSending(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte { return writeAck(r, 0xFF) })
	c := connectTo(t, s.addr)
	for name, call := range map[string]func() error{
		"IEC counter buffer": func() error { return c.AGReadArea(AreaIECCounter, 0, 1, 1, WLIECCounter, make([]byte, 2)) },
		"byte buffer":        func() error { return c.AGReadArea(AreaMK, 0, 0, 4, WLByte, make([]byte, 3)) },
		"two bits":           func() error { return c.AGWriteArea(AreaMK, 0, 0, 2, WLBit, []byte{1, 1}) },
		"no elements":        func() error { return c.AGReadArea(AreaMK, 0, 0, 0, WLByte, nil) },
		"IEC counter write":  func() error { return c.AGWriteArea(AreaIECCounter, 0, 1, 1, WLByte, []byte{0, 0, 1}) },
		"IEC timer write":    func() error { return c.AGWriteArea(AreaDB, 0, 1, 1, WLIECTimer, make([]byte, 5)) },
		"unknown word len":   func() error { return c.AGReadArea(AreaMK, 0, 0, 1, 0x42, make([]byte, 8)) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(s.requests()); n != 0 {
		t.Errorf("%d requests reached the CPU, want none", n)
	}
}

// A read split by the PDU continues where the first part ended: timers are
// numbered, so the second request starts after the timers already read,
// not twice as far (2 bytes each).
func TestAGReadTM_SplitByThePDU(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte {
		_, n, _, _, _ := item(r)
		return readItem(r, 0xFF, 0x09, 2*n, make([]byte, 2*n))
	})
	c := connectTo(t, s.addr)
	if err := c.AGReadTM(7, 150, make([]byte, 300)); err != nil {
		t.Fatal(err)
	}
	reqs := s.requests()
	if len(reqs) != 2 {
		t.Fatalf("%d requests, want 2 (111 timers fit a PDU of 240)", len(reqs))
	}
	_, n1, _, _, a1 := item(reqs[0])
	_, n2, _, _, a2 := item(reqs[1])
	if a1 != 7 || n1 != 111 || a2 != 118 || n2 != 39 {
		t.Errorf("requests = %d from %d, %d from %d; want 111 from 7, 39 from 118", n1, a1, n2, a2)
	}
}

// Dial is used to open the connection, and closing the connection it
// returned ends a request blocked on it at once.
func TestDial_TheCallerCanEndABlockedRequest(t *testing.T) {
	s := newScriptedS7(t, func(r []byte) []byte { return nil }) // never answers a request
	var conn net.Conn
	h := NewTCPClientHandlerWithTSAP(s.addr, 0x0200, 0x0102)
	h.Timeout = 30 * time.Second
	h.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, network, address)
		conn = c
		return c, err
	}
	if err := h.Connect(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if conn == nil {
		t.Fatal("Dial was not used")
	}
	done := make(chan error, 1)
	go func() { done <- NewClient(h).AGReadMB(0, 1, make([]byte, 1)) }()
	time.Sleep(100 * time.Millisecond)
	_ = conn.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("want the request to fail once its connection closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request did not end when its connection was closed")
	}
}
