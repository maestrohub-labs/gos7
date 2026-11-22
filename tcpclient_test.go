package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.
import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTCPTransporter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, err = io.Copy(conn, conn)
		if err != nil {
			t.Error(err)
			return
		}
	}()
	client := &tcpTransporter{
		Address:     ln.Addr().String(),
		Timeout:     200 * time.Second,
		IdleTimeout: 100 * time.Millisecond,
	}
	req := []byte{0, 1, 0, 17, 0, 2, 1, 2, 0, 1, 0, 17, 0, 2, 1, 2, 2} //lengh 17, > MinPduSize

	client.tcpConnect(context.Background()) //assume tcp connect to test locally
	rsp, err := client.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	//lth: just compare 7 first byte
	if !bytes.Equal(req, rsp) {
		t.Fatalf("unexpected response: %x", rsp)
	}
	time.Sleep(150 * time.Millisecond)
	client.mu.Lock() // the idle timer closes the connection under mu
	conn := client.conn
	client.mu.Unlock()
	if conn != nil {
		t.Fatalf("connection is not closed: %+v", conn)
	}
}

// A failed receive is reported through the transporter's own Logger only:
// with none set, nothing reaches the process's standard logger (a caller
// that closes the connection on purpose to end a request would otherwise
// print a line on every interrupt).
func TestTCPTransporter_AFailedReceiveLogsOnlyThroughItsLogger(t *testing.T) {
	var std bytes.Buffer
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	for _, withLogger := range []bool{false, true} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				_ = conn.Close() // answer nothing: the receive fails with EOF
			}
		}()
		var own bytes.Buffer
		client := &tcpTransporter{Address: ln.Addr().String(), Timeout: 2 * time.Second}
		if withLogger {
			client.Logger = log.New(&own, "", 0)
		}
		if err := client.tcpConnect(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Send([]byte{0, 1, 0, 17, 0, 2, 1, 2, 0, 1, 0, 17, 0, 2, 1, 2, 2}); err == nil {
			t.Fatal("a closed peer must fail the receive")
		}
		_ = client.Close()
		_ = ln.Close()
		if withLogger && !strings.Contains(own.String(), "receive failed") {
			t.Fatalf("the transporter's Logger did not get the failure: %q", own.String())
		}
	}
	if std.Len() != 0 {
		t.Fatalf("the standard logger got output: %q", std.String())
	}
}
