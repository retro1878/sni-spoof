//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

// frame builds a minimal Ethernet+IPv4 frame for the given L4 protocol, src/dst
// IPs, optional TCP header (with the given data-offset words and flags) plus
// payload. It exercises the same offsets sniffFilterInsns computes.
func frame(proto byte, src, dst net.IP, tcpDataOffWords int, payload int) []byte {
	const eth = 14
	ihl := 20
	tcpHdr := tcpDataOffWords * 4
	ipTotal := ihl + tcpHdr + payload

	f := make([]byte, eth+ipTotal)
	binary.BigEndian.PutUint16(f[12:14], 0x0800) // IPv4 ethertype

	ip := f[eth:]
	ip[0] = 0x40 | byte(ihl/4) // version 4, IHL
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotal))
	ip[9] = proto
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())

	if proto == 6 {
		tcp := ip[ihl:]
		tcp[12] = byte(tcpDataOffWords << 4)
	}
	return f
}

func TestSniffFilterAcceptsOnlyZeroPayloadTCPToHost(t *testing.T) {
	conn := net.ParseIP("104.18.4.130")
	local := net.ParseIP("10.0.0.5")
	other := net.ParseIP("8.8.8.8")

	vm, err := bpf.NewVM(sniffFilterInsns(binary.BigEndian.Uint32(conn.To4())))
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	run := func(f []byte) bool {
		n, err := vm.Run(f)
		if err != nil {
			t.Fatalf("vm.Run: %v", err)
		}
		return n > 0
	}

	cases := []struct {
		name string
		f    []byte
		want bool
	}{
		{"outbound SYN (no payload)", frame(6, local, conn, 5, 0), true},
		{"outbound pure ACK", frame(6, local, conn, 5, 0), true},
		{"inbound pure ACK", frame(6, conn, local, 5, 0), true},
		{"pure ACK, TCP options (no payload)", frame(6, conn, local, 8, 0), true},
		{"outbound data packet", frame(6, local, conn, 5, 1400), false},
		{"inbound data packet", frame(6, conn, local, 5, 1400), false},
		{"TCP but unrelated host", frame(6, local, other, 5, 0), false},
		{"UDP to host", frame(17, local, conn, 5, 0), false},
	}
	for _, c := range cases {
		if got := run(c.f); got != c.want {
			t.Errorf("%s: filter pass = %v, want %v", c.name, got, c.want)
		}
	}
}

// frame6 builds a minimal Ethernet+IPv6 frame carrying a TCP header and an
// optional payload. Extension headers are not produced: sniffLoop and the v6
// filter both expect TCP immediately after the fixed 40-byte header.
func frame6(proto byte, src, dst net.IP, tcpDataOffWords int, payload int) []byte {
	const eth, ip6h = 14, 40
	tcpHdr := tcpDataOffWords * 4
	payloadLen := tcpHdr + payload

	f := make([]byte, eth+ip6h+payloadLen)
	binary.BigEndian.PutUint16(f[12:14], 0x86DD)

	ip := f[eth:]
	ip[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))
	ip[6] = proto
	ip[7] = 64
	copy(ip[8:24], src.To16())
	copy(ip[24:40], dst.To16())

	if proto == 6 {
		ip[ip6h+12] = byte(tcpDataOffWords << 4)
	}
	return f
}

func TestSniffFilter6AcceptsOnlyZeroPayloadTCP(t *testing.T) {
	conn := net.ParseIP("2606:4700:4700::1111")
	local := net.ParseIP("2a14:52c0:ae43:b::7550:e2d5")
	other := net.ParseIP("2001:4188:2:600:10:10:34:36")

	vm, err := bpf.NewVM(sniffFilterInsns6())
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	run := func(f []byte) bool {
		n, err := vm.Run(f)
		if err != nil {
			t.Fatalf("vm.Run: %v", err)
		}
		return n > 0
	}

	cases := []struct {
		name string
		f    []byte
		want bool
	}{
		{"outbound SYN", frame6(6, local, conn, 5, 0), true},
		{"inbound pure ACK", frame6(6, conn, local, 5, 0), true},
		{"pure ACK, TCP options", frame6(6, conn, local, 8, 0), true},
		{"unrelated host still passes (Go filters)", frame6(6, local, other, 5, 0), true},
		{"outbound data packet", frame6(6, local, conn, 5, 1400), false},
		{"inbound data packet", frame6(6, conn, local, 5, 1400), false},
		{"UDP (next header 17)", frame6(17, local, conn, 5, 0), false},
		{"IPv4 frame", frame(6, net.ParseIP("10.0.0.5"), net.ParseIP("104.18.4.130"), 5, 0), false},
	}
	for _, c := range cases {
		if got := run(c.f); got != c.want {
			t.Errorf("%s: filter pass = %v, want %v", c.name, got, c.want)
		}
	}
}

// Vector computed independently from RFC 8200 s8.1.
func TestTCPChecksum6KnownVector(t *testing.T) {
	ip6 := make([]byte, 40)
	copy(ip6[8:24], net.ParseIP("2606:4700:4700::1111").To16())
	copy(ip6[24:40], net.ParseIP("2a14:52c0:ae43:b::7550:e2d5").To16())

	payload := []byte("hello world")
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], 1234)
	binary.BigEndian.PutUint16(seg[2:4], 443)
	binary.BigEndian.PutUint32(seg[4:8], 0x11223344)
	seg[12] = 5 << 4
	seg[13] = 0x18
	binary.BigEndian.PutUint16(seg[14:16], 0x2000)
	copy(seg[20:], payload)

	if got, want := tcpChecksum6(ip6, seg), uint16(0x6a9f); got != want {
		t.Fatalf("tcpChecksum6 = 0x%04x, want 0x%04x", got, want)
	}
}

// Tests the dispatch, not just the instruction lists: sniffFilter used to
// call connIP.To4() unconditionally, which panics on an IPv6 address.
func TestSniffFilterDispatchesOnFamily(t *testing.T) {
	v4 := net.ParseIP("104.18.4.130")
	v6 := net.ParseIP("2606:4700:4700::1111")

	if _, err := sniffFilter(v4, false); err != nil {
		t.Fatalf("v4: %v", err)
	}
	if _, err := sniffFilter(v6, true); err != nil {
		t.Fatalf("v6: %v", err)
	}
	// A v6 address with v6=false is a configuration error: it must return an
	// error rather than dereference a nil To4().
	if _, err := sniffFilter(v6, false); err == nil {
		t.Fatal("v6 address with v6=false should be rejected")
	}
}
