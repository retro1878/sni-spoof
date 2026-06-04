//go:build linux

// Linux raw-socket backend: AF_PACKET SOCK_RAW bound to the egress interface.
// Requires CAP_NET_RAW (run as root).

package main

import (
	"encoding/binary"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

// captureBufBytes is the SO_RCVBUF we request for the AF_PACKET socket. A few
// MiB absorbs short bursts so we don't drop the handshake/confirmation control
// packets the sniffer depends on. The kernel silently caps this at
// net.core.rmem_max, so the effective value may be lower.
const captureBufBytes = 4 * 1024 * 1024

// sniffFilter builds a classic-BPF program that the kernel applies to the
// AF_PACKET socket so only the packets sniffLoop actually acts on reach
// userspace: IPv4 TCP segments to/from connectIP that carry no payload (SYNs
// and pure ACKs). This drops every relayed data frame in the kernel, which is
// the bulk of the traffic on a busy forwarder. It is a safe superset of what
// sniffLoop inspects — every branch there already requires plen == 0 — and the
// precise localIP/connectIP matching still happens in Go.
//
// Equivalent tcpdump:
//
//	tcp and host <connectIP> and
//	  (ip[2:2] - ((ip[0]&0x0f)<<2) - ((tcp[12]&0xf0)>>2)) == 0
//
// Offsets are into the full Ethernet frame (14-byte L2 header included).
func sniffFilter(connIP []byte) ([]unix.SockFilter, error) {
	raw, err := bpf.Assemble(sniffFilterInsns(binary.BigEndian.Uint32(connIP)))
	if err != nil {
		return nil, err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return filter, nil
}

// sniffFilterInsns is the instruction list for sniffFilter, split out so it can
// be exercised by the pure-Go bpf.VM in tests.
func sniffFilterInsns(conn uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},                            // A = ethertype
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800, SkipTrue: 18}, // not IPv4 -> drop
		bpf.LoadAbsolute{Off: 23, Size: 1},                            // A = IP protocol
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 16},      // not TCP -> drop
		bpf.LoadAbsolute{Off: 26, Size: 4},                            // A = src IP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: conn, SkipTrue: 2},       // src==connIP -> hostOK
		bpf.LoadAbsolute{Off: 30, Size: 4},                            // A = dst IP
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: conn, SkipTrue: 12},   // dst!=connIP -> drop
		bpf.LoadMemShift{Off: 14},                                     // X = IP header length (bytes)
		bpf.LoadAbsolute{Off: 16, Size: 2},                            // A = IP total length
		bpf.ALUOpX{Op: bpf.ALUOpSub},                                  // A = total - ihl
		bpf.StoreScratch{Src: bpf.RegA, N: 0},                         // M[0] = A
		bpf.LoadIndirect{Off: 26, Size: 1},                            // A = tcp[12] (data-offset byte)
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},                //
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 2},            // A = TCP header length (bytes)
		bpf.TAX{},                            // X = TCP header length
		bpf.LoadScratch{Dst: bpf.RegA, N: 0}, // A = total - ihl
		bpf.ALUOpX{Op: bpf.ALUOpSub},         // A = TCP payload length
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0, SkipTrue: 1}, // payload != 0 -> drop
		bpf.RetConstant{Val: 262144},                            // accept (whole frame)
		bpf.RetConstant{Val: 0},                                 // drop
	}
}

func openRaw() error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}

	// Attach the kernel-side filter before binding so data frames are dropped
	// in the kernel and never reach the single sniffLoop goroutine.
	filter, err := sniffFilter(connectIP)
	if err != nil {
		unix.Close(fd)
		return err
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		unix.Close(fd)
		return err
	}

	// Grow the receive buffer so bursts don't drop the control packets.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, captureBufBytes)

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifaceIdx,
	}); err != nil {
		unix.Close(fd)
		return err
	}
	rawFd = fd
	return nil
}

func recvFrame(buf []byte) (int, error) {
	for {
		n, _, err := unix.Recvfrom(rawFd, buf, 0)
		if err == unix.EINTR {
			continue
		}
		return n, err
	}
}

func sendFrame(frame []byte) error {
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  ifaceIdx,
		Halen:    6,
	}
	copy(sll.Addr[:6], frame[0:6])
	return unix.Sendto(rawFd, frame, 0, sll)
}
