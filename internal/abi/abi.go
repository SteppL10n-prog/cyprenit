// Package abi defines the KERNEL<->USER wire contract (TEST-04).
//
// This layout MUST stay byte-for-byte identical to `struct cyprenit_evt` in
// ebpf/tls_probe.bpf.c. It is the only shared contract between the eBPF
// ring-buffer producer (kernel space) and the async Go consumer (user space).
// Any offset drift silently corrupts the PQC risk map, so sizes are pinned as
// constants and verified with golden hex vectors in abi_test.go.
package abi

import (
	"encoding/binary"
	"fmt"
)

// EventSize is sizeof(struct cyprenit_evt) — pinned, never derived at runtime.
//
//	off  0  u64 timestamp_ns      (bpf_ktime_get_ns)
//	off  8  u32 pid_tgid          (bpf_get_current_pid_tgid)
//	off 12  u32 saddr             (IPv4)
//	off 16  u32 daddr             (IPv4)
//	off 20  u16 sport
//	off 22  u16 dport
//	off 24  u8  direction         (0=egress,1=ingress)
//	off 25  u8  hs_type           (TLS HandshakeType: 1=ClientHello, 2=ServerHello, ...)
//	off 26  u16 tls_version       (0x0303 = TLS1.2, 0x0304 = TLS1.3)
//	off 28  u16 record_len        // valid bytes inside payload[]
//	off 30  u16 pad0
//	off 32  u32 cookie            // flow correlation id from socket_filter
//	off 36..128  payload[92]      // truncated TLS handshake bytes
const EventSize = 128

// PayloadMax mirrors the kernel-side truncation limit.
const PayloadMax = 92

// Handshake type constants (RFC 8446 §4.2.3 enum HandshakeType).
const (
	HSClientHello       uint8 = 1
	HSServerHello       uint8 = 2
	HSCertificate       uint8 = 11
	HSServerKeyExchange uint8 = 12
	HSCertificateVerify uint8 = 15
	HSFinished          uint8 = 20
)

// Direction constants.
const (
	DirEgress  uint8 = 0
	DirIngress uint8 = 1
)

// Event is one decoded ring-buffer record.
type Event struct {
	TimestampNS uint64
	PidTgid     uint32
	Saddr       [4]byte
	Daddr       [4]byte
	Sport       uint16
	Dport       uint16
	Direction   uint8
	HSType      uint8
	TLSVersion  uint16
	RecordLen   uint16
	Cookie      uint32
	Payload     []byte // len <= PayloadMax; owned by caller after Decode
}

// Encode serialises an Event into exactly EventSize bytes (big-endian wire
// order, matching the BPF side which reads raw packet bytes).
func (e *Event) Encode(buf []byte) error {
	if len(buf) < EventSize {
		return fmt.Errorf("abi: buffer too small: %d < %d", len(buf), EventSize)
	}
	pl := e.Payload
	if len(pl) > PayloadMax {
		pl = pl[:PayloadMax] // same truncation policy as the kernel probe
	}
	recLen := e.RecordLen
	if recLen == 0 {
		recLen = uint16(len(pl))
	}
	binary.BigEndian.PutUint64(buf[0:8], e.TimestampNS)
	binary.BigEndian.PutUint32(buf[8:12], e.PidTgid)
	copy(buf[12:16], e.Saddr[:])
	copy(buf[16:20], e.Daddr[:])
	binary.BigEndian.PutUint16(buf[20:22], e.Sport)
	binary.BigEndian.PutUint16(buf[22:24], e.Dport)
	buf[24] = e.Direction
	buf[25] = e.HSType
	binary.BigEndian.PutUint16(buf[26:28], e.TLSVersion)
	binary.BigEndian.PutUint16(buf[28:30], recLen)
	binary.BigEndian.PutUint16(buf[30:32], 0) // pad
	binary.BigEndian.PutUint32(buf[32:36], e.Cookie)
	copy(buf[36:EventSize], pl)
	for i := 36 + len(pl); i < EventSize; i++ {
		buf[i] = 0 // zero-fill tail so golden vectors are deterministic
	}
	return nil
}

// Decode parses exactly one record. It returns an error — never panics — on
// short buffers or inconsistent RecordLen: malformed kernel data must degrade
// to drops, not crashes (TEST-05 panic isolation).
func Decode(buf []byte) (*Event, error) {
	if len(buf) < EventSize {
		return nil, fmt.Errorf("abi: short event: %d < %d", len(buf), EventSize)
	}
	e := &Event{
		TimestampNS: binary.BigEndian.Uint64(buf[0:8]),
		PidTgid:     binary.BigEndian.Uint32(buf[8:12]),
		Sport:       binary.BigEndian.Uint16(buf[20:22]),
		Dport:       binary.BigEndian.Uint16(buf[22:24]),
		Direction:   buf[24],
		HSType:      buf[25],
		TLSVersion:  binary.BigEndian.Uint16(buf[26:28]),
		RecordLen:   binary.BigEndian.Uint16(buf[28:30]),
		Cookie:      binary.BigEndian.Uint32(buf[32:36]),
	}
	copy(e.Saddr[:], buf[12:16])
	copy(e.Daddr[:], buf[16:20])
	if e.RecordLen > PayloadMax {
		return nil, fmt.Errorf("abi: record_len %d exceeds payload cap %d", e.RecordLen, PayloadMax)
	}
	e.Payload = append([]byte(nil), buf[36:36+e.RecordLen]...) // fresh copy
	return e, nil
}
