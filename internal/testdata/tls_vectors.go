// Package testdata builds REAL RFC 8446 wire-format TLS ClientHello vectors
// used by TEST-03 (algorithm detection) and the --dry-run feed. Shared
// between tests and the loader so both exercise identical bytes.
package testdata

import "encoding/binary"

// KeyShareEntry is one client_side share: named group + opaque key material.
type KeyShareEntry struct {
	Group uint16
	Key   []byte
}

// ClientHello assembles a full TLS record:
//
//	0x16 | ver(2) | len(2) || hs_type=1 | hs_len(3) | legacy_version(2)
//	| random(32) | sid_len(1) sid | cs_len(2) suites | cm(1+len) | ext block
func ClientHello(tlsVersion uint16, suites []uint16, shares []KeyShareEntry) []byte {
	var body []byte
	body = append(body, byte(tlsVersion>>8), byte(tlsVersion)) // legacy_version
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}
	body = append(body, random...)
	body = append(body, 0x20) // session id length 32 (TLS1.3 style)
	sid := make([]byte, 32)
	body = append(body, sid...)

	cs := make([]byte, 2*len(suites))
	for i, s := range suites {
		binary.BigEndian.PutUint16(cs[2*i:], s)
	}
	body = append(body, byte(len(cs)>>8), byte(len(cs)))
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // one compression method: NULL

	var exts []byte
	if len(shares) > 0 {
		var ks []byte
		for _, sh := range shares {
			var e [4]byte
			binary.BigEndian.PutUint16(e[0:2], sh.Group)
			binary.BigEndian.PutUint16(e[2:4], uint16(len(sh.Key)))
			ks = append(ks, e[:]...)
			ks = append(ks, sh.Key...)
		}
		lst := make([]byte, 2+len(ks))
		binary.BigEndian.PutUint16(lst, uint16(len(ks)))
		copy(lst[2:], ks)
		hdr := []byte{0x00, 0x33, byte(len(lst) >> 8), byte(len(lst))} // ext type 51 key_share
		exts = append(exts, hdr...)
		exts = append(exts, lst...)
	}
	if len(exts) > 0 {
		body = append(body, byte(len(exts)>>8), byte(len(exts)))
		body = append(body, exts...)
	}

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// ---------------------------------------------------------------------------
// TEST-03 vectors — sized to fit the kernel's 92-byte payload window after
// the probe strips the 5-byte record header (see abi.PayloadMax).
// ---------------------------------------------------------------------------

var (
	// RSA key exchange: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x002C), no key_share.
	RSAClientHello = ClientHello(0x0303, []uint16{0x002C, 0x0035}, nil)

	// Pure ECC: TLS1.3 suite + X25519 (0x001D) share.
	ECCClientHello = ClientHello(0x0303, []uint16{0x1301, 0x1303},
		[]KeyShareEntry{{Group: 0x001D, Key: make([]byte, 8)}})

	// Pure PQC: ML-KEM-768 codepoint 4588 only.
	PQCClientHello = ClientHello(0x0303, []uint16{0x1301},
		[]KeyShareEntry{{Group: 4588, Key: make([]byte, 8)}})

	// Hybrid: X25519 + ML-KEM-768 offered together (current Chrome/CF style).
	HybridClientHello = ClientHello(0x0303, []uint16{0x1301},
		[]KeyShareEntry{
			{Group: 0x001D, Key: make([]byte, 8)},
			{Group: 4588, Key: make([]byte, 8)},
		})
)
