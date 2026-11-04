package myguard

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzReadPacket: no panic on any byte stream; a packet is only returned
// when its whole payload arrived, with the length from its header. The
// payload helpers (query attributes, capability rewrite, login checks)
// never panic on it either.
func FuzzReadPacket(f *testing.F) {
	f.Add([]byte("\x09\x00\x00\x00\x03SELECT 1"))
	f.Add([]byte("\x03\x00\x00\x00\x03\x00\x01"))
	f.Add([]byte{0xff, 0xff, 0xff, 0x00})
	f.Add(append([]byte{byte(len(greetingPacket(0xffffffff))), 0, 0, 0}, greetingPacket(0xffffffff)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		consumed := 0
		for {
			seq, p, err := readPacket(r)
			if err != nil {
				return
			}
			declared := int(data[consumed]) | int(data[consumed+1])<<8 | int(data[consumed+2])<<16
			if len(p) != declared {
				t.Fatalf("payload %d bytes, header said %d", len(p), declared)
			}
			consumed += 4 + len(p)
			if consumed > len(data) {
				t.Fatal("returned more bytes than were received")
			}
			if len(p) > 0 {
				if text, err := queryText(p[1:], true); err == nil && !bytes.HasSuffix(p[1:], []byte(text)) {
					t.Fatalf("query text %q is not a suffix of the body", text)
				}
			}
			_ = refuseLogin(seq, p)
			caps := hideCapabilities(append([]byte(nil), p...))
			_ = caps
		}
	})
}
