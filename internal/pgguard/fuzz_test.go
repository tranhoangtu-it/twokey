package pgguard

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzReadMessage: no panic on any client byte stream; a message is only
// returned when its whole payload arrived (so nothing is allocated beyond
// the bytes received), and its length matches the header.
func FuzzReadMessage(f *testing.F) {
	f.Add([]byte("Q\x00\x00\x00\x0dSELECT 1\x00"))
	f.Add([]byte("P\x00\x00\x00\x08\x00x\x00\x00"))
	f.Add([]byte("Q\x04\x00\x00\x00"))
	f.Add([]byte("Q\x00\x00\x00\x03"))
	f.Add([]byte{'S', 0, 0, 0, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		consumed := 0
		for {
			_, payload, err := readMessage(r, maxClientMessage)
			if err != nil {
				return
			}
			declared := int(binary.BigEndian.Uint32(data[consumed+1:])) - 4
			if len(payload) != declared {
				t.Fatalf("payload %d bytes, header said %d", len(payload), declared)
			}
			consumed += 5 + len(payload)
			if consumed > len(data) {
				t.Fatalf("returned more bytes than were received")
			}
			_ = startupParam(payload, "database")
			_ = cstring(payload)
		}
	})
}
