package myguard

import (
	"encoding/binary"
	"testing"
)

// TestQueryTextStripsQueryAttributes guards the bypass found against a
// real MySQL 9 server: with CLIENT_QUERY_ATTRIBUTES the SQL is preceded by
// lenenc(param_count)=0 and lenenc(param_set_count)=1.
func TestQueryTextStripsQueryAttributes(t *testing.T) {
	body := append([]byte{0x00, 0x01}, "DROP TABLE shop.users"...)
	got, err := queryText(body, true)
	if err != nil || got != "DROP TABLE shop.users" {
		t.Fatalf("queryText = %q, %v", got, err)
	}
	if got, _ := queryText([]byte("SELECT 1"), false); got != "SELECT 1" {
		t.Fatalf("without attributes the body is the SQL, got %q", got)
	}
	if _, err := queryText([]byte{0x02, 0x01, 0x00}, true); err == nil {
		t.Fatal("queries carrying attributes must fail closed")
	}
	if _, err := queryText([]byte{0xfc, 0x01}, true); err == nil {
		t.Fatal("truncated lenenc must be an error")
	}
}

func TestLenencInt(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
		n    int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0xfc, 0x34, 0x12}, 0x1234, 3},
		{[]byte{0xfd, 0x01, 0x02, 0x03}, 0x030201, 4},
	}
	for _, c := range cases {
		v, n, ok := lenencInt(c.in)
		if !ok || v != c.want || n != c.n {
			t.Errorf("lenencInt(%x) = %d,%d,%v want %d,%d", c.in, v, n, ok, c.want, c.n)
		}
	}
}

func TestClearSSLCapabilityReturnsServerCaps(t *testing.T) {
	// Minimal v10 greeting: version "9.6.0\0", conn id, 8 bytes auth, filler,
	// caps lower, charset, status, caps upper.
	p := []byte{10}
	p = append(p, "9.6.0\x00"...)
	p = append(p, 1, 0, 0, 0)
	p = append(p, make([]byte, 8)...)
	p = append(p, 0)
	lower := make([]byte, 2)
	binary.LittleEndian.PutUint16(lower, 0xffff)
	p = append(p, lower...)
	p = append(p, 0xff, 0x02, 0x00)
	upper := make([]byte, 2)
	binary.LittleEndian.PutUint16(upper, uint16(clientQueryAttributes>>16))
	p = append(p, upper...)

	caps := clearSSLCapability(p)
	if caps&clientSSL == 0 {
		t.Fatal("the server's original caps (incl. CLIENT_SSL) must be reported for upstream TLS")
	}
	if caps&clientQueryAttributes == 0 {
		t.Fatal("upper capability flags must be read")
	}
	if binary.LittleEndian.Uint16(p[1+6+4+8+1:])&clientSSL != 0 {
		t.Fatal("CLIENT_SSL must be cleared in the packet sent to the client")
	}
}
