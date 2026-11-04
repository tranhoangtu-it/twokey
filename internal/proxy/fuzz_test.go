package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"strings"
	"testing"
)

func FuzzDecodeForInspection(f *testing.F) {
	plain := []byte(`{"query":"mutation { volumeDelete(volumeId: \"v\") }"}`)
	var gz, zl bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(plain)
	gw.Close()
	zw := zlib.NewWriter(&zl)
	_, _ = zw.Write(plain)
	zw.Close()
	f.Add("", plain)
	f.Add("gzip", gz.Bytes())
	f.Add("x-gzip", gz.Bytes()[:10])
	f.Add("deflate", zl.Bytes())
	f.Add("br", plain)
	f.Add(" GZIP ", []byte{})
	f.Fuzz(func(t *testing.T, encoding string, body []byte) {
		out, err := decodeForInspection(encoding, body)
		if err != nil {
			return // check() turns this into an uninspectable hold
		}
		if len(out) > maxInspectBody {
			t.Fatalf("decoded %d bytes, cap is %d", len(out), maxInspectBody)
		}
		switch strings.ToLower(strings.TrimSpace(encoding)) {
		case "", "identity", "gzip", "x-gzip", "deflate":
		default:
			if len(body) > 0 {
				t.Fatalf("unsupported encoding %q decoded without error", encoding)
			}
		}
	})
}
