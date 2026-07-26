package privacy

import "testing"

func TestMaskIP(t *testing.T) {
	tests := map[string]string{
		"29.35.12.34":        "29.35.*.*",
		"2408:8214:1234::99": "2408:8214:1234:*:*:*:*:*",
	}
	for input, expected := range tests {
		actual, err := MaskIP(input)
		if err != nil {
			t.Fatalf("MaskIP(%q): %v", input, err)
		}
		if actual != expected {
			t.Fatalf("MaskIP(%q)=%q, want %q", input, actual, expected)
		}
	}
}

func TestScanJSON(t *testing.T) {
	if err := ScanJSON([]byte(`{"masked_ipv4":"29.35.*.*"}`)); err != nil {
		t.Fatalf("masked payload rejected: %v", err)
	}
	if err := ScanJSON([]byte(`{"masked_ipv4":"29.35.12.34"}`)); err == nil {
		t.Fatal("full IPv4 was accepted")
	}
	if err := ScanJSON([]byte(`{"hostname":"secret-host"}`)); err == nil {
		t.Fatal("forbidden hostname was accepted")
	}
}
