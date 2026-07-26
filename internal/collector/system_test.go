package collector

import "testing"

func TestNormalizeVirtualization(t *testing.T) {
	tests := map[string]string{
		"KVM":                                   "KVM",
		"QEMU Standard PC (i440FX + PIIX)":      "KVM",
		"VMware, Inc.":                          "VMware",
		"Microsoft Corporation Virtual Machine": "Hyper-V",
	}
	for input, want := range tests {
		if got := normalizeVirtualization(input); got != want {
			t.Fatalf("normalizeVirtualization(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseCacheBytes(t *testing.T) {
	for input, want := range map[string]int64{
		"32K": 32 * 1024,
		"1M":  1024 * 1024,
		"64":  64,
	} {
		if got := parseCacheBytes(input); got != want {
			t.Fatalf("parseCacheBytes(%q) = %d, want %d", input, got, want)
		}
	}
}
